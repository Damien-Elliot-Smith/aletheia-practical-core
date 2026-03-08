"""
aletheia.streaming.scheduler — Rolling Window Scheduler (Phase 2.1)

Problem: v1 is batch-oriented — you manually open, append, seal.
Real deployments (OT sensors, security streams, AI agent logs) generate
continuous data. A crash mid-session loses the entire unseal period.

Solution: WindowScheduler auto-seals the current window and rolls to a
new one when a configurable threshold is crossed:
  - max_events_per_window: seal when N events written (default: 10,000)
  - max_window_age_s: seal when window has been open N seconds (default: 3600)

Both conditions are checked independently — whichever fires first.

The naming convention for auto-rolled windows:
  <base_id>_<YYYYMMDD_HHMMSS>_<seq>
e.g. ingest_20260308_143022_001

Design rules:
  - Never drops events. If the current window must seal mid-stream, the
    event is appended to the new window after the roll.
  - Thread-safe: a single threading.Lock guards window state.
  - No background threads by default — check() is called by the caller
    or by the adapter's ingest loop. An optional background thread mode
    is available for wall-clock-based rolling.
  - INCONCLUSIVE-first: if the scheduler cannot open a new window,
    it raises SchedulerError — never silently drops.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Tuple

from aletheia.spine.ledger import SpineLedger
from aletheia.siren.state_machine import Siren, SirenState, MaydayCode


class SchedulerError(Exception):
    pass


class SchedulerState(str, Enum):
    RUNNING = "RUNNING"
    ROLLING = "ROLLING"   # mid-seal/open transition
    STOPPED = "STOPPED"


@dataclass
class SchedulerConfig:
    # Base window ID. Rolled windows are named <base_id>_<ts>_<seq>
    base_window_id: str = "ingest"
    # Seal + roll when event count reaches this (0 = disabled)
    max_events_per_window: int = 10_000
    # Seal + roll when window age in seconds reaches this (0 = disabled)
    max_window_age_s: float = 3600.0
    # Roll immediately when Siren enters SUMMARIES_ONLY or HALT
    roll_on_siren_degrade: bool = True


@dataclass
class WindowSlot:
    window_id: str
    opened_at: float        # monotonic
    event_count: int = 0


class WindowScheduler:
    """
    Auto-rolling window manager.

    Usage:
        scheduler = WindowScheduler(ledger, siren=siren)
        scheduler.start()

        # Instead of ledger.append_event(...), use:
        scheduler.append_event("WITNESS", {"sensor": "A", "value": 42})

        # When done:
        scheduler.stop()  # seals current window cleanly

    The scheduler opens the first window on start(). It checks roll
    conditions on every append_event() call — no polling thread needed
    for event-count-based rolling.

    For time-based rolling in a low-traffic deployment, call
    scheduler.check() periodically, or enable background_tick=True
    which starts a daemon thread calling check() every tick_interval_s.
    """

    def __init__(
        self,
        ledger: SpineLedger,
        *,
        config: Optional[SchedulerConfig] = None,
        siren: Optional[Siren] = None,
        background_tick: bool = False,
        tick_interval_s: float = 30.0,
    ) -> None:
        self.ledger = ledger
        self.config = config or SchedulerConfig()
        self.siren = siren
        self._lock = threading.Lock()
        self._state = SchedulerState.STOPPED
        self._seq = 0
        self._current: Optional[WindowSlot] = None
        self._sealed_windows: List[str] = []
        self._background_tick = background_tick
        self._tick_interval_s = tick_interval_s
        self._tick_thread: Optional[threading.Thread] = None

    # ── Public API ──────────────────────────────────────────────────────────

    def start(self) -> str:
        """Open first window. Returns window_id. Idempotent if already running."""
        with self._lock:
            if self._state == SchedulerState.RUNNING:
                assert self._current is not None
                return self._current.window_id
            wid = self._new_window_id()
            self.ledger.open_window(wid)
            self._current = WindowSlot(window_id=wid, opened_at=time.monotonic())
            self._state = SchedulerState.RUNNING

        if self._background_tick:
            self._start_tick_thread()

        return wid

    def stop(self) -> Optional[str]:
        """Seal current window cleanly. Returns sealed window_id or None."""
        with self._lock:
            if self._state != SchedulerState.RUNNING or self._current is None:
                self._state = SchedulerState.STOPPED
                return None
            wid = self._current.window_id
            self._seal_current()
            self._state = SchedulerState.STOPPED
            return wid

    def append_event(self, event_type: str, payload: dict) -> str:
        """
        Append an event to the current window.
        Rolls to a new window first if thresholds are crossed.
        Returns the window_id the event was written to.
        """
        with self._lock:
            if self._state != SchedulerState.RUNNING:
                raise SchedulerError(
                    f"WindowScheduler not running (state={self._state}). Call start() first."
                )
            # Check Siren state before appending
            if self.siren is not None and self.config.roll_on_siren_degrade:
                if self.siren.state in (SirenState.SUMMARIES_ONLY, SirenState.HALT):
                    raise SchedulerError(
                        f"Ingest blocked: Siren is {self.siren.state.value}. "
                        "System must recover before evidence capture resumes."
                    )

            # Roll if needed before writing
            if self._should_roll():
                self._roll()

            assert self._current is not None
            self.ledger.append_event(self._current.window_id, event_type, payload)
            self._current.event_count += 1
            return self._current.window_id

    def check(self) -> bool:
        """
        Check roll conditions. Roll if triggered.
        Returns True if a roll occurred.
        Call this periodically for time-based rolling in low-traffic deployments.
        """
        with self._lock:
            if self._state != SchedulerState.RUNNING:
                return False
            if self._should_roll():
                self._roll()
                return True
            return False

    @property
    def current_window_id(self) -> Optional[str]:
        return self._current.window_id if self._current else None

    @property
    def sealed_windows(self) -> List[str]:
        return list(self._sealed_windows)

    @property
    def state(self) -> SchedulerState:
        return self._state

    @property
    def current_event_count(self) -> int:
        return self._current.event_count if self._current else 0

    # ── Internal ─────────────────────────────────────────────────────────────

    def _should_roll(self) -> bool:
        if self._current is None:
            return False
        cfg = self.config
        if cfg.max_events_per_window > 0:
            if self._current.event_count >= cfg.max_events_per_window:
                return True
        if cfg.max_window_age_s > 0:
            age = time.monotonic() - self._current.opened_at
            if age >= cfg.max_window_age_s:
                return True
        return False

    def _roll(self) -> None:
        """Seal current window, open next. Called with lock held."""
        assert self._current is not None
        self._state = SchedulerState.ROLLING
        try:
            old_wid = self._current.window_id
            self.ledger.seal_window(old_wid)
            self._sealed_windows.append(old_wid)

            new_wid = self._new_window_id()
            self.ledger.open_window(new_wid)
            self._current = WindowSlot(window_id=new_wid, opened_at=time.monotonic())
        finally:
            self._state = SchedulerState.RUNNING

    def _seal_current(self) -> None:
        """Seal without rolling. Called with lock held."""
        if self._current is not None:
            self.ledger.seal_window(self._current.window_id)
            self._sealed_windows.append(self._current.window_id)
            self._current = None

    def _new_window_id(self) -> str:
        self._seq += 1
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        return f"{self.config.base_window_id}_{ts}_{self._seq:03d}"

    def _start_tick_thread(self) -> None:
        def _tick():
            while self._state == SchedulerState.RUNNING:
                time.sleep(self._tick_interval_s)
                try:
                    self.check()
                except Exception:
                    pass  # never crash background thread

        self._tick_thread = threading.Thread(target=_tick, daemon=True, name="aletheia-scheduler-tick")
        self._tick_thread.start()
