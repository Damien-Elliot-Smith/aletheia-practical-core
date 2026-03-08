"""
Aletheia Siren v1 (Practical Core)

Purpose:
- Track health/degradation state deterministically
- Emit MAYDAY events on every state transition
- Emit periodic heartbeat events while degraded
- Persist state so restarts don't silently reset reality

Philosophy:
- Siren does NOT fix problems. It reports them.
- Transitions are explicit and logged to Spine (the single truth trail).
"""

from __future__ import annotations

import time
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional

from aletheia.spine.ledger import SpineLedger


class SirenState(str, Enum):
    NORMAL = "NORMAL"
    DEGRADED_CAPTURE = "DEGRADED_CAPTURE"   # witness capture off (or reduced)
    SUMMARIES_ONLY = "SUMMARIES_ONLY"       # only summaries, no full witness
    HALT = "HALT"                           # ingest halted


# Minimal reason code registry (expand later; keep closed + versioned in future)
class MaydayCode(str, Enum):
    DISK_PRESSURE = "DISK_PRESSURE"
    VERIFY_FAIL = "VERIFY_FAIL"
    INTEGRITY_COMPROMISE = "INTEGRITY_COMPROMISE"
    MANUAL = "MANUAL"
    RECOVERED = "RECOVERED"
    HEARTBEAT = "HEARTBEAT"


@dataclass
class SirenConfig:
    window_id: str = "siren"
    heartbeat_interval_s: int = 10


class Siren:
    """
    Siren controller bound to a Spine ledger.

    State is persisted under: <root>/spine/siren_state.json
    using atomic writes via SpineLedger's durable write pattern (implemented here similarly).
    """
    def __init__(self, ledger: SpineLedger, config: Optional[SirenConfig] = None):
        self.ledger = ledger
        self.config = config or SirenConfig()
        self.state_path = self.ledger.spine_dir / "siren_state.json"
        self._state: SirenState = SirenState.NORMAL
        self._last_heartbeat_ns: Optional[int] = None

        self._load_or_init_state()
        # Ensure window exists for Siren events
        self.ledger.open_window(self.config.window_id)

    @property
    def state(self) -> SirenState:
        return self._state

    def transition(self, new_state: SirenState, reason: MaydayCode, details: Optional[Dict[str, Any]] = None) -> None:
        """
        Transition and emit MAYDAY (always, even if state repeats).
        Repeats are allowed because the point is explicit audit trails.
        """
        old = self._state
        self._state = new_state
        self._persist_state()

        payload: Dict[str, Any] = {
            "from_state": old.value,
            "to_state": new_state.value,
            "reason_code": reason.value,
        }
        if details:
            payload["details"] = details

        self.ledger.append_event(self.config.window_id, "MAYDAY", payload)

        # Heartbeat handling
        if new_state == SirenState.NORMAL:
            self._last_heartbeat_ns = None
        else:
            # start heartbeat clock immediately
            self._last_heartbeat_ns = time.monotonic_ns()

    def recover_to_normal(self, details: Optional[Dict[str, Any]] = None) -> None:
        self.transition(SirenState.NORMAL, MaydayCode.RECOVERED, details=details)

    def tick(self, now_ns: Optional[int] = None) -> None:
        """
        Call periodically by host loop.
        Emits heartbeat MAYDAY_HEARTBEAT while degraded.
        """
        if self._state == SirenState.NORMAL:
            return

        now_ns = now_ns if now_ns is not None else time.monotonic_ns()
        if self._last_heartbeat_ns is None:
            self._last_heartbeat_ns = now_ns
            return

        interval_ns = int(self.config.heartbeat_interval_s * 1_000_000_000)
        if now_ns - self._last_heartbeat_ns >= interval_ns:
            self._last_heartbeat_ns = now_ns
            payload = {
                "state": self._state.value,
                "reason_code": MaydayCode.HEARTBEAT.value,
            }
            self.ledger.append_event(self.config.window_id, "MAYDAY_HEARTBEAT", payload)
            self._persist_state()  # keep last heartbeat persisted

    # ---------- Persistence ----------

    def _load_or_init_state(self) -> None:
        """
        Phase 1.2 — Siren State Verified Against Spine (closes RT-02).

        Previously: siren_state.json was loaded and trusted on boot (overwritable).
        Now: replay the siren window from Spine to reconstruct the true last state.

        siren_state.json is now a performance cache only. If the file says NORMAL but
        Spine replay shows DEGRADED_CAPTURE, the Spine wins. If the file is unreadable,
        fall back to Spine replay entirely.
        """
        # Step 1: replay Spine to find ground-truth last state
        spine_state = self._replay_state_from_spine()

        # Step 2: read the cache file
        cached_state = None
        cached_lhb = None
        if self.state_path.exists():
            try:
                obj = json.loads(self.state_path.read_text(encoding="utf-8"))
                st = obj.get("state")
                if st in SirenState._value2member_map_:
                    cached_state = SirenState(st)
                lhb = obj.get("last_heartbeat_ns")
                if isinstance(lhb, int):
                    cached_lhb = lhb
            except Exception:
                cached_state = None

        # Step 3: Spine wins on conflict. Cache is only used if it matches or spine has no opinion.
        if spine_state is not None:
            if cached_state is not None and cached_state != spine_state:
                # Log the discrepancy — file was tampered or stale
                self._state = spine_state
                self._persist_state()
                self.ledger.append_event(self.config.window_id, "MAYDAY", {
                    "from_state": cached_state.value,
                    "to_state": spine_state.value,
                    "reason_code": MaydayCode.VERIFY_FAIL.value,
                    "details": {
                        "note": "siren_state.json conflicted with Spine replay; Spine wins.",
                        "cached": cached_state.value,
                        "spine": spine_state.value,
                    },
                })
                return
            self._state = spine_state
        elif cached_state is not None:
            self._state = cached_state
        else:
            self._state = SirenState.NORMAL

        if cached_lhb is not None:
            self._last_heartbeat_ns = cached_lhb

        self._persist_state()

    def _replay_state_from_spine(self) -> "Optional[SirenState]":
        """
        Walk the siren window events in order and reconstruct the final state.
        Returns the last known SirenState, or None if no siren events found.
        Cost: negligible — siren window is small.
        """
        windows_dir = self.ledger.spine_dir / "windows"
        siren_wdir = windows_dir / self.config.window_id
        events_dir = siren_wdir / "events"
        if not events_dir.exists():
            return None

        import os as _os
        files = sorted(events_dir.glob("*.json"))
        files = [f for f in files if f.name[:6].isdigit()]
        if not files:
            return None

        state: Optional[SirenState] = None
        for f in files:
            try:
                ev = json.loads(f.read_text(encoding="utf-8"))
                etype = ev.get("event_type", "")
                payload = ev.get("payload", {})
                if etype == "MAYDAY":
                    to_state = payload.get("to_state")
                    if to_state in SirenState._value2member_map_:
                        state = SirenState(to_state)
            except Exception:
                continue
        return state

    def _persist_state(self) -> None:
        obj = {
            "state": self._state.value,
            "last_heartbeat_ns": self._last_heartbeat_ns,
        }
        data = (json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
        # Atomic write pattern (temp -> fsync -> replace)
        tmp = self.state_path.with_suffix(".json.tmp")
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        import os as _os
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            _os.fsync(f.fileno())
        _os.replace(tmp, self.state_path)
        try:
            dir_fd = _os.open(str(self.state_path.parent), _os.O_DIRECTORY)
            try:
                _os.fsync(dir_fd)
            finally:
                _os.close(dir_fd)
        except Exception:
            pass
