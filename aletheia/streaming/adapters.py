"""
aletheia.streaming.adapters — Stream Adapters (Phase 2.1)

A StreamAdapter wraps IngestGate and WindowScheduler, providing a
standard lifecycle for continuous evidence sources.

Lifecycle:
  adapter.start()           — open window, begin capture
  adapter.run() or .step()  — consume + ingest (blocking or one step)
  adapter.stop()            — drain, seal window cleanly

Implementations shipped:
  FileAdapter     — tail a log file, ingest each new line as a WITNESS
  CallbackAdapter — ingest from a caller-supplied generator or iterable

All adapters emit structured Spine events, not raw strings.
The IngestGate validates and rejects at the edge — adapters never bypass it.

Design rules:
  - Adapters are stateless between calls — all state is in the Spine.
  - An adapter that cannot parse a record emits a PARSE_SKIP event
    (not a crash, not a silent drop).
  - rate_limit and payload_limits are enforced by IngestGate — adapters
    do not duplicate this logic.
"""
from __future__ import annotations

import io
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Generator, Iterable, Iterator, Optional

from aletheia.ingest.gate import IngestGate, IngestConfig, IngestDecision
from aletheia.spine.ledger import SpineLedger
from aletheia.siren.state_machine import Siren
from aletheia.streaming.scheduler import WindowScheduler, SchedulerConfig


# ── Base class ────────────────────────────────────────────────────────────────

class AdapterError(Exception):
    pass


@dataclass
class AdapterStats:
    accepted: int = 0
    rejected: int = 0
    skipped: int = 0    # parse failures
    rolled: int = 0     # window rolls triggered
    errors: int = 0


class StreamAdapter(ABC):
    """
    Abstract base class for all stream adapters.

    Subclasses implement _next_record() which returns a single
    (source, event_type, payload) tuple or None when the stream
    is exhausted or paused.
    """

    def __init__(
        self,
        ledger: SpineLedger,
        *,
        scheduler: Optional[WindowScheduler] = None,
        gate: Optional[IngestGate] = None,
        siren: Optional[Siren] = None,
        scheduler_config: Optional[SchedulerConfig] = None,
        gate_config: Optional[IngestConfig] = None,
        source_name: str = "adapter",
        allow_float_payload: bool = False,
    ) -> None:
        self.ledger = ledger
        self.siren = siren
        self.source_name = source_name
        self.stats = AdapterStats()
        self._running = False

        # If floats are needed, use a float-permitting ledger for the scheduler
        if allow_float_payload and not ledger.allow_float_payload:
            from aletheia.spine.ledger import SpineLedger as _SL
            _sched_ledger = _SL(ledger.root_dir, allow_float_payload=True,
                                signer=ledger._signer)
        else:
            _sched_ledger = ledger

        # Build scheduler if not supplied
        if scheduler is not None:
            self.scheduler = scheduler
        else:
            self.scheduler = WindowScheduler(
                _sched_ledger,
                config=scheduler_config or SchedulerConfig(base_window_id=source_name),
                siren=siren,
            )

        # Build gate if not supplied (validation-only — writes go through scheduler)
        if gate is not None:
            self.gate = gate
        else:
            cfg = gate_config or IngestConfig(window_id=self.scheduler.config.base_window_id)
            self.gate = IngestGate(ledger, siren=siren, config=cfg)

    def start(self) -> str:
        """Open first window and mark adapter as running. Returns window_id."""
        wid = self.scheduler.start()
        self._running = True
        return wid

    def stop(self) -> None:
        """Drain pending work, seal window cleanly."""
        self._running = False
        self.scheduler.stop()

    def step(self) -> bool:
        """
        Process one record from the source.
        Returns True if a record was processed, False if source is paused/empty.

        Design: gate validates + rate-limits; scheduler writes + rolls.
        The gate is used in validate-only mode — its window_id is irrelevant
        because the scheduler controls which window events land in.
        """
        if not self._running:
            raise AdapterError("Adapter not started. Call start() first.")

        record = self._next_record()
        if record is None:
            return False

        source, event_type, payload = record

        # Validate through gate (rejects malformed, oversized, rate-limited records)
        val_result = self.gate._validate({
            "source": source or self.source_name,
            "event_type": event_type,
            "payload": payload,
        })

        if val_result.decision.value == "REJECT":
            # Record the rejection in the gate's ring log
            self.gate._record_reject(val_result, {"source": source, "event_type": event_type})
            self.stats.rejected += 1
            return True

        # Rate-limit check
        if not self.gate.bucket.allow(1.0):
            from aletheia.ingest.gate import IngestResult, IngestDecision, RejectReason
            rate_result = IngestResult(decision=IngestDecision.REJECT, reason=RejectReason.RATE_LIMIT)
            self.gate._record_reject(rate_result, {})
            self.stats.rejected += 1
            return True

        # Write through scheduler so rolling works
        assert val_result.payload is not None
        self.scheduler.append_event(val_result.event_type, val_result.payload)
        self.stats.accepted += 1

        # Check for time-based roll after writing
        rolled_before = len(self.scheduler.sealed_windows)
        self.scheduler.check()
        if len(self.scheduler.sealed_windows) > rolled_before:
            self.stats.rolled += 1

        return True

    def run(self, max_records: Optional[int] = None) -> AdapterStats:
        """
        Run until source exhausted, stop() called, or max_records reached.
        Blocks. Returns stats.
        """
        count = 0
        while self._running:
            got = self.step()
            if not got:
                break
            count += 1
            if max_records is not None and count >= max_records:
                break
        return self.stats

    @abstractmethod
    def _next_record(self) -> Optional[tuple]:
        """
        Return (source, event_type, payload) or None if nothing available.
        Never raise — log + return None on parse failures.
        """


# ── FileAdapter ────────────────────────────────────────────────────────────────

@dataclass
class FileAdapterConfig:
    # If True, tail the file (wait for new lines). If False, read once and stop.
    follow: bool = False
    # Poll interval when tailing with no new data (seconds)
    poll_interval_s: float = 0.5
    # Function to parse a raw line into (event_type, payload_dict).
    # Default: treat each line as {"line": raw_line}, event_type=LINE
    line_parser: Optional[Callable[[str], tuple]] = None
    # Event type to emit when parser is not set
    default_event_type: str = "LINE"
    # Encoding for the file
    encoding: str = "utf-8"
    # Skip lines that fail to parse (emit PARSE_SKIP event instead)
    skip_parse_errors: bool = True


def _default_line_parser(line: str) -> tuple:
    """Default: wrap raw line as a WITNESS event payload."""
    return ("LINE", {"line": line.rstrip("\n\r")})


class FileAdapter(StreamAdapter):
    """
    Tail a log file and ingest each new line as a Spine event.

    Each line is passed through line_parser (default: raw string payload).
    Bad lines emit a PARSE_SKIP event with the raw line truncated to 200 chars.

    Example:
        adapter = FileAdapter(ledger, path="/var/log/app.log", follow=True)
        adapter.start()
        adapter.run()   # blocks until stop() called from another thread
    """

    def __init__(
        self,
        ledger: SpineLedger,
        path: str,
        *,
        config: Optional[FileAdapterConfig] = None,
        **kwargs,
    ) -> None:
        super().__init__(ledger, **kwargs)
        self.path = path
        self.config = config or FileAdapterConfig()
        self._parser = self.config.line_parser or _default_line_parser
        self._fh: Optional[io.TextIOWrapper] = None
        self._eof = False

    def start(self) -> str:
        wid = super().start()
        self._fh = open(self.path, "r", encoding=self.config.encoding, errors="replace")
        return wid

    def stop(self) -> None:
        super().stop()
        if self._fh:
            self._fh.close()
            self._fh = None

    def _next_record(self) -> Optional[tuple]:
        if self._fh is None:
            return None

        line = self._fh.readline()

        if not line:
            # EOF
            if not self.config.follow:
                self._eof = True
                self._running = False
                return None
            # Tailing: wait and try again next call
            time.sleep(self.config.poll_interval_s)
            return None

        try:
            event_type, payload = self._parser(line)
            return (self.source_name, event_type, payload)
        except Exception as exc:
            self.stats.skipped += 1
            if self.config.skip_parse_errors:
                # Emit a PARSE_SKIP event — never silently drop
                return (
                    self.source_name,
                    "PARSE_SKIP",
                    {"raw": line[:200], "error": str(exc)[:200]},
                )
            raise AdapterError(f"Line parse failed: {exc}") from exc


# ── CallbackAdapter ────────────────────────────────────────────────────────────

class CallbackAdapter(StreamAdapter):
    """
    Ingest from a caller-supplied generator or iterable.

    Each item yielded by the generator must be a dict with keys:
      source     (optional, defaults to adapter source_name)
      event_type (required)
      payload    (required, dict)

    Or a tuple: (event_type, payload)
    Or a tuple: (source, event_type, payload)

    Example — ingest from a list:
        records = [
            {"event_type": "WITNESS", "payload": {"sensor": "A", "value": 42}},
            {"event_type": "WITNESS", "payload": {"sensor": "B", "value": 17}},
        ]
        adapter = CallbackAdapter(ledger, source=iter(records))
        adapter.start()
        adapter.run()

    Example — ingest from a live queue:
        import queue
        q = queue.Queue()
        def gen():
            while True:
                yield q.get()

        adapter = CallbackAdapter(ledger, source=gen())
        adapter.start()
        # In another thread: q.put({"event_type": "WITNESS", "payload": {...}})
    """

    def __init__(
        self,
        ledger: SpineLedger,
        source: Iterable,
        **kwargs,
    ) -> None:
        super().__init__(ledger, **kwargs)
        self._source: Iterator = iter(source)
        self._exhausted = False

    def _next_record(self) -> Optional[tuple]:
        if self._exhausted:
            return None
        try:
            item = next(self._source)
        except StopIteration:
            self._exhausted = True
            self._running = False
            return None

        # Normalise item to (source, event_type, payload)
        if isinstance(item, dict):
            src = item.get("source", self.source_name)
            etype = item.get("event_type", "UNKNOWN")
            payload = item.get("payload", {})
            if not isinstance(payload, dict):
                payload = {"value": str(payload)}
            return (src, etype, payload)

        if isinstance(item, (list, tuple)):
            if len(item) == 2:
                return (self.source_name, item[0], item[1])
            if len(item) == 3:
                return (item[0], item[1], item[2])

        # Fallback: wrap as raw value
        return (self.source_name, "RAW", {"value": str(item)[:1000]})
