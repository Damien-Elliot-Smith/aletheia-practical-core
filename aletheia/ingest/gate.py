"""
Strict Ingest Gate v1 (Practical Core)

Purpose:
- Validate-or-reject at the edge (no guessing)
- Bounded reject log (cannot grow unbounded)
- Reject-surge detection (signals DoS/input storms)
- Simple rate limiting to prevent host overload
- Adapter isolation: vendor quirks never touch Spine core

Outputs:
- ACCEPT: returns sanitized (validated) event tuple for Spine
- REJECT: writes bounded reject record and may trigger MAYDAY via Siren (optional)
"""

from __future__ import annotations

import os
import json
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from aletheia.spine.ledger import SpineLedger, canonicalize_json
from aletheia.siren.state_machine import Siren, SirenState, MaydayCode


class RejectReason(str, Enum):
    SCHEMA_INVALID = "SCHEMA_INVALID"
    PAYLOAD_NOT_DICT = "PAYLOAD_NOT_DICT"
    FIELD_TYPE_INVALID = "FIELD_TYPE_INVALID"
    RATE_LIMIT = "RATE_LIMIT"
    REJECT_LOG_FULL = "REJECT_LOG_FULL"  # should not happen (bounded ring), but explicit
    INTERNAL_ERROR = "INTERNAL_ERROR"
    # Phase 1.3 — Bounded Ingest (closes RT-04)
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"   # serialised payload exceeds max_payload_bytes
    PAYLOAD_TOO_DEEP = "PAYLOAD_TOO_DEEP"     # nested dict/list depth exceeds max_payload_depth


class IngestDecision(str, Enum):
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"


@dataclass
class IngestResult:
    decision: IngestDecision
    reason: Optional[RejectReason] = None
    detail: Optional[Dict[str, Any]] = None
    # if ACCEPT:
    window_id: Optional[str] = None
    event_type: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None


@dataclass
class IngestConfig:
    # Where Spine events go
    window_id: str = "ingest"
    # Bounded reject log config
    reject_max_records: int = 500
    # Rate limit: max accepts per second (approx; token bucket)
    max_accepts_per_sec: float = 50.0
    # Reject surge detection window
    surge_window_s: int = 10
    surge_reject_threshold: int = 200
    # Phase 1.3 — Bounded Ingest (closes RT-04)
    # Max serialised payload size in bytes. Default 64 KiB.
    # A payload flood of large events can exhaust disk without triggering Siren.
    max_payload_bytes: int = 65536
    # Max nesting depth of payload dict/list. Guards against stack-busting structures.
    max_payload_depth: int = 32


def _measure_depth(obj: Any, _current: int = 0) -> int:
    """Phase 1.3: Measure the maximum nesting depth of a JSON-compatible object."""
    if _current > 64:  # hard ceiling to prevent stack overflow during measurement itself
        return _current
    if isinstance(obj, dict):
        if not obj:
            return _current
        return max(_measure_depth(v, _current + 1) for v in obj.values())
    if isinstance(obj, list):
        if not obj:
            return _current
        return max(_measure_depth(v, _current + 1) for v in obj)
    return _current


class TokenBucket:
    def __init__(self, rate_per_sec: float, burst: float):
        self.rate = float(rate_per_sec)
        self.capacity = float(burst)
        self.tokens = float(burst)
        self.last = time.monotonic()

    def allow(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = now - self.last
        self.last = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


class BoundedRejectLog:
    """
    A bounded, overwrite-on-wrap JSONL ring log.
    Stored as:
      rejects/
        meta.json
        ring.jsonl  (fixed number of lines, each line is JSON or '{}' placeholder)
    This design avoids unbounded growth and is robust on restart.
    """
    def __init__(self, root: Path, max_records: int):
        self.dir = root / "rejects"
        self.meta = self.dir / "meta.json"
        self.ring = self.dir / "ring.jsonl"
        self.max_records = int(max_records)

        self.dir.mkdir(parents=True, exist_ok=True)
        if not self.meta.exists() or not self.ring.exists():
            self._init_files()
        self._load_meta()

    def _init_files(self) -> None:
        # initialize ring with placeholders
        self.dir.mkdir(parents=True, exist_ok=True)
        placeholders = ("{}\n" * self.max_records).encode("utf-8")
        tmp = self.ring.with_suffix(".jsonl.tmp")
        with open(tmp, "wb") as f:
            f.write(placeholders)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.ring)
        self._atomic_write_json(self.meta, {"write_index": 0, "total_rejects": 0})

    def _load_meta(self) -> None:
        try:
            obj = json.loads(self.meta.read_text(encoding="utf-8"))
            self.write_index = int(obj.get("write_index", 0))
            self.total_rejects = int(obj.get("total_rejects", 0))
        except Exception:
            # Reset meta but keep ring content
            self.write_index = 0
            self.total_rejects = 0
            self._atomic_write_json(self.meta, {"write_index": 0, "total_rejects": 0})

    def append(self, rec: Dict[str, Any]) -> None:
        # Write record at current index (line replacement)
        line = (json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
        # Replace specific line in file. For bounded size, we do a simple rewrite strategy:
        # Read all lines (bounded), replace one, write atomically.
        lines = self.ring.read_text(encoding="utf-8").splitlines(True)
        if len(lines) != self.max_records:
            # Re-init if corrupted length
            self._init_files()
            lines = self.ring.read_text(encoding="utf-8").splitlines(True)

        idx = self.write_index % self.max_records
        lines[idx] = line

        tmp = self.ring.with_suffix(".jsonl.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            f.writelines(lines)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.ring)

        # Update meta
        self.write_index = (self.write_index + 1) % self.max_records
        self.total_rejects += 1
        self._atomic_write_json(self.meta, {"write_index": self.write_index, "total_rejects": self.total_rejects})

    def _atomic_write_json(self, path: Path, obj: Dict[str, Any]) -> None:
        data = (json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
        tmp = path.with_suffix(path.suffix + ".tmp")
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        try:
            dir_fd = os.open(str(path.parent), os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except Exception:
            pass


class IngestGate:
    """
    Ingest gate validates incoming adapter events and writes to Spine if accepted.

    Expected incoming record schema (strict):
    {
      "source": "string",
      "event_type": "STRING",
      "payload": { ... JSON-safe ... },
      "time_wall": "optional ISO8601 string",
      "meta": { ... optional JSON-safe ... }
    }

    Rules:
    - source and event_type must be short strings
    - payload MUST be dict
    - no unknown top-level types
    - no guessing / coercion
    """
    def __init__(self, ledger: SpineLedger, *, siren: Optional[Siren] = None, config: Optional[IngestConfig] = None):
        self.ledger = ledger
        self.siren = siren
        self.config = config or IngestConfig()
        self.ledger.open_window(self.config.window_id)

        # Rate limiting accepts
        burst = max(1.0, self.config.max_accepts_per_sec)
        self.bucket = TokenBucket(self.config.max_accepts_per_sec, burst)

        # Reject log
        self.reject_log = BoundedRejectLog(self.ledger.spine_dir, self.config.reject_max_records)

        # Reject surge tracking
        self._surge_start = time.monotonic()
        self._surge_rejects = 0

    def ingest(self, record: Dict[str, Any]) -> IngestResult:
        try:
            res = self._validate(record)
            if res.decision == IngestDecision.REJECT:
                self._record_reject(res, record)
                return res

            # rate-limit accepts to protect host
            if not self.bucket.allow(1.0):
                res = IngestResult(decision=IngestDecision.REJECT, reason=RejectReason.RATE_LIMIT)
                self._record_reject(res, record)
                return res

            # ACCEPT: write to Spine
            assert res.window_id and res.event_type and isinstance(res.payload, dict)
            self.ledger.append_event(self.config.window_id, res.event_type, res.payload)
            return res

        except Exception as e:
            res = IngestResult(decision=IngestDecision.REJECT, reason=RejectReason.INTERNAL_ERROR, detail={"error": str(e)})
            self._record_reject(res, record)
            return res

    def _validate(self, record: Dict[str, Any]) -> IngestResult:
        if not isinstance(record, dict):
            return IngestResult(decision=IngestDecision.REJECT, reason=RejectReason.SCHEMA_INVALID)

        source = record.get("source")
        event_type = record.get("event_type")
        payload = record.get("payload")

        if not isinstance(source, str) or not (1 <= len(source) <= 64):
            return IngestResult(decision=IngestDecision.REJECT, reason=RejectReason.FIELD_TYPE_INVALID, detail={"field": "source"})
        if not isinstance(event_type, str) or not (1 <= len(event_type) <= 64):
            return IngestResult(decision=IngestDecision.REJECT, reason=RejectReason.FIELD_TYPE_INVALID, detail={"field": "event_type"})
        if not isinstance(payload, dict):
            return IngestResult(decision=IngestDecision.REJECT, reason=RejectReason.PAYLOAD_NOT_DICT)

        # Phase 1.3 — payload size guard (RT-04)
        try:
            payload_bytes = len(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
        except (TypeError, ValueError):
            return IngestResult(decision=IngestDecision.REJECT, reason=RejectReason.SCHEMA_INVALID,
                                detail={"note": "payload not JSON-serialisable"})
        if payload_bytes > self.config.max_payload_bytes:
            return IngestResult(
                decision=IngestDecision.REJECT,
                reason=RejectReason.PAYLOAD_TOO_LARGE,
                detail={"bytes": payload_bytes, "limit": self.config.max_payload_bytes},
            )

        # Phase 1.3 — payload depth guard (RT-04)
        depth = _measure_depth(payload)
        if depth > self.config.max_payload_depth:
            return IngestResult(
                decision=IngestDecision.REJECT,
                reason=RejectReason.PAYLOAD_TOO_DEEP,
                detail={"depth": depth, "limit": self.config.max_payload_depth},
            )

        # minimal sanitized payload that goes into Spine (adapter isolation)
        sanitized = {
            "source": source,
            "payload": payload,
        }
        # optional metadata
        if "meta" in record:
            meta = record.get("meta")
            if not isinstance(meta, dict):
                return IngestResult(decision=IngestDecision.REJECT, reason=RejectReason.FIELD_TYPE_INVALID, detail={"field": "meta"})
            sanitized["meta"] = meta
        if "time_wall" in record:
            tw = record.get("time_wall")
            if not isinstance(tw, str):
                return IngestResult(decision=IngestDecision.REJECT, reason=RejectReason.FIELD_TYPE_INVALID, detail={"field": "time_wall"})
            sanitized["time_wall"] = tw

        return IngestResult(decision=IngestDecision.ACCEPT, window_id=self.config.window_id, event_type=event_type, payload=sanitized)

    def _record_reject(self, res: IngestResult, record: Dict[str, Any]) -> None:
        now = time.monotonic()
        if now - self._surge_start > self.config.surge_window_s:
            self._surge_start = now
            self._surge_rejects = 0

        self._surge_rejects += 1
        surge = self._surge_rejects >= self.config.surge_reject_threshold

        rec = {
            "ts": int(time.time()),
            "reason": res.reason.value if res.reason else "UNKNOWN",
            "detail": res.detail or {},
            "surge": surge,
            # Do not store entire raw record if huge; cap size by storing canonical bytes length
            "record_keys": sorted(list(record.keys())) if isinstance(record, dict) else [],
        }
        self.reject_log.append(rec)

        # Optionally raise MAYDAY on surge
        if surge and self.siren is not None:
            # Escalate to SUMMARIES_ONLY as practical protective measure (can be tuned)
            self.siren.transition(
                SirenState.SUMMARIES_ONLY,
                MaydayCode.MANUAL,
                details={"note": "Reject surge detected", "window_s": self.config.surge_window_s, "count": self._surge_rejects},
            )
