"""
aletheia.adapters.base — Universal Adapter Base Class

Phase 2: Adapter Framework

Every adapter inherits from AdapterBase and implements adapt().
The framework handles:
  - deterministic raw input hashing (Phase 0)
  - canonical output validation (Phase 0)
  - structured loss and rejection accumulation (Phase 0)
  - adapter identity attachment (Phase 1)
  - raw input reference record (Phase 8)

Determinism rules (Phase 0):
  - Raw bytes are hashed with SHA256 before any processing.
  - adapt() is called exactly once per input.
  - All field normalisation uses functions from determinism.py.
  - All timestamp handling uses the canonical timestamp policy.
  - Adapter output order is deterministic (insertion order = processing order).
  - Failure outcomes are always explicit — never silently discarded.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from aletheia.adapters.taxonomy import (
    LOSS_TYPES, REJECTION_TYPES, ADAPTER_STATUSES, TRUST_LEVELS,
    STATUS_ACCEPTED, STATUS_ACCEPTED_WITH_LOSS, STATUS_REJECTED, STATUS_UNSUPPORTED,
    TRUST_UNAUTHENTICATED, RETAIN_HASHED,
)


# ── Loss and Rejection records ────────────────────────────────────────────────

@dataclass
class LossRecord:
    """A single instance of documented information loss during translation."""
    loss_type: str   # one of LOSS_TYPES
    field: str       # field or path that suffered loss
    detail: str      # human-readable explanation

    def __post_init__(self) -> None:
        if self.loss_type not in LOSS_TYPES:
            raise ValueError(f"Unknown loss_type: {self.loss_type!r}")

    def to_dict(self) -> Dict[str, Any]:
        return {"loss_type": self.loss_type, "field": self.field, "detail": self.detail}


@dataclass
class RejectionRecord:
    """A single rejection of part or all of an input."""
    rejection_type: str   # one of REJECTION_TYPES
    detail: str
    field: Optional[str] = None

    def __post_init__(self) -> None:
        if self.rejection_type not in REJECTION_TYPES:
            raise ValueError(f"Unknown rejection_type: {self.rejection_type!r}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rejection_type": self.rejection_type,
            "field": self.field,
            "detail": self.detail,
        }


@dataclass
class CanonicalEvent:
    """
    A single canonical event ready for the Ingest Gate.

    source and event_type must satisfy IngestGate constraints:
      - string, 1..64 chars
    payload must be a JSON-safe dict.
    """
    source: str
    event_type: str
    payload: Dict[str, Any]
    time_wall: Optional[str] = None    # ISO8601 UTC Z, or None
    adapter_meta: Dict[str, Any] = field(default_factory=dict)

    def to_ingest_record(self) -> Dict[str, Any]:
        """
        Produce the record dict expected by IngestGate.ingest().
        adapter_meta is included in payload under _adapter key so it
        passes through the Spine without polluting the top-level schema.
        """
        p = dict(self.payload)
        if self.adapter_meta:
            p["_adapter"] = self.adapter_meta
        record: Dict[str, Any] = {
            "source": self.source,
            "event_type": self.event_type,
            "payload": p,
        }
        if self.time_wall is not None:
            record["time_wall"] = self.time_wall
        return record


@dataclass
class AdapterResult:
    """
    The complete output of one adapter run against one raw input.

    status is computed from the events/rejections accumulated:
      - Any rejections and no events → REJECTED
      - Any losses → ACCEPTED_WITH_LOSS
      - No events and no rejections → UNSUPPORTED
      - Otherwise → ACCEPTED
    """
    adapter_name: str
    adapter_version: str
    trust_level: str
    input_hash: str            # SHA256 hex of raw input bytes
    canonical_events: List[CanonicalEvent] = field(default_factory=list)
    losses: List[LossRecord] = field(default_factory=list)
    rejections: List[RejectionRecord] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    raw_ref: Optional[Dict[str, Any]] = None

    @property
    def status(self) -> str:
        if self.rejections and not self.canonical_events:
            return STATUS_REJECTED
        if not self.canonical_events and not self.rejections:
            return STATUS_UNSUPPORTED
        if self.losses or (self.rejections and self.canonical_events):
            return STATUS_ACCEPTED_WITH_LOSS
        return STATUS_ACCEPTED

    def add_loss(self, loss_type: str, field_path: str, detail: str) -> None:
        self.losses.append(LossRecord(loss_type=loss_type, field=field_path, detail=detail))

    def add_rejection(self, rejection_type: str, detail: str, field_path: Optional[str] = None) -> None:
        self.rejections.append(RejectionRecord(rejection_type=rejection_type, detail=detail, field=field_path))

    def add_event(self, event: CanonicalEvent) -> None:
        self.canonical_events.append(event)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "adapter_name":     self.adapter_name,
            "adapter_version":  self.adapter_version,
            "trust_level":      self.trust_level,
            "status":           self.status,
            "input_hash":       self.input_hash,
            "canonical_events": [
                {
                    "source":      e.source,
                    "event_type":  e.event_type,
                    "payload":     e.payload,
                    "time_wall":   e.time_wall,
                    "adapter_meta": e.adapter_meta,
                }
                for e in self.canonical_events
            ],
            "losses":     [l.to_dict() for l in self.losses],
            "rejections": [r.to_dict() for r in self.rejections],
            "warnings":   list(self.warnings),
            "raw_ref":    self.raw_ref,
        }

    def to_ingest_records(self) -> List[Dict[str, Any]]:
        """Produce all IngestGate-ready records from accepted events."""
        return [e.to_ingest_record() for e in self.canonical_events]


# ── Raw input hashing (Phase 0, Phase 8) ─────────────────────────────────────

def hash_raw_bytes(raw: bytes) -> str:
    """Deterministic SHA256 of raw input bytes. Always called before any processing."""
    return hashlib.sha256(raw).hexdigest()


def build_raw_ref(
    raw: bytes,
    retention_mode: str = RETAIN_HASHED,
    external_ref: Optional[str] = None,
    redaction_note: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build a raw input reference record (Phase 8).
    The raw hash is always stored regardless of retention mode.
    """
    ref: Dict[str, Any] = {
        "retention_mode": retention_mode,
        "input_hash": hash_raw_bytes(raw),
        "byte_length": len(raw),
        "content": None,
        "external_ref": None,
        "redaction_note": None,
    }
    if retention_mode == "FULL":
        try:
            ref["content"] = json.loads(raw.decode("utf-8", errors="replace"))
        except Exception:
            ref["content"] = raw.decode("utf-8", errors="replace")
    elif retention_mode == "REDACTED":
        ref["redaction_note"] = redaction_note or "redacted"
    elif retention_mode == "EXTERNAL_REF":
        ref["external_ref"] = external_ref
    return ref


# ── Adapter base class (Phase 2) ──────────────────────────────────────────────

class AdapterBase:
    """
    Base class for all Aletheia adapters.

    Subclasses must implement:
      adapt(raw: bytes, *, profile=None) -> AdapterResult

    Subclasses should use the helper methods (loss, reject, event) and
    call _make_result() to produce the AdapterResult.

    Subclasses must NOT:
      - return ACCEPTED when losses exist (the framework handles this)
      - invent certainty not present in the source
      - silently discard parse failures
    """

    NAME: str = "abstract"
    VERSION: str = "0.0.0"
    DEFAULT_TRUST: str = TRUST_UNAUTHENTICATED
    DEFAULT_RETENTION: str = RETAIN_HASHED

    def adapt(self, raw: bytes, *, profile: Optional[Dict[str, Any]] = None) -> AdapterResult:
        raise NotImplementedError

    # ── Convenience: build a result with identity pre-filled ─────────────────

    def _start_result(self, raw: bytes, trust_level: Optional[str] = None) -> AdapterResult:
        """Create an AdapterResult pre-filled with adapter identity and raw hash."""
        return AdapterResult(
            adapter_name=self.NAME,
            adapter_version=self.VERSION,
            trust_level=trust_level or self.DEFAULT_TRUST,
            input_hash=hash_raw_bytes(raw),
            raw_ref=build_raw_ref(raw, self.DEFAULT_RETENTION),
        )

    def _make_event(
        self,
        result: AdapterResult,
        source: str,
        event_type: str,
        payload: Dict[str, Any],
        time_wall: Optional[str] = None,
    ) -> CanonicalEvent:
        """
        Build a CanonicalEvent with adapter_meta pre-filled and add it to result.
        Enforces source/event_type length constraints so gate rejection is
        caught at the adapter layer with a clear error.
        """
        source = _clamp_str(source, 64, result, "source")
        event_type = _clamp_str(event_type, 64, result, "event_type")

        meta = {
            "adapter_name":    self.NAME,
            "adapter_version": self.VERSION,
            "trust_level":     result.trust_level,
            "input_hash":      result.input_hash,
            "losses":          [l.to_dict() for l in result.losses],
            "warnings":        list(result.warnings),
        }
        ev = CanonicalEvent(
            source=source,
            event_type=event_type,
            payload=payload,
            time_wall=time_wall,
            adapter_meta=meta,
        )
        result.add_event(ev)
        return ev


def _clamp_str(s: str, max_len: int, result: AdapterResult, field_name: str) -> str:
    """Clamp a string to max_len, recording LOSS_OF_PRECISION if truncated."""
    from aletheia.adapters.taxonomy import LOSS_OF_PRECISION
    if not isinstance(s, str):
        s = str(s)
    if len(s) > max_len:
        result.add_loss(LOSS_OF_PRECISION, field_name,
                        f"{field_name} truncated from {len(s)} to {max_len} chars")
        return s[:max_len]
    if len(s) == 0:
        return "unknown"
    return s
