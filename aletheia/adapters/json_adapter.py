"""
aletheia.adapters.json_adapter — JSON Adapter

Phase 3: Translate structured JSON inputs into canonical Aletheia events.

Inputs: APIs, exported application data, AI logs, machine-generated event streams.

Rules (Phase 0):
  - Malformed JSON -> REJECTED / MALFORMED
  - Missing required fields -> REJECTED / INCOMPLETE
  - Inferred values -> ACCEPTED_WITH_LOSS
  - Unknown fields preserved only if preserve_unknown=True in profile or config

Rules (Phase 11 — Security Hardening):
  - Input byte length enforced before parsing
  - Payload depth enforced after parsing
  - Max events per input enforced
  - String fields clamped to 4096 chars with LOSS_OF_PRECISION
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from aletheia.adapters.base import AdapterBase, AdapterResult, CanonicalEvent, build_raw_ref
from aletheia.adapters.determinism import (
    parse_timestamp, normalise_unicode, measure_depth,
    MAX_PAYLOAD_BYTES, MAX_PAYLOAD_DEPTH, MAX_EVENTS_PER_INPUT,
)
from aletheia.adapters.profiles import load_profile, apply_profile
from aletheia.adapters.taxonomy import (
    LOSS_OF_COMPLETENESS, LOSS_OF_STRUCTURE, LOSS_OF_AUTHENTICITY,
    REJECT_MALFORMED, REJECT_INCOMPLETE, REJECT_HOSTILE,
    TRUST_UNAUTHENTICATED, STATUS_REJECTED,
)


class JSONAdapter(AdapterBase):
    """
    Translates a JSON byte payload into one or more canonical events.

    Without a profile: expects the input to already be a dict with
    'source', 'event_type', and 'payload' keys (direct passthrough with
    provenance wrapping).

    With a profile: applies the profile's event_mappings to translate
    arbitrary JSON structures into canonical events.
    """

    NAME = "json_adapter"
    VERSION = "1.0.0"
    DEFAULT_TRUST = TRUST_UNAUTHENTICATED
    DEFAULT_RETENTION = "HASHED"

    # Phase 11 hardening limits
    MAX_INPUT_BYTES = 10 * 1024 * 1024  # 10 MiB hard ceiling before JSON parse

    def adapt(self, raw: bytes, *, profile: Optional[Dict[str, Any]] = None) -> AdapterResult:
        result = self._start_result(raw)

        # Phase 11: input explosion guard before parsing
        if len(raw) > self.MAX_INPUT_BYTES:
            result.add_rejection(REJECT_HOSTILE, "root",
                                 f"Input size {len(raw)} bytes exceeds limit {self.MAX_INPUT_BYTES}")
            return result

        # Parse JSON
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError as e:
            result.add_rejection(REJECT_MALFORMED, "root", f"Not valid UTF-8: {e}")
            return result

        try:
            data = json.loads(decoded)
        except json.JSONDecodeError as e:
            result.add_rejection(REJECT_MALFORMED, "root", f"JSON parse error: {e}")
            return result

        # Phase 11: NaN/Inf scan
        nan_path = _find_nan_inf(data)
        if nan_path is not None:
            result.add_rejection(REJECT_MALFORMED, nan_path,
                                 f"NaN or Infinity at path {nan_path!r} — not permitted")
            return result

        # Phase 11: depth guard
        depth = measure_depth(data)
        if depth > MAX_PAYLOAD_DEPTH:
            result.add_rejection(REJECT_HOSTILE, "root",
                                 f"Payload nesting depth {depth} exceeds limit {MAX_PAYLOAD_DEPTH}")
            return result

        # Profile-driven translation
        if profile is not None:
            return self._adapt_with_profile(raw, data, profile, result)

        # Direct mode: input must be a single dict or a list of dicts
        if isinstance(data, dict):
            return self._adapt_single(raw, data, result)
        if isinstance(data, list):
            return self._adapt_list(raw, data, result)

        result.add_rejection(REJECT_MALFORMED, "root",
                             f"Expected JSON object or array, got {type(data).__name__}")
        return result

    # ── Direct mode ───────────────────────────────────────────────────────────

    def _adapt_single(self, raw: bytes, data: Dict[str, Any], result: AdapterResult) -> AdapterResult:
        self._translate_dict(data, result)
        return result

    def _adapt_list(self, raw: bytes, data: List[Any], result: AdapterResult) -> AdapterResult:
        if len(data) > MAX_EVENTS_PER_INPUT:
            result.add_rejection(REJECT_HOSTILE, "root",
                                 f"Input array length {len(data)} exceeds max {MAX_EVENTS_PER_INPUT}")
            return result
        for i, item in enumerate(data):
            if not isinstance(item, dict):
                result.add_rejection(REJECT_MALFORMED, f"[{i}]",
                                     f"Array item {i} is not a JSON object")
                continue
            self._translate_dict(item, result, item_index=i)
        return result

    def _translate_dict(
        self,
        data: Dict[str, Any],
        result: AdapterResult,
        item_index: Optional[int] = None,
    ) -> None:
        """
        Translate a single dict to a canonical event in direct (no-profile) mode.
        Expects keys: source, event_type, payload (required).
        Optional: time_wall.
        Unknown keys -> LOSS_OF_STRUCTURE unless explicitly ignored.
        """
        prefix = f"[{item_index}]." if item_index is not None else ""

        source = data.get("source")
        event_type = data.get("event_type")
        payload = data.get("payload")

        # Required field checks
        missing = [k for k, v in [("source", source), ("event_type", event_type), ("payload", payload)] if v is None]
        if missing:
            result.add_rejection(REJECT_INCOMPLETE, f"{prefix}root",
                                 f"Missing required fields: {missing}")
            return

        if not isinstance(source, str) or len(source) < 1:
            result.add_rejection(REJECT_MALFORMED, f"{prefix}source",
                                 "source must be a non-empty string")
            return
        if not isinstance(event_type, str) or len(event_type) < 1:
            result.add_rejection(REJECT_MALFORMED, f"{prefix}event_type",
                                 "event_type must be a non-empty string")
            return
        if not isinstance(payload, dict):
            result.add_rejection(REJECT_MALFORMED, f"{prefix}payload",
                                 "payload must be a JSON object")
            return

        # Normalise source/event_type
        source = normalise_unicode(source)
        event_type = normalise_unicode(event_type)

        # Optional timestamp
        time_wall, ts_ambiguous = _extract_timestamp(data, result, prefix)
        if ts_ambiguous:
            result.add_loss(LOSS_OF_AUTHENTICITY, f"{prefix}time_wall",
                            "Timestamp had no timezone; UTC assumed")

        # Unknown top-level fields
        known = {"source", "event_type", "payload", "time_wall"}
        unknown = {k: v for k, v in data.items() if k not in known}
        if unknown:
            result.add_loss(LOSS_OF_STRUCTURE, f"{prefix}root",
                            f"Unknown top-level fields discarded: {sorted(unknown.keys())}")

        self._make_event(result, source, event_type, payload, time_wall)

    # ── Profile mode ──────────────────────────────────────────────────────────

    def _adapt_with_profile(
        self,
        raw: bytes,
        data: Any,
        profile: Dict[str, Any],
        result: AdapterResult,
    ) -> AdapterResult:
        """Apply a loaded profile dict to the parsed data."""
        # Trust level from profile
        trust = profile.get("trust_level", self.DEFAULT_TRUST)
        result.trust_level = trust

        items = data if isinstance(data, list) else [data]

        if len(items) > MAX_EVENTS_PER_INPUT:
            result.add_rejection(REJECT_HOSTILE, "root",
                                 f"Input array length {len(items)} exceeds max {MAX_EVENTS_PER_INPUT}")
            return result

        source_name = profile.get("source_name", "unknown_source")

        for i, item in enumerate(items):
            if not isinstance(item, dict):
                result.add_rejection(REJECT_MALFORMED, f"[{i}]",
                                     f"Array item {i} is not a JSON object")
                continue

            pr = apply_profile(profile, item)
            # Propagate losses and rejections
            from aletheia.adapters.base import LossRecord, RejectionRecord
            for l in pr.losses:
                result.losses.append(LossRecord(**l))
            for r in pr.rejections:
                result.rejections.append(RejectionRecord(**r))

            for ev in pr.events:
                self._make_event(result, source_name, ev["event_type"], ev["payload"])

        return result


def _extract_timestamp(
    data: Dict[str, Any],
    result: AdapterResult,
    prefix: str = "",
) -> tuple[Optional[str], bool]:
    """Extract and parse a timestamp from common field names."""
    from aletheia.adapters.determinism import parse_timestamp
    for key in ("time_wall", "timestamp", "ts", "time", "created_at", "event_time"):
        if key in data:
            ts, ambiguous = parse_timestamp(data[key])
            if ts is None:
                result.add_loss(LOSS_OF_AUTHENTICITY, f"{prefix}{key}",
                                f"Could not parse timestamp {data[key]!r}; omitted")
                return None, False
            return ts, ambiguous
    return None, False



def _find_nan_inf(obj, _path="root"):
    """
    Recursively scan a parsed JSON object for NaN or Infinity values.
    Returns the dot-path of the first offending value, or None if clean.
    Python's json.loads accepts bare NaN/Infinity as a non-standard extension;
    this function enforces the strict RFC 8259 requirement.
    """
    import math
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            return _path
    elif isinstance(obj, dict):
        for k, v in obj.items():
            found = _find_nan_inf(v, f"{_path}.{k}")
            if found:
                return found
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            found = _find_nan_inf(v, f"{_path}[{i}]")
            if found:
                return found
    return None

# Auto-register
from aletheia.adapters.registry import register as _reg
_reg(JSONAdapter())
