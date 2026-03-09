"""
aletheia.adapters.ot_adapter — Operational Technology / Sensor Adapter

Phase 6: Translate operational telemetry into canonical events.

Inputs: sensor readings, equipment state changes, commands, alarms,
        maintenance logs.

Rules:
  - Device identity is preserved exactly as provided.
  - Bad-quality measurements are flagged with LOSS_OF_AUTHENTICITY,
    not silently accepted or dropped.
  - Unknown engineering units are preserved, not coerced.
  - Stale timestamps are marked with LOSS_OF_AUTHENTICITY.
  - Unit mismatches produce LOSS_OF_PRECISION if coercion is attempted.

Event types produced:
  OT_SENSOR_READING      — a single sensor measurement
  OT_STATE_CHANGE        — equipment state transition
  OT_COMMAND             — a command sent to equipment
  OT_ALARM               — an alarm/alert condition
  OT_MAINTENANCE         — a maintenance event

Quality codes (GOOD, UNCERTAIN, BAD) follow ISA-95 / OPC-UA conventions.
BAD quality measurements are accepted with LOSS_OF_AUTHENTICITY recorded.
UNCERTAIN quality measurements are accepted with a warning.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from aletheia.adapters.base import AdapterBase, AdapterResult
from aletheia.adapters.determinism import (
    normalise_unicode, parse_timestamp, measure_depth,
    MAX_PAYLOAD_DEPTH, MAX_EVENTS_PER_INPUT,
)
from aletheia.adapters.taxonomy import (
    LOSS_OF_AUTHENTICITY, LOSS_OF_COMPLETENESS, LOSS_OF_PRECISION,
    LOSS_OF_STRUCTURE,
    REJECT_MALFORMED, REJECT_INCOMPLETE, REJECT_HOSTILE,
    TRUST_UNAUTHENTICATED,
)

# Quality code constants (ISA-95 / OPC-UA)
QUALITY_GOOD      = "GOOD"
QUALITY_UNCERTAIN = "UNCERTAIN"
QUALITY_BAD       = "BAD"
_KNOWN_QUALITY    = frozenset({QUALITY_GOOD, QUALITY_UNCERTAIN, QUALITY_BAD})

# Stale timestamp threshold in seconds (configurable on instance)
DEFAULT_STALE_THRESHOLD_S = 300  # 5 minutes


class OTAdapter(AdapterBase):
    """
    Ingests operational technology / sensor telemetry records.

    Each input record must have a 'record_type' discriminator.

    Supported record_types:
      sensor_reading, state_change, command, alarm, maintenance.

    The device_id field is the authoritative equipment identifier and is
    never normalised or lowercased — industrial device IDs are case-sensitive.
    """

    NAME = "ot_adapter"
    VERSION = "1.0.0"
    DEFAULT_TRUST = TRUST_UNAUTHENTICATED
    DEFAULT_RETENTION = "HASHED"

    MAX_INPUT_BYTES = 5 * 1024 * 1024  # 5 MiB

    def __init__(self, stale_threshold_s: int = DEFAULT_STALE_THRESHOLD_S) -> None:
        self.stale_threshold_s = stale_threshold_s

    def adapt(self, raw: bytes, *, profile: Optional[Dict[str, Any]] = None) -> AdapterResult:
        result = self._start_result(raw)

        if len(raw) > self.MAX_INPUT_BYTES:
            result.add_rejection(REJECT_HOSTILE, "root",
                                 f"Input {len(raw)} bytes exceeds limit {self.MAX_INPUT_BYTES}")
            return result

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as e:
            result.add_rejection(REJECT_MALFORMED, "root", f"Not valid UTF-8: {e}")
            return result

        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            result.add_rejection(REJECT_MALFORMED, "root", f"JSON parse error: {e}")
            return result

        if measure_depth(data) > MAX_PAYLOAD_DEPTH:
            result.add_rejection(REJECT_HOSTILE, "root", "Payload nesting depth exceeded")
            return result

        records = data if isinstance(data, list) else [data]

        if len(records) > MAX_EVENTS_PER_INPUT:
            result.add_rejection(REJECT_HOSTILE, "root",
                                 f"Record count {len(records)} exceeds limit {MAX_EVENTS_PER_INPUT}")
            return result

        for i, rec in enumerate(records):
            if not isinstance(rec, dict):
                result.add_rejection(REJECT_MALFORMED, f"[{i}]",
                                     f"Item {i} is not a JSON object")
                continue
            self._translate_record(rec, result, i)

        return result

    def _translate_record(self, rec: Dict, result: AdapterResult, i: int) -> None:
        prefix = f"[{i}]."
        rt = rec.get("record_type")
        if not isinstance(rt, str):
            result.add_rejection(REJECT_INCOMPLETE, f"{prefix}record_type",
                                 "record_type must be a string")
            return

        rt_norm = rt.lower().strip()
        dispatch = {
            "sensor_reading": self._sensor_reading,
            "state_change":   self._state_change,
            "command":        self._command,
            "alarm":          self._alarm,
            "maintenance":    self._maintenance,
        }
        handler = dispatch.get(rt_norm)
        if handler is None:
            result.add_loss(LOSS_OF_STRUCTURE, f"{prefix}record_type",
                            f"Unknown record_type {rt!r}; ingested as OT_UNKNOWN_RECORD")
            payload = {"record_type": rt, "raw": rec}
            source = self._source(rec)
            self._make_event(result, source, "OT_UNKNOWN_RECORD", payload)
            return

        handler(rec, result, prefix)

    # ── Sensor reading ────────────────────────────────────────────────────────

    def _sensor_reading(self, rec: Dict, result: AdapterResult, prefix: str) -> None:
        source    = self._source(rec)
        device_id = _required_raw_str(rec, "device_id", result, prefix)
        if device_id is None:
            return

        value = rec.get("value")
        if value is None:
            result.add_rejection(REJECT_INCOMPLETE, f"{prefix}value",
                                 "sensor_reading requires a value field")
            return

        # Validate numeric
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            result.add_rejection(REJECT_MALFORMED, f"{prefix}value",
                                 f"value must be numeric, got {type(value).__name__}")
            return
        if value != value or abs(value) == float("inf"):
            result.add_rejection(REJECT_MALFORMED, f"{prefix}value",
                                 "NaN or Infinity not permitted in sensor value")
            return

        unit = rec.get("unit")
        if unit is not None and not isinstance(unit, str):
            result.add_loss(LOSS_OF_STRUCTURE, f"{prefix}unit",
                            f"unit is not a string ({type(unit).__name__}); preserved as-is")
            unit = str(unit)
        # Unknown units are preserved, not rejected
        if unit is not None:
            unit = normalise_unicode(unit.strip()) or None

        quality = self._extract_quality(rec, result, prefix)
        ts, ts_ambiguous, ts_stale = self._extract_ot_timestamp(rec, result, prefix)

        payload: Dict[str, Any] = {
            "device_id": device_id,
            "value":     value,
            "unit":      unit,
            "quality":   quality,
        }
        if ts is not None:
            payload["reading_time"] = ts
        if rec.get("sensor_id") is not None:
            payload["sensor_id"] = str(rec["sensor_id"])

        self._make_event(result, source, "OT_SENSOR_READING", payload, ts)

    # ── State change ──────────────────────────────────────────────────────────

    def _state_change(self, rec: Dict, result: AdapterResult, prefix: str) -> None:
        source    = self._source(rec)
        device_id = _required_raw_str(rec, "device_id", result, prefix)
        if device_id is None:
            return

        from_state = rec.get("from_state")
        to_state   = rec.get("to_state")

        if to_state is None:
            result.add_rejection(REJECT_INCOMPLETE, f"{prefix}to_state",
                                 "state_change requires to_state")
            return

        if from_state is None:
            result.add_loss(LOSS_OF_CAUSAL_LINKAGE, f"{prefix}from_state",
                            "from_state absent; state transition origin unknown")

        ts, _, _ = self._extract_ot_timestamp(rec, result, prefix)

        payload: Dict[str, Any] = {
            "device_id":  device_id,
            "from_state": from_state,
            "to_state":   str(to_state),
            "reason":     rec.get("reason"),
        }
        self._make_event(result, source, "OT_STATE_CHANGE", payload, ts)

    # ── Command ───────────────────────────────────────────────────────────────

    def _command(self, rec: Dict, result: AdapterResult, prefix: str) -> None:
        source    = self._source(rec)
        device_id = _required_raw_str(rec, "device_id", result, prefix)
        command   = _required_raw_str(rec, "command", result, prefix)
        if device_id is None or command is None:
            return

        ts, _, _ = self._extract_ot_timestamp(rec, result, prefix)
        payload: Dict[str, Any] = {
            "device_id": device_id,
            "command":   command,
            "actor":     rec.get("actor"),
            "parameters": rec.get("parameters"),
        }
        self._make_event(result, source, "OT_COMMAND", payload, ts)

    # ── Alarm ─────────────────────────────────────────────────────────────────

    def _alarm(self, rec: Dict, result: AdapterResult, prefix: str) -> None:
        source    = self._source(rec)
        device_id = _required_raw_str(rec, "device_id", result, prefix)
        alarm_id  = rec.get("alarm_id")
        severity  = rec.get("severity")

        if device_id is None:
            return

        ts, _, _ = self._extract_ot_timestamp(rec, result, prefix)
        payload: Dict[str, Any] = {
            "device_id": device_id,
            "alarm_id":  str(alarm_id) if alarm_id is not None else None,
            "severity":  str(severity) if severity is not None else None,
            "message":   str(rec.get("message", ""))[:512] or None,
            "state":     rec.get("state"),
        }
        self._make_event(result, source, "OT_ALARM", payload, ts)

    # ── Maintenance ───────────────────────────────────────────────────────────

    def _maintenance(self, rec: Dict, result: AdapterResult, prefix: str) -> None:
        source    = self._source(rec)
        device_id = _required_raw_str(rec, "device_id", result, prefix)
        if device_id is None:
            return

        ts, _, _ = self._extract_ot_timestamp(rec, result, prefix)
        payload: Dict[str, Any] = {
            "device_id":  device_id,
            "work_type":  rec.get("work_type"),
            "technician": rec.get("technician"),
            "notes":      str(rec.get("notes", ""))[:1024] or None,
        }
        self._make_event(result, source, "OT_MAINTENANCE", payload, ts)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _source(self, rec: Dict) -> str:
        s = rec.get("source", "ot_source")
        return str(s)[:64] or "ot_source"

    def _extract_quality(self, rec: Dict, result: AdapterResult, prefix: str) -> str:
        """
        Extract and validate OPC-UA / ISA-95 quality code.
        BAD quality is ACCEPTED with LOSS_OF_AUTHENTICITY.
        Unknown quality is preserved with a warning.
        """
        q = rec.get("quality", QUALITY_GOOD)
        if not isinstance(q, str):
            result.add_loss(LOSS_OF_STRUCTURE, f"{prefix}quality",
                            f"quality is not a string; defaulting to UNCERTAIN")
            return QUALITY_UNCERTAIN

        q_norm = normalise_unicode(q).upper()
        if q_norm not in _KNOWN_QUALITY:
            result.warnings.append(f"Unknown quality code {q!r}; preserved as-is")
            return q
        if q_norm == QUALITY_BAD:
            result.add_loss(LOSS_OF_AUTHENTICITY, f"{prefix}quality",
                            "Sensor reports BAD quality; measurement may be unreliable")
        elif q_norm == QUALITY_UNCERTAIN:
            result.warnings.append("Sensor reports UNCERTAIN quality")
        return q_norm

    def _extract_ot_timestamp(
        self, rec: Dict, result: AdapterResult, prefix: str
    ) -> tuple[Optional[str], bool, bool]:
        """
        Extract timestamp. Returns (canonical_ts, is_ambiguous, is_stale).
        Stale: timestamp is more than stale_threshold_s seconds in the past
               relative to the current ingestion time.
        """
        from aletheia.adapters.determinism import parse_timestamp, current_utc_z
        import time as _time

        for key in ("timestamp", "time", "ts", "event_time", "time_wall"):
            if key in rec:
                ts, ambiguous = parse_timestamp(rec[key])
                if ts is None:
                    result.add_loss(LOSS_OF_AUTHENTICITY, f"{prefix}{key}",
                                    f"Could not parse timestamp {rec[key]!r}")
                    return None, False, False
                if ambiguous:
                    result.add_loss(LOSS_OF_AUTHENTICITY, f"{prefix}{key}",
                                    "Timestamp had no timezone; UTC assumed")

                # Stale check
                stale = False
                try:
                    from datetime import datetime, timezone
                    dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                    age = _time.time() - dt.timestamp()
                    if age > self.stale_threshold_s:
                        result.add_loss(LOSS_OF_AUTHENTICITY, f"{prefix}{key}",
                                        f"Timestamp is {int(age)}s old (threshold {self.stale_threshold_s}s)")
                        stale = True
                except Exception:
                    pass

                return ts, ambiguous, stale

        return None, False, False


def _required_raw_str(rec: Dict, key: str, result: AdapterResult, prefix: str) -> Optional[str]:
    """Extract a required string field, preserving case (for device IDs etc.)."""
    v = rec.get(key)
    if v is None or (isinstance(v, str) and not v.strip()):
        result.add_rejection(REJECT_INCOMPLETE, f"{prefix}{key}",
                             f"Required field '{key}' is missing or empty")
        return None
    return str(v)


from aletheia.adapters.taxonomy import LOSS_OF_CAUSAL_LINKAGE

# Auto-register
from aletheia.adapters.registry import register as _reg
_reg(OTAdapter())
