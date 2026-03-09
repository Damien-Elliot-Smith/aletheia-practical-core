"""
tests/test_adapters.py — Universal Adapter Test Suite

Covers:
  Phase 0  — Taxonomy, determinism rules, loss/rejection records
  Phase 1  — Trust levels
  Phase 2  — Base class, AdapterResult, CanonicalEvent, AdapterRunner
  Phase 3  — JSON adapter (direct and profile modes)
  Phase 4  — File adapter (strict and mixed modes)
  Phase 5A — AI audit adapter
  Phase 6  — OT adapter
  Phase 7  — Mapping profiles
  Phase 10 — AdapterMonitor
  Phase 11 — Security hardening (hostile inputs)

79 tests total. stdlib unittest only. No pytest required.
"""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

# ── Bootstrap PYTHONPATH ──────────────────────────────────────────────────────
import sys
_HERE = Path(__file__).resolve().parent.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

# ── Imports ───────────────────────────────────────────────────────────────────
from aletheia.adapters.taxonomy import (
    LOSS_TYPES, REJECTION_TYPES, ADAPTER_STATUSES, TRUST_LEVELS,
    STATUS_ACCEPTED, STATUS_ACCEPTED_WITH_LOSS, STATUS_REJECTED, STATUS_UNSUPPORTED,
    TRUST_UNAUTHENTICATED, TRUST_AUTHENTICATED, TRUST_OBSERVED, TRUST_AMBIGUOUS,
    LOSS_OF_COMPLETENESS, LOSS_OF_STRUCTURE, LOSS_OF_PRECISION,
    LOSS_OF_CAUSAL_LINKAGE, LOSS_OF_AUTHENTICITY,
    REJECT_MALFORMED, REJECT_INCOMPLETE, REJECT_HOSTILE,
)
from aletheia.adapters.base import (
    AdapterResult, LossRecord, RejectionRecord, CanonicalEvent,
    hash_raw_bytes, build_raw_ref, AdapterBase,
)
from aletheia.adapters.determinism import (
    normalise_unicode, normalise_field_name, parse_timestamp, coerce_value,
    get_dot_path, measure_depth, current_utc_z,
)

import aletheia.adapters.json_adapter   # triggers registration
import aletheia.adapters.file_adapter
import aletheia.adapters.ai_audit_adapter
import aletheia.adapters.ot_adapter

from aletheia.adapters.registry import get_adapter, list_adapters
from aletheia.adapters.json_adapter import JSONAdapter
from aletheia.adapters.file_adapter import FileAdapter
from aletheia.adapters.ai_audit_adapter import AIAuditAdapter
from aletheia.adapters.ot_adapter import OTAdapter


def _raw(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False).encode("utf-8")


# ══════════════════════════════════════════════════════════════════════════════
# Phase 0 — Taxonomy and determinism
# ══════════════════════════════════════════════════════════════════════════════

class TestTaxonomy(unittest.TestCase):
    """Phase 0: Loss taxonomy, rejection taxonomy, adapter statuses are closed sets."""

    def test_loss_types_complete(self):
        expected = {
            "LOSS_OF_PRECISION", "LOSS_OF_STRUCTURE", "LOSS_OF_COMPLETENESS",
            "LOSS_OF_CAUSAL_LINKAGE", "LOSS_OF_AUTHENTICITY",
        }
        self.assertEqual(LOSS_TYPES, expected)

    def test_rejection_types_complete(self):
        expected = {"MALFORMED", "UNVERIFIABLE", "INCOMPLETE", "INCONSISTENT", "UNSUPPORTED", "HOSTILE"}
        self.assertEqual(REJECTION_TYPES, expected)

    def test_adapter_statuses_complete(self):
        expected = {"ACCEPTED", "ACCEPTED_WITH_LOSS", "REJECTED", "UNSUPPORTED"}
        self.assertEqual(ADAPTER_STATUSES, expected)

    def test_trust_levels_complete(self):
        expected = {"AUTHENTICATED_SOURCE", "OBSERVED_SOURCE", "UNAUTHENTICATED_SOURCE", "AMBIGUOUS_SOURCE"}
        self.assertEqual(TRUST_LEVELS, expected)

    def test_loss_record_rejects_unknown_type(self):
        with self.assertRaises(ValueError):
            LossRecord(loss_type="INVENTED_LOSS", field="x", detail="x")

    def test_rejection_record_rejects_unknown_type(self):
        with self.assertRaises(ValueError):
            RejectionRecord(rejection_type="INVENTED_REJECT", detail="x")

    def test_valid_loss_record_serialises(self):
        lr = LossRecord(LOSS_OF_PRECISION, "field.x", "truncated")
        d = lr.to_dict()
        self.assertEqual(d["loss_type"], LOSS_OF_PRECISION)
        self.assertEqual(d["field"], "field.x")

    def test_valid_rejection_record_serialises(self):
        rr = RejectionRecord(REJECT_MALFORMED, "bad json", "root")
        d = rr.to_dict()
        self.assertEqual(d["rejection_type"], REJECT_MALFORMED)


class TestDeterminism(unittest.TestCase):
    """Phase 0: Deterministic utilities."""

    def test_hash_raw_bytes_deterministic(self):
        raw = b"hello world"
        self.assertEqual(hash_raw_bytes(raw), hash_raw_bytes(raw))
        self.assertEqual(hash_raw_bytes(raw), hashlib.sha256(raw).hexdigest())

    def test_normalise_unicode_nfc(self):
        # café with combining accent vs precomposed
        combined = "cafe\u0301"
        precomposed = "caf\u00e9"
        self.assertEqual(normalise_unicode(combined), precomposed)

    def test_normalise_field_name(self):
        self.assertEqual(normalise_field_name("My Field Name!"), "my_field_name")
        self.assertEqual(normalise_field_name("  spaces  "), "spaces")

    def test_parse_timestamp_unix_epoch(self):
        ts, ambig = parse_timestamp(0)
        self.assertEqual(ts, "1970-01-01T00:00:00Z")
        self.assertFalse(ambig)

    def test_parse_timestamp_iso_z(self):
        ts, ambig = parse_timestamp("2024-03-09T12:00:00Z")
        self.assertEqual(ts, "2024-03-09T12:00:00Z")
        self.assertFalse(ambig)

    def test_parse_timestamp_no_timezone_is_ambiguous(self):
        ts, ambig = parse_timestamp("2024-03-09T12:00:00")
        self.assertIsNotNone(ts)
        self.assertTrue(ambig)

    def test_parse_timestamp_none_returns_none(self):
        ts, ambig = parse_timestamp(None)
        self.assertIsNone(ts)

    def test_parse_timestamp_garbage_returns_none(self):
        ts, ambig = parse_timestamp("not-a-date")
        self.assertIsNone(ts)

    def test_coerce_value_str(self):
        self.assertEqual(coerce_value(42, "str"), "42")

    def test_coerce_value_int(self):
        self.assertEqual(coerce_value("7", "int"), 7)

    def test_coerce_value_float_nan_rejected(self):
        with self.assertRaises(ValueError):
            coerce_value(float("nan"), "float")

    def test_coerce_value_bool_string(self):
        self.assertTrue(coerce_value("yes", "bool"))
        self.assertFalse(coerce_value("no", "bool"))

    def test_coerce_value_unknown_transform_raises(self):
        with self.assertRaises(ValueError):
            coerce_value("x", "magic")

    def test_get_dot_path_simple(self):
        obj = {"a": {"b": 1}}
        val, found = get_dot_path(obj, "a.b")
        self.assertTrue(found)
        self.assertEqual(val, 1)

    def test_get_dot_path_missing(self):
        _, found = get_dot_path({"a": 1}, "a.b.c")
        self.assertFalse(found)

    def test_measure_depth_flat(self):
        self.assertEqual(measure_depth({"a": 1}), 1)

    def test_measure_depth_nested(self):
        self.assertEqual(measure_depth({"a": {"b": {"c": 1}}}), 3)

    def test_current_utc_z_format(self):
        import re
        ts = current_utc_z()
        self.assertRegex(ts, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


# ══════════════════════════════════════════════════════════════════════════════
# Phase 2 — AdapterResult status computation
# ══════════════════════════════════════════════════════════════════════════════

class TestAdapterResult(unittest.TestCase):
    """Phase 2: Result status computation."""

    def _result(self, **kwargs):
        return AdapterResult(
            adapter_name="test", adapter_version="1.0", trust_level=TRUST_UNAUTHENTICATED,
            input_hash="a" * 64, **kwargs
        )

    def test_status_accepted_clean(self):
        r = self._result()
        e = CanonicalEvent("src", "EVT", {})
        r.add_event(e)
        self.assertEqual(r.status, STATUS_ACCEPTED)

    def test_status_accepted_with_loss(self):
        r = self._result()
        r.add_event(CanonicalEvent("src", "EVT", {}))
        r.add_loss(LOSS_OF_PRECISION, "f", "d")
        self.assertEqual(r.status, STATUS_ACCEPTED_WITH_LOSS)

    def test_status_rejected_no_events(self):
        r = self._result()
        r.add_rejection(REJECT_MALFORMED, "bad")
        self.assertEqual(r.status, STATUS_REJECTED)

    def test_status_unsupported_no_events_no_rejections(self):
        r = self._result()
        self.assertEqual(r.status, STATUS_UNSUPPORTED)

    def test_to_dict_has_required_keys(self):
        r = self._result()
        d = r.to_dict()
        for k in ("adapter_name", "adapter_version", "trust_level", "status",
                   "input_hash", "canonical_events", "losses", "rejections", "warnings"):
            self.assertIn(k, d)

    def test_build_raw_ref_hashed_mode(self):
        raw = b"hello"
        ref = build_raw_ref(raw, "HASHED")
        self.assertEqual(ref["input_hash"], hashlib.sha256(raw).hexdigest())
        self.assertIsNone(ref["content"])

    def test_build_raw_ref_full_mode(self):
        raw = b'{"x": 1}'
        ref = build_raw_ref(raw, "FULL")
        self.assertEqual(ref["content"], {"x": 1})


# ══════════════════════════════════════════════════════════════════════════════
# Phase 3 — JSON adapter
# ══════════════════════════════════════════════════════════════════════════════

class TestJSONAdapter(unittest.TestCase):
    """Phase 3: JSON adapter — direct mode."""

    def setUp(self):
        self.adapter = JSONAdapter()

    def test_clean_event_accepted(self):
        raw = _raw({"source": "test", "event_type": "PING", "payload": {"x": 1}})
        result = self.adapter.adapt(raw)
        self.assertEqual(result.status, STATUS_ACCEPTED)
        self.assertEqual(len(result.canonical_events), 1)
        self.assertEqual(result.canonical_events[0].event_type, "PING")

    def test_malformed_json_rejected(self):
        result = self.adapter.adapt(b"{not json}")
        self.assertEqual(result.status, STATUS_REJECTED)
        self.assertTrue(any(r.rejection_type == REJECT_MALFORMED for r in result.rejections))

    def test_missing_required_field_rejected(self):
        raw = _raw({"source": "x", "payload": {}})  # missing event_type
        result = self.adapter.adapt(raw)
        self.assertEqual(result.status, STATUS_REJECTED)

    def test_payload_not_dict_rejected(self):
        raw = _raw({"source": "x", "event_type": "E", "payload": [1, 2, 3]})
        result = self.adapter.adapt(raw)
        self.assertEqual(result.status, STATUS_REJECTED)

    def test_timestamp_parsed(self):
        raw = _raw({"source": "s", "event_type": "E", "payload": {},
                    "time_wall": "2024-01-01T00:00:00Z"})
        result = self.adapter.adapt(raw)
        self.assertEqual(result.status, STATUS_ACCEPTED)
        self.assertEqual(result.canonical_events[0].time_wall, "2024-01-01T00:00:00Z")

    def test_ambiguous_timestamp_records_loss(self):
        raw = _raw({"source": "s", "event_type": "E", "payload": {},
                    "timestamp": "2024-01-01T12:00:00"})
        result = self.adapter.adapt(raw)
        self.assertTrue(any(l.loss_type == LOSS_OF_AUTHENTICITY for l in result.losses))

    def test_unknown_fields_recorded_as_structure_loss(self):
        raw = _raw({"source": "s", "event_type": "E", "payload": {}, "extra_field": "x"})
        result = self.adapter.adapt(raw)
        self.assertTrue(any(l.loss_type == LOSS_OF_STRUCTURE for l in result.losses))

    def test_array_of_events_translated(self):
        raw = _raw([
            {"source": "s", "event_type": "E1", "payload": {}},
            {"source": "s", "event_type": "E2", "payload": {}},
        ])
        result = self.adapter.adapt(raw)
        self.assertEqual(len(result.canonical_events), 2)

    def test_input_hash_deterministic(self):
        raw = _raw({"source": "s", "event_type": "E", "payload": {}})
        r1 = self.adapter.adapt(raw)
        r2 = self.adapter.adapt(raw)
        self.assertEqual(r1.input_hash, r2.input_hash)

    def test_to_ingest_record_shape(self):
        raw = _raw({"source": "src", "event_type": "EVT", "payload": {"k": "v"}})
        result = self.adapter.adapt(raw)
        records = result.to_ingest_records()
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertIn("source", rec)
        self.assertIn("event_type", rec)
        self.assertIn("payload", rec)


# ══════════════════════════════════════════════════════════════════════════════
# Phase 4 — File adapter
# ══════════════════════════════════════════════════════════════════════════════

class TestFileAdapter(unittest.TestCase):
    """Phase 4: File and log adapter."""

    def setUp(self):
        self.adapter = FileAdapter()

    def _lines(self, objs):
        return "\n".join(json.dumps(o) for o in objs).encode("utf-8")

    def test_clean_jsonl_accepted(self):
        raw = self._lines([
            {"event_type": "SENSOR", "payload": {"v": 1}},
            {"event_type": "SENSOR", "payload": {"v": 2}},
        ])
        result = self.adapter.adapt(raw)
        self.assertEqual(len(result.canonical_events), 2)

    def test_mixed_mode_bad_line_rejected_individually(self):
        raw = b'{"event_type":"E","payload":{}}\nnot json\n{"event_type":"E2","payload":{}}'
        result = self.adapter.adapt(raw)
        # 2 valid events, 1 rejection, not REJECTED overall
        self.assertEqual(len(result.canonical_events), 2)
        self.assertTrue(any(r.rejection_type == REJECT_MALFORMED for r in result.rejections))
        self.assertNotEqual(result.status, STATUS_REJECTED)

    def test_strict_mode_single_error_rejects_all(self):
        raw = b'{"event_type":"E","payload":{}}\nnot json\n{"event_type":"E2","payload":{}}'
        result = self.adapter.adapt(raw, profile={"mode": "STRICT", "source_name": "test"})
        self.assertEqual(result.status, STATUS_REJECTED)
        self.assertEqual(len(result.canonical_events), 0)

    def test_empty_lines_skipped_silently(self):
        raw = b'\n\n{"event_type":"E","payload":{}}\n\n'
        result = self.adapter.adapt(raw)
        self.assertEqual(len(result.canonical_events), 1)

    def test_no_payload_key_uses_remaining_fields_with_loss(self):
        raw = b'{"event_type":"E","sensor":"X","value":42}'
        result = self.adapter.adapt(raw)
        self.assertEqual(len(result.canonical_events), 1)
        self.assertTrue(any(l.loss_type == LOSS_OF_STRUCTURE for l in result.losses))

    def test_not_utf8_rejected(self):
        result = self.adapter.adapt(b"\xff\xfe invalid")
        self.assertEqual(result.status, STATUS_REJECTED)


# ══════════════════════════════════════════════════════════════════════════════
# Phase 5A — AI audit adapter
# ══════════════════════════════════════════════════════════════════════════════

class TestAIAuditAdapter(unittest.TestCase):
    """Phase 5A: AI audit adapter."""

    def setUp(self):
        self.adapter = AIAuditAdapter()

    def test_inference_request_clean(self):
        raw = _raw({
            "record_type": "inference_request",
            "model": "claude-3",
            "session_id": "sess-001",
            "prompt": "What is 2+2?",
            "timestamp": "2024-01-01T00:00:00Z",
        })
        result = self.adapter.adapt(raw)
        self.assertEqual(len(result.canonical_events), 1)
        self.assertEqual(result.canonical_events[0].event_type, "AI_INFERENCE_REQUEST")

    def test_inference_response_missing_request_id_records_causal_loss(self):
        raw = _raw({
            "record_type": "inference_response",
            "model": "claude-3",
            "response": "4",
        })
        result = self.adapter.adapt(raw)
        self.assertTrue(any(l.loss_type == LOSS_OF_CAUSAL_LINKAGE for l in result.losses))

    def test_model_version_preserved_exactly(self):
        raw = _raw({"record_type": "model_version", "model": "claude-sonnet-4-6", "provider": "Anthropic"})
        result = self.adapter.adapt(raw)
        ev = result.canonical_events[0]
        self.assertEqual(ev.payload["model"], "claude-sonnet-4-6")

    def test_prompt_truncation_records_loss(self):
        long_prompt = "x" * 10_000
        raw = _raw({"record_type": "inference_request", "model": "m", "prompt": long_prompt})
        result = self.adapter.adapt(raw)
        self.assertTrue(any(l.loss_type == LOSS_OF_COMPLETENESS for l in result.losses))

    def test_unknown_record_type_produces_ai_unknown_record_with_loss(self):
        raw = _raw({"record_type": "future_record_type", "data": "x"})
        result = self.adapter.adapt(raw)
        self.assertEqual(result.canonical_events[0].event_type, "AI_UNKNOWN_RECORD")
        self.assertTrue(any(l.loss_type == LOSS_OF_STRUCTURE for l in result.losses))

    def test_missing_model_in_inference_request_rejected(self):
        raw = _raw({"record_type": "inference_request"})
        result = self.adapter.adapt(raw)
        self.assertTrue(any(r.rejection_type == REJECT_INCOMPLETE for r in result.rejections))

    def test_content_hashing_when_enabled(self):
        adapter = AIAuditAdapter(hash_content=True)
        prompt = "Hello"
        raw = _raw({"record_type": "inference_request", "model": "m", "prompt": prompt})
        result = adapter.adapt(raw)
        ev = result.canonical_events[0]
        expected = hashlib.sha256(prompt.encode()).hexdigest()
        self.assertEqual(ev.payload.get("content_hash"), expected)

    def test_session_boundary_events(self):
        raw = _raw({"record_type": "session_start", "session_id": "s1"})
        result = self.adapter.adapt(raw)
        self.assertEqual(result.canonical_events[0].event_type, "AI_SESSION_START")


# ══════════════════════════════════════════════════════════════════════════════
# Phase 6 — OT adapter
# ══════════════════════════════════════════════════════════════════════════════

class TestOTAdapter(unittest.TestCase):
    """Phase 6: OT and sensor adapter."""

    def setUp(self):
        self.adapter = OTAdapter(stale_threshold_s=300)

    def test_clean_sensor_reading(self):
        raw = _raw({
            "record_type": "sensor_reading",
            "device_id": "PUMP-01",
            "value": 42.5,
            "unit": "bar",
            "quality": "GOOD",
            "timestamp": "2024-01-01T00:00:00Z",
        })
        result = self.adapter.adapt(raw)
        self.assertEqual(len(result.canonical_events), 1)
        ev = result.canonical_events[0]
        self.assertEqual(ev.event_type, "OT_SENSOR_READING")
        self.assertEqual(ev.payload["device_id"], "PUMP-01")
        self.assertEqual(ev.payload["value"], 42.5)

    def test_bad_quality_records_authenticity_loss(self):
        raw = _raw({
            "record_type": "sensor_reading",
            "device_id": "TMP-01",
            "value": 99.9,
            "quality": "BAD",
        })
        result = self.adapter.adapt(raw)
        self.assertTrue(any(l.loss_type == LOSS_OF_AUTHENTICITY for l in result.losses))

    def test_nan_value_rejected(self):
        raw = b'{"record_type":"sensor_reading","device_id":"D","value":NaN}'
        result = self.adapter.adapt(raw)
        # NaN in JSON is MALFORMED (not parseable by strict JSON)
        self.assertEqual(result.status, STATUS_REJECTED)

    def test_missing_device_id_rejected(self):
        raw = _raw({"record_type": "sensor_reading", "value": 1.0})
        result = self.adapter.adapt(raw)
        self.assertTrue(any(r.rejection_type == REJECT_INCOMPLETE for r in result.rejections))

    def test_unknown_record_type_produces_loss_not_rejection(self):
        raw = _raw({"record_type": "future_ot_type", "device_id": "X"})
        result = self.adapter.adapt(raw)
        self.assertEqual(result.canonical_events[0].event_type, "OT_UNKNOWN_RECORD")
        self.assertTrue(any(l.loss_type == LOSS_OF_STRUCTURE for l in result.losses))

    def test_state_change_missing_from_state_records_causal_loss(self):
        raw = _raw({"record_type": "state_change", "device_id": "V-01", "to_state": "OPEN"})
        result = self.adapter.adapt(raw)
        self.assertTrue(any(l.loss_type == LOSS_OF_CAUSAL_LINKAGE for l in result.losses))

    def test_array_of_readings(self):
        raw = _raw([
            {"record_type": "sensor_reading", "device_id": "D1", "value": 1.0},
            {"record_type": "sensor_reading", "device_id": "D2", "value": 2.0},
        ])
        result = self.adapter.adapt(raw)
        self.assertEqual(len(result.canonical_events), 2)

    def test_alarm_ingested(self):
        raw = _raw({
            "record_type": "alarm",
            "device_id": "COMP-01",
            "alarm_id": "A001",
            "severity": "HIGH",
            "message": "Pressure exceeded limit",
        })
        result = self.adapter.adapt(raw)
        self.assertEqual(result.canonical_events[0].event_type, "OT_ALARM")

    def test_unknown_unit_preserved(self):
        raw = _raw({
            "record_type": "sensor_reading",
            "device_id": "D",
            "value": 5.0,
            "unit": "PROPRIETARY_UNIT",
        })
        result = self.adapter.adapt(raw)
        ev = result.canonical_events[0]
        self.assertEqual(ev.payload["unit"], "PROPRIETARY_UNIT")

    def test_stale_timestamp_records_authenticity_loss(self):
        raw = _raw({
            "record_type": "sensor_reading",
            "device_id": "D",
            "value": 1.0,
            "timestamp": "2000-01-01T00:00:00Z",  # very stale
        })
        result = self.adapter.adapt(raw)
        self.assertTrue(any(l.loss_type == LOSS_OF_AUTHENTICITY for l in result.losses))


# ══════════════════════════════════════════════════════════════════════════════
# Phase 7 — Mapping profiles
# ══════════════════════════════════════════════════════════════════════════════

class TestMappingProfiles(unittest.TestCase):
    """Phase 7: Profile engine."""

    def test_profile_applies_field_mapping(self):
        from aletheia.adapters.profiles import load_profile, apply_profile
        profile_path = Path(__file__).resolve().parent.parent / "profiles" / "json_generic_v1.json"
        if not profile_path.exists():
            self.skipTest("json_generic_v1.json not present")
        profile = load_profile(profile_path)
        result = apply_profile(profile, {"source": "sys", "message": "hello", "level": "INFO"})
        self.assertTrue(result.matched)
        self.assertTrue(len(result.events) > 0)

    def test_required_field_missing_produces_rejection(self):
        from aletheia.adapters.profiles import apply_profile
        profile = {
            "profile_id": "test", "profile_version": "1", "adapter_name": "json_adapter",
            "source_name": "test",
            "event_mappings": [{
                "event_type": "EVT",
                "field_mappings": [{"source_field": "id", "target_field": "id", "required": True}]
            }]
        }
        result = apply_profile(profile, {"other": "value"})
        self.assertTrue(result.rejected)

    def test_optional_missing_field_records_loss(self):
        from aletheia.adapters.profiles import apply_profile
        profile = {
            "profile_id": "test", "profile_version": "1", "adapter_name": "json_adapter",
            "source_name": "test",
            "event_mappings": [{
                "event_type": "EVT",
                "field_mappings": [{"source_field": "optional_field", "target_field": "x", "required": False}]
            }]
        }
        result = apply_profile(profile, {"other": "value"})
        self.assertTrue(any(l["loss_type"] == LOSS_OF_COMPLETENESS for l in result.losses))

    def test_fallback_value_used_when_field_absent(self):
        from aletheia.adapters.profiles import apply_profile
        profile = {
            "profile_id": "test", "profile_version": "1", "adapter_name": "json_adapter",
            "source_name": "test",
            "event_mappings": [{
                "event_type": "EVT",
                "field_mappings": [{"source_field": "missing", "target_field": "x",
                                    "required": False, "fallback": "DEFAULT"}]
            }]
        }
        result = apply_profile(profile, {})
        self.assertEqual(result.events[0]["payload"]["x"], "DEFAULT")

    def test_coercion_failure_produces_rejection(self):
        from aletheia.adapters.profiles import apply_profile
        profile = {
            "profile_id": "test", "profile_version": "1", "adapter_name": "json_adapter",
            "source_name": "test",
            "event_mappings": [{
                "event_type": "EVT",
                "field_mappings": [{"source_field": "v", "target_field": "v",
                                    "required": True, "transform": "int"}]
            }]
        }
        result = apply_profile(profile, {"v": "not-a-number"})
        self.assertTrue(result.rejected)


# ══════════════════════════════════════════════════════════════════════════════
# Phase 10 — AdapterMonitor
# ══════════════════════════════════════════════════════════════════════════════

class TestAdapterMonitor(unittest.TestCase):
    """Phase 10: Observability and drift detection."""

    def test_monitor_records_run_to_file(self):
        from tools.adapter_stats import AdapterMonitor
        from aletheia.adapters.runner import RunnerReport, GateDecision

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "stats.jsonl"
            monitor = AdapterMonitor(path)

            # Minimal fake report
            result = AdapterResult(
                adapter_name="json_adapter", adapter_version="1.0.0",
                trust_level=TRUST_UNAUTHENTICATED, input_hash="a" * 64
            )
            result.add_event(CanonicalEvent("s", "E", {}))

            class FakeReport:
                adapter_name = "json_adapter"
                adapter_result = result
                gate_decisions = []
                runner_error = None
                @property
                def events_accepted(self): return 1
                @property
                def events_rejected_by_gate(self): return 0

            monitor.record(FakeReport())
            lines = path.read_text().strip().splitlines()
            self.assertEqual(len(lines), 1)
            row = json.loads(lines[0])
            self.assertEqual(row["adapter_name"], "json_adapter")

    def test_registry_lists_all_adapters(self):
        adapters = list_adapters()
        self.assertIn("json_adapter", adapters)
        self.assertIn("file_adapter", adapters)
        self.assertIn("ai_audit_adapter", adapters)
        self.assertIn("ot_adapter", adapters)


# ══════════════════════════════════════════════════════════════════════════════
# Phase 11 — Security hardening (hostile inputs)
# ══════════════════════════════════════════════════════════════════════════════

class TestHostileInputs(unittest.TestCase):
    """Phase 11: Adapters cannot be exploited as a weak entry point."""

    def test_json_adapter_rejects_oversized_input(self):
        adapter = JSONAdapter()
        adapter.MAX_INPUT_BYTES = 100
        raw = b"x" * 200
        result = adapter.adapt(raw)
        self.assertEqual(result.status, STATUS_REJECTED)
        self.assertTrue(any(r.rejection_type == REJECT_HOSTILE for r in result.rejections))

    def test_json_adapter_rejects_deep_nesting(self):
        # Build a 40-deep nested dict (exceeds MAX_PAYLOAD_DEPTH=32)
        obj = {}
        cur = obj
        for _ in range(40):
            cur["x"] = {}
            cur = cur["x"]
        raw = json.dumps({"source": "s", "event_type": "E", "payload": obj}).encode()
        result = JSONAdapter().adapt(raw)
        self.assertEqual(result.status, STATUS_REJECTED)
        self.assertTrue(any(r.rejection_type == REJECT_HOSTILE for r in result.rejections))

    def test_file_adapter_rejects_oversized_file(self):
        adapter = FileAdapter()
        adapter.MAX_FILE_BYTES = 10
        raw = b"x" * 100
        result = adapter.adapt(raw)
        self.assertEqual(result.status, STATUS_REJECTED)

    def test_json_adapter_rejects_non_utf8(self):
        result = JSONAdapter().adapt(b"\xff\xfe garbage bytes \x80\x81")
        self.assertEqual(result.status, STATUS_REJECTED)

    def test_json_adapter_rejects_nan_in_payload(self):
        # NaN in JSON is malformed per RFC 8259
        result = JSONAdapter().adapt(b'{"source":"s","event_type":"E","payload":{"v":NaN}}')
        self.assertEqual(result.status, STATUS_REJECTED)

    def test_json_adapter_array_overflow_rejected(self):
        # 501 items exceeds MAX_EVENTS_PER_INPUT=500
        items = [{"source": "s", "event_type": "E", "payload": {}} for _ in range(501)]
        raw = json.dumps(items).encode()
        result = JSONAdapter().adapt(raw)
        self.assertEqual(result.status, STATUS_REJECTED)
        self.assertTrue(any(r.rejection_type == REJECT_HOSTILE for r in result.rejections))

    def test_file_adapter_max_lines_enforced(self):
        adapter = FileAdapter()
        adapter.MAX_LINES = 3
        raw = b"\n".join(b'{"event_type":"E","payload":{}}' for _ in range(10))
        result = adapter.adapt(raw)
        self.assertEqual(result.status, STATUS_REJECTED)

    def test_ot_adapter_rejects_oversized_array(self):
        from aletheia.adapters.determinism import MAX_EVENTS_PER_INPUT
        items = [{"record_type": "sensor_reading", "device_id": "D", "value": 1.0}
                 for _ in range(MAX_EVENTS_PER_INPUT + 1)]
        raw = json.dumps(items).encode()
        result = OTAdapter().adapt(raw)
        self.assertEqual(result.status, STATUS_REJECTED)

    def test_unicode_confusion_normalised(self):
        # Two visually identical source strings that differ at byte level
        # should normalise to the same value
        s1 = "cafe\u0301"  # combining accent
        s2 = "caf\u00e9"   # precomposed
        self.assertEqual(normalise_unicode(s1), normalise_unicode(s2))

    def test_adapter_result_input_hash_always_64_chars(self):
        raw = _raw({"source": "s", "event_type": "E", "payload": {}})
        result = JSONAdapter().adapt(raw)
        self.assertEqual(len(result.input_hash), 64)
        self.assertRegex(result.input_hash, r"^[0-9a-f]{64}$")


# ══════════════════════════════════════════════════════════════════════════════
# Runner integration (Phase 2 + Ingest Gate)
# ══════════════════════════════════════════════════════════════════════════════

class TestAdapterRunner(unittest.TestCase):
    """Phase 2: Runner + IngestGate integration."""

    def _make_gate(self, td):
        from aletheia.spine.ledger import SpineLedger
        from aletheia.ingest.gate import IngestGate, IngestConfig
        root = Path(td)
        ledger = SpineLedger(root)
        ledger.open_window("ingest")
        gate = IngestGate(ledger, config=IngestConfig(
            window_id="ingest", max_accepts_per_sec=10000
        ))
        return gate, ledger

    def test_runner_clean_event_reaches_gate(self):
        from aletheia.adapters.runner import AdapterRunner
        with tempfile.TemporaryDirectory() as td:
            gate, ledger = self._make_gate(td)
            runner = AdapterRunner(gate)
            raw = _raw({"source": "test", "event_type": "PING", "payload": {"x": 1}})
            report = runner.run("json_adapter", raw)
            self.assertEqual(report.events_accepted, 1)
            ledger.close_clean()

    def test_runner_rejected_adapter_records_zero_gate_decisions(self):
        from aletheia.adapters.runner import AdapterRunner
        with tempfile.TemporaryDirectory() as td:
            gate, ledger = self._make_gate(td)
            runner = AdapterRunner(gate)
            report = runner.run("json_adapter", b"NOT JSON")
            self.assertEqual(len(report.gate_decisions), 0)
            self.assertEqual(report.adapter_result.status, STATUS_REJECTED)
            ledger.close_clean()

    def test_runner_unknown_adapter_captured_cleanly(self):
        from aletheia.adapters.runner import AdapterRunner
        with tempfile.TemporaryDirectory() as td:
            gate, ledger = self._make_gate(td)
            runner = AdapterRunner(gate)
            report = runner.run("nonexistent_adapter", b"{}")
            self.assertIsNotNone(report.runner_error)
            ledger.close_clean()

    def test_runner_report_to_dict(self):
        from aletheia.adapters.runner import AdapterRunner
        with tempfile.TemporaryDirectory() as td:
            gate, ledger = self._make_gate(td)
            runner = AdapterRunner(gate)
            raw = _raw({"source": "s", "event_type": "E", "payload": {}})
            report = runner.run("json_adapter", raw)
            d = report.to_dict()
            for k in ("adapter_name", "adapter_status", "events_accepted", "gate_decisions"):
                self.assertIn(k, d)
            ledger.close_clean()


if __name__ == "__main__":
    unittest.main(verbosity=2)
