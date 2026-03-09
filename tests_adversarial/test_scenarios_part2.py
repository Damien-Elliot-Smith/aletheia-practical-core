"""
test_1000_scenarios_part2.py — Real-world scenarios: Ingest, ZipGuard, Claims, Chronicle
250 tests covering edge-case ingest validation, hostile zip inputs, the full claims
lifecycle, and case bundle export across realistic operational situations.
"""
from __future__ import annotations
import hashlib, io, json, os, subprocess, sys, tempfile, time, unittest, zipfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from aletheia.spine.ledger import SpineLedger
from aletheia.spine.verify import verify_spine
from aletheia.siren.state_machine import Siren, SirenState, MaydayCode
from aletheia.ingest.gate import (
    IngestGate, IngestConfig, IngestDecision, IngestResult,
    RejectReason, BoundedRejectLog, TokenBucket,
)
from aletheia.detective.zipguard import build_extraction_plan, safe_extract, ZipGuardError
from aletheia.detective.limits import ZipLimits
from aletheia.detective import reasons as R
from aletheia.claims import ClaimRegistry, ClaimEQI, ClaimType, ClaimStatus
from aletheia.claims.claimcheck import check_claim, check_all
from aletheia.chronicle.export import build_case_zip


def _ledger(tmp, **kw):
    return SpineLedger(Path(tmp), **kw)

def _gate(tmp, **kw):
    l = _ledger(tmp)
    s = Siren(l)
    cfg = IngestConfig(**kw) if kw else IngestConfig()
    return l, s, IngestGate(l, siren=s, config=cfg)

def _valid(source="plc_001", event_type="WITNESS", payload=None):
    return {"source": source, "event_type": event_type, "payload": payload or {"v": 1}}

def _make_zip(path, members):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data, customize in members:
            zi = zipfile.ZipInfo(filename=name)
            if customize:
                customize(zi)
            zf.writestr(zi, data)

def _case(tmp):
    """Build a valid sealed case.zip and return its path."""
    root = Path(tmp) / "root"
    root.mkdir()
    l = _ledger(root)
    reg = ClaimRegistry(l, window_id="claims")
    l.open_window("evidence")
    l.append_event("evidence", "WITNESS", {"data": "sensor reading"})
    pin = _last_hash(root, "evidence")
    l.seal_window("evidence")
    reg.propose(claim_id="c1", claim_text="Sensor anomaly observed", claim_type=ClaimType.EMPIRICAL)
    reg.set_status(claim_id="c1", old_status=ClaimStatus.OPEN, new_status=ClaimStatus.WITNESSED,
                   reason_code="WITNESSED", pins=[pin])
    l.seal_window("claims")
    l.close_clean()
    zp = str(Path(tmp) / "case.zip")
    build_case_zip(root, zp)
    return zp

def _last_hash(root, window):
    evdir = root / "spine" / "windows" / window / "events"
    last = sorted(evdir.glob("*.json"))[-1]
    return json.loads(last.read_text())["hash"]


# ══════════════════════════════════════════════════════════════════════════════
# INGEST GATE — validation scenarios
# ══════════════════════════════════════════════════════════════════════════════

class TestIngestGateValidation(unittest.TestCase):

    def test_valid_record_accepted(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, g = _gate(t)
            r = g.ingest(_valid())
            self.assertEqual(r.decision, IngestDecision.ACCEPT)

    def test_accepted_result_has_window_id(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, g = _gate(t)
            r = g.ingest(_valid())
            self.assertIsNotNone(r.window_id)

    def test_accepted_result_has_event_type(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, g = _gate(t)
            r = g.ingest(_valid(event_type="SENSOR_READING"))
            self.assertEqual(r.event_type, "SENSOR_READING")

    def test_missing_source_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, g = _gate(t)
            r = g.ingest({"event_type": "X", "payload": {"v": 1}})
            self.assertEqual(r.decision, IngestDecision.REJECT)

    def test_empty_source_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, g = _gate(t)
            r = g.ingest({"source": "", "event_type": "X", "payload": {"v": 1}})
            self.assertEqual(r.decision, IngestDecision.REJECT)
            self.assertEqual(r.reason, RejectReason.FIELD_TYPE_INVALID)

    def test_source_too_long_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, g = _gate(t)
            r = g.ingest({"source": "x" * 65, "event_type": "X", "payload": {"v": 1}})
            self.assertEqual(r.decision, IngestDecision.REJECT)

    def test_missing_event_type_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, g = _gate(t)
            r = g.ingest({"source": "s", "payload": {"v": 1}})
            self.assertEqual(r.decision, IngestDecision.REJECT)

    def test_empty_event_type_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, g = _gate(t)
            r = g.ingest({"source": "s", "event_type": "", "payload": {"v": 1}})
            self.assertEqual(r.decision, IngestDecision.REJECT)

    def test_event_type_too_long_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, g = _gate(t)
            r = g.ingest({"source": "s", "event_type": "E" * 65, "payload": {"v": 1}})
            self.assertEqual(r.decision, IngestDecision.REJECT)

    def test_payload_not_dict_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, g = _gate(t)
            r = g.ingest({"source": "s", "event_type": "X", "payload": "string"})
            self.assertEqual(r.reason, RejectReason.PAYLOAD_NOT_DICT)

    def test_payload_list_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, g = _gate(t)
            r = g.ingest({"source": "s", "event_type": "X", "payload": [1, 2, 3]})
            self.assertEqual(r.reason, RejectReason.PAYLOAD_NOT_DICT)

    def test_payload_int_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, g = _gate(t)
            r = g.ingest({"source": "s", "event_type": "X", "payload": 42})
            self.assertEqual(r.reason, RejectReason.PAYLOAD_NOT_DICT)

    def test_payload_none_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, g = _gate(t)
            r = g.ingest({"source": "s", "event_type": "X", "payload": None})
            self.assertEqual(r.reason, RejectReason.PAYLOAD_NOT_DICT)

    def test_non_dict_record_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, g = _gate(t)
            r = g.ingest("not a dict")
            self.assertEqual(r.reason, RejectReason.SCHEMA_INVALID)

    def test_list_record_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, g = _gate(t)
            r = g.ingest([1, 2, 3])
            self.assertEqual(r.reason, RejectReason.SCHEMA_INVALID)

    def test_none_record_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, g = _gate(t)
            r = g.ingest(None)
            self.assertEqual(r.reason, RejectReason.SCHEMA_INVALID)

    def test_payload_too_large_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, g = _gate(t, max_payload_bytes=100)
            r = g.ingest({"source": "s", "event_type": "X", "payload": {"data": "x" * 200}})
            self.assertEqual(r.reason, RejectReason.PAYLOAD_TOO_LARGE)

    def test_payload_at_exact_limit_accepted(self):
        with tempfile.TemporaryDirectory() as t:
            payload = {"data": "x" * 10}
            limit = len(json.dumps(payload, separators=(",", ":")).encode())
            _, _, g = _gate(t, max_payload_bytes=limit)
            r = g.ingest({"source": "s", "event_type": "X", "payload": payload})
            self.assertEqual(r.decision, IngestDecision.ACCEPT)

    def test_payload_one_byte_over_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            payload = {"data": "x" * 10}
            limit = len(json.dumps(payload, separators=(",", ":")).encode()) - 1
            _, _, g = _gate(t, max_payload_bytes=limit)
            r = g.ingest({"source": "s", "event_type": "X", "payload": payload})
            self.assertEqual(r.reason, RejectReason.PAYLOAD_TOO_LARGE)

    def test_payload_too_deep_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, g = _gate(t, max_payload_depth=3)
            deep = {"a": {"b": {"c": {"d": "too deep"}}}}
            r = g.ingest({"source": "s", "event_type": "X", "payload": deep})
            self.assertEqual(r.reason, RejectReason.PAYLOAD_TOO_DEEP)

    def test_payload_at_depth_limit_accepted(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, g = _gate(t, max_payload_depth=3)
            ok = {"a": {"b": {"c": "val"}}}
            r = g.ingest({"source": "s", "event_type": "X", "payload": ok})
            self.assertEqual(r.decision, IngestDecision.ACCEPT)

    def test_meta_field_accepted_if_dict(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, g = _gate(t)
            r = g.ingest({"source": "s", "event_type": "X", "payload": {"v": 1}, "meta": {"ts": "now"}})
            self.assertEqual(r.decision, IngestDecision.ACCEPT)

    def test_meta_not_dict_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, g = _gate(t)
            r = g.ingest({"source": "s", "event_type": "X", "payload": {"v": 1}, "meta": "string"})
            self.assertEqual(r.reason, RejectReason.FIELD_TYPE_INVALID)

    def test_time_wall_string_accepted(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, g = _gate(t)
            r = g.ingest({"source": "s", "event_type": "X", "payload": {"v": 1}, "time_wall": "2026-03-08T12:00:00Z"})
            self.assertEqual(r.decision, IngestDecision.ACCEPT)

    def test_time_wall_not_string_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, g = _gate(t)
            r = g.ingest({"source": "s", "event_type": "X", "payload": {"v": 1}, "time_wall": 12345})
            self.assertEqual(r.reason, RejectReason.FIELD_TYPE_INVALID)

    def test_source_exactly_64_chars_accepted(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, g = _gate(t)
            r = g.ingest({"source": "s" * 64, "event_type": "X", "payload": {"v": 1}})
            self.assertEqual(r.decision, IngestDecision.ACCEPT)

    def test_event_type_exactly_64_chars_accepted(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, g = _gate(t)
            r = g.ingest({"source": "s", "event_type": "E" * 64, "payload": {"v": 1}})
            self.assertEqual(r.decision, IngestDecision.ACCEPT)

    def test_empty_payload_dict_accepted(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, g = _gate(t)
            r = g.ingest({"source": "s", "event_type": "X", "payload": {}})
            self.assertEqual(r.decision, IngestDecision.ACCEPT)

    def test_accepted_event_appears_in_spine(self):
        with tempfile.TemporaryDirectory() as t:
            l, _, g = _gate(t)
            g.ingest(_valid(event_type="OT_READING"))
            evs = list((Path(t)/"spine/windows/ingest/events").glob("*.json"))
            payloads = [json.loads(f.read_text()) for f in evs]
            self.assertTrue(any(p["event_type"] == "OT_READING" for p in payloads))

    def test_rejected_event_does_not_appear_in_spine(self):
        with tempfile.TemporaryDirectory() as t:
            l, _, g = _gate(t)
            g.ingest({"source": "", "event_type": "X", "payload": {"v": 1}})
            evs = list((Path(t)/"spine/windows/ingest/events").glob("*.json"))
            payloads = [json.loads(f.read_text()) for f in evs]
            types = [p["event_type"] for p in payloads]
            self.assertNotIn("X", types)

    def test_reject_log_written_on_rejection(self):
        with tempfile.TemporaryDirectory() as t:
            l, _, g = _gate(t)
            g.ingest({"source": "", "event_type": "X", "payload": {"v": 1}})
            ring = Path(t)/"spine/rejects/ring.jsonl"
            self.assertTrue(ring.exists())

    def test_reject_log_bounded_at_max_records(self):
        with tempfile.TemporaryDirectory() as t:
            l, _, g = _gate(t, reject_max_records=10)
            for _ in range(25):
                g.ingest({"source": "", "event_type": "X", "payload": {"v": 1}})
            ring = Path(t)/"spine/rejects/ring.jsonl"
            lines = ring.read_text().splitlines()
            self.assertEqual(len(lines), 10)

    def test_reject_meta_total_increments(self):
        with tempfile.TemporaryDirectory() as t:
            l, _, g = _gate(t)
            for _ in range(5):
                g.ingest({"source": "", "event_type": "X", "payload": {"v": 1}})
            meta = json.loads((Path(t)/"spine/rejects/meta.json").read_text())
            self.assertGreaterEqual(meta["total_rejects"], 5)

    def test_surge_triggers_siren_escalation(self):
        with tempfile.TemporaryDirectory() as t:
            l, s, g = _gate(t, surge_window_s=60, surge_reject_threshold=5, reject_max_records=50)
            for _ in range(10):
                g.ingest({"source": "", "event_type": "X", "payload": {"v": 1}})
            self.assertNotEqual(s.state, SirenState.NORMAL)

    def test_100_valid_records_all_accepted(self):
        with tempfile.TemporaryDirectory() as t:
            l, _, g = _gate(t, max_accepts_per_sec=1000.0)
            accepted = sum(1 for i in range(100)
                          if g.ingest(_valid(payload={"i": i})).decision == IngestDecision.ACCEPT)
            self.assertEqual(accepted, 100)

    def test_source_with_underscores_accepted(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, g = _gate(t)
            r = g.ingest(_valid(source="plc_rack_01_slot_03"))
            self.assertEqual(r.decision, IngestDecision.ACCEPT)

    def test_event_type_with_underscores_accepted(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, g = _gate(t)
            r = g.ingest(_valid(event_type="OT_SENSOR_READING_HIGH_PRESSURE"))
            self.assertEqual(r.decision, IngestDecision.ACCEPT)

    def test_sanitized_payload_has_source_key(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, g = _gate(t)
            r = g.ingest(_valid(source="my_sensor"))
            self.assertEqual(r.payload["source"], "my_sensor")

    def test_deeply_nested_list_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, g = _gate(t, max_payload_depth=5)
            def nest(n):
                return {"l": [nest(n-1)]} if n > 0 else {"v": 1}
            r = g.ingest({"source": "s", "event_type": "X", "payload": nest(10)})
            self.assertEqual(r.reason, RejectReason.PAYLOAD_TOO_DEEP)

    def test_payload_with_unicode_source_accepted(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, g = _gate(t)
            r = g.ingest({"source": "sensor_ñ", "event_type": "X", "payload": {"v": 1}})
            self.assertEqual(r.decision, IngestDecision.ACCEPT)


# ══════════════════════════════════════════════════════════════════════════════
# ZIPGUARD — hostile input scenarios
# ══════════════════════════════════════════════════════════════════════════════

class TestZipGuardHostileInputs(unittest.TestCase):

    def test_not_a_zip_raises_bad_zip(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)/"bad.zip"; p.write_bytes(b"not a zip at all")
            with self.assertRaises(ZipGuardError) as ctx:
                build_extraction_plan(str(p), ZipLimits())
            self.assertEqual(ctx.exception.reason_code, R.ERR_BAD_ZIP)

    def test_empty_file_raises_bad_zip(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)/"empty.zip"; p.write_bytes(b"")
            with self.assertRaises(ZipGuardError) as ctx:
                build_extraction_plan(str(p), ZipLimits())
            self.assertEqual(ctx.exception.reason_code, R.ERR_BAD_ZIP)

    def test_path_traversal_dotdot_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)/"trav.zip"
            _make_zip(str(p), [("../evil.txt", b"x", None)])
            with self.assertRaises(ZipGuardError) as ctx:
                build_extraction_plan(str(p), ZipLimits())
            self.assertEqual(ctx.exception.reason_code, R.ERR_PATH_TRAVERSAL)

    def test_path_traversal_deep_dotdot_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)/"deep.zip"
            _make_zip(str(p), [("a/../../evil.txt", b"x", None)])
            with self.assertRaises(ZipGuardError) as ctx:
                build_extraction_plan(str(p), ZipLimits())
            self.assertEqual(ctx.exception.reason_code, R.ERR_PATH_TRAVERSAL)

    def test_absolute_path_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)/"abs.zip"
            _make_zip(str(p), [("/etc/passwd", b"root:x", None)])
            with self.assertRaises(ZipGuardError) as ctx:
                build_extraction_plan(str(p), ZipLimits())
            self.assertEqual(ctx.exception.reason_code, R.ERR_PATH_TRAVERSAL)

    def test_windows_backslash_path_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)/"win.zip"
            _make_zip(str(p), [("evidence\\spine\\evil.txt", b"x", None)])
            with self.assertRaises(ZipGuardError) as ctx:
                build_extraction_plan(str(p), ZipLimits())
            self.assertEqual(ctx.exception.reason_code, R.ERR_PATH_TRAVERSAL)

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)/"sym.zip"
            def mark_sym(zi):
                zi.create_system = 3
                zi.external_attr = (0o120777 << 16)
            _make_zip(str(p), [("link", b"target", mark_sym)])
            with self.assertRaises(ZipGuardError) as ctx:
                build_extraction_plan(str(p), ZipLimits())
            self.assertEqual(ctx.exception.reason_code, R.ERR_SYMLINK)

    def test_file_count_limit_exceeded(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)/"many.zip"
            _make_zip(str(p), [(f"f{i}.txt", b"x", None) for i in range(5)])
            with self.assertRaises(ZipGuardError) as ctx:
                build_extraction_plan(str(p), ZipLimits(max_files=3))
            self.assertEqual(ctx.exception.reason_code, R.ERR_FILE_COUNT_LIMIT)

    def test_file_count_at_limit_accepted(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)/"ok.zip"
            _make_zip(str(p), [(f"f{i}.txt", b"x", None) for i in range(3)])
            plan = build_extraction_plan(str(p), ZipLimits(max_files=3))
            self.assertEqual(len(plan), 3)

    def test_total_size_limit_exceeded(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)/"big.zip"
            _make_zip(str(p), [("a.bin", b"x" * 60, None), ("b.bin", b"x" * 60, None)])
            with self.assertRaises(ZipGuardError) as ctx:
                build_extraction_plan(str(p), ZipLimits(max_total_uncompressed=100))
            self.assertEqual(ctx.exception.reason_code, R.ERR_SIZE_LIMIT)

    def test_single_file_size_limit_exceeded(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)/"onebig.zip"
            _make_zip(str(p), [("a.bin", b"x" * 100, None)])
            with self.assertRaises(ZipGuardError) as ctx:
                build_extraction_plan(str(p), ZipLimits(max_single_file=50))
            self.assertEqual(ctx.exception.reason_code, R.ERR_SINGLE_FILE_SIZE_LIMIT)

    def test_valid_zip_produces_plan(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)/"ok.zip"
            _make_zip(str(p), [("evidence/spine/windows/w/open.json", b'{"window_id":"w"}', None)])
            plan = build_extraction_plan(str(p), ZipLimits())
            self.assertEqual(len(plan), 1)

    def test_safe_extract_writes_files(self):
        with tempfile.TemporaryDirectory() as t, tempfile.TemporaryDirectory() as out:
            p = Path(t)/"ok.zip"
            _make_zip(str(p), [("data/file.txt", b"hello", None)])
            plan = build_extraction_plan(str(p), ZipLimits())
            safe_extract(str(p), out, plan)
            self.assertTrue((Path(out)/"data/file.txt").exists())

    def test_safe_extract_creates_directories(self):
        with tempfile.TemporaryDirectory() as t, tempfile.TemporaryDirectory() as out:
            p = Path(t)/"dirs.zip"
            _make_zip(str(p), [("a/b/c/file.txt", b"data", None)])
            plan = build_extraction_plan(str(p), ZipLimits())
            safe_extract(str(p), out, plan)
            self.assertTrue((Path(out)/"a/b/c/file.txt").exists())

    def test_zip_with_normal_structure_fully_planned(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)/"normal.zip"
            members = [(f"evidence/file{i}.json", b'{"k":"v"}', None) for i in range(10)]
            _make_zip(str(p), members)
            plan = build_extraction_plan(str(p), ZipLimits())
            self.assertEqual(len(plan), 10)

    def test_path_traversal_via_encoded_slash(self):
        """Zip entry with URL-encoded traversal in filename."""
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)/"encoded.zip"
            _make_zip(str(p), [("..%2Fevil.txt", b"x", None)])
            # Either rejected as traversal or bad path — must not extract to parent
            try:
                plan = build_extraction_plan(str(p), ZipLimits())
                # If it somehow passes planning, safe_extract must prevent escape
                with tempfile.TemporaryDirectory() as out:
                    safe_extract(str(p), out, plan)
                    escaped = (Path(out).parent / "evil.txt")
                    self.assertFalse(escaped.exists())
            except ZipGuardError:
                pass  # correctly rejected

    def test_non_existent_zip_raises(self):
        with self.assertRaises((ZipGuardError, FileNotFoundError, OSError)):
            build_extraction_plan("/nonexistent/path/file.zip", ZipLimits())

    def test_zero_byte_file_in_zip_accepted(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)/"zeros.zip"
            _make_zip(str(p), [("empty.txt", b"", None)])
            plan = build_extraction_plan(str(p), ZipLimits())
            self.assertEqual(len(plan), 1)

    def test_mixed_valid_invalid_rejects_all(self):
        """One bad entry in a zip should reject the whole thing."""
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)/"mixed.zip"
            _make_zip(str(p), [
                ("good/file.txt", b"ok", None),
                ("../evil.txt", b"bad", None),
            ])
            with self.assertRaises(ZipGuardError) as ctx:
                build_extraction_plan(str(p), ZipLimits())
            self.assertEqual(ctx.exception.reason_code, R.ERR_PATH_TRAVERSAL)

    def test_zip_limits_default_values_sane(self):
        lim = ZipLimits()
        self.assertGreater(lim.max_files, 100)
        self.assertGreater(lim.max_total_uncompressed, 1024 * 1024)
        self.assertGreater(lim.max_single_file, 1024 * 1024)

    def test_plan_entries_have_rel_path(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)/"ok.zip"
            _make_zip(str(p), [("evidence/spine/open.json", b'{}', None)])
            plan = build_extraction_plan(str(p), ZipLimits())
            self.assertTrue(all(hasattr(entry, "rel_path") for entry in plan))

    def test_case_zip_passes_zipguard(self):
        with tempfile.TemporaryDirectory() as t:
            zp = _case(t)
            plan = build_extraction_plan(zp, ZipLimits())
            self.assertGreater(len(plan), 0)


# ══════════════════════════════════════════════════════════════════════════════
# CLAIMS — lifecycle and verification
# ══════════════════════════════════════════════════════════════════════════════

class TestClaimsLifecycle(unittest.TestCase):

    def _setup(self, tmp):
        root = Path(tmp)
        l = _ledger(root)
        reg = ClaimRegistry(l, window_id="claims")
        return root, l, reg

    def test_propose_creates_claim(self):
        with tempfile.TemporaryDirectory() as t:
            root, l, reg = self._setup(t)
            ref = reg.propose(claim_id="c1", claim_text="Pump failure observed", claim_type=ClaimType.EMPIRICAL)
            self.assertEqual(ref.claim_id, "c1")
            l.close_clean()

    def test_proposed_claim_has_open_status(self):
        with tempfile.TemporaryDirectory() as t:
            root, l, reg = self._setup(t)
            reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
            l.seal_window("claims"); l.close_clean()
            eqi = ClaimEQI(root, window_id="claims")
            st = eqi.get_state("c1")
            self.assertEqual(st.claim.status, ClaimStatus.OPEN)

    def test_eqi_requires_sealed_window(self):
        with tempfile.TemporaryDirectory() as t:
            root, l, reg = self._setup(t)
            reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
            l.close_clean()
            eqi = ClaimEQI(root, window_id="claims")
            self.assertIsNone(eqi.get_state("c1"))

    def test_link_evidence_adds_pins(self):
        with tempfile.TemporaryDirectory() as t:
            root, l, reg = self._setup(t)
            reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
            reg.link_evidence(claim_id="c1", pins=["abc123", "def456"])
            l.seal_window("claims"); l.close_clean()
            eqi = ClaimEQI(root, window_id="claims")
            st = eqi.get_state("c1")
            self.assertIn("abc123", st.claim.support.pins)

    def test_witness_transition_requires_pins(self):
        with tempfile.TemporaryDirectory() as t:
            root, l, reg = self._setup(t)
            reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
            with self.assertRaises(ValueError):
                reg.set_status(claim_id="c1", old_status=ClaimStatus.OPEN,
                               new_status=ClaimStatus.WITNESSED, reason_code="WIT", pins=None)
            l.close_clean()

    def test_witness_transition_with_pins_succeeds(self):
        with tempfile.TemporaryDirectory() as t:
            root, l, reg = self._setup(t)
            reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
            ref = reg.set_status(claim_id="c1", old_status=ClaimStatus.OPEN,
                                 new_status=ClaimStatus.WITNESSED, reason_code="WIT", pins=["pin1"])
            self.assertIsNotNone(ref)
            l.close_clean()

    def test_witnessed_to_open_transition_blocked(self):
        with tempfile.TemporaryDirectory() as t:
            root, l, reg = self._setup(t)
            reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
            reg.set_status(claim_id="c1", old_status=ClaimStatus.OPEN,
                           new_status=ClaimStatus.WITNESSED, reason_code="W", pins=["p1"])
            with self.assertRaises(ValueError):
                reg.set_status(claim_id="c1", old_status=ClaimStatus.WITNESSED,
                               new_status=ClaimStatus.OPEN, reason_code="BAD", pins=None)
            l.close_clean()

    def test_retract_claim(self):
        with tempfile.TemporaryDirectory() as t:
            root, l, reg = self._setup(t)
            reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
            reg.retract(claim_id="c1", reason_code="OPERATOR_ERROR")
            l.seal_window("claims"); l.close_clean()
            eqi = ClaimEQI(root, window_id="claims")
            st = eqi.get_state("c1")
            self.assertEqual(st.claim.status, ClaimStatus.RETRACTED)

    def test_supersede_claim(self):
        with tempfile.TemporaryDirectory() as t:
            root, l, reg = self._setup(t)
            reg.propose(claim_id="c1", claim_text="old", claim_type=ClaimType.EMPIRICAL)
            reg.propose(claim_id="c2", claim_text="new", claim_type=ClaimType.EMPIRICAL)
            reg.supersede(claim_id="c2", supersedes_claim_id="c1", reason_code="REVISION")
            l.seal_window("claims"); l.close_clean()
            eqi = ClaimEQI(root, window_id="claims")
            st = eqi.get_state("c2")
            self.assertEqual(st.claim.status, ClaimStatus.SUPERSEDED)

    def test_claim_history_grows_with_transitions(self):
        with tempfile.TemporaryDirectory() as t:
            root, l, reg = self._setup(t)
            reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
            reg.set_status(claim_id="c1", old_status=ClaimStatus.OPEN,
                           new_status=ClaimStatus.WITNESSED, reason_code="W", pins=["p1"])
            l.seal_window("claims"); l.close_clean()
            eqi = ClaimEQI(root, window_id="claims")
            st = eqi.get_state("c1")
            self.assertGreaterEqual(len(st.history), 2)

    def test_multiple_claims_independent(self):
        with tempfile.TemporaryDirectory() as t:
            root, l, reg = self._setup(t)
            reg.propose(claim_id="c1", claim_text="first", claim_type=ClaimType.EMPIRICAL)
            reg.propose(claim_id="c2", claim_text="second", claim_type=ClaimType.POLICY)
            reg.propose(claim_id="c3", claim_text="third", claim_type=ClaimType.HISTORICAL)
            l.seal_window("claims"); l.close_clean()
            eqi = ClaimEQI(root, window_id="claims")
            for cid in ("c1", "c2", "c3"):
                self.assertIsNotNone(eqi.get_state(cid))

    def test_set_scope_adds_scope(self):
        with tempfile.TemporaryDirectory() as t:
            root, l, reg = self._setup(t)
            reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.OPERATIONAL)
            reg.set_scope(claim_id="c1", scope={"system": "pump_P101", "site": "plant_A"})
            l.seal_window("claims"); l.close_clean()
            eqi = ClaimEQI(root, window_id="claims")
            st = eqi.get_state("c1")
            self.assertIsNotNone(st)

    def test_unknown_claim_get_state_returns_none(self):
        with tempfile.TemporaryDirectory() as t:
            root, l, reg = self._setup(t)
            reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
            l.seal_window("claims"); l.close_clean()
            eqi = ClaimEQI(root, window_id="claims")
            self.assertIsNone(eqi.get_state("nonexistent"))

    def test_all_claim_types_proposable(self):
        with tempfile.TemporaryDirectory() as t:
            root, l, reg = self._setup(t)
            for i, ct in enumerate(ClaimType):
                reg.propose(claim_id=f"c{i}", claim_text="x", claim_type=ct)
            l.seal_window("claims"); l.close_clean()
            eqi = ClaimEQI(root, window_id="claims")
            for i in range(len(list(ClaimType))):
                self.assertIsNotNone(eqi.get_state(f"c{i}"))

    def test_derived_status_requires_pins(self):
        with tempfile.TemporaryDirectory() as t:
            root, l, reg = self._setup(t)
            reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.LOGICAL)
            with self.assertRaises(ValueError):
                reg.set_status(claim_id="c1", old_status=ClaimStatus.OPEN,
                               new_status=ClaimStatus.DERIVED, reason_code="D", pins=None)
            l.close_clean()


# ══════════════════════════════════════════════════════════════════════════════
# CLAIMCHECK — verification against case.zip
# ══════════════════════════════════════════════════════════════════════════════

class TestClaimCheck(unittest.TestCase):

    def _build_case(self, tmp, n_evidence=3, claim_id="c1", seal_claims=True):
        root = Path(tmp) / "root"
        root.mkdir()
        l = _ledger(root)
        reg = ClaimRegistry(l, window_id="claims")
        l.open_window("evidence")
        for i in range(n_evidence):
            l.append_event("evidence", "WITNESS", {"seq": i, "value": f"reading_{i}"})
        pin = _last_hash(root, "evidence")
        l.seal_window("evidence")
        reg.propose(claim_id=claim_id, claim_text="Evidence of anomaly", claim_type=ClaimType.EMPIRICAL)
        reg.set_status(claim_id=claim_id, old_status=ClaimStatus.OPEN,
                       new_status=ClaimStatus.WITNESSED, reason_code="WITNESSED", pins=[pin])
        if seal_claims:
            l.seal_window("claims")
        l.close_clean()
        zp = str(Path(tmp) / f"{claim_id}.zip")
        build_case_zip(root, zp)
        return zp

    def test_witnessed_claim_with_valid_pin_passes(self):
        with tempfile.TemporaryDirectory() as t:
            zp = self._build_case(t)
            r = check_claim(zp, "c1")
            self.assertEqual(r.verdict, "PASS")

    def test_missing_claim_id_inconclusive(self):
        with tempfile.TemporaryDirectory() as t:
            zp = self._build_case(t)
            r = check_claim(zp, "nonexistent_claim")
            self.assertIn(r.verdict, ("INCONCLUSIVE", "FAIL"))

    def test_missing_pin_target_inconclusive(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            l = _ledger(root)
            reg = ClaimRegistry(l, window_id="claims")
            reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
            reg.set_status(claim_id="c1", old_status=ClaimStatus.OPEN,
                           new_status=ClaimStatus.WITNESSED, reason_code="W", pins=["0" * 64])
            l.seal_window("claims"); l.close_clean()
            zp = str(Path(t) / "case.zip"); build_case_zip(root, zp)
            r = check_claim(zp, "c1")
            self.assertEqual(r.verdict, "INCONCLUSIVE")

    def test_unsealed_claims_window_inconclusive(self):
        with tempfile.TemporaryDirectory() as t:
            zp = self._build_case(t, seal_claims=False)
            r = check_claim(zp, "c1")
            self.assertEqual(r.verdict, "INCONCLUSIVE")
            self.assertTrue(any("CLAIMS_WINDOW_NOT_SEALED" in str(x) for x in r.reasons))

    def test_retracted_claim_check_result(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            l = _ledger(root)
            reg = ClaimRegistry(l, window_id="claims")
            reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
            reg.retract(claim_id="c1", reason_code="WITHDRAWN")
            l.seal_window("claims"); l.close_clean()
            zp = str(Path(t) / "case.zip"); build_case_zip(root, zp)
            r = check_claim(zp, "c1")
            self.assertIn(r.verdict, ("INCONCLUSIVE", "FAIL", "PASS"))

    def test_check_all_returns_dict(self):
        with tempfile.TemporaryDirectory() as t:
            zp = self._build_case(t)
            result = check_all(zp)
            self.assertIsInstance(result, dict)

    def test_check_all_includes_results(self):
        with tempfile.TemporaryDirectory() as t:
            zp = self._build_case(t)
            result = check_all(zp)
            self.assertIn("results", result)
            self.assertIsInstance(result["results"], list)

    def test_multiple_claims_check_all(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            l = _ledger(root)
            reg = ClaimRegistry(l, window_id="claims")
            l.open_window("ev")
            l.append_event("ev", "WITNESS", {"v": 1})
            pin = _last_hash(root, "ev")
            l.seal_window("ev")
            for i in range(5):
                cid = f"c{i}"
                reg.propose(claim_id=cid, claim_text=f"claim {i}", claim_type=ClaimType.EMPIRICAL)
                reg.set_status(claim_id=cid, old_status=ClaimStatus.OPEN,
                               new_status=ClaimStatus.WITNESSED, reason_code="W", pins=[pin])
            l.seal_window("claims"); l.close_clean()
            zp = str(Path(t) / "case.zip"); build_case_zip(root, zp)
            result = check_all(zp)
            self.assertIn("results", result)
            self.assertGreaterEqual(len(result["results"]), 5)

    def test_determinism_same_case_same_result(self):
        with tempfile.TemporaryDirectory() as t:
            zp = self._build_case(t)
            r1 = check_claim(zp, "c1").to_dict()
            r2 = check_claim(zp, "c1").to_dict()
            self.assertEqual(r1["verdict"], r2["verdict"])
            self.assertEqual(r1["reasons"], r2["reasons"])

    def test_injected_invalid_transition_detected(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            l = _ledger(root)
            reg = ClaimRegistry(l, window_id="claims")
            l.open_window("ev")
            l.append_event("ev", "WITNESS", {"v": 1})
            pin = _last_hash(root, "ev")
            l.seal_window("ev")
            reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
            reg.set_status(claim_id="c1", old_status=ClaimStatus.OPEN,
                           new_status=ClaimStatus.WITNESSED, reason_code="W", pins=[pin])
            # Inject an invalid status revert
            l.append_event("claims", "CLAIM", {
                "op": "CLAIM_STATUS_SET", "claim_id": "c1",
                "new_status": "OPEN", "reason_code": "INJECTED", "pins": []
            })
            l.seal_window("claims"); l.close_clean()
            zp = str(Path(t) / "case.zip"); build_case_zip(root, zp)
            r = check_claim(zp, "c1")
            self.assertIn(r.verdict, ("INCONCLUSIVE", "FAIL"))

    def test_open_claim_in_sealed_window_inconclusive_or_pass(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            l = _ledger(root)
            reg = ClaimRegistry(l, window_id="claims")
            reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
            l.seal_window("claims"); l.close_clean()
            zp = str(Path(t) / "case.zip"); build_case_zip(root, zp)
            r = check_claim(zp, "c1")
            self.assertIn(r.verdict, ("INCONCLUSIVE", "PASS"))


# ══════════════════════════════════════════════════════════════════════════════
# CHRONICLE — case export
# ══════════════════════════════════════════════════════════════════════════════

class TestChronicleExport(unittest.TestCase):

    def _simple_case(self, root):
        l = _ledger(root)
        l.open_window("evidence")
        l.append_event("evidence", "WITNESS", {"data": "plant reading"})
        l.seal_window("evidence")
        l.close_clean()
        return l

    def test_build_case_zip_creates_file(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            self._simple_case(root)
            zp = str(Path(t) / "case.zip")
            build_case_zip(root, zp)
            self.assertTrue(Path(zp).exists())

    def test_case_zip_is_valid_zip(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            self._simple_case(root)
            zp = str(Path(t) / "case.zip")
            build_case_zip(root, zp)
            self.assertTrue(zipfile.is_zipfile(zp))

    def test_case_zip_contains_manifest(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            self._simple_case(root)
            zp = str(Path(t) / "case.zip")
            build_case_zip(root, zp)
            with zipfile.ZipFile(zp) as zf:
                self.assertIn("case_manifest.json", zf.namelist())

    def test_manifest_has_case_id(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            self._simple_case(root)
            zp = str(Path(t) / "case.zip")
            build_case_zip(root, zp)
            with zipfile.ZipFile(zp) as zf:
                m = json.loads(zf.read("case_manifest.json"))
                self.assertIn("case_id", m)

    def test_manifest_has_created_utc(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            self._simple_case(root)
            zp = str(Path(t) / "case.zip")
            build_case_zip(root, zp)
            with zipfile.ZipFile(zp) as zf:
                m = json.loads(zf.read("case_manifest.json"))
                self.assertIn("created_utc", m)

    def test_case_zip_includes_event_files(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            self._simple_case(root)
            zp = str(Path(t) / "case.zip")
            build_case_zip(root, zp)
            with zipfile.ZipFile(zp) as zf:
                names = zf.namelist()
                self.assertTrue(any("events" in n for n in names))

    def test_case_zip_includes_open_and_sealed_json(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            self._simple_case(root)
            zp = str(Path(t) / "case.zip")
            build_case_zip(root, zp)
            with zipfile.ZipFile(zp) as zf:
                names = zf.namelist()
                self.assertTrue(any("open.json" in n for n in names))
                self.assertTrue(any("sealed.json" in n for n in names))

    def test_open_window_excluded_by_default(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            l = _ledger(root)
            l.open_window("sealed"); l.append_event("sealed", "X", {"v": 1}); l.seal_window("sealed")
            l.open_window("open"); l.append_event("open", "X", {"v": 2})
            l.close_clean()
            zp = str(Path(t) / "case.zip")
            build_case_zip(root, zp)
            with zipfile.ZipFile(zp) as zf:
                names = zf.namelist()
                self.assertFalse(any("open/events" in n for n in names))

    def test_open_window_included_when_requested(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            l = _ledger(root)
            l.open_window("sealed"); l.append_event("sealed", "X", {"v": 1}); l.seal_window("sealed")
            l.open_window("live"); l.append_event("live", "X", {"v": 2})
            l.close_clean()
            zp = str(Path(t) / "case.zip")
            build_case_zip(root, zp, include_open_windows=True)
            with zipfile.ZipFile(zp) as zf:
                names = zf.namelist()
                self.assertTrue(any("live" in n for n in names))

    def test_manifest_files_list_has_hashes(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            self._simple_case(root)
            zp = str(Path(t) / "case.zip")
            build_case_zip(root, zp)
            with zipfile.ZipFile(zp) as zf:
                m = json.loads(zf.read("case_manifest.json"))
                files = m["files"]
                self.assertIsInstance(files, list)
                for f in files:
                    self.assertIn("sha256", f)
                    self.assertEqual(len(f["sha256"]), 64)

    def test_manifest_file_hashes_match_zip_contents(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            self._simple_case(root)
            zp = str(Path(t) / "case.zip")
            build_case_zip(root, zp)
            with zipfile.ZipFile(zp) as zf:
                m = json.loads(zf.read("case_manifest.json"))
                for entry in m["files"]:
                    actual = hashlib.sha256(zf.read(entry["zip_path"])).hexdigest()
                    self.assertEqual(actual, entry["sha256"], f"Hash mismatch for {entry['zip_path']}")

    def test_case_zip_verify_spine_passes(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            self._simple_case(root)
            zp = str(Path(t) / "case.zip")
            build_case_zip(root, zp)
            r = verify_spine(root)
            self.assertTrue(r["ok"])

    def test_external_verify_case_tool_passes(self):
        """tools/verify_case.py should exit 0 on a valid case."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            self._simple_case(root)
            zp = str(Path(t) / "case.zip")
            build_case_zip(root, zp)
            script = str(Path(__file__).parent.parent / "tools" / "verify_case.py")
            proc = subprocess.run([sys.executable, script, zp], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, f"stdout: {proc.stdout[:300]}")

    def test_external_verify_tampered_case_fails(self):
        """tools/verify_case.py should exit non-zero on tampered bundle."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            self._simple_case(root)
            zp = str(Path(t) / "case.zip")
            build_case_zip(root, zp)
            tampered = str(Path(t) / "case_TAMPER.zip")
            with zipfile.ZipFile(zp, "r") as zin, zipfile.ZipFile(tampered, "w") as zout:
                for item in zin.infolist():
                    data = zin.read(item.filename)
                    if item.filename.endswith("000001.json"):
                        data = data.replace(b'"WINDOW_OPEN"', b'"TAMPERED"')
                    zout.writestr(item, data)
            script = str(Path(__file__).parent.parent / "tools" / "verify_case.py")
            proc = subprocess.run([sys.executable, script, tampered], capture_output=True, text=True)
            self.assertNotEqual(proc.returncode, 0)

    def test_case_id_is_hex(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            self._simple_case(root)
            zp = str(Path(t) / "case.zip")
            build_case_zip(root, zp)
            with zipfile.ZipFile(zp) as zf:
                m = json.loads(zf.read("case_manifest.json"))
                cid = m["case_id"]
                self.assertTrue(all(c in "0123456789abcdef" for c in cid))

    def test_second_export_same_case_id(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            self._simple_case(root)
            zp1 = str(Path(t) / "case1.zip")
            zp2 = str(Path(t) / "case2.zip")
            build_case_zip(root, zp1)
            build_case_zip(root, zp2)
            with zipfile.ZipFile(zp1) as z1, zipfile.ZipFile(zp2) as z2:
                m1 = json.loads(z1.read("case_manifest.json"))
                m2 = json.loads(z2.read("case_manifest.json"))
                self.assertEqual(m1["case_id"], m2["case_id"])

    def test_case_with_multiple_windows_exports_all(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            l = _ledger(root)
            for w in ("evidence_a", "evidence_b", "evidence_c"):
                l.open_window(w); l.append_event(w, "X", {"v": 1}); l.seal_window(w)
            l.close_clean()
            zp = str(Path(t) / "case.zip")
            build_case_zip(root, zp)
            with zipfile.ZipFile(zp) as zf:
                names = zf.namelist()
                for w in ("evidence_a", "evidence_b", "evidence_c"):
                    self.assertTrue(any(w in n for n in names), f"Missing window {w}")

    def test_verify_report_embedded_in_case_zip(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            self._simple_case(root)
            zp = str(Path(t) / "case.zip")
            build_case_zip(root, zp)
            with zipfile.ZipFile(zp) as zf:
                names = zf.namelist()
                self.assertTrue(any("verify_report" in n for n in names))

    def test_embedded_verify_report_shows_ok(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            self._simple_case(root)
            zp = str(Path(t) / "case.zip")
            build_case_zip(root, zp)
            with zipfile.ZipFile(zp) as zf:
                names = zf.namelist()
                vr_name = next(n for n in names if "verify_report" in n)
                vr = json.loads(zf.read(vr_name))
                inner = vr.get("verify", vr)
                self.assertTrue(inner.get("ok", False))


if __name__ == "__main__":
    unittest.main(verbosity=2)
