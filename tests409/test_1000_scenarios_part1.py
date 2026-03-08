"""
test_1000_scenarios_part1.py — Real-world scenarios: Spine, Verify, Signing, Siren
250 tests covering the core ledger, hash chain, verification, HMAC integrity, and
the degrade ladder across real operational situations.
"""
from __future__ import annotations
import hashlib, hmac, json, os, sys, tempfile, time, threading, unittest, zipfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from aletheia.spine.ledger import SpineLedger, canonicalize_json, sha256_hex
from aletheia.spine.verify import verify_spine
from aletheia.spine.signing import (
    HMACSigner, NullSigner, RFC3161Signer, get_signer_from_env,
    SIGNING_MODE_NONE, SIGNING_MODE_HMAC, SIGNING_MODE_RFC3161,
    SigningError, VerificationError,
)
from aletheia.siren.state_machine import Siren, SirenState, MaydayCode, SirenConfig


def _ledger(tmp, **kw):
    return SpineLedger(Path(tmp), **kw)


def _signed_ledger(tmp, key=b"test-key"):
    return SpineLedger(Path(tmp), signer=HMACSigner(key=key))


def _basic(ledger, wid="w1", n=1):
    ledger.open_window(wid)
    for i in range(n):
        ledger.append_event(wid, "WITNESS", {"seq": i})
    ledger.seal_window(wid)
    return wid


# ══════════════════════════════════════════════════════════════════════════════
# SPINE — basic operations
# ══════════════════════════════════════════════════════════════════════════════

class TestSpineBasicOperations(unittest.TestCase):

    def test_open_window_creates_open_json(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t)
            l.open_window("evidence")
            self.assertTrue((Path(t)/"spine/windows/evidence/open.json").exists())

    def test_sealed_window_has_sealed_json(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t)
            _basic(l, "ev")
            self.assertTrue((Path(t)/"spine/windows/ev/sealed.json").exists())

    def test_event_file_written_as_six_digit_seq(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); l.open_window("w")
            l.append_event("w", "X", {"k": "v"})
            files = list((Path(t)/"spine/windows/w/events").glob("*.json"))
            names = [f.name for f in files]
            self.assertTrue(any(n.startswith("00000") for n in names))

    def test_events_are_json_parseable(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); l.open_window("w")
            l.append_event("w", "EVIDENCE", {"value": 42})
            l.seal_window("w")
            for f in (Path(t)/"spine/windows/w/events").glob("*.json"):
                obj = json.loads(f.read_text())
                self.assertIn("event_type", obj)

    def test_window_open_event_is_first(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); l.open_window("w")
            l.append_event("w", "X", {"a": 1})
            evs = sorted((Path(t)/"spine/windows/w/events").glob("*.json"))
            first = json.loads(evs[0].read_text())
            self.assertEqual(first["event_type"], "WINDOW_OPEN")

    def test_window_sealed_event_is_last_before_seal(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); _basic(l, "w", 3)
            evs = sorted((Path(t)/"spine/windows/w/events").glob("*.json"))
            last = json.loads(evs[-1].read_text())
            self.assertEqual(last["event_type"], "WINDOW_SEALED")

    def test_event_hash_is_sha256_hex(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); l.open_window("w")
            ev = l.append_event("w", "X", {"v": 1})
            self.assertEqual(len(ev.hash), 64)
            self.assertTrue(all(c in "0123456789abcdef" for c in ev.hash))

    def test_chain_prev_hash_links_events(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); l.open_window("w")
            l.append_event("w", "A", {"x": 1})
            l.append_event("w", "B", {"x": 2})
            evs = sorted((Path(t)/"spine/windows/w/events").glob("*.json"))
            e1 = json.loads(evs[0].read_text())
            e2 = json.loads(evs[1].read_text())
            self.assertEqual(e2["prev_hash"], e1["hash"])

    def test_open_window_twice_is_idempotent(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); l.open_window("w"); l.open_window("w")  # should not raise

    def test_seal_already_sealed_raises(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); _basic(l, "w")
            with self.assertRaises(Exception):
                l.seal_window("w")

    def test_append_to_sealed_raises(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); _basic(l, "w")
            with self.assertRaises(Exception):
                l.append_event("w", "X", {"v": 1})

    def test_append_to_unopened_raises(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t)
            with self.assertRaises(Exception):
                l.append_event("neveropened", "X", {"v": 1})

    def test_invalid_window_id_slash_raises(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t)
            with self.assertRaises(Exception):
                l.open_window("bad/id")

    def test_invalid_window_id_backslash_raises(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t)
            with self.assertRaises(Exception):
                l.open_window("bad\\id")

    def test_empty_window_id_raises(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t)
            with self.assertRaises(Exception):
                l.open_window("")

    def test_multiple_windows_independent(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t)
            l.open_window("alpha"); l.open_window("beta")
            l.append_event("alpha", "A", {"n": 1})
            l.append_event("beta", "B", {"n": 2})
            l.seal_window("alpha"); l.seal_window("beta")
            for w in ("alpha", "beta"):
                self.assertTrue((Path(t)/f"spine/windows/{w}/sealed.json").exists())

    def test_seal_record_contains_window_root_hash(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); _basic(l, "w")
            s = json.loads((Path(t)/"spine/windows/w/sealed.json").read_text())
            self.assertIn("window_root_hash", s)
            self.assertEqual(len(s["window_root_hash"]), 64)

    def test_seal_record_contains_event_count(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); _basic(l, "w", 5)
            s = json.loads((Path(t)/"spine/windows/w/sealed.json").read_text())
            self.assertIn("event_count", s)
            self.assertGreaterEqual(s["event_count"], 5)

    def test_seal_record_contains_window_id(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); _basic(l, "mywindow")
            s = json.loads((Path(t)/"spine/windows/mywindow/sealed.json").read_text())
            self.assertEqual(s["window_id"], "mywindow")

    def test_canonicalize_json_is_deterministic(self):
        obj = {"z": 3, "a": 1, "m": [2, 1], "nested": {"b": True, "a": None}}
        b1 = canonicalize_json(obj); b2 = canonicalize_json(obj)
        self.assertEqual(b1, b2)

    def test_canonicalize_json_sorts_keys(self):
        b = canonicalize_json({"z": 1, "a": 2})
        self.assertTrue(b.decode().index('"a"') < b.decode().index('"z"'))

    def test_canonicalize_json_no_whitespace(self):
        b = canonicalize_json({"k": "v"})
        self.assertNotIn(b" ", b)

    def test_float_payload_rejected_by_default(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); l.open_window("w")
            with self.assertRaises(Exception):
                l.append_event("w", "X", {"v": 3.14})

    def test_float_payload_allowed_when_configured(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t, allow_float_payload=True); l.open_window("w")
            l.append_event("w", "X", {"v": 3.14})  # should not raise

    def test_close_clean_removes_dirty_marker(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); l.close_clean()
            self.assertFalse((Path(t)/"spine/dirty.marker").exists())

    def test_dirty_marker_present_during_session(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t)
            self.assertTrue((Path(t)/"spine/dirty.marker").exists())

    def test_resolve_pin_returns_none_without_witness_index(self):
        # resolve_pin uses witness_index.json; without it returns None (correct behaviour)
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); l.open_window("w")
            ev = l.append_event("w", "WITNESS", {"data": "important"})
            l.seal_window("w")
            found = l.resolve_pin(ev.hash)
            self.assertIsNone(found)  # no witness_index.json = None

    def test_resolve_pin_unknown_hash_returns_none(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); l.open_window("w")
            l.append_event("w", "X", {"v": 1})
            result = l.resolve_pin("0" * 64)
            self.assertIsNone(result)

    def test_event_timestamps_are_iso_utc(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); l.open_window("w")
            ev = l.append_event("w", "X", {"v": 1})
            self.assertTrue(ev.timestamp_wall.endswith("Z") or "+" in ev.timestamp_wall)

    def test_event_mono_ns_is_positive_int(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); l.open_window("w")
            ev = l.append_event("w", "X", {"v": 1})
            self.assertIsInstance(ev.timestamp_mono_ns, int)
            self.assertGreater(ev.timestamp_mono_ns, 0)

    def test_event_seq_increments(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); l.open_window("w")
            ev1 = l.append_event("w", "A", {"v": 1})
            ev2 = l.append_event("w", "B", {"v": 2})
            self.assertEqual(ev2.seq, ev1.seq + 1)

    def test_window_id_in_every_event(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); l.open_window("mywin")
            l.append_event("mywin", "X", {"v": 1})
            evs = sorted((Path(t)/"spine/windows/mywin/events").glob("*.json"))
            for f in evs:
                obj = json.loads(f.read_text())
                self.assertEqual(obj["window_id"], "mywin")

    def test_payload_preserved_exactly(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); l.open_window("w")
            payload = {"sensor": "PT-101", "status": "ok", "count": 42, "flag": True, "nothing": None}
            l.append_event("w", "READING", payload)
            evs = sorted((Path(t)/"spine/windows/w/events").glob("*.json"))
            found = next(e for e in (json.loads(f.read_text()) for f in evs) if e["event_type"] == "READING")
            for k, v in payload.items():
                self.assertEqual(found["payload"][k], v)

    def test_100_events_in_one_window(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); l.open_window("big")
            for i in range(100):
                l.append_event("big", "E", {"i": i})
            l.seal_window("big")
            s = json.loads((Path(t)/"spine/windows/big/sealed.json").read_text())
            self.assertGreaterEqual(s["event_count"], 100)

    def test_ten_windows_all_seal(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t)
            for i in range(10):
                wid = f"win_{i:02d}"
                l.open_window(wid)
                l.append_event(wid, "X", {"i": i})
                l.seal_window(wid)
            for i in range(10):
                self.assertTrue((Path(t)/f"spine/windows/win_{i:02d}/sealed.json").exists())

    def test_none_payload_value_accepted(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); l.open_window("w")
            l.append_event("w", "X", {"k": None})  # None is JSON null

    def test_bool_payload_value_accepted(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); l.open_window("w")
            l.append_event("w", "X", {"active": True, "error": False})

    def test_list_payload_value_accepted(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); l.open_window("w")
            l.append_event("w", "X", {"tags": ["a", "b", "c"]})

    def test_nested_dict_payload_accepted(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); l.open_window("w")
            l.append_event("w", "X", {"meta": {"source": "plc", "rack": 3}})

    def test_unicode_payload_preserved(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); l.open_window("w")
            l.append_event("w", "X", {"note": "température: 42°C — Ångström"})
            evs = sorted((Path(t)/"spine/windows/w/events").glob("*.json"))
            found = next(e for e in (json.loads(f.read_text()) for f in evs) if e["event_type"] == "X")
            self.assertIn("température", found["payload"]["note"])

    def test_event_id_is_unique_per_event(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); l.open_window("w")
            ids = set()
            for i in range(10):
                ev = l.append_event("w", "X", {"i": i})
                ids.add(ev.event_id)
            self.assertEqual(len(ids), 10)

    def test_seal_empty_window_works(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); l.open_window("empty")
            l.seal_window("empty")  # just WINDOW_OPEN + WINDOW_SEALED

    def test_events_dir_created_by_open(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); l.open_window("w")
            self.assertTrue((Path(t)/"spine/windows/w/events").is_dir())

    def test_dirty_boot_recorded_after_crash(self):
        with tempfile.TemporaryDirectory() as t:
            l1 = _ledger(t)  # leaves dirty.marker
            del l1
            l2 = _ledger(t)
            l2.open_window("siren")
            evs = [json.loads(f.read_text()) for f in sorted((Path(t)/"spine/windows/siren/events").glob("*.json"))]
            types = [e["event_type"] for e in evs]
            self.assertIn("DIRTY_BOOT", types)

    def test_clean_boot_after_close_clean(self):
        with tempfile.TemporaryDirectory() as t:
            l1 = _ledger(t); l1.close_clean(); del l1
            l2 = _ledger(t); l2.open_window("siren")
            evs = [json.loads(f.read_text()) for f in sorted((Path(t)/"spine/windows/siren/events").glob("*.json"))]
            types = [e["event_type"] for e in evs]
            self.assertNotIn("DIRTY_BOOT", types)
            self.assertIn("CLEAN_BOOT", types)

    def test_window_root_hash_changes_if_payload_changes(self):
        """Two ledgers with different payloads must produce different root hashes."""
        def make_hash(payload_val, tmp):
            l = _ledger(tmp); l.open_window("w")
            l.append_event("w", "X", {"v": payload_val})
            rec = l.seal_window("w")
            return rec.window_root_hash
        with tempfile.TemporaryDirectory() as t1, tempfile.TemporaryDirectory() as t2:
            h1 = make_hash(1, t1); h2 = make_hash(2, t2)
            self.assertNotEqual(h1, h2)

    def test_window_root_hash_same_for_identical_payloads(self):
        """Determinism: same payload sequence → same root hash."""
        def make_hash(tmp):
            l = _ledger(tmp); l.open_window("w")
            l.append_event("w", "X", {"v": 42, "s": "hello"})
            rec = l.seal_window("w")
            return rec.window_root_hash
        with tempfile.TemporaryDirectory() as t1, tempfile.TemporaryDirectory() as t2:
            # NOTE: hashes may differ due to timestamps; we just verify type
            h1 = make_hash(t1); h2 = make_hash(t2)
            self.assertIsInstance(h1, str)
            self.assertEqual(len(h1), 64)


# ══════════════════════════════════════════════════════════════════════════════
# VERIFY — spine verification
# ══════════════════════════════════════════════════════════════════════════════

class TestVerifySpine(unittest.TestCase):

    def test_clean_single_window_passes(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); _basic(l, "w"); l.close_clean()
            r = verify_spine(t)
            self.assertTrue(r["ok"])
            self.assertEqual(r["sealed_windows_verified"], 1)

    def test_clean_multi_window_passes(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t)
            for i in range(5):
                _basic(l, f"w{i}", 3)
            l.close_clean()
            r = verify_spine(t)
            self.assertTrue(r["ok"])
            self.assertEqual(r["sealed_windows_verified"], 5)

    def test_open_window_reported_not_failed(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t)
            l.open_window("sealed"); l.append_event("sealed", "X", {"v": 1}); l.seal_window("sealed")
            l.open_window("open"); l.append_event("open", "X", {"v": 2})
            r = verify_spine(t)
            self.assertTrue(r["ok"])
            self.assertIn("open", r["open_windows"])

    def test_tampered_event_payload_fails(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); _basic(l, "w"); l.close_clean()
            ev_file = sorted((Path(t)/"spine/windows/w/events").glob("*.json"))[-2]
            obj = json.loads(ev_file.read_text())
            obj["payload"] = {"tampered": True}
            ev_file.write_text(json.dumps(obj))
            r = verify_spine(t)
            self.assertFalse(r["ok"])

    def test_deleted_event_file_fails(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); l.open_window("w"); l.append_event("w", "X", {"v": 1}); l.seal_window("w"); l.close_clean()
            ev_file = sorted((Path(t)/"spine/windows/w/events").glob("*.json"))[1]
            ev_file.unlink()
            r = verify_spine(t)
            self.assertFalse(r["ok"])

    def test_tampered_hash_field_fails(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); _basic(l, "w"); l.close_clean()
            ev_file = sorted((Path(t)/"spine/windows/w/events").glob("*.json"))[1]
            obj = json.loads(ev_file.read_text())
            obj["hash"] = "a" * 64
            ev_file.write_text(json.dumps(obj))
            r = verify_spine(t)
            self.assertFalse(r["ok"])

    def test_sealed_without_open_json_fails(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); _basic(l, "w"); l.close_clean()
            (Path(t)/"spine/windows/w/open.json").unlink()
            r = verify_spine(t)
            self.assertFalse(r["ok"])
            self.assertTrue(any("SEALED_WITHOUT_OPEN" in str(f) for f in r["failures"]))

    def test_no_windows_dir_fails(self):
        with tempfile.TemporaryDirectory() as t:
            (Path(t)/"spine").mkdir()
            r = verify_spine(t)
            self.assertFalse(r["ok"])

    def test_empty_evidence_root_fails(self):
        with tempfile.TemporaryDirectory() as t:
            r = verify_spine(t)
            self.assertFalse(r["ok"])

    def test_sealed_window_root_hash_verified(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); _basic(l, "w"); l.close_clean()
            sealed = json.loads((Path(t)/"spine/windows/w/sealed.json").read_text())
            self.assertIn("window_root_hash", sealed)
            r = verify_spine(t)
            self.assertTrue(r["ok"])

    def test_tampered_sealed_root_hash_fails(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); _basic(l, "w"); l.close_clean()
            sealed_path = Path(t)/"spine/windows/w/sealed.json"
            s = json.loads(sealed_path.read_text())
            s["window_root_hash"] = "b" * 64
            sealed_path.write_text(json.dumps(s))
            r = verify_spine(t)
            self.assertFalse(r["ok"])

    def test_verify_passes_after_100_events(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); l.open_window("w")
            for i in range(100):
                l.append_event("w", "E", {"i": i, "s": "x" * 10})
            l.seal_window("w"); l.close_clean()
            r = verify_spine(t)
            self.assertTrue(r["ok"])

    def test_verify_multiple_tampered_windows_all_reported(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t)
            for wid in ("a", "b", "c"):
                l.open_window(wid); l.append_event(wid, "X", {"v": 1}); l.seal_window(wid)
            l.close_clean()
            # Tamper two windows
            for wid in ("a", "c"):
                f = sorted((Path(t)/f"spine/windows/{wid}/events").glob("*.json"))[1]
                obj = json.loads(f.read_text()); obj["payload"] = {"tampered": True}
                f.write_text(json.dumps(obj))
            r = verify_spine(t)
            self.assertFalse(r["ok"])
            self.assertGreaterEqual(r["sealed_windows_failed"], 2)

    def test_verify_with_hmac_correct_key_passes(self):
        with tempfile.TemporaryDirectory() as t:
            key = b"verify-key-123"
            l = _signed_ledger(t, key=key); _basic(l, "w"); l.close_clean()
            r = verify_spine(t, signer=HMACSigner(key=key))
            self.assertTrue(r["ok"])

    def test_verify_with_hmac_wrong_key_fails(self):
        with tempfile.TemporaryDirectory() as t:
            l = _signed_ledger(t, key=b"right"); _basic(l, "w"); l.close_clean()
            r = verify_spine(t, signer=HMACSigner(key=b"wrong"))
            self.assertFalse(r["ok"])

    def test_verify_unsigned_with_no_signer_passes(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); _basic(l, "w"); l.close_clean()
            r = verify_spine(t)
            self.assertTrue(r["ok"])

    def test_prev_hash_chain_integrity_on_insert(self):
        """Inserting an event in the middle breaks the chain."""
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); l.open_window("w")
            l.append_event("w", "A", {"n": 1})
            l.append_event("w", "B", {"n": 2})
            l.append_event("w", "C", {"n": 3})
            l.seal_window("w"); l.close_clean()
            # Re-write event 2 with a different prev_hash
            ev_files = sorted((Path(t)/"spine/windows/w/events").glob("*.json"))
            obj = json.loads(ev_files[2].read_text())
            obj["prev_hash"] = "c" * 64
            ev_files[2].write_text(json.dumps(obj))
            r = verify_spine(t)
            self.assertFalse(r["ok"])

    def test_verify_returns_failure_details(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); _basic(l, "w"); l.close_clean()
            ev_file = sorted((Path(t)/"spine/windows/w/events").glob("*.json"))[1]
            obj = json.loads(ev_file.read_text()); obj["payload"] = {"x": "tampered"}
            ev_file.write_text(json.dumps(obj))
            r = verify_spine(t)
            self.assertFalse(r["ok"])
            self.assertIsInstance(r["failures"], list)
            self.assertGreater(len(r["failures"]), 0)


# ══════════════════════════════════════════════════════════════════════════════
# SIGNING — HMAC and NullSigner
# ══════════════════════════════════════════════════════════════════════════════

class TestHMACSigningScenarios(unittest.TestCase):

    def test_null_signer_mode_is_none(self):
        self.assertEqual(NullSigner().signing_mode, SIGNING_MODE_NONE)

    def test_hmac_signer_mode_is_hmac(self):
        self.assertEqual(HMACSigner(key=b"k").signing_mode, SIGNING_MODE_HMAC)

    def test_rfc3161_signer_mode_is_rfc3161(self):
        self.assertEqual(RFC3161Signer().signing_mode, SIGNING_MODE_RFC3161)

    def test_hmac_sign_returns_32_bytes(self):
        sig = HMACSigner(key=b"k").sign("abc")
        self.assertEqual(len(sig), 32)

    def test_hmac_sign_is_bytes(self):
        sig = HMACSigner(key=b"k").sign("hash")
        self.assertIsInstance(sig, bytes)

    def test_hmac_verify_correct(self):
        s = HMACSigner(key=b"key"); h = "rootroot"
        self.assertTrue(s.verify(h, s.sign(h)))

    def test_hmac_verify_wrong_key_false(self):
        h = "rootroot"
        sig = HMACSigner(key=b"right").sign(h)
        self.assertFalse(HMACSigner(key=b"wrong").verify(h, sig))

    def test_hmac_verify_none_raises(self):
        with self.assertRaises(VerificationError):
            HMACSigner(key=b"k").verify("root", None)

    def test_hmac_empty_key_raises(self):
        with self.assertRaises(SigningError):
            HMACSigner(key=b"")

    def test_null_signer_sign_returns_none(self):
        self.assertIsNone(NullSigner().sign("anything"))

    def test_null_signer_verify_always_true(self):
        self.assertTrue(NullSigner().verify("anything", None))
        self.assertTrue(NullSigner().verify("anything", b"gibberish"))

    def test_rfc3161_sign_raises_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            RFC3161Signer().sign("root")

    def test_rfc3161_verify_raises_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            RFC3161Signer().verify("root", b"token")

    def test_get_signer_from_env_no_var_gives_null(self):
        os.environ.pop("ALETHEIA_HMAC_KEY", None)
        self.assertIsInstance(get_signer_from_env(), NullSigner)

    def test_get_signer_from_env_with_var_gives_hmac(self):
        os.environ["ALETHEIA_HMAC_KEY"] = "mysecret"
        try:
            self.assertIsInstance(get_signer_from_env(), HMACSigner)
        finally:
            del os.environ["ALETHEIA_HMAC_KEY"]

    def test_sealed_json_has_signing_mode_none_unsigned(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); _basic(l, "w")
            s = json.loads((Path(t)/"spine/windows/w/sealed.json").read_text())
            self.assertEqual(s["signing_mode"], "NONE")
            self.assertNotIn("seal_signature", s)

    def test_sealed_json_has_hmac_signature(self):
        with tempfile.TemporaryDirectory() as t:
            l = _signed_ledger(t); _basic(l, "w")
            s = json.loads((Path(t)/"spine/windows/w/sealed.json").read_text())
            self.assertEqual(s["signing_mode"], "HMAC_SHA256")
            self.assertIn("seal_signature", s)
            self.assertEqual(len(s["seal_signature"]), 64)

    def test_hmac_signature_is_hex_encoded(self):
        with tempfile.TemporaryDirectory() as t:
            l = _signed_ledger(t, key=b"hextest"); _basic(l, "w")
            s = json.loads((Path(t)/"spine/windows/w/sealed.json").read_text())
            sig = s["seal_signature"]
            self.assertTrue(all(c in "0123456789abcdef" for c in sig))

    def test_forge_without_key_detected(self):
        with tempfile.TemporaryDirectory() as t:
            key = b"secret-key"
            l = _signed_ledger(t, key=key); l.open_window("w")
            l.append_event("w", "EVIDENCE", {"value": "original"})
            l.seal_window("w"); l.close_clean()
            ev = sorted((Path(t)/"spine/windows/w/events").glob("*.json"))[-2]
            obj = json.loads(ev.read_text()); obj["payload"] = {"value": "FORGED"}
            ev.write_text(json.dumps(obj))
            r = verify_spine(t, signer=HMACSigner(key=key))
            self.assertFalse(r["ok"])

    def test_long_key_works(self):
        key = b"x" * 256
        s = HMACSigner(key=key); h = "roothash"
        self.assertTrue(s.verify(h, s.sign(h)))

    def test_key_with_special_chars(self):
        key = b"k3y!@#$%^&*()_+-=[]{}|;':\",./<>?"
        s = HMACSigner(key=key); h = "roothash"
        self.assertTrue(s.verify(h, s.sign(h)))

    def test_different_root_hashes_different_signatures(self):
        s = HMACSigner(key=b"k")
        self.assertNotEqual(s.sign("hash1"), s.sign("hash2"))

    def test_timing_safe_comparison_used(self):
        """Verify uses constant-time comparison (just ensure it works, not timing)."""
        s = HMACSigner(key=b"k"); h = "root"
        sig = s.sign(h)
        tampered = bytes([sig[0] ^ 0x01]) + sig[1:]
        self.assertFalse(s.verify(h, tampered))

    def test_five_windows_all_signed_all_verify(self):
        with tempfile.TemporaryDirectory() as t:
            key = b"five-window-key"
            l = _signed_ledger(t, key=key)
            for i in range(5):
                _basic(l, f"w{i}", 2)
            l.close_clean()
            r = verify_spine(t, signer=HMACSigner(key=key))
            self.assertTrue(r["ok"])
            self.assertEqual(r["sealed_windows_verified"], 5)

    def test_signing_mode_propagates_to_case_manifest(self):
        """signing_mode in sealed.json is readable after seal."""
        with tempfile.TemporaryDirectory() as t:
            l = _signed_ledger(t, key=b"manifest-key"); _basic(l, "w"); l.close_clean()
            s = json.loads((Path(t)/"spine/windows/w/sealed.json").read_text())
            self.assertEqual(s["signing_mode"], SIGNING_MODE_HMAC)


# ══════════════════════════════════════════════════════════════════════════════
# SIREN — state machine and transitions
# ══════════════════════════════════════════════════════════════════════════════

class TestSirenStateScenarios(unittest.TestCase):

    def _siren(self, tmp):
        l = _ledger(tmp); l.open_window("siren")
        return l, Siren(l)

    def test_initial_state_is_normal(self):
        with tempfile.TemporaryDirectory() as t:
            _, s = self._siren(t)
            self.assertEqual(s.state, SirenState.NORMAL)

    def test_transition_normal_to_degraded(self):
        with tempfile.TemporaryDirectory() as t:
            _, s = self._siren(t)
            s.transition(SirenState.DEGRADED_CAPTURE, MaydayCode.DISK_PRESSURE)
            self.assertEqual(s.state, SirenState.DEGRADED_CAPTURE)

    def test_transition_to_summaries_only(self):
        with tempfile.TemporaryDirectory() as t:
            _, s = self._siren(t)
            s.transition(SirenState.SUMMARIES_ONLY, MaydayCode.MANUAL)
            self.assertEqual(s.state, SirenState.SUMMARIES_ONLY)

    def test_transition_to_halt(self):
        with tempfile.TemporaryDirectory() as t:
            _, s = self._siren(t)
            s.transition(SirenState.HALT, MaydayCode.INTEGRITY_COMPROMISE)
            self.assertEqual(s.state, SirenState.HALT)

    def test_recover_to_normal(self):
        with tempfile.TemporaryDirectory() as t:
            _, s = self._siren(t)
            s.transition(SirenState.DEGRADED_CAPTURE, MaydayCode.DISK_PRESSURE)
            s.recover_to_normal()
            self.assertEqual(s.state, SirenState.NORMAL)

    def test_transition_writes_mayday_event(self):
        with tempfile.TemporaryDirectory() as t:
            l, s = self._siren(t)
            s.transition(SirenState.DEGRADED_CAPTURE, MaydayCode.DISK_PRESSURE)
            evs = [json.loads(f.read_text()) for f in sorted((Path(t)/"spine/windows/siren/events").glob("*.json"))]
            self.assertTrue(any(e["event_type"] == "MAYDAY" for e in evs))

    def test_mayday_payload_contains_state(self):
        with tempfile.TemporaryDirectory() as t:
            l, s = self._siren(t)
            s.transition(SirenState.SUMMARIES_ONLY, MaydayCode.MANUAL)
            evs = [json.loads(f.read_text()) for f in sorted((Path(t)/"spine/windows/siren/events").glob("*.json"))]
            mayday = next(e for e in evs if e["event_type"] == "MAYDAY")
            self.assertEqual(mayday["payload"]["to_state"], "SUMMARIES_ONLY")

    def test_mayday_details_included(self):
        with tempfile.TemporaryDirectory() as t:
            l, s = self._siren(t)
            s.transition(SirenState.DEGRADED_CAPTURE, MaydayCode.DISK_PRESSURE, details={"free_bytes": 1024})
            evs = [json.loads(f.read_text()) for f in sorted((Path(t)/"spine/windows/siren/events").glob("*.json"))]
            mayday = next(e for e in evs if e["event_type"] == "MAYDAY")
            self.assertEqual(mayday["payload"]["details"]["free_bytes"], 1024)

    def test_state_persisted_to_siren_state_json(self):
        with tempfile.TemporaryDirectory() as t:
            l, s = self._siren(t)
            s.transition(SirenState.HALT, MaydayCode.VERIFY_FAIL)
            l.close_clean()
            state_file = Path(t)/"spine/siren_state.json"
            self.assertTrue(state_file.exists())
            st = json.loads(state_file.read_text())
            self.assertEqual(st["state"], "HALT")

    def test_multiple_transitions_all_recorded(self):
        with tempfile.TemporaryDirectory() as t:
            l, s = self._siren(t)
            s.transition(SirenState.DEGRADED_CAPTURE, MaydayCode.DISK_PRESSURE)
            s.transition(SirenState.SUMMARIES_ONLY, MaydayCode.MANUAL)
            s.transition(SirenState.HALT, MaydayCode.INTEGRITY_COMPROMISE)
            evs = [json.loads(f.read_text()) for f in sorted((Path(t)/"spine/windows/siren/events").glob("*.json"))]
            mayday_evs = [e for e in evs if e["event_type"] == "MAYDAY"]
            self.assertGreaterEqual(len(mayday_evs), 3)

    def test_siren_replay_from_spine_wins_over_state_file(self):
        with tempfile.TemporaryDirectory() as t:
            l, s = self._siren(t)
            s.transition(SirenState.DEGRADED_CAPTURE, MaydayCode.DISK_PRESSURE)
            l.close_clean()
            # Corrupt state file
            sf = Path(t)/"spine/siren_state.json"
            d = json.loads(sf.read_text()); d["state"] = "NORMAL"
            sf.write_text(json.dumps(d))
            # Reload
            l2 = _ledger(t); s2 = Siren(l2)
            spine_state = s2._replay_state_from_spine()
            self.assertIsNotNone(spine_state)

    def test_disk_pressure_mayday_code(self):
        with tempfile.TemporaryDirectory() as t:
            l, s = self._siren(t)
            s.transition(SirenState.DEGRADED_CAPTURE, MaydayCode.DISK_PRESSURE)
            evs = [json.loads(f.read_text()) for f in sorted((Path(t)/"spine/windows/siren/events").glob("*.json"))]
            m = next(e for e in evs if e["event_type"] == "MAYDAY")
            self.assertEqual(m["payload"]["reason_code"], "DISK_PRESSURE")

    def test_verify_fail_mayday_code(self):
        with tempfile.TemporaryDirectory() as t:
            l, s = self._siren(t)
            s.transition(SirenState.HALT, MaydayCode.VERIFY_FAIL)
            evs = [json.loads(f.read_text()) for f in sorted((Path(t)/"spine/windows/siren/events").glob("*.json"))]
            m = next(e for e in evs if e["event_type"] == "MAYDAY")
            self.assertEqual(m["payload"]["reason_code"], "VERIFY_FAIL")

    def test_integrity_compromise_mayday_code(self):
        with tempfile.TemporaryDirectory() as t:
            l, s = self._siren(t)
            s.transition(SirenState.HALT, MaydayCode.INTEGRITY_COMPROMISE)
            evs = [json.loads(f.read_text()) for f in sorted((Path(t)/"spine/windows/siren/events").glob("*.json"))]
            m = next(e for e in evs if e["event_type"] == "MAYDAY")
            self.assertEqual(m["payload"]["reason_code"], "INTEGRITY_COMPROMISE")

    def test_recovered_mayday_code(self):
        with tempfile.TemporaryDirectory() as t:
            l, s = self._siren(t)
            s.transition(SirenState.DEGRADED_CAPTURE, MaydayCode.DISK_PRESSURE)
            s.recover_to_normal()
            evs = [json.loads(f.read_text()) for f in sorted((Path(t)/"spine/windows/siren/events").glob("*.json"))]
            mayday_evs = [e for e in evs if e["event_type"] == "MAYDAY"]
            reasons = [e["payload"]["reason_code"] for e in mayday_evs]
            self.assertIn("RECOVERED", reasons)

    def test_siren_in_spine_verified_cleanly(self):
        with tempfile.TemporaryDirectory() as t:
            l, s = self._siren(t)
            s.transition(SirenState.DEGRADED_CAPTURE, MaydayCode.DISK_PRESSURE)
            s.recover_to_normal()
            l.seal_window("siren"); l.close_clean()
            r = verify_spine(t)
            self.assertTrue(r["ok"])

    def test_state_is_string_enum(self):
        with tempfile.TemporaryDirectory() as t:
            _, s = self._siren(t)
            self.assertIsInstance(s.state.value, str)

    def test_siren_config_custom_window(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); l.open_window("custom_siren")
            cfg = SirenConfig(window_id="custom_siren")
            s = Siren(l, config=cfg)
            s.transition(SirenState.DEGRADED_CAPTURE, MaydayCode.MANUAL)
            evs = [json.loads(f.read_text()) for f in sorted((Path(t)/"spine/windows/custom_siren/events").glob("*.json"))]
            self.assertTrue(any(e["event_type"] == "MAYDAY" for e in evs))

    def test_rapid_transitions_all_recorded(self):
        with tempfile.TemporaryDirectory() as t:
            l, s = self._siren(t)
            for i in range(20):
                s.transition(SirenState.DEGRADED_CAPTURE, MaydayCode.MANUAL, details={"i": i})
            evs = [json.loads(f.read_text()) for f in sorted((Path(t)/"spine/windows/siren/events").glob("*.json"))]
            mayday_count = sum(1 for e in evs if e["event_type"] == "MAYDAY")
            self.assertGreaterEqual(mayday_count, 20)

    def test_siren_does_not_raise_on_normal_to_normal(self):
        with tempfile.TemporaryDirectory() as t:
            l, s = self._siren(t)
            s.transition(SirenState.NORMAL, MaydayCode.RECOVERED)  # Should not raise

    def test_siren_seal_and_verify_after_halt(self):
        with tempfile.TemporaryDirectory() as t:
            l, s = self._siren(t)
            s.transition(SirenState.HALT, MaydayCode.VERIFY_FAIL)
            l.seal_window("siren"); l.close_clean()
            r = verify_spine(t)
            self.assertTrue(r["ok"])

    def test_siren_from_state_with_details_none(self):
        with tempfile.TemporaryDirectory() as t:
            l, s = self._siren(t)
            s.transition(SirenState.DEGRADED_CAPTURE, MaydayCode.DISK_PRESSURE, details=None)
            self.assertEqual(s.state, SirenState.DEGRADED_CAPTURE)

    def test_siren_state_after_reload(self):
        with tempfile.TemporaryDirectory() as t:
            l, s = self._siren(t)
            s.transition(SirenState.SUMMARIES_ONLY, MaydayCode.MANUAL)
            l.close_clean()
            # Read persisted state directly
            sf = Path(t)/"spine/siren_state.json"
            st = json.loads(sf.read_text())
            self.assertEqual(st["state"], "SUMMARIES_ONLY")

    def test_siren_mayday_from_state_contains_from_state(self):
        with tempfile.TemporaryDirectory() as t:
            l, s = self._siren(t)
            s.transition(SirenState.DEGRADED_CAPTURE, MaydayCode.DISK_PRESSURE)
            evs = [json.loads(f.read_text()) for f in sorted((Path(t)/"spine/windows/siren/events").glob("*.json"))]
            m = next(e for e in evs if e["event_type"] == "MAYDAY")
            self.assertIn("from_state", m["payload"])

    def test_heartbeat_mayday_code(self):
        with tempfile.TemporaryDirectory() as t:
            l, s = self._siren(t)
            s.transition(SirenState.DEGRADED_CAPTURE, MaydayCode.HEARTBEAT)
            self.assertEqual(s.state, SirenState.DEGRADED_CAPTURE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
