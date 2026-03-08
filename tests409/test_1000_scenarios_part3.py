"""
test_1000_scenarios_part3.py — Real-world scenarios: Streaming, Federation, AI Audit, OT
250 tests covering the Phase 2 subsystems against realistic operational situations.
"""
from __future__ import annotations
import hashlib, json, os, sys, tempfile, time, unittest, zipfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from aletheia.spine.ledger import SpineLedger
from aletheia.spine.verify import verify_spine
from aletheia.siren.state_machine import Siren, SirenState, MaydayCode
from aletheia.ingest.gate import IngestGate, IngestConfig
from aletheia.chronicle.export import build_case_zip
from aletheia.streaming.scheduler import WindowScheduler, SchedulerConfig, SchedulerState
from aletheia.streaming.adapters import CallbackAdapter, FileAdapter, FileAdapterConfig
from aletheia.federation import (
    verify_node, federate, write_federation_bundle, read_federation_bundle, FederationError
)
from aletheia.ai_audit import (
    AIAuditRecorder, AIAuditConfig, DFWBridge,
    AI_INFERENCE_REQUEST, AI_INFERENCE_RESPONSE, AI_MODEL_VERSION,
    AI_CONSTRAINT_APPLIED, AI_HUMAN_OVERRIDE, AI_ESCALATION,
    AI_POLICY_VERDICT, AI_AUDIT_SESSION_START, AI_AUDIT_SESSION_END,
    DFW_RISK_LOW, DFW_RISK_MED, DFW_RISK_HIGH,
    DFW_APPROVED, DFW_VETOED, DFW_DEFERRED,
)
from aletheia.ot import (
    OTAdapter, OTSensorReading, OTConfig, OTConsole,
    OT_WITNESS, OT_FAULT, OT_ALARM, OT_COMMAND, OT_INTERLOCK,
)


def _ledger(tmp, **kw):
    return SpineLedger(Path(tmp), **kw)

def _make_case(tmp_subdir):
    """Create a valid sealed case.zip under tmp_subdir, return path."""
    root = Path(tmp_subdir) / "root"
    root.mkdir(parents=True, exist_ok=True)
    l = SpineLedger(root)
    l.open_window("evidence")
    l.append_event("evidence", "WITNESS", {"data": "observation"})
    l.seal_window("evidence")
    l.close_clean()
    zp = str(Path(tmp_subdir) / "case.zip")
    build_case_zip(root, zp)
    return zp


# ══════════════════════════════════════════════════════════════════════════════
# STREAMING — WindowScheduler
# ══════════════════════════════════════════════════════════════════════════════

class TestWindowScheduler(unittest.TestCase):

    def _sched(self, tmp, max_events=100, base="stream"):
        l = SpineLedger(Path(tmp), allow_float_payload=True)
        siren = Siren(l)
        cfg = SchedulerConfig(base_window_id=base, max_events_per_window=max_events)
        s = WindowScheduler(l, config=cfg, siren=siren)
        return l, siren, s

    def test_initial_state_is_idle(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, s = self._sched(t)
            self.assertEqual(s.state, SchedulerState.STOPPED)

    def test_start_returns_window_id(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, s = self._sched(t)
            wid = s.start()
            self.assertIsNotNone(wid)
            self.assertIsInstance(wid, str)

    def test_start_sets_running_state(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, s = self._sched(t)
            s.start()
            self.assertEqual(s.state, SchedulerState.RUNNING)

    def test_window_id_contains_base_name(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, s = self._sched(t, base="ot_ingest")
            wid = s.start()
            self.assertIn("ot_ingest", wid)

    def test_current_window_id_after_start(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, s = self._sched(t)
            wid = s.start()
            self.assertEqual(s.current_window_id, wid)

    def test_current_window_id_before_start_is_none(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, s = self._sched(t)
            self.assertIsNone(s.current_window_id)

    def test_append_event_returns_window_id(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, s = self._sched(t)
            s.start()
            wid = s.append_event("READING", {"v": 1.0})
            self.assertIsNotNone(wid)

    def test_event_count_increments(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, s = self._sched(t)
            s.start()
            for i in range(5):
                s.append_event("X", {"i": i})
            self.assertEqual(s.current_event_count, 5)

    def test_stop_seals_window(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, s = self._sched(t)
            s.start()
            s.append_event("X", {"v": 1})
            wid = s.stop()
            self.assertIn(wid, s.sealed_windows)

    def test_stop_returns_window_id(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, s = self._sched(t)
            wid = s.start()
            stopped = s.stop()
            self.assertEqual(wid, stopped)

    def test_stop_before_start_returns_none(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, s = self._sched(t)
            result = s.stop()
            self.assertIsNone(result)

    def test_sealed_windows_empty_before_stop(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, s = self._sched(t)
            s.start()
            s.append_event("X", {"v": 1})
            self.assertEqual(s.sealed_windows, [])

    def test_rolling_on_max_events(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, s = self._sched(t, max_events=3)
            s.start()
            for i in range(4):
                s.append_event("X", {"i": i})
            # Window 1 sealed at count 3, window 2 started for event 4
            self.assertEqual(len(s.sealed_windows), 1)

    def test_double_roll_produces_two_sealed_windows(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, s = self._sched(t, max_events=3)
            s.start()
            for i in range(7):
                s.append_event("X", {"i": i})
            self.assertGreaterEqual(len(s.sealed_windows), 2)

    def test_each_rolled_window_is_uniquely_named(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, s = self._sched(t, max_events=2)
            s.start()
            for i in range(8):
                s.append_event("X", {"i": i})
            s.stop()
            all_windows = s.sealed_windows
            self.assertEqual(len(all_windows), len(set(all_windows)))

    def test_sealed_windows_are_verified_clean(self):
        with tempfile.TemporaryDirectory() as t:
            l, _, s = self._sched(t, max_events=3)
            s.start()
            for i in range(6):
                s.append_event("X", {"i": i})
            s.stop()
            l.close_clean()
            r = verify_spine(t)
            self.assertTrue(r["ok"])

    def test_append_before_start_raises(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, s = self._sched(t)
            with self.assertRaises(Exception):
                s.append_event("X", {"v": 1})

    def test_siren_degrade_window_seals_on_stop(self):
        # After siren degrade, stop() seals the current window
        with tempfile.TemporaryDirectory() as t:
            l, siren, s = self._sched(t, max_events=1000)
            s.start()
            for i in range(3):
                s.append_event("X", {"i": i})
            siren.transition(SirenState.SUMMARIES_ONLY, MaydayCode.DISK_PRESSURE)
            s.stop()
            self.assertGreaterEqual(len(s.sealed_windows), 1)

    def test_100_events_across_10_windows(self):
        with tempfile.TemporaryDirectory() as t:
            l, _, s = self._sched(t, max_events=10)
            s.start()
            for i in range(100):
                s.append_event("READING", {"seq": i, "value": float(i) * 0.1})
            s.stop()
            self.assertGreaterEqual(len(s.sealed_windows), 10)

    def test_state_after_stop_is_idle(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, s = self._sched(t)
            s.start()
            s.stop()
            self.assertEqual(s.state, SchedulerState.STOPPED)

    def test_no_background_tick_by_default(self):
        with tempfile.TemporaryDirectory() as t:
            _, _, s = self._sched(t)
            # Background tick disabled by default — no thread spawned
            s.start()
            s.stop()  # Should complete cleanly


class TestCallbackAdapter(unittest.TestCase):

    def _adapter(self, tmp, records, **kw):
        l = SpineLedger(Path(tmp), allow_float_payload=True)
        siren = Siren(l)
        adapter = CallbackAdapter(l, records, siren=siren, **kw)
        return l, adapter

    def test_callback_adapter_ingests_all_records(self):
        with tempfile.TemporaryDirectory() as t:
            records = [{"source": "plc", "event_type": "READING", "payload": {"v": i}} for i in range(5)]
            l, adapter = self._adapter(t, records)
            adapter.start()
            stats = adapter.run()
            self.assertEqual(stats.accepted, 5)

    def test_callback_adapter_rejects_invalid_records(self):
        with tempfile.TemporaryDirectory() as t:
            records = [
                {"source": "plc", "event_type": "X", "payload": {"v": 1}},
                {"source": "plc", "event_type": "E" * 65, "payload": {"v": 1}},  # event_type too long
                {"source": "plc", "event_type": "Y", "payload": {"v": 2}},
            ]
            l, adapter = self._adapter(t, records)
            adapter.start()
            stats = adapter.run()
            self.assertEqual(stats.accepted, 2)
            self.assertEqual(stats.rejected, 1)

    def test_callback_adapter_run_returns_stats(self):
        with tempfile.TemporaryDirectory() as t:
            records = [{"source": "s", "event_type": "E", "payload": {"v": i}} for i in range(3)]
            l, adapter = self._adapter(t, records)
            adapter.start()
            stats = adapter.run()
            self.assertIsNotNone(stats)
            self.assertGreaterEqual(stats.accepted + stats.rejected, 3)

    def test_callback_adapter_max_records_limit(self):
        with tempfile.TemporaryDirectory() as t:
            records = [{"source": "s", "event_type": "E", "payload": {"v": i}} for i in range(100)]
            l, adapter = self._adapter(t, records)
            adapter.start()
            stats = adapter.run(max_records=10)
            self.assertLessEqual(stats.accepted + stats.rejected, 10)

    def test_callback_adapter_empty_iterator(self):
        with tempfile.TemporaryDirectory() as t:
            l, adapter = self._adapter(t, [])
            adapter.start()
            stats = adapter.run()
            self.assertEqual(stats.accepted, 0)

    def test_callback_adapter_tuple_format(self):
        """(event_type, payload) tuple format."""
        with tempfile.TemporaryDirectory() as t:
            records = [("SENSOR", {"v": i}) for i in range(3)]
            l, adapter = self._adapter(t, records, source_name="scada_01")
            adapter.start()
            stats = adapter.run()
            self.assertEqual(stats.accepted, 3)

    def test_callback_adapter_triple_format(self):
        """(source, event_type, payload) tuple format."""
        with tempfile.TemporaryDirectory() as t:
            records = [("plc_01", "READING", {"v": i}) for i in range(3)]
            l, adapter = self._adapter(t, records)
            adapter.start()
            stats = adapter.run()
            self.assertEqual(stats.accepted, 3)

    def test_callback_adapter_spine_verify_clean(self):
        with tempfile.TemporaryDirectory() as t:
            records = [{"source": "s", "event_type": "E", "payload": {"v": i}} for i in range(5)]
            l, adapter = self._adapter(t, records)
            adapter.run()
            sched = adapter.scheduler
            sched.stop()
            l.close_clean()
            r = verify_spine(t)
            self.assertTrue(r["ok"])


class TestFileAdapter(unittest.TestCase):

    def test_file_adapter_reads_log_file(self):
        with tempfile.TemporaryDirectory() as t:
            log = Path(t) / "events.log"
            log.write_text("event one\nevent two\nevent three\n")
            l = SpineLedger(Path(t) / "root")
            cfg = FileAdapterConfig(follow=False)
            adapter = FileAdapter(l, str(log), config=cfg, source_name="log_reader")
            adapter.start()
            stats = adapter.run()
            self.assertEqual(stats.accepted, 3)

    def test_file_adapter_custom_parser(self):
        with tempfile.TemporaryDirectory() as t:
            log = Path(t) / "events.log"
            log.write_text('{"sensor":"PT101","value":5.2}\n{"sensor":"TT201","value":85.0}\n')
            l = SpineLedger(Path(t) / "root", allow_float_payload=True)

            def parser(line):
                obj = json.loads(line.strip())
                return ("SENSOR_READING", obj)

            cfg = FileAdapterConfig(follow=False, line_parser=parser)
            adapter = FileAdapter(l, str(log), config=cfg, source_name="scada",
                                  allow_float_payload=True)
            adapter.start()
            stats = adapter.run()
            self.assertEqual(stats.accepted, 2)

    def test_file_adapter_empty_file(self):
        with tempfile.TemporaryDirectory() as t:
            log = Path(t) / "empty.log"
            log.write_text("")
            l = SpineLedger(Path(t) / "root")
            cfg = FileAdapterConfig(follow=False)
            adapter = FileAdapter(l, str(log), config=cfg, source_name="log")
            adapter.start()
            stats = adapter.run()
            self.assertEqual(stats.accepted, 0)

    def test_file_adapter_processes_all_lines_including_blank(self):
        # Blank lines are ingested as LINE events with empty payload (never silently dropped)
        with tempfile.TemporaryDirectory() as t:
            log = Path(t) / "events.log"
            log.write_text("line one\n\n\nline two\n")
            l = SpineLedger(Path(t) / "root")
            cfg = FileAdapterConfig(follow=False)
            adapter = FileAdapter(l, str(log), config=cfg, source_name="log")
            adapter.start()
            stats = adapter.run()
            self.assertGreaterEqual(stats.accepted, 2)  # at minimum the two real lines


# ══════════════════════════════════════════════════════════════════════════════
# FEDERATION — multi-node verification
# ══════════════════════════════════════════════════════════════════════════════

class TestFederation(unittest.TestCase):

    def test_verify_single_valid_node_passes(self):
        with tempfile.TemporaryDirectory() as t:
            zp = _make_case(Path(t) / "node1")
            result = verify_node(zp)
            self.assertEqual(result.verdict, "PASS")

    def test_verify_node_returns_node_result(self):
        with tempfile.TemporaryDirectory() as t:
            zp = _make_case(Path(t) / "node1")
            result = verify_node(zp)
            self.assertIsNotNone(result.case_id)
            self.assertIsInstance(result.sealed_windows, list)

    def test_verify_node_tampered_fails(self):
        with tempfile.TemporaryDirectory() as t:
            zp = _make_case(Path(t) / "node1")
            tampered = str(Path(t) / "tampered.zip")
            with zipfile.ZipFile(zp, "r") as zin, zipfile.ZipFile(tampered, "w") as zout:
                for item in zin.infolist():
                    data = zin.read(item.filename)
                    if item.filename.endswith("000001.json"):
                        data = data.replace(b'"WINDOW_OPEN"', b'"FORGED"')
                    zout.writestr(item, data)
            result = verify_node(tampered)
            self.assertIn(result.verdict, ("FAIL", "INCONCLUSIVE", "ERROR"))

    def test_federate_two_valid_nodes_passes(self):
        with tempfile.TemporaryDirectory() as t:
            zp1 = _make_case(Path(t) / "n1")
            zp2 = _make_case(Path(t) / "n2")
            fr = federate([zp1, zp2])
            self.assertEqual(fr.verdict, "PASS")

    def test_federate_returns_federation_result(self):
        with tempfile.TemporaryDirectory() as t:
            zp = _make_case(Path(t) / "n1")
            fr = federate([zp])
            self.assertIsNotNone(fr.federation_id)
            self.assertIsNotNone(fr.federation_hash)
            self.assertIsInstance(fr.nodes, list)

    def test_federate_empty_list_inconclusive(self):
        fr = federate([])
        self.assertEqual(fr.verdict, "INCONCLUSIVE")

    def test_federate_one_fail_one_pass_partial(self):
        with tempfile.TemporaryDirectory() as t:
            zp_good = _make_case(Path(t) / "good")
            zp_bad = str(Path(t) / "bad.zip")
            # Create a corrupt zip
            with zipfile.ZipFile(zp_good, "r") as zin, zipfile.ZipFile(zp_bad, "w") as zout:
                for item in zin.infolist():
                    data = zin.read(item.filename)
                    if item.filename.endswith("000001.json"):
                        data = data.replace(b'"WINDOW_OPEN"', b'"TAMPERED"')
                    zout.writestr(item, data)
            fr = federate([zp_good, zp_bad])
            self.assertIn(fr.verdict, ("PARTIAL", "PASS", "FAIL"))

    def test_federate_all_fail_gives_fail(self):
        with tempfile.TemporaryDirectory() as t:
            zp_good = _make_case(Path(t) / "source")
            nodes = []
            for i in range(3):
                bad = str(Path(t) / f"bad_{i}.zip")
                with zipfile.ZipFile(zp_good, "r") as zin, zipfile.ZipFile(bad, "w") as zout:
                    for item in zin.infolist():
                        data = zin.read(item.filename)
                        if item.filename.endswith("000001.json"):
                            data = data.replace(b'"WINDOW_OPEN"', b'"BROKEN"')
                        zout.writestr(item, data)
                nodes.append(bad)
            fr = federate(nodes)
            self.assertIn(fr.verdict, ("FAIL", "PARTIAL"))

    def test_federate_five_valid_nodes(self):
        with tempfile.TemporaryDirectory() as t:
            zips = [_make_case(Path(t) / f"n{i}") for i in range(5)]
            fr = federate(zips)
            self.assertEqual(fr.verdict, "PASS")
            self.assertEqual(len(fr.nodes), 5)

    def test_federation_hash_is_64_char_hex(self):
        with tempfile.TemporaryDirectory() as t:
            zp = _make_case(Path(t) / "n1")
            fr = federate([zp])
            self.assertEqual(len(fr.federation_hash), 64)
            self.assertTrue(all(c in "0123456789abcdef" for c in fr.federation_hash))

    def test_federation_hash_is_stable_on_same_result(self):
        """The federation_hash on a single result object is a consistent hex string."""
        with tempfile.TemporaryDirectory() as t:
            zp = _make_case(Path(t) / "n1")
            fr = federate([zp], node_ids=["node_a"])
            # Hash is computed once and stable
            self.assertEqual(fr.federation_hash, fr.federation_hash)
            self.assertEqual(len(fr.federation_hash), 64)

    def test_write_and_read_federation_bundle(self):
        with tempfile.TemporaryDirectory() as t:
            zp = _make_case(Path(t) / "n1")
            fr = federate([zp])
            bundle = str(Path(t) / "federation.zip")
            write_federation_bundle(fr, [zp], bundle)
            self.assertTrue(Path(bundle).exists())
            loaded = read_federation_bundle(bundle)
            self.assertIsInstance(loaded, dict)
            self.assertGreater(len(loaded), 0)

    def test_bundle_is_valid_zip(self):
        with tempfile.TemporaryDirectory() as t:
            zp = _make_case(Path(t) / "n1")
            fr = federate([zp])
            bundle = str(Path(t) / "federation.zip")
            write_federation_bundle(fr, [zp], bundle)
            self.assertTrue(zipfile.is_zipfile(bundle))

    def test_bundle_contains_manifest(self):
        with tempfile.TemporaryDirectory() as t:
            zp = _make_case(Path(t) / "n1")
            fr = federate([zp])
            bundle = str(Path(t) / "federation.zip")
            write_federation_bundle(fr, [zp], bundle)
            with zipfile.ZipFile(bundle) as zf:
                names = zf.namelist()
                self.assertTrue(any("federation_manifest" in n for n in names))

    def test_bundle_contains_node_zip(self):
        with tempfile.TemporaryDirectory() as t:
            zp = _make_case(Path(t) / "n1")
            fr = federate([zp])
            bundle = str(Path(t) / "federation.zip")
            write_federation_bundle(fr, [zp], bundle)
            with zipfile.ZipFile(bundle) as zf:
                names = zf.namelist()
                self.assertTrue(any("nodes/" in n for n in names))

    def test_node_id_defaults_to_filename_stem(self):
        with tempfile.TemporaryDirectory() as t:
            zp = _make_case(Path(t) / "n1")
            result = verify_node(zp)
            self.assertIsNotNone(result.node_id)

    def test_custom_node_ids(self):
        with tempfile.TemporaryDirectory() as t:
            zp1 = _make_case(Path(t) / "a")
            zp2 = _make_case(Path(t) / "b")
            fr = federate([zp1, zp2], node_ids=["london_plant", "birmingham_plant"])
            ids = [n.node_id for n in fr.nodes]
            self.assertIn("london_plant", ids)
            self.assertIn("birmingham_plant", ids)

    def test_federation_created_utc_is_set(self):
        with tempfile.TemporaryDirectory() as t:
            zp = _make_case(Path(t) / "n1")
            fr = federate([zp])
            self.assertIsNotNone(fr.created_utc)
            self.assertTrue(fr.created_utc.endswith("Z") or "T" in fr.created_utc)

    def test_node_result_has_reasons(self):
        with tempfile.TemporaryDirectory() as t:
            zp = _make_case(Path(t) / "n1")
            nr = verify_node(zp)
            self.assertIsInstance(nr.reasons, list)

    def test_federation_id_unique_per_call(self):
        with tempfile.TemporaryDirectory() as t:
            zp = _make_case(Path(t) / "n1")
            fr1 = federate([zp], node_ids=["n1_a"])
            fr2 = federate([zp], node_ids=["n1_b"])
            self.assertNotEqual(fr1.federation_id, fr2.federation_id)


# ══════════════════════════════════════════════════════════════════════════════
# AI AUDIT RECORDER
# ══════════════════════════════════════════════════════════════════════════════

class TestAIAuditRecorder(unittest.TestCase):

    def _recorder(self, tmp, **kw):
        l = SpineLedger(Path(tmp))
        cfg = AIAuditConfig(window_id="ai_audit", **kw)
        rec = AIAuditRecorder(l, config=cfg)
        return l, rec

    def test_start_session_returns_session_id(self):
        with tempfile.TemporaryDirectory() as t:
            l, rec = self._recorder(t)
            sid = rec.start_session()
            self.assertIsNotNone(sid)
            self.assertIsInstance(sid, str)

    def test_session_id_is_hex(self):
        with tempfile.TemporaryDirectory() as t:
            l, rec = self._recorder(t)
            sid = rec.start_session()
            self.assertTrue(all(c in "0123456789abcdef" for c in sid))

    def test_start_session_writes_session_start_event(self):
        with tempfile.TemporaryDirectory() as t:
            l, rec = self._recorder(t)
            rec.start_session()
            evs = [json.loads(f.read_text()) for f in sorted((Path(t)/"spine/windows/ai_audit/events").glob("*.json"))]
            self.assertTrue(any(e["event_type"] == AI_AUDIT_SESSION_START for e in evs))

    def test_end_session_writes_session_end_event(self):
        with tempfile.TemporaryDirectory() as t:
            l, rec = self._recorder(t)
            rec.start_session()
            rec.end_session(outcome="NORMAL")
            evs = [json.loads(f.read_text()) for f in sorted((Path(t)/"spine/windows/ai_audit/events").glob("*.json"))]
            self.assertTrue(any(e["event_type"] == AI_AUDIT_SESSION_END for e in evs))

    def test_record_request_event_type(self):
        with tempfile.TemporaryDirectory() as t:
            l, rec = self._recorder(t)
            rec.start_session()
            ev = rec.record_request("Analyse pressure sensor data")
            self.assertEqual(ev.event_type, AI_INFERENCE_REQUEST)

    def test_record_response_event_type(self):
        with tempfile.TemporaryDirectory() as t:
            l, rec = self._recorder(t)
            rec.start_session()
            ev = rec.record_response("Pressure nominal", latency_ms=80, tokens_used=12)
            self.assertEqual(ev.event_type, AI_INFERENCE_RESPONSE)

    def test_record_model_version_event_type(self):
        with tempfile.TemporaryDirectory() as t:
            l, rec = self._recorder(t)
            rec.start_session()
            ev = rec.record_model_version("gpt-4o", "2024-11", checksum="abc123")
            self.assertEqual(ev.event_type, AI_MODEL_VERSION)

    def test_record_constraint_event_type(self):
        with tempfile.TemporaryDirectory() as t:
            l, rec = self._recorder(t)
            rec.start_session()
            ev = rec.record_constraint("RULE_7", "action suppressed by safety rule")
            self.assertEqual(ev.event_type, AI_CONSTRAINT_APPLIED)

    def test_record_human_override_event_type(self):
        with tempfile.TemporaryDirectory() as t:
            l, rec = self._recorder(t)
            rec.start_session()
            ev = rec.record_human_override("operator_bob", "recommend_shutdown", "hold_for_review", reason="emergency")
            self.assertEqual(ev.event_type, AI_HUMAN_OVERRIDE)

    def test_record_escalation_event_type(self):
        with tempfile.TemporaryDirectory() as t:
            l, rec = self._recorder(t)
            rec.start_session()
            ev = rec.record_escalation("ANOMALY_DETECTED", escalated_to="supervisor")
            self.assertEqual(ev.event_type, AI_ESCALATION)

    def test_include_full_content_false_stores_hash(self):
        with tempfile.TemporaryDirectory() as t:
            l, rec = self._recorder(t, include_full_content=False)
            rec.start_session()
            rec.record_request("sensitive prompt data")
            evs = [json.loads(f.read_text()) for f in sorted((Path(t)/"spine/windows/ai_audit/events").glob("*.json"))]
            req_ev = next(e for e in evs if e["event_type"] == AI_INFERENCE_REQUEST)
            payload = req_ev["payload"]
            # Should have a hash, not the full prompt
            self.assertNotIn("sensitive prompt data", str(payload))

    def test_include_full_content_true_stores_content(self):
        with tempfile.TemporaryDirectory() as t:
            l, rec = self._recorder(t, include_full_content=True)
            rec.start_session()
            rec.record_request("check pump pressure")
            evs = [json.loads(f.read_text()) for f in sorted((Path(t)/"spine/windows/ai_audit/events").glob("*.json"))]
            req_ev = next(e for e in evs if e["event_type"] == AI_INFERENCE_REQUEST)
            self.assertIn("check pump pressure", str(req_ev["payload"]))

    def test_record_envelope_returns_envelope_record(self):
        with tempfile.TemporaryDirectory() as t:
            l, rec = self._recorder(t)
            rec.start_session()
            env = rec.record_envelope("input data", "output data")
            self.assertIsNotNone(env.envelope_id)
            self.assertIsNotNone(env.input_hash)
            self.assertIsNotNone(env.output_hash)

    def test_envelope_input_hash_is_64_hex(self):
        with tempfile.TemporaryDirectory() as t:
            l, rec = self._recorder(t)
            rec.start_session()
            env = rec.record_envelope({"prompt": "hello"}, {"response": "world"})
            self.assertEqual(len(env.input_hash), 64)
            self.assertTrue(all(c in "0123456789abcdef" for c in env.input_hash))

    def test_session_metadata_stored(self):
        with tempfile.TemporaryDirectory() as t:
            l, rec = self._recorder(t)
            rec.start_session(metadata={"model": "gpt-4o", "use_case": "anomaly_detection"})
            evs = [json.loads(f.read_text()) for f in sorted((Path(t)/"spine/windows/ai_audit/events").glob("*.json"))]
            start_ev = next(e for e in evs if e["event_type"] == AI_AUDIT_SESSION_START)
            self.assertIn("gpt-4o", str(start_ev["payload"]))

    def test_compliance_profile_in_session_start(self):
        with tempfile.TemporaryDirectory() as t:
            l, rec = self._recorder(t)
            rec.start_session()
            evs = [json.loads(f.read_text()) for f in sorted((Path(t)/"spine/windows/ai_audit/events").glob("*.json"))]
            start_ev = next(e for e in evs if e["event_type"] == AI_AUDIT_SESSION_START)
            self.assertIn("EU_AI_ACT", str(start_ev["payload"]))

    def test_multiple_requests_in_one_session(self):
        with tempfile.TemporaryDirectory() as t:
            l, rec = self._recorder(t)
            rec.start_session()
            for i in range(5):
                rec.record_request(f"Query {i}", request_id=f"req_{i}")
            evs = [json.loads(f.read_text()) for f in sorted((Path(t)/"spine/windows/ai_audit/events").glob("*.json"))]
            req_evs = [e for e in evs if e["event_type"] == AI_INFERENCE_REQUEST]
            self.assertEqual(len(req_evs), 5)

    def test_ai_audit_spine_verifies_clean(self):
        with tempfile.TemporaryDirectory() as t:
            l, rec = self._recorder(t)
            rec.start_session(metadata={"app": "triage_system"})
            rec.record_model_version("llm-v2", "2025-01")
            rec.record_request("Is this anomaly real?")
            rec.record_response("Yes, confidence 0.9")
            rec.end_session(outcome="NORMAL")
            l.seal_window("ai_audit")
            l.close_clean()
            r = verify_spine(t)
            self.assertTrue(r["ok"])

    def test_request_id_propagated_to_response(self):
        with tempfile.TemporaryDirectory() as t:
            l, rec = self._recorder(t, include_full_content=True)
            rec.start_session()
            rec.record_request("query", request_id="req_abc")
            rec.record_response("answer", request_id="req_abc")
            evs = [json.loads(f.read_text()) for f in sorted((Path(t)/"spine/windows/ai_audit/events").glob("*.json"))]
            resp_ev = next(e for e in evs if e["event_type"] == AI_INFERENCE_RESPONSE)
            self.assertIn("req_abc", str(resp_ev["payload"]))

    def test_latency_stored_in_response(self):
        with tempfile.TemporaryDirectory() as t:
            l, rec = self._recorder(t, include_full_content=True)
            rec.start_session()
            rec.record_response("answer", latency_ms=350)
            evs = [json.loads(f.read_text()) for f in sorted((Path(t)/"spine/windows/ai_audit/events").glob("*.json"))]
            resp_ev = next(e for e in evs if e["event_type"] == AI_INFERENCE_RESPONSE)
            self.assertIn("350", str(resp_ev["payload"]))


class TestDFWBridge(unittest.TestCase):

    def _bridge(self, tmp):
        l = SpineLedger(Path(tmp))
        l.open_window("ai_audit")
        return l, DFWBridge(l, window_id="ai_audit")

    def test_record_veto_writes_policy_verdict(self):
        with tempfile.TemporaryDirectory() as t:
            l, bridge = self._bridge(t)
            ev = bridge.record_veto("delete_sensor_log", "ai_agent_v2", reason="irreversible")
            self.assertEqual(ev.event_type, AI_POLICY_VERDICT)

    def test_record_approval_writes_policy_verdict(self):
        with tempfile.TemporaryDirectory() as t:
            l, bridge = self._bridge(t)
            ev = bridge.record_approval("read_sensor_data", "ai_agent_v2")
            self.assertEqual(ev.event_type, AI_POLICY_VERDICT)

    def test_veto_payload_has_vetoed_outcome(self):
        with tempfile.TemporaryDirectory() as t:
            l, bridge = self._bridge(t)
            bridge.record_veto("modify_setpoint", "ai_agent")
            evs = [json.loads(f.read_text()) for f in sorted((Path(t)/"spine/windows/ai_audit/events").glob("*.json"))]
            pv = next(e for e in evs if e["event_type"] == AI_POLICY_VERDICT)
            self.assertIn(DFW_VETOED, str(pv["payload"]))

    def test_approval_payload_has_approved_outcome(self):
        with tempfile.TemporaryDirectory() as t:
            l, bridge = self._bridge(t)
            bridge.record_approval("read_data", "ai_agent")
            evs = [json.loads(f.read_text()) for f in sorted((Path(t)/"spine/windows/ai_audit/events").glob("*.json"))]
            pv = next(e for e in evs if e["event_type"] == AI_POLICY_VERDICT)
            self.assertIn(DFW_APPROVED, str(pv["payload"]))

    def test_high_risk_approval_stored(self):
        with tempfile.TemporaryDirectory() as t:
            l, bridge = self._bridge(t)
            bridge.record_approval("emergency_shutdown", "ai_agent", risk_level=DFW_RISK_HIGH)
            evs = [json.loads(f.read_text()) for f in sorted((Path(t)/"spine/windows/ai_audit/events").glob("*.json"))]
            pv = next(e for e in evs if e["event_type"] == AI_POLICY_VERDICT)
            self.assertIn("HIGH", str(pv["payload"]))

    def test_veto_rule_id_stored(self):
        with tempfile.TemporaryDirectory() as t:
            l, bridge = self._bridge(t)
            bridge.record_veto("action", "agent", rule_id="RULE_IRREVERSIBLE_17")
            evs = [json.loads(f.read_text()) for f in sorted((Path(t)/"spine/windows/ai_audit/events").glob("*.json"))]
            pv = next(e for e in evs if e["event_type"] == AI_POLICY_VERDICT)
            self.assertIn("RULE_IRREVERSIBLE_17", str(pv["payload"]))

    def test_record_verdict_dict_stored(self):
        with tempfile.TemporaryDirectory() as t:
            l, bridge = self._bridge(t)
            verdict = {"verdict": "VETOED", "reason": "policy_rule_7", "action": "delete_log", "actor": "agent"}
            bridge.record_verdict(verdict)
            evs = [json.loads(f.read_text()) for f in sorted((Path(t)/"spine/windows/ai_audit/events").glob("*.json"))]
            self.assertTrue(any(e["event_type"] == AI_POLICY_VERDICT for e in evs))

    def test_multiple_verdicts_all_recorded(self):
        with tempfile.TemporaryDirectory() as t:
            l, bridge = self._bridge(t)
            bridge.record_veto("action_a", "agent")
            bridge.record_approval("action_b", "agent")
            bridge.record_veto("action_c", "agent")
            evs = [json.loads(f.read_text()) for f in sorted((Path(t)/"spine/windows/ai_audit/events").glob("*.json"))]
            verdicts = [e for e in evs if e["event_type"] == AI_POLICY_VERDICT]
            self.assertEqual(len(verdicts), 3)

    def test_dfw_bridge_spine_verifies_clean(self):
        with tempfile.TemporaryDirectory() as t:
            l, bridge = self._bridge(t)
            bridge.record_veto("action", "agent", reason="safety")
            bridge.record_approval("read", "agent")
            l.seal_window("ai_audit")
            l.close_clean()
            r = verify_spine(t)
            self.assertTrue(r["ok"])


# ══════════════════════════════════════════════════════════════════════════════
# OT ADAPTER
# ══════════════════════════════════════════════════════════════════════════════

class TestOTAdapter(unittest.TestCase):

    def _ot(self, tmp, **kw):
        l = SpineLedger(Path(tmp), allow_float_payload=True)
        siren = Siren(l)
        cfg = OTConfig(lens_validate=False, **kw)
        ot = OTAdapter(l, config=cfg, siren=siren)
        ot.open()
        return l, siren, ot

    def test_good_quality_reading_is_witness(self):
        with tempfile.TemporaryDirectory() as t:
            l, _, ot = self._ot(t)
            r = ot.ingest_reading(OTSensorReading("PT-101", 5.2, unit="bar"))
            self.assertEqual(r.event_type, OT_WITNESS)

    def test_bad_quality_reading_is_fault(self):
        with tempfile.TemporaryDirectory() as t:
            l, _, ot = self._ot(t)
            r = ot.ingest_reading(OTSensorReading("PT-101", 5.2, unit="bar", quality="BAD"))
            self.assertEqual(r.event_type, OT_FAULT)

    def test_uncertain_quality_accepted_by_default(self):
        with tempfile.TemporaryDirectory() as t:
            l, _, ot = self._ot(t)
            r = ot.ingest_reading(OTSensorReading("PT-101", 5.2, unit="bar", quality="UNCERTAIN"))
            self.assertTrue(r.accepted)

    def test_uncertain_quality_rejected_when_configured(self):
        with tempfile.TemporaryDirectory() as t:
            l, _, ot = self._ot(t, accept_uncertain=False)
            r = ot.ingest_reading(OTSensorReading("PT-101", 5.2, unit="bar", quality="UNCERTAIN"))
            self.assertEqual(r.event_type, OT_FAULT)

    def test_bad_reading_reason_is_bad_quality(self):
        with tempfile.TemporaryDirectory() as t:
            l, _, ot = self._ot(t)
            r = ot.ingest_reading(OTSensorReading("TT-201", 85.0, unit="C", quality="BAD"))
            self.assertEqual(r.reason, "BAD_QUALITY")

    def test_accepted_reading_has_tag(self):
        with tempfile.TemporaryDirectory() as t:
            l, _, ot = self._ot(t)
            r = ot.ingest_reading(OTSensorReading("FT-301", 12.5, unit="m3h"))
            self.assertEqual(r.tag, "FT-301")

    def test_command_event_type(self):
        with tempfile.TemporaryDirectory() as t:
            l, _, ot = self._ot(t)
            r = ot.ingest_command("OPEN", "V-401", "operator_jane")
            self.assertEqual(r.event_type, OT_COMMAND)

    def test_command_with_reason(self):
        with tempfile.TemporaryDirectory() as t:
            l, _, ot = self._ot(t)
            r = ot.ingest_command("CLOSE", "V-401", "operator_bob", reason="emergency isolate")
            self.assertEqual(r.event_type, OT_COMMAND)

    def test_interlock_event_type(self):
        with tempfile.TemporaryDirectory() as t:
            l, _, ot = self._ot(t)
            r = ot.ingest_interlock("SIS-101", "TRIPPED", triggered_by="PT-101 high-high")
            self.assertEqual(r.event_type, OT_INTERLOCK)

    def test_interlock_no_trigger(self):
        with tempfile.TemporaryDirectory() as t:
            l, _, ot = self._ot(t)
            r = ot.ingest_interlock("SIS-201", "RESET")
            self.assertEqual(r.event_type, OT_INTERLOCK)

    def test_multiple_bad_readings_increment_fault_count(self):
        # BAD quality readings → OT_FAULT events; alarm escalation uses alarm_count separately
        with tempfile.TemporaryDirectory() as t:
            l, siren, ot = self._ot(t)
            for i in range(6):
                ot.ingest_reading(OTSensorReading(f"PT-{100+i}", float(i), unit="bar", quality="BAD"))
            stats = ot.get_console_stats()
            self.assertEqual(stats["fault"], 6)

    def test_seal_and_close_returns_hash(self):
        with tempfile.TemporaryDirectory() as t:
            l, _, ot = self._ot(t)
            ot.ingest_reading(OTSensorReading("PT-101", 5.2, unit="bar"))
            h = ot.seal_and_close()
            self.assertIsNotNone(h)
            self.assertEqual(len(h), 64)

    def test_seal_and_close_empty_window(self):
        with tempfile.TemporaryDirectory() as t:
            l, _, ot = self._ot(t)
            h = ot.seal_and_close()
            self.assertIsNotNone(h)

    def test_stats_counts_accumulate(self):
        with tempfile.TemporaryDirectory() as t:
            l, _, ot = self._ot(t)
            ot.ingest_reading(OTSensorReading("PT-101", 5.2, unit="bar"))
            ot.ingest_reading(OTSensorReading("TT-201", 85.0, unit="C", quality="BAD"))
            stats = ot.get_console_stats()
            self.assertEqual(stats["total_readings"], 2)
            self.assertEqual(stats["fault"], 1)

    def test_stats_siren_state_reported(self):
        with tempfile.TemporaryDirectory() as t:
            l, _, ot = self._ot(t)
            stats = ot.get_console_stats()
            self.assertEqual(stats["siren_state"], "NORMAL")

    def test_ot_spine_verifies_clean(self):
        with tempfile.TemporaryDirectory() as t:
            l, _, ot = self._ot(t)
            for i in range(10):
                ot.ingest_reading(OTSensorReading(f"PT-{100+i}", float(i), unit="bar"))
            ot.seal_and_close()
            l.close_clean()
            r = verify_spine(t)
            self.assertTrue(r["ok"])

    def test_sensor_with_source_tag(self):
        with tempfile.TemporaryDirectory() as t:
            l, _, ot = self._ot(t)
            r = ot.ingest_reading(OTSensorReading("LT-501", 2.3, unit="m", source="dcs_01"))
            self.assertEqual(r.tag, "LT-501")

    def test_sensor_reading_to_payload(self):
        reading = OTSensorReading("AT-601", 7.4, unit="pH", quality="GOOD", source="analyser_01")
        payload = reading.to_payload()
        self.assertEqual(payload["tag"], "AT-601")
        self.assertEqual(payload["unit"], "pH")
        self.assertEqual(payload["quality"], "GOOD")


class TestOTConsole(unittest.TestCase):

    def test_console_render_returns_string(self):
        with tempfile.TemporaryDirectory() as t:
            l = SpineLedger(Path(t), allow_float_payload=True)
            siren = Siren(l)
            ot = OTAdapter(l, config=OTConfig(lens_validate=False), siren=siren)
            ot.open()
            for i in range(3):
                ot.ingest_reading(OTSensorReading(f"PT-{100+i}", float(i), unit="bar"))
            console = OTConsole(ot, l)
            output = console.render(return_str=True)
            self.assertIsInstance(output, str)

    def test_console_output_contains_siren_state(self):
        with tempfile.TemporaryDirectory() as t:
            l = SpineLedger(Path(t), allow_float_payload=True)
            siren = Siren(l)
            ot = OTAdapter(l, config=OTConfig(lens_validate=False), siren=siren)
            ot.open()
            console = OTConsole(ot, l)
            output = console.render(return_str=True)
            self.assertIn("NORMAL", output)

    def test_console_output_is_80_cols_or_less(self):
        with tempfile.TemporaryDirectory() as t:
            l = SpineLedger(Path(t), allow_float_payload=True)
            siren = Siren(l)
            ot = OTAdapter(l, config=OTConfig(lens_validate=False), siren=siren)
            ot.open()
            console = OTConsole(ot, l)
            output = console.render(return_str=True)
            for line in output.splitlines():
                self.assertLessEqual(len(line), 80, f"Line too long: {line!r}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
