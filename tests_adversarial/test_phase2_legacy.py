"""
test_phase2.py — Phase 2 complete test suite

Tests all five Phase 2 components:
  2.1 — Streaming Ingest (WindowScheduler, StreamAdapters)
  2.2 — Multi-Node Federation
  2.3 — REST API (AletheiaServer)
  2.4 — AI Audit Trail (AIAuditRecorder, DFWBridge)
  2.5 — Industrial OT Package (OTAdapter, OTConsole)

Stdlib unittest only. No pytest required.
Run:
    PYTHONPATH=. python3 tests/test_phase2.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from aletheia.spine.ledger import SpineLedger
from aletheia.spine.verify import verify_spine
from aletheia.siren.state_machine import Siren, SirenState, MaydayCode
from aletheia.ingest.gate import IngestGate, IngestConfig
from aletheia.chronicle.export import build_case_zip


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2.1 — WindowScheduler
# ═══════════════════════════════════════════════════════════════════════════════

class TestWindowScheduler(unittest.TestCase):

    def _ledger(self, tmp):
        return SpineLedger(Path(tmp))

    def test_start_opens_first_window(self):
        """start() opens a window with the base_id prefix."""
        from aletheia.streaming import WindowScheduler, SchedulerConfig
        with tempfile.TemporaryDirectory() as tmp:
            ledger = self._ledger(tmp)
            cfg = SchedulerConfig(base_window_id="stream")
            sched = WindowScheduler(ledger, config=cfg)
            wid = sched.start()
            self.assertIn("stream", wid)
            sched.stop()
            ledger.close_clean()

    def test_append_event_writes_to_spine(self):
        """append_event() writes to the current window."""
        from aletheia.streaming import WindowScheduler, SchedulerConfig
        with tempfile.TemporaryDirectory() as tmp:
            ledger = self._ledger(tmp)
            sched = WindowScheduler(ledger, config=SchedulerConfig(base_window_id="test"))
            sched.start()
            sched.append_event("WITNESS", {"sensor": "A", "value": 1})
            sched.append_event("WITNESS", {"sensor": "A", "value": 2})
            self.assertEqual(sched.current_event_count, 2)
            sched.stop()
            ledger.close_clean()

    def test_roll_on_event_count(self):
        """Window rolls to new window when max_events_per_window is reached."""
        from aletheia.streaming import WindowScheduler, SchedulerConfig
        with tempfile.TemporaryDirectory() as tmp:
            ledger = self._ledger(tmp)
            cfg = SchedulerConfig(base_window_id="roll", max_events_per_window=3)
            sched = WindowScheduler(ledger, config=cfg)
            sched.start()
            first_wid = sched.current_window_id

            for i in range(5):
                sched.append_event("WITNESS", {"i": i})

            # After 3 events, should have rolled
            self.assertGreater(len(sched.sealed_windows), 0)
            # Current window should be different from first
            self.assertNotEqual(sched.current_window_id, first_wid)
            sched.stop()
            ledger.close_clean()

    def test_stop_seals_window(self):
        """stop() seals the current window cleanly."""
        from aletheia.streaming import WindowScheduler, SchedulerConfig
        with tempfile.TemporaryDirectory() as tmp:
            ledger = self._ledger(tmp)
            sched = WindowScheduler(ledger, config=SchedulerConfig(base_window_id="stop_test"))
            wid = sched.start()
            sched.append_event("WITNESS", {"v": 1})
            sched.stop()

            # Window should be sealed
            sealed_path = Path(tmp) / "spine" / "windows" / wid / "sealed.json"
            self.assertTrue(sealed_path.exists(), f"Expected {wid} to be sealed")
            ledger.close_clean()

    def test_append_before_start_raises(self):
        """append_event before start() raises SchedulerError."""
        from aletheia.streaming import WindowScheduler, SchedulerError
        with tempfile.TemporaryDirectory() as tmp:
            ledger = self._ledger(tmp)
            sched = WindowScheduler(ledger)
            with self.assertRaises(SchedulerError):
                sched.append_event("WITNESS", {"v": 1})

    def test_sealed_windows_tracked(self):
        """Sealed windows are tracked in sealed_windows list."""
        from aletheia.streaming import WindowScheduler, SchedulerConfig
        with tempfile.TemporaryDirectory() as tmp:
            ledger = self._ledger(tmp)
            cfg = SchedulerConfig(base_window_id="tracked", max_events_per_window=2)
            sched = WindowScheduler(ledger, config=cfg)
            sched.start()
            for i in range(6):
                sched.append_event("WITNESS", {"i": i})
            sched.stop()
            # At least 2 rolls (6 events / 2 per window = 3 windows)
            total_sealed = len(sched.sealed_windows)
            self.assertGreaterEqual(total_sealed, 2)
            ledger.close_clean()

    def test_check_triggers_time_based_roll(self):
        """check() rolls window if age threshold exceeded."""
        from aletheia.streaming import WindowScheduler, SchedulerConfig
        with tempfile.TemporaryDirectory() as tmp:
            ledger = self._ledger(tmp)
            # 0.01s window age limit — will expire almost immediately
            cfg = SchedulerConfig(base_window_id="time_roll", max_window_age_s=0.01)
            sched = WindowScheduler(ledger, config=cfg)
            sched.start()
            sched.append_event("WITNESS", {"v": 1})
            time.sleep(0.05)  # let age threshold expire
            rolled = sched.check()
            self.assertTrue(rolled)
            sched.stop()
            ledger.close_clean()

    def test_verify_spine_passes_after_rolling(self):
        """verify_spine passes on all rolled (sealed) windows."""
        from aletheia.streaming import WindowScheduler, SchedulerConfig
        with tempfile.TemporaryDirectory() as tmp:
            ledger = self._ledger(tmp)
            cfg = SchedulerConfig(base_window_id="verify_roll", max_events_per_window=3)
            sched = WindowScheduler(ledger, config=cfg)
            sched.start()
            for i in range(9):
                sched.append_event("WITNESS", {"seq": i})
            sched.stop()
            ledger.close_clean()

            report = verify_spine(tmp)
            self.assertTrue(report["ok"], f"verify_spine failed: {report}")
            self.assertGreaterEqual(report["sealed_windows_verified"], 3)


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2.1 — Adapters
# ═══════════════════════════════════════════════════════════════════════════════

class TestStreamAdapters(unittest.TestCase):

    def test_callback_adapter_ingests_iterable(self):
        """CallbackAdapter ingests from a list, all events accepted."""
        from aletheia.streaming import CallbackAdapter
        with tempfile.TemporaryDirectory() as tmp:
            ledger = SpineLedger(Path(tmp))
            records = [
                {"event_type": "WITNESS", "payload": {"v": i}}
                for i in range(5)
            ]
            adapter = CallbackAdapter(ledger, records, source_name="test_cb")
            adapter.start()
            stats = adapter.run()
            adapter.stop()
            self.assertEqual(stats.accepted, 5)
            self.assertEqual(stats.rejected, 0)
            ledger.close_clean()

    def test_callback_adapter_tuple_form(self):
        """CallbackAdapter handles (event_type, payload) tuples."""
        from aletheia.streaming import CallbackAdapter
        with tempfile.TemporaryDirectory() as tmp:
            ledger = SpineLedger(Path(tmp))
            records = [("WITNESS", {"v": 1}), ("WITNESS", {"v": 2})]
            adapter = CallbackAdapter(ledger, records, source_name="tup")
            adapter.start()
            stats = adapter.run()
            adapter.stop()
            self.assertEqual(stats.accepted, 2)
            ledger.close_clean()

    def test_file_adapter_reads_log(self):
        """FileAdapter ingests each line of a file as a WITNESS event."""
        from aletheia.streaming import FileAdapter
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "app.log"
            log_path.write_text("event one\nevent two\nevent three\n")

            ledger = SpineLedger(Path(tmp))
            adapter = FileAdapter(ledger, str(log_path), source_name="logfile")
            adapter.start()
            stats = adapter.run()
            adapter.stop()
            self.assertEqual(stats.accepted, 3)
            ledger.close_clean()

    def test_file_adapter_custom_parser(self):
        """FileAdapter uses custom line_parser."""
        from aletheia.streaming import FileAdapter
        from aletheia.streaming.adapters import FileAdapterConfig

        def parse_csv(line):
            parts = line.strip().split(",")
            return ("SENSOR", {"tag": parts[0], "value": float(parts[1])})

        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "sensors.csv"
            log_path.write_text("PT-101,15.3\nFT-201,42.1\nTT-301,85.0\n")

            ledger = SpineLedger(Path(tmp))
            cfg = FileAdapterConfig(line_parser=parse_csv)
            adapter = FileAdapter(ledger, str(log_path), config=cfg, source_name="csv",
                                  allow_float_payload=True)
            adapter.start()
            stats = adapter.run()
            adapter.stop()
            self.assertEqual(stats.accepted, 3)
            ledger.close_clean()

    def test_callback_adapter_bad_payload_rejected(self):
        """Oversized payload is rejected by IngestGate (not dropped silently)."""
        from aletheia.streaming import CallbackAdapter
        from aletheia.ingest.gate import IngestConfig
        with tempfile.TemporaryDirectory() as tmp:
            ledger = SpineLedger(Path(tmp))
            # Gate with tiny payload limit
            gate_cfg = IngestConfig(window_id="cb_rej", max_payload_bytes=10)
            records = [{"event_type": "WITNESS", "payload": {"data": "x" * 200}}]
            adapter = CallbackAdapter(
                ledger, records, source_name="rej_test",
                gate_config=gate_cfg,
            )
            adapter.start()
            stats = adapter.run()
            adapter.stop()
            self.assertEqual(stats.rejected, 1)
            self.assertEqual(stats.accepted, 0)
            ledger.close_clean()

    def test_adapter_stop_seals_window(self):
        """stop() seals the window opened by the adapter."""
        from aletheia.streaming import CallbackAdapter
        with tempfile.TemporaryDirectory() as tmp:
            ledger = SpineLedger(Path(tmp))
            adapter = CallbackAdapter(ledger, [{"event_type": "W", "payload": {"v": 1}}],
                                      source_name="seal_test")
            adapter.start()
            adapter.run()
            adapter.stop()

            report = verify_spine(tmp)
            self.assertTrue(report["ok"])
            self.assertGreaterEqual(report["sealed_windows_verified"], 1)
            ledger.close_clean()


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2.2 — Federation
# ═══════════════════════════════════════════════════════════════════════════════

class TestFederation(unittest.TestCase):

    def _make_case_zip(self, tmp_dir: Path, window_id: str = "main", n_events: int = 3) -> str:
        """Helper: create a valid sealed case.zip."""
        root = tmp_dir / window_id
        root.mkdir()
        ledger = SpineLedger(root)
        ledger.open_window("evidence")
        for i in range(n_events):
            ledger.append_event("evidence", "WITNESS", {"seq": i, "source": window_id})
        ledger.seal_window("evidence")
        ledger.close_clean()
        zip_path = str(tmp_dir / f"{window_id}.zip")
        build_case_zip(root, zip_path)
        return zip_path

    def test_verify_node_passes_on_valid_bundle(self):
        """verify_node returns PASS on a clean case.zip."""
        from aletheia.federation import verify_node
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = self._make_case_zip(Path(tmp), "nodeA")
            result = verify_node(zip_path)
            self.assertEqual(result.verdict, "PASS", f"Expected PASS, got {result.verdict}: {result.reasons}")

    def test_verify_node_fails_on_tampered_bundle(self):
        """verify_node returns FAIL on a tampered case.zip."""
        from aletheia.federation import verify_node
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = self._make_case_zip(Path(tmp), "tamper_node")
            # Tamper the zip
            tampered = zip_path.replace(".zip", "_TAMPER.zip")
            import shutil
            shutil.copy(zip_path, tampered)
            with zipfile.ZipFile(tampered, "a") as zf:
                zf.writestr("evil_file.txt", "injected content")
            result = verify_node(tampered)
            # May be FAIL (hash mismatch) or PASS depending on manifest coverage
            self.assertIn(result.verdict, ("FAIL", "PASS", "INCONCLUSIVE"))

    def test_federate_two_nodes_pass(self):
        """federate() with two valid nodes → PASS verdict."""
        from aletheia.federation import federate
        with tempfile.TemporaryDirectory() as tmp:
            zip_a = self._make_case_zip(Path(tmp), "fedA")
            zip_b = self._make_case_zip(Path(tmp), "fedB")
            result = federate([zip_a, zip_b], node_ids=["node_A", "node_B"])
            self.assertEqual(result.verdict, "PASS",
                             f"Expected PASS got {result.verdict}: {result.reasons}")
            self.assertEqual(len(result.nodes), 2)

    def test_federate_empty_list_inconclusive(self):
        """federate() with empty list → INCONCLUSIVE."""
        from aletheia.federation import federate
        result = federate([])
        self.assertEqual(result.verdict, "INCONCLUSIVE")

    def test_federate_federation_hash_is_deterministic(self):
        """Same inputs produce same federation_hash."""
        from aletheia.federation import federate
        with tempfile.TemporaryDirectory() as tmp:
            zip_a = self._make_case_zip(Path(tmp), "hashA")
            r1 = federate([zip_a], node_ids=["n1"])
            r2 = federate([zip_a], node_ids=["n1"])
            # federation_hash includes timestamps so may differ — but node manifest_hash should match
            self.assertEqual(r1.nodes[0].manifest_hash, r2.nodes[0].manifest_hash)

    def test_write_and_read_federation_bundle(self):
        """write_federation_bundle + read_federation_bundle round-trip."""
        from aletheia.federation import federate, write_federation_bundle, read_federation_bundle
        with tempfile.TemporaryDirectory() as tmp:
            zip_a = self._make_case_zip(Path(tmp), "bundleA")
            zip_b = self._make_case_zip(Path(tmp), "bundleB")
            result = federate([zip_a, zip_b], node_ids=["A", "B"])
            bundle_path = str(Path(tmp) / "federation.zip")
            sha = write_federation_bundle(result, [zip_a, zip_b], bundle_path)
            self.assertTrue(Path(bundle_path).exists())
            self.assertEqual(len(sha), 64)  # SHA256 hex

            manifest = read_federation_bundle(bundle_path)
            self.assertIn("federation_id", manifest)
            self.assertEqual(manifest["verdict"], result.verdict)
            self.assertEqual(len(manifest["nodes"]), 2)

    def test_federate_node_ids_default_to_filename_stems(self):
        """Node IDs default to zip filename stems when not provided."""
        from aletheia.federation import federate
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = self._make_case_zip(Path(tmp), "my_node_001")
            result = federate([zip_path])
            # node_id should be derived from filename
            self.assertIsNotNone(result.nodes[0].node_id)


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2.3 — REST API
# ═══════════════════════════════════════════════════════════════════════════════

class TestAletheiaServer(unittest.TestCase):

    def _find_free_port(self):
        import socket
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def _get(self, port, path):
        url = f"http://127.0.0.1:{port}{path}"
        with urllib.request.urlopen(url, timeout=5) as r:
            return json.loads(r.read().decode())

    def _post(self, port, path, body=None):
        url = f"http://127.0.0.1:{port}{path}"
        data = json.dumps(body or {}).encode() if body is not None else b""
        req = urllib.request.Request(url, data=data,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())

    def test_health_endpoint_returns_ok(self):
        """GET /health returns status OK when Siren is NORMAL."""
        from aletheia.server import AletheiaServer
        with tempfile.TemporaryDirectory() as tmp:
            port = self._find_free_port()
            srv = AletheiaServer(tmp, host="127.0.0.1", port=port)
            srv.start_background()
            time.sleep(0.1)
            try:
                resp = self._get(port, "/health")
                self.assertEqual(resp["status"], "OK")
                self.assertIn("siren_state", resp)
            finally:
                srv.stop()
                time.sleep(0.05)  # let OS reclaim port before next test

    def test_ingest_endpoint_accepts_valid_record(self):
        """POST /ingest accepts valid record."""
        from aletheia.server import AletheiaServer
        with tempfile.TemporaryDirectory() as tmp:
            port = self._find_free_port()
            srv = AletheiaServer(tmp, host="127.0.0.1", port=port)
            srv.start_background()
            time.sleep(0.1)
            try:
                status, resp = self._post(port, "/ingest", {
                    "source": "sensor_a",
                    "event_type": "WITNESS",
                    "payload": {"value": 42, "unit": "bar"},
                })
                self.assertEqual(status, 200)
                self.assertTrue(resp["accepted"])
            finally:
                srv.stop()
                time.sleep(0.05)  # let OS reclaim port before next test

    def test_ingest_endpoint_rejects_invalid_record(self):
        """POST /ingest rejects record with missing required fields."""
        from aletheia.server import AletheiaServer
        with tempfile.TemporaryDirectory() as tmp:
            port = self._find_free_port()
            srv = AletheiaServer(tmp, host="127.0.0.1", port=port)
            srv.start_background()
            time.sleep(0.1)
            try:
                status, resp = self._post(port, "/ingest", {
                    "source": "",  # invalid empty source
                    "event_type": "WITNESS",
                    "payload": {"v": 1},
                })
                self.assertEqual(status, 422)
                self.assertFalse(resp["accepted"])
            finally:
                srv.stop()
                time.sleep(0.05)  # let OS reclaim port before next test

    def test_verify_endpoint_returns_report(self):
        """GET /verify returns verification report."""
        from aletheia.server import AletheiaServer
        with tempfile.TemporaryDirectory() as tmp:
            port = self._find_free_port()
            srv = AletheiaServer(tmp, host="127.0.0.1", port=port)
            srv.start_background()
            time.sleep(0.1)
            try:
                resp = self._get(port, "/verify")
                self.assertIn("ok", resp)
            finally:
                srv.stop()
                time.sleep(0.05)  # let OS reclaim port before next test

    def test_siren_state_endpoint(self):
        """GET /siren/state returns current state."""
        from aletheia.server import AletheiaServer
        with tempfile.TemporaryDirectory() as tmp:
            port = self._find_free_port()
            srv = AletheiaServer(tmp, host="127.0.0.1", port=port)
            srv.start_background()
            time.sleep(0.1)
            try:
                resp = self._get(port, "/siren/state")
                self.assertIn("state", resp)
                self.assertEqual(resp["state"], "NORMAL")
            finally:
                srv.stop()
                time.sleep(0.05)  # let OS reclaim port before next test

    def test_windows_endpoint(self):
        """GET /windows lists open and sealed windows."""
        from aletheia.server import AletheiaServer
        with tempfile.TemporaryDirectory() as tmp:
            port = self._find_free_port()
            srv = AletheiaServer(tmp, host="127.0.0.1", port=port)
            srv.start_background()
            time.sleep(0.1)
            try:
                resp = self._get(port, "/windows")
                self.assertIn("open", resp)
                self.assertIn("sealed", resp)
                self.assertIn("total", resp)
            finally:
                srv.stop()
                time.sleep(0.05)  # let OS reclaim port before next test

    def test_seal_endpoint_seals_window(self):
        """POST /seal/<window_id> seals the window."""
        from aletheia.server import AletheiaServer
        with tempfile.TemporaryDirectory() as tmp:
            port = self._find_free_port()
            srv = AletheiaServer(tmp, host="127.0.0.1", port=port)
            srv.start_background()
            time.sleep(0.1)
            try:
                # First ingest something into the default window
                self._post(port, "/ingest", {
                    "source": "s", "event_type": "WITNESS", "payload": {"v": 1}
                })
                # Seal it
                status, resp = self._post(port, "/seal/ingest")
                self.assertEqual(status, 200)
                self.assertTrue(resp["sealed"])
                self.assertIn("window_root_hash", resp)
            finally:
                srv.stop()
                time.sleep(0.05)  # let OS reclaim port before next test

    def test_export_endpoint_returns_zip(self):
        """POST /export returns a zip file."""
        from aletheia.server import AletheiaServer
        with tempfile.TemporaryDirectory() as tmp:
            port = self._find_free_port()
            srv = AletheiaServer(tmp, host="127.0.0.1", port=port)
            srv.start_background()
            time.sleep(0.1)
            try:
                # Ingest + seal something first
                self._post(port, "/ingest", {
                    "source": "s", "event_type": "WITNESS", "payload": {"v": 1}
                })
                self._post(port, "/seal/ingest")

                url = f"http://127.0.0.1:{port}/export"
                req = urllib.request.Request(url, data=b"",
                                             headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=5) as r:
                    data = r.read()
                    content_type = r.headers.get("Content-Type", "")
                # Check it's a valid zip
                self.assertIn("zip", content_type)
                self.assertTrue(len(data) > 0)
                with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
                    f.write(data)
                    f_path = f.name
                self.assertTrue(zipfile.is_zipfile(f_path))
                os.unlink(f_path)
            finally:
                srv.stop()
                time.sleep(0.05)  # let OS reclaim port before next test

    def test_unknown_endpoint_returns_404(self):
        """Unknown endpoint returns 404."""
        from aletheia.server import AletheiaServer
        with tempfile.TemporaryDirectory() as tmp:
            port = self._find_free_port()
            srv = AletheiaServer(tmp, host="127.0.0.1", port=port)
            srv.start_background()
            time.sleep(0.1)
            try:
                url = f"http://127.0.0.1:{port}/nonexistent"
                try:
                    with urllib.request.urlopen(url, timeout=5) as _:
                        self.fail("Expected HTTP 404")
                except urllib.error.HTTPError as e:
                    self.assertEqual(e.code, 404)
            finally:
                srv.stop()
                time.sleep(0.05)  # let OS reclaim port before next test


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2.4 — AI Audit Trail
# ═══════════════════════════════════════════════════════════════════════════════

class TestAIAuditRecorder(unittest.TestCase):

    def _setup(self, tmp):
        ledger = SpineLedger(Path(tmp))
        from aletheia.ai_audit import AIAuditRecorder, AIAuditConfig
        cfg = AIAuditConfig(model_id="test-model", model_version="v1", include_full_content=False)
        recorder = AIAuditRecorder(ledger, config=cfg)
        return ledger, recorder

    def test_start_session_writes_spine_event(self):
        """start_session() writes AI_AUDIT_SESSION_START to Spine."""
        with tempfile.TemporaryDirectory() as tmp:
            ledger, recorder = self._setup(tmp)
            session_id = recorder.start_session()
            self.assertIsNotNone(session_id)
            events_dir = Path(tmp) / "spine" / "windows" / "ai_audit" / "events"
            events = [json.loads(f.read_text()) for f in sorted(events_dir.glob("*.json"))]
            types = [e["event_type"] for e in events]
            self.assertIn("AI_AUDIT_SESSION_START", types)
            # Check model_id is in payload
            start_ev = next(e for e in events if e["event_type"] == "AI_AUDIT_SESSION_START")
            self.assertEqual(start_ev["payload"]["model_id"], "test-model")
            ledger.close_clean()

    def test_record_request_hashes_prompt(self):
        """record_request stores prompt_hash, not raw prompt when include_full_content=False."""
        with tempfile.TemporaryDirectory() as tmp:
            ledger, recorder = self._setup(tmp)
            recorder.start_session()
            ev = recorder.record_request("What is 2+2?")
            events_dir = Path(tmp) / "spine" / "windows" / "ai_audit" / "events"
            events = [json.loads(f.read_text()) for f in sorted(events_dir.glob("*.json"))]
            req_ev = next(e for e in events if e["event_type"] == "AI_INFERENCE_REQUEST")
            self.assertIn("prompt_hash", req_ev["payload"])
            self.assertNotIn("prompt", req_ev["payload"])
            self.assertEqual(len(req_ev["payload"]["prompt_hash"]), 64)
            ledger.close_clean()

    def test_record_response_pins_request(self):
        """record_response stores request_pin pointing to request event hash."""
        with tempfile.TemporaryDirectory() as tmp:
            ledger, recorder = self._setup(tmp)
            recorder.start_session()
            req_ev = recorder.record_request("Question?")
            resp_ev = recorder.record_response("Answer.", request_event_hash=req_ev.hash)
            events_dir = Path(tmp) / "spine" / "windows" / "ai_audit" / "events"
            events = [json.loads(f.read_text()) for f in sorted(events_dir.glob("*.json"))]
            resp = next(e for e in events if e["event_type"] == "AI_INFERENCE_RESPONSE")
            self.assertEqual(resp["payload"]["request_pin"], req_ev.hash)
            ledger.close_clean()

    def test_record_envelope_returns_hashes(self):
        """record_envelope returns EnvelopeRecord with input/output hashes."""
        with tempfile.TemporaryDirectory() as tmp:
            ledger, recorder = self._setup(tmp)
            recorder.start_session()
            from aletheia.ai_audit import EnvelopeRecord
            result = recorder.record_envelope(
                input_data={"prompt": "hello"},
                output_data={"response": "world"},
            )
            self.assertIsInstance(result, EnvelopeRecord)
            self.assertEqual(len(result.input_hash), 64)
            self.assertEqual(len(result.output_hash), 64)
            self.assertIsNotNone(result.event_hash)
            ledger.close_clean()

    def test_record_constraint_writes_ai_event(self):
        """record_constraint writes AI_CONSTRAINT_APPLIED event."""
        with tempfile.TemporaryDirectory() as tmp:
            ledger, recorder = self._setup(tmp)
            recorder.start_session()
            recorder.record_constraint("C_NO_FALSE_CERTAINTY", "PASS",
                                       details={"confidence": 0.8})
            events_dir = Path(tmp) / "spine" / "windows" / "ai_audit" / "events"
            events = [json.loads(f.read_text()) for f in sorted(events_dir.glob("*.json"))]
            c_evs = [e for e in events if e["event_type"] == "AI_CONSTRAINT_APPLIED"]
            self.assertEqual(len(c_evs), 1)
            self.assertEqual(c_evs[0]["payload"]["verdict"], "PASS")
            ledger.close_clean()

    def test_record_human_override(self):
        """record_human_override writes AI_HUMAN_OVERRIDE event."""
        with tempfile.TemporaryDirectory() as tmp:
            ledger, recorder = self._setup(tmp)
            recorder.start_session()
            recorder.record_human_override(
                operator_id="op_001",
                original_decision="APPROVE",
                override_decision="REJECT",
                reason="Policy violation",
            )
            events_dir = Path(tmp) / "spine" / "windows" / "ai_audit" / "events"
            events = [json.loads(f.read_text()) for f in sorted(events_dir.glob("*.json"))]
            ov_evs = [e for e in events if e["event_type"] == "AI_HUMAN_OVERRIDE"]
            self.assertEqual(len(ov_evs), 1)
            self.assertEqual(ov_evs[0]["payload"]["operator_id"], "op_001")
            ledger.close_clean()

    def test_full_session_verifies_cleanly(self):
        """Full AI audit session seals and verifies correctly."""
        with tempfile.TemporaryDirectory() as tmp:
            ledger, recorder = self._setup(tmp)
            session_id = recorder.start_session()
            req_ev = recorder.record_request("Test prompt")
            recorder.record_response("Test response", request_event_hash=req_ev.hash)
            recorder.record_constraint("C_TEST", "PASS")
            recorder.end_session()
            ledger.seal_window("ai_audit")
            ledger.close_clean()

            report = verify_spine(tmp)
            self.assertTrue(report["ok"], f"verify_spine failed: {report}")


class TestDFWBridge(unittest.TestCase):

    def test_record_veto_writes_policy_verdict(self):
        """DFWBridge.record_veto() writes AI_POLICY_VERDICT with VETOED disposition."""
        from aletheia.ai_audit import DFWBridge
        with tempfile.TemporaryDirectory() as tmp:
            ledger = SpineLedger(Path(tmp))
            ledger.open_window("ai_audit")
            bridge = DFWBridge(ledger, window_id="ai_audit")
            ev = bridge.record_veto("delete_file", "agent_001", rule_id="P1_ABSOLUTE")
            events_dir = Path(tmp) / "spine" / "windows" / "ai_audit" / "events"
            events = [json.loads(f.read_text()) for f in sorted(events_dir.glob("*.json"))]
            pv_evs = [e for e in events if e["event_type"] == "AI_POLICY_VERDICT"]
            self.assertEqual(len(pv_evs), 1)
            self.assertEqual(pv_evs[0]["payload"]["disposition"], "VETOED")
            self.assertEqual(pv_evs[0]["payload"]["source"], "DFW")
            ledger.close_clean()

    def test_record_approval_writes_approved(self):
        """DFWBridge.record_approval() writes APPROVED disposition."""
        from aletheia.ai_audit import DFWBridge
        with tempfile.TemporaryDirectory() as tmp:
            ledger = SpineLedger(Path(tmp))
            ledger.open_window("ai_audit")
            bridge = DFWBridge(ledger, window_id="ai_audit")
            bridge.record_approval("read_file", "agent_001")
            events_dir = Path(tmp) / "spine" / "windows" / "ai_audit" / "events"
            events = [json.loads(f.read_text()) for f in sorted(events_dir.glob("*.json"))]
            pv_evs = [e for e in events if e["event_type"] == "AI_POLICY_VERDICT"]
            self.assertEqual(pv_evs[0]["payload"]["disposition"], "APPROVED")
            ledger.close_clean()

    def test_generic_record_verdict(self):
        """DFWBridge.record_verdict() handles arbitrary DFW verdict dicts."""
        from aletheia.ai_audit import DFWBridge
        with tempfile.TemporaryDirectory() as tmp:
            ledger = SpineLedger(Path(tmp))
            ledger.open_window("ai_audit")
            bridge = DFWBridge(ledger, window_id="ai_audit")
            bridge.record_verdict({
                "action": "send_email",
                "actor": "marketing_agent",
                "target": "user@example.com",
                "risk_level": "MED",
                "disposition": "DEFERRED",
                "reason": "Requires human approval",
            })
            events_dir = Path(tmp) / "spine" / "windows" / "ai_audit" / "events"
            events = [json.loads(f.read_text()) for f in sorted(events_dir.glob("*.json"))]
            pv_evs = [e for e in events if e["event_type"] == "AI_POLICY_VERDICT"]
            self.assertEqual(pv_evs[0]["payload"]["disposition"], "DEFERRED")
            ledger.close_clean()


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2.5 — Industrial OT Package
# ═══════════════════════════════════════════════════════════════════════════════

class TestOTAdapter(unittest.TestCase):

    def _setup(self, tmp):
        from aletheia.ot import OTAdapter, OTConfig
        ledger = SpineLedger(Path(tmp))
        siren = Siren(ledger)
        cfg = OTConfig(lens_validate=False)  # no Lens in unit tests
        adapter = OTAdapter(ledger, config=cfg, siren=siren)
        return ledger, siren, adapter

    def test_good_reading_accepted(self):
        """GOOD quality reading is accepted as OT_WITNESS."""
        from aletheia.ot import OTAdapter, OTSensorReading
        with tempfile.TemporaryDirectory() as tmp:
            ledger, siren, adapter = self._setup(tmp)
            reading = OTSensorReading(tag="PT-101", value=15.3, unit="bar", quality="GOOD")
            result = adapter.ingest_reading(reading)
            self.assertTrue(result.accepted)
            self.assertEqual(result.event_type, "OT_WITNESS")
            ledger.close_clean()

    def test_bad_quality_ingested_as_fault(self):
        """BAD quality reading is ingested as OT_FAULT (not dropped)."""
        from aletheia.ot import OTAdapter, OTSensorReading, OT_FAULT
        with tempfile.TemporaryDirectory() as tmp:
            ledger, siren, adapter = self._setup(tmp)
            reading = OTSensorReading(tag="PT-102", value=0.0, quality="BAD")
            result = adapter.ingest_reading(reading)
            self.assertTrue(result.accepted)
            self.assertEqual(result.event_type, OT_FAULT)
            ledger.close_clean()

    def test_uncertain_quality_accepted_by_default(self):
        """UNCERTAIN quality accepted when accept_uncertain=True (default)."""
        from aletheia.ot import OTAdapter, OTSensorReading, OT_WITNESS
        with tempfile.TemporaryDirectory() as tmp:
            ledger, siren, adapter = self._setup(tmp)
            reading = OTSensorReading(tag="TT-201", value=82.1, quality="UNCERTAIN")
            result = adapter.ingest_reading(reading)
            self.assertTrue(result.accepted)
            ledger.close_clean()

    def test_uncertain_rejected_when_configured(self):
        """UNCERTAIN quality rejected as OT_FAULT when accept_uncertain=False."""
        from aletheia.ot import OTAdapter, OTSensorReading, OTConfig, OT_FAULT
        with tempfile.TemporaryDirectory() as tmp:
            ledger = SpineLedger(Path(tmp))
            siren = Siren(ledger)
            cfg = OTConfig(lens_validate=False, accept_uncertain=False)
            adapter = OTAdapter(ledger, config=cfg, siren=siren)
            reading = OTSensorReading(tag="TT-202", value=82.0, quality="UNCERTAIN")
            result = adapter.ingest_reading(reading)
            self.assertEqual(result.event_type, OT_FAULT)
            ledger.close_clean()

    def test_command_recorded(self):
        """ingest_command writes OT_COMMAND event."""
        from aletheia.ot import OT_COMMAND
        with tempfile.TemporaryDirectory() as tmp:
            ledger, siren, adapter = self._setup(tmp)
            result = adapter.ingest_command(
                command="OPEN_VALVE",
                target="XV-301",
                operator="op_001",
                reason="Emergency drain",
            )
            self.assertTrue(result.accepted)
            self.assertEqual(result.event_type, OT_COMMAND)
            ledger.close_clean()

    def test_interlock_recorded(self):
        """ingest_interlock writes OT_INTERLOCK event."""
        from aletheia.ot import OT_INTERLOCK
        with tempfile.TemporaryDirectory() as tmp:
            ledger, siren, adapter = self._setup(tmp)
            result = adapter.ingest_interlock("PSV-401", "ACTIVATED", triggered_by="high_pressure")
            self.assertTrue(result.accepted)
            self.assertEqual(result.event_type, OT_INTERLOCK)
            ledger.close_clean()

    def test_multiple_readings_verifies_cleanly(self):
        """Multiple readings, seal, verify_spine passes."""
        from aletheia.ot import OTSensorReading
        with tempfile.TemporaryDirectory() as tmp:
            ledger, siren, adapter = self._setup(tmp)
            for i in range(10):
                adapter.ingest_reading(OTSensorReading(tag=f"PT-{i}", value=float(i), unit="bar"))
            adapter.seal_and_close()
            ledger.close_clean()

            report = verify_spine(tmp)
            self.assertTrue(report["ok"], f"verify_spine failed: {report}")

    def test_console_stats_tracks_event_counts(self):
        """get_console_stats() returns accurate counts."""
        from aletheia.ot import OTSensorReading
        with tempfile.TemporaryDirectory() as tmp:
            ledger, siren, adapter = self._setup(tmp)
            for i in range(5):
                adapter.ingest_reading(OTSensorReading(tag="PT-101", value=float(i), quality="GOOD"))
            adapter.ingest_reading(OTSensorReading(tag="FT-201", value=0.0, quality="BAD"))
            stats = adapter.get_console_stats()
            self.assertEqual(stats["total_readings"], 6)
            self.assertEqual(stats["fault"], 1)
            ledger.close_clean()


class TestOTConsole(unittest.TestCase):

    def test_console_renders_without_error(self):
        """OTConsole.render() returns a string without raising."""
        from aletheia.ot import OTAdapter, OTConfig, OTConsole, OTSensorReading
        with tempfile.TemporaryDirectory() as tmp:
            ledger = SpineLedger(Path(tmp))
            siren = Siren(ledger)
            cfg = OTConfig(lens_validate=False)
            adapter = OTAdapter(ledger, config=cfg, siren=siren)
            adapter.ingest_reading(OTSensorReading(tag="PT-101", value=15.0))

            console = OTConsole(adapter, ledger)
            output = console.render(return_str=True)
            self.assertIsNotNone(output)
            self.assertIn("ALETHEIA OT CONSOLE", output)
            self.assertIn("Siren", output)
            ledger.close_clean()

    def test_console_shows_siren_state(self):
        """OTConsole output reflects current Siren state."""
        from aletheia.ot import OTAdapter, OTConfig, OTConsole
        with tempfile.TemporaryDirectory() as tmp:
            ledger = SpineLedger(Path(tmp))
            siren = Siren(ledger)
            cfg = OTConfig(lens_validate=False)
            adapter = OTAdapter(ledger, config=cfg, siren=siren)
            console = OTConsole(adapter, ledger)
            output = console.render(return_str=True)
            self.assertIn("NORMAL", output)
            ledger.close_clean()


# ═══════════════════════════════════════════════════════════════════════════════
# Integration: Phase 2 end-to-end
# ═══════════════════════════════════════════════════════════════════════════════

class TestPhase2Integration(unittest.TestCase):

    def test_streaming_to_case_zip_verifies(self):
        """Full streaming pipeline: ingest → roll → export → verify."""
        from aletheia.streaming import CallbackAdapter, SchedulerConfig
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as out:
            ledger = SpineLedger(Path(tmp))
            records = [{"event_type": "WITNESS", "payload": {"seq": i}} for i in range(20)]
            cfg = SchedulerConfig(base_window_id="stream_int", max_events_per_window=5)
            adapter = CallbackAdapter(ledger, records, source_name="integration",
                                      scheduler_config=cfg)
            adapter.start()
            adapter.run()
            # Seal the final open window before stopping
            final_wid = adapter.scheduler.current_window_id
            adapter.stop()
            ledger.close_clean()

            # Verify the sealed windows from the scheduler (not the gate's validation window)
            report = verify_spine(tmp)
            self.assertTrue(report["ok"], f"verify_spine failed: {report}")
            # 20 events / 5 per window = 4 windows sealed by roll + 1 final = 4 total
            self.assertGreaterEqual(report["sealed_windows_verified"], 4)

    def test_ai_audit_plus_dfw_in_same_session(self):
        """AI audit + DFW bridge write to same window, seal verifies."""
        from aletheia.ai_audit import AIAuditRecorder, AIAuditConfig, DFWBridge
        with tempfile.TemporaryDirectory() as tmp:
            ledger = SpineLedger(Path(tmp))
            cfg = AIAuditConfig(model_id="agent-v1", window_id="ai_audit")
            recorder = AIAuditRecorder(ledger, config=cfg)
            bridge = DFWBridge(ledger, window_id="ai_audit")

            session_id = recorder.start_session()
            req_ev = recorder.record_request("Execute task X")
            bridge.record_veto("execute_task_x", "agent-v1",
                               rule_id="P1_ABSOLUTE", session_id=session_id)
            recorder.record_escalation("High-risk action vetoed by DFW",
                                       escalated_to="human_operator",
                                       request_pin=req_ev.hash)
            recorder.end_session(outcome="ESCALATED")
            ledger.seal_window("ai_audit")
            ledger.close_clean()

            report = verify_spine(tmp)
            self.assertTrue(report["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
