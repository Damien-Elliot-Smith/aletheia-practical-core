"""
tests/test_adapters_extended.py — Extended adapter test suite

Covers:
  Phase 5B — AI Audit Causal chain reconstruction
  Phase 9  — Streaming (buffer, batch, runner, webhook)
  Phase 10 — Adapter selfcheck tool
  Phase 2  — __init__ package exports and run_adapter convenience function

stdlib unittest only. No pytest required.
"""
from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

import sys
_HERE = Path(__file__).resolve().parent.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import aletheia.adapters  # triggers all registrations via __init__

from aletheia.adapters.taxonomy import (
    LOSS_OF_CAUSAL_LINKAGE, LOSS_OF_COMPLETENESS, LOSS_OF_STRUCTURE,
    STATUS_ACCEPTED, STATUS_ACCEPTED_WITH_LOSS, STATUS_REJECTED,
    TRUST_UNAUTHENTICATED,
)
from aletheia.adapters.base import AdapterResult, CanonicalEvent
from aletheia.adapters.registry import list_adapters


def _raw(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False).encode("utf-8")


# ══════════════════════════════════════════════════════════════════════════════
# Phase 5B — AI Audit Causal
# ══════════════════════════════════════════════════════════════════════════════

class TestAIAuditCausal(unittest.TestCase):

    def setUp(self):
        from aletheia.adapters.ai_audit_causal import AIAuditCausalAdapter
        self.adapter = AIAuditCausalAdapter()

    def test_tool_link_with_request_id_produces_verified_link(self):
        batch = [
            {"record_type": "inference_request", "request_id": "req-1",
             "model": "m", "source": "s"},
            {"record_type": "tool_link", "request_id": "req-1",
             "tool_name": "calculator", "chain_id": "c1", "source": "s"},
        ]
        result = self.adapter.adapt(_raw(batch))
        tool_events = [e for e in result.canonical_events
                       if e.event_type == "AI_CAUSAL_TOOL_LINK"]
        self.assertTrue(len(tool_events) >= 1)
        self.assertTrue(tool_events[0].payload["link_verified"])

    def test_tool_link_without_request_id_records_causal_loss(self):
        batch = [
            {"record_type": "tool_link", "tool_name": "search", "chain_id": "c2"},
        ]
        result = self.adapter.adapt(_raw(batch))
        self.assertTrue(any(l.loss_type == LOSS_OF_CAUSAL_LINKAGE for l in result.losses))

    def test_tool_link_missing_tool_name_rejected(self):
        batch = [{"record_type": "tool_link", "request_id": "req-x"}]
        result = self.adapter.adapt(_raw(batch))
        self.assertTrue(any(r.rejection_type == "INCOMPLETE" for r in result.rejections))

    def test_reasoning_chain_complete_when_all_steps_present(self):
        batch = [
            {"record_type": "reasoning_step", "chain_id": "ch1", "step_index": 0,
             "content": "Step A", "source": "s"},
            {"record_type": "reasoning_step", "chain_id": "ch1", "step_index": 1,
             "content": "Step B", "source": "s"},
            {"record_type": "reasoning_step", "chain_id": "ch1", "step_index": 2,
             "content": "Step C", "source": "s"},
        ]
        result = self.adapter.adapt(_raw(batch))
        complete = [e for e in result.canonical_events
                    if e.event_type == "AI_REASONING_CHAIN_COMPLETE"]
        self.assertEqual(len(complete), 1)
        self.assertEqual(complete[0].payload["step_count"], 3)
        self.assertTrue(complete[0].payload["chain_complete"])

    def test_reasoning_chain_incomplete_on_step_gap(self):
        batch = [
            {"record_type": "reasoning_step", "chain_id": "ch2", "step_index": 0, "source": "s"},
            {"record_type": "reasoning_step", "chain_id": "ch2", "step_index": 2, "source": "s"},
            # step_index 1 is missing
        ]
        result = self.adapter.adapt(_raw(batch))
        incomplete = [e for e in result.canonical_events
                      if e.event_type == "AI_CAUSAL_INCOMPLETE"]
        self.assertEqual(len(incomplete), 1)
        self.assertTrue(any(l.loss_type == LOSS_OF_COMPLETENESS for l in result.losses))

    def test_reasoning_step_without_chain_id_emitted_standalone(self):
        batch = [{"record_type": "reasoning_step", "step_index": 0, "content": "x"}]
        result = self.adapter.adapt(_raw(batch))
        steps = [e for e in result.canonical_events if e.event_type == "AI_REASONING_STEP"]
        self.assertEqual(len(steps), 1)
        self.assertTrue(any(l.loss_type == LOSS_OF_CAUSAL_LINKAGE for l in result.losses))

    def test_override_record_emitted_correctly(self):
        batch = [{"record_type": "override", "override_type": "HUMAN",
                  "target_id": "req-1", "actor": "user@example.com",
                  "original_decision": "allow", "new_decision": "deny"}]
        result = self.adapter.adapt(_raw(batch))
        overrides = [e for e in result.canonical_events if e.event_type == "AI_OVERRIDE_RECORD"]
        self.assertEqual(len(overrides), 1)
        self.assertEqual(overrides[0].payload["override_type"], "HUMAN")

    def test_override_missing_target_id_records_causal_loss(self):
        batch = [{"record_type": "override", "override_type": "SYSTEM"}]
        result = self.adapter.adapt(_raw(batch))
        self.assertTrue(any(l.loss_type == LOSS_OF_CAUSAL_LINKAGE for l in result.losses))

    def test_moderation_lineage_linked_when_request_present(self):
        batch = [
            {"record_type": "inference_request", "request_id": "req-2", "model": "m"},
            {"record_type": "moderation_lineage", "request_id": "req-2",
             "verdict": "ALLOW", "source": "s"},
        ]
        result = self.adapter.adapt(_raw(batch))
        lineage = [e for e in result.canonical_events
                   if e.event_type == "AI_MODERATION_LINEAGE"]
        self.assertEqual(len(lineage), 1)
        self.assertTrue(lineage[0].payload["request_linked"])

    def test_moderation_lineage_missing_verdict_rejected(self):
        batch = [{"record_type": "moderation_lineage", "request_id": "req-3"}]
        result = self.adapter.adapt(_raw(batch))
        self.assertTrue(any(r.rejection_type == "INCOMPLETE" for r in result.rejections))

    def test_unhandled_record_emitted_as_ai_unlinked_record(self):
        batch = [{"record_type": "some_future_type", "data": "x"}]
        result = self.adapter.adapt(_raw(batch))
        unlinked = [e for e in result.canonical_events
                    if e.event_type == "AI_UNLINKED_RECORD"]
        self.assertEqual(len(unlinked), 1)

    def test_content_hashed_in_tool_output(self):
        batch = [{"record_type": "tool_link", "tool_name": "calc",
                  "tool_output": {"result": 42}}]
        result = self.adapter.adapt(_raw(batch))
        ev = next((e for e in result.canonical_events
                   if e.event_type == "AI_CAUSAL_TOOL_LINK"), None)
        self.assertIsNotNone(ev)
        # Should have a content hash for tool_output
        self.assertIn("tool_output_hash", ev.payload)
        self.assertIsNotNone(ev.payload["tool_output_hash"])

    def test_malformed_json_rejected(self):
        result = self.adapter.adapt(b"not json")
        self.assertEqual(result.status, STATUS_REJECTED)


# ══════════════════════════════════════════════════════════════════════════════
# Phase 9 — Streaming
# ══════════════════════════════════════════════════════════════════════════════

class TestStreamingBuffer(unittest.TestCase):

    def test_push_and_drain(self):
        from aletheia.adapters.streaming import StreamingBuffer
        buf = StreamingBuffer(max_items=10)
        for i in range(5):
            ok = buf.push(f'{{"n":{i}}}'.encode())
            self.assertTrue(ok)
        batch = buf.drain()
        self.assertEqual(batch.item_count, 5)
        self.assertEqual(buf.size, 0)

    def test_overflow_rejected_not_silent(self):
        from aletheia.adapters.streaming import StreamingBuffer
        buf = StreamingBuffer(max_items=3)
        for i in range(5):
            buf.push(b'{}')
        self.assertEqual(buf.dropped_count, 2)

    def test_drain_records_dropped_count(self):
        from aletheia.adapters.streaming import StreamingBuffer
        buf = StreamingBuffer(max_items=2)
        for _ in range(5):
            buf.push(b'{}')
        batch = buf.drain()
        self.assertEqual(batch.dropped_before_drain, 3)

    def test_batch_hash_deterministic(self):
        from aletheia.adapters.streaming import StreamingBuffer
        buf1 = StreamingBuffer()
        buf2 = StreamingBuffer()
        data = [b'{"a":1}', b'{"b":2}', b'{"c":3}']
        for d in data:
            buf1.push(d)
            buf2.push(d)
        b1 = buf1.drain()
        b2 = buf2.drain()
        self.assertEqual(b1.batch_hash, b2.batch_hash)

    def test_batch_hash_changes_with_different_content(self):
        from aletheia.adapters.streaming import StreamingBuffer
        buf1 = StreamingBuffer()
        buf2 = StreamingBuffer()
        buf1.push(b'{"a":1}')
        buf2.push(b'{"a":2}')
        b1 = buf1.drain()
        b2 = buf2.drain()
        self.assertNotEqual(b1.batch_hash, b2.batch_hash)

    def test_late_arrival_flagged(self):
        from aletheia.adapters.streaming import StreamingBuffer
        buf = StreamingBuffer(max_items=10, late_threshold_s=0.0)
        # All items will be late because threshold is 0s and time passes
        time.sleep(0.01)
        buf.push(b'{"x":1}')
        batch = buf.drain()
        self.assertTrue(batch.items[0].late)

    def test_thread_safe_push(self):
        from aletheia.adapters.streaming import StreamingBuffer
        buf = StreamingBuffer(max_items=200)
        errors = []

        def pusher():
            for _ in range(20):
                try:
                    buf.push(b'{"x":1}')
                except Exception as e:
                    errors.append(e)

        threads = [threading.Thread(target=pusher) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        self.assertLessEqual(buf.size + buf.dropped_count, 100)

    def test_drain_max_items_respected(self):
        from aletheia.adapters.streaming import StreamingBuffer
        buf = StreamingBuffer(max_items=20)
        for _ in range(10):
            buf.push(b'{}')
        batch = buf.drain(max_items=3)
        self.assertEqual(batch.item_count, 3)
        self.assertEqual(buf.size, 7)


class TestStreamingRunner(unittest.TestCase):

    def _make_gate(self, td):
        from aletheia.spine.ledger import SpineLedger
        from aletheia.ingest.gate import IngestGate, IngestConfig
        root = Path(td)
        ledger = SpineLedger(root)
        ledger.open_window("stream")
        gate = IngestGate(ledger, config=IngestConfig(
            window_id="stream", max_accepts_per_sec=10000
        ))
        return gate, ledger

    def test_streaming_runner_accepts_clean_events(self):
        from aletheia.adapters.streaming import StreamingBuffer, StreamingRunner
        from aletheia.adapters.runner import AdapterRunner

        with tempfile.TemporaryDirectory() as td:
            gate, ledger = self._make_gate(td)
            buf = StreamingBuffer(max_items=50)
            runner = AdapterRunner(gate)
            sr = StreamingRunner(buf, runner, adapter_name="json_adapter")

            for i in range(3):
                buf.push(_raw({"source": "s", "event_type": "E", "payload": {"n": i}}))

            report = sr.drain_and_run()
            self.assertEqual(report.batch.item_count, 3)
            self.assertEqual(report.total_accepted, 3)
            ledger.close_clean()

    def test_streaming_runner_rejected_items_not_counted_as_accepted(self):
        from aletheia.adapters.streaming import StreamingBuffer, StreamingRunner
        from aletheia.adapters.runner import AdapterRunner

        with tempfile.TemporaryDirectory() as td:
            gate, ledger = self._make_gate(td)
            buf = StreamingBuffer(max_items=50)
            runner = AdapterRunner(gate)
            sr = StreamingRunner(buf, runner, adapter_name="json_adapter")

            buf.push(b"not json at all")

            report = sr.drain_and_run()
            self.assertEqual(report.total_adapter_rejected, 1)
            self.assertEqual(report.total_accepted, 0)
            ledger.close_clean()

    def test_streaming_run_report_to_dict(self):
        from aletheia.adapters.streaming import StreamingBuffer, StreamingRunner
        from aletheia.adapters.runner import AdapterRunner

        with tempfile.TemporaryDirectory() as td:
            gate, ledger = self._make_gate(td)
            buf = StreamingBuffer()
            runner = AdapterRunner(gate)
            sr = StreamingRunner(buf, runner, "json_adapter")
            buf.push(_raw({"source": "s", "event_type": "E", "payload": {}}))
            report = sr.drain_and_run()
            d = report.to_dict()
            self.assertIn("batch", d)
            self.assertIn("total_accepted", d)
            ledger.close_clean()


class TestWebhookAdapter(unittest.TestCase):

    def test_webhook_accepts_unsigned_payload(self):
        from aletheia.adapters.streaming import StreamingBuffer, WebhookAdapter
        buf = StreamingBuffer(max_items=10)
        hook = WebhookAdapter(buf)
        ok = hook.receive(b'{"event":"test"}')
        self.assertTrue(ok)
        self.assertEqual(buf.size, 1)

    def test_webhook_verifies_hmac_signature(self):
        import hmac as _hmac
        from aletheia.adapters.streaming import StreamingBuffer, WebhookAdapter
        buf = StreamingBuffer(max_items=10)
        secret = "test-secret"
        hook = WebhookAdapter(buf, secret=secret)
        body = b'{"event":"signed"}'
        sig = _hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        ok = hook.receive(body, headers={"x-hub-signature-256": f"sha256={sig}"})
        self.assertTrue(ok)

    def test_webhook_rejects_bad_signature(self):
        from aletheia.adapters.streaming import StreamingBuffer, WebhookAdapter
        buf = StreamingBuffer(max_items=10)
        hook = WebhookAdapter(buf, secret="real-secret")
        ok = hook.receive(b'{"event":"tampered"}',
                          headers={"x-hub-signature-256": "sha256=" + "0" * 64})
        self.assertFalse(ok)
        self.assertEqual(buf.size, 0)

    def test_webhook_buffer_full_returns_false(self):
        from aletheia.adapters.streaming import StreamingBuffer, WebhookAdapter
        buf = StreamingBuffer(max_items=1)
        hook = WebhookAdapter(buf)
        hook.receive(b'first')
        ok = hook.receive(b'second')
        self.assertFalse(ok)


# ══════════════════════════════════════════════════════════════════════════════
# Phase 10 — Adapter selfcheck
# ══════════════════════════════════════════════════════════════════════════════

class TestAdapterSelfcheck(unittest.TestCase):

    def test_selfcheck_all_pass(self):
        import tools.adapter_selfcheck as sc
        result = sc.main(["--json"])
        # main() returns exit code: 0 = all pass
        # We test by calling the internal runner directly
        results = []
        for check_args in sc._CHECKS:
            results.append(sc._run_check(*check_args))
        all_pass = all(r["passed"] for r in results)
        self.assertTrue(all_pass, msg=str([r for r in results if not r["passed"]]))

    def test_selfcheck_detects_wrong_version(self):
        import tools.adapter_selfcheck as sc
        # Pass wrong version
        result = sc._run_check(
            "json_adapter", "9.9.9",
            b'{"source":"s","event_type":"E","payload":{}}',
            b"{bad",
        )
        version_check = next(c for c in result["checks"] if c["check"] == "version_match")
        self.assertFalse(version_check["ok"])

    def test_selfcheck_json_output_parseable(self):
        import subprocess
        r = subprocess.run(
            [sys.executable, "tools/adapter_selfcheck.py", "--json"],
            capture_output=True, text=True,
            cwd=str(_HERE),
        )
        data = json.loads(r.stdout)
        self.assertIn("passed", data)
        self.assertIn("results", data)


# ══════════════════════════════════════════════════════════════════════════════
# Phase 2 — Package __init__ and run_adapter convenience
# ══════════════════════════════════════════════════════════════════════════════

class TestPackageInit(unittest.TestCase):

    def test_all_adapters_registered_after_import(self):
        adapters = list_adapters()
        for name in ("json_adapter", "file_adapter", "ai_audit_adapter",
                     "ai_audit_causal", "ot_adapter"):
            self.assertIn(name, adapters)

    def test_run_adapter_convenience(self):
        from aletheia.adapters import run_adapter
        from aletheia.spine.ledger import SpineLedger
        from aletheia.ingest.gate import IngestGate, IngestConfig

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ledger = SpineLedger(root)
            ledger.open_window("ingest")
            gate = IngestGate(ledger, config=IngestConfig(
                window_id="ingest", max_accepts_per_sec=10000
            ))
            raw = _raw({"source": "pkg", "event_type": "INIT", "payload": {"ok": True}})
            report = run_adapter(gate, "json_adapter", raw)
            self.assertEqual(report.events_accepted, 1)
            ledger.close_clean()

    def test_package_exports_taxonomy_constants(self):
        from aletheia.adapters import (
            LOSS_OF_PRECISION, LOSS_OF_STRUCTURE, LOSS_OF_COMPLETENESS,
            LOSS_OF_CAUSAL_LINKAGE, LOSS_OF_AUTHENTICITY,
            REJECT_MALFORMED, REJECT_HOSTILE, REJECT_INCOMPLETE,
            STATUS_ACCEPTED, STATUS_REJECTED,
            TRUST_UNAUTHENTICATED, TRUST_AUTHENTICATED,
        )
        # Just verifying they are importable and have expected values
        self.assertEqual(LOSS_OF_PRECISION, "LOSS_OF_PRECISION")
        self.assertEqual(REJECT_MALFORMED, "MALFORMED")
        self.assertEqual(STATUS_ACCEPTED, "ACCEPTED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
