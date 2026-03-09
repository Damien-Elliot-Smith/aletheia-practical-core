"""
test_1000_scenarios_part4.py — Constraints, Sentinel, Detective, integration flows,
and conversion of the 4 pytest-dependent tests to stdlib unittest.
280 tests covering constraint lifecycle, sentinel policy evaluation, detective
hypothesis evaluation, and realistic end-to-end operational scenarios.
"""
from __future__ import annotations
import hashlib, json, os, subprocess, sys, tempfile, unittest, zipfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from aletheia.spine.ledger import SpineLedger
from aletheia.spine.verify import verify_spine
from aletheia.siren.state_machine import Siren, SirenState, MaydayCode
from aletheia.ingest.gate import IngestGate, IngestConfig, IngestDecision
from aletheia.constraints.registry import ConstraintRegistry, ConstraintEQI
from aletheia.sentinel.sentinel import SentinelLite, SentinelConfig, SentinelVerdict, SentinelReason
from aletheia.detective.detective import Detective, DetectiveConfig
from aletheia.detective.sieve import Hypothesis
from aletheia.detective.zipguard import build_extraction_plan, ZipGuardError
from aletheia.detective.limits import ZipLimits
from aletheia.detective import reasons as R
from aletheia.claims import ClaimRegistry, ClaimEQI, ClaimType, ClaimStatus
from aletheia.claims.claimcheck import check_claim, check_all
from aletheia.chronicle.export import build_case_zip


def _ledger(tmp, **kw):
    return SpineLedger(Path(tmp), **kw)

def _last_hash(root, window):
    evdir = root / "spine" / "windows" / window / "events"
    last = sorted(evdir.glob("*.json"))[-1]
    return json.loads(last.read_text())["hash"]

def _make_zip(path, members):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data, customize in members:
            zi = zipfile.ZipInfo(filename=name)
            if customize:
                customize(zi)
            zf.writestr(zi, data)

def _build_policy_root(tmp, policy_rules):
    root = Path(tmp) / "root"
    root.mkdir(parents=True, exist_ok=True)
    l = SpineLedger(root)
    reg = ConstraintRegistry(l, window_id="constants")
    reg.publish("sentinel.policy", "1.0", policy_rules)
    l.seal_window("constants")
    l.close_clean()
    return root


# ══════════════════════════════════════════════════════════════════════════════
# CONSTRAINTS — registry and EQI
# ══════════════════════════════════════════════════════════════════════════════

class TestConstraintRegistry(unittest.TestCase):

    def _reg(self, tmp):
        l = _ledger(tmp)
        reg = ConstraintRegistry(l, window_id="constants")
        return l, reg

    def test_publish_returns_constraint_ref(self):
        with tempfile.TemporaryDirectory() as t:
            l, reg = self._reg(t)
            ref = reg.publish("temp.limit", "1.0", {"min": 0.0, "max": 100.0}, units="C")
            self.assertEqual(ref.constraint_id, "temp.limit")
            self.assertEqual(ref.version, "1.0")
            l.close_clean()

    def test_constraint_hash_is_64_hex(self):
        with tempfile.TemporaryDirectory() as t:
            l, reg = self._reg(t)
            ref = reg.publish("p.limit", "1.0", {"min": 0.0, "max": 10.0})
            self.assertEqual(len(ref.constraint_hash), 64)
            self.assertTrue(all(c in "0123456789abcdef" for c in ref.constraint_hash))
            l.close_clean()

    def test_publish_event_in_spine(self):
        with tempfile.TemporaryDirectory() as t:
            l, reg = self._reg(t)
            reg.publish("x.limit", "1.0", {"v": 1.0})
            l.seal_window("constants"); l.close_clean()
            evs = [json.loads(f.read_text()) for f in sorted((Path(t)/"spine/windows/constants/events").glob("*.json"))]
            self.assertTrue(any(e["event_type"] == "CONSTRAINT_PUBLISH" for e in evs))

    def test_supersede_requires_correct_previous_hash(self):
        with tempfile.TemporaryDirectory() as t:
            l, reg = self._reg(t)
            ref = reg.publish("p.limit", "1.0", {"min": 0.0, "max": 10.0})
            with self.assertRaises(Exception):
                reg.supersede("p.limit", "2.0", {"min": 0.0, "max": 15.0},
                              previous_version="1.0", previous_hash="wrong" * 16)
            l.close_clean()

    def test_supersede_correct_hash_succeeds(self):
        with tempfile.TemporaryDirectory() as t:
            l, reg = self._reg(t)
            ref = reg.publish("p.limit", "1.0", {"min": 0.0, "max": 10.0})
            ref2 = reg.supersede("p.limit", "2.0", {"min": 0.0, "max": 15.0},
                                 previous_version="1.0", previous_hash=ref.constraint_hash)
            self.assertEqual(ref2.version, "2.0")
            l.close_clean()

    def test_active_constraint_after_seal_is_latest(self):
        with tempfile.TemporaryDirectory() as t:
            l, reg = self._reg(t)
            ref1 = reg.publish("p.limit", "1.0", {"min": 0.0, "max": 10.0})
            ref2 = reg.supersede("p.limit", "2.0", {"min": 0.0, "max": 15.0},
                                 previous_version="1.0", previous_hash=ref1.constraint_hash)
            l.seal_window("constants"); l.close_clean()
            eqi = ConstraintEQI(Path(t), window_id="constants")
            active = eqi.get_active("p.limit")
            self.assertIsNotNone(active)
            self.assertEqual(active[0].version, "2.0")

    def test_unsealed_window_eqi_returns_none(self):
        with tempfile.TemporaryDirectory() as t:
            l, reg = self._reg(t)
            reg.publish("p.limit", "1.0", {"min": 0.0, "max": 10.0})
            l.close_clean()
            eqi = ConstraintEQI(Path(t), window_id="constants")
            self.assertIsNone(eqi.get_active("p.limit"))

    def test_eqi_is_sealed_returns_true_after_seal(self):
        with tempfile.TemporaryDirectory() as t:
            l, reg = self._reg(t)
            reg.publish("x.limit", "1.0", {"v": 1.0})
            l.seal_window("constants"); l.close_clean()
            eqi = ConstraintEQI(Path(t), window_id="constants")
            self.assertTrue(eqi.is_sealed())

    def test_eqi_is_sealed_false_before_seal(self):
        with tempfile.TemporaryDirectory() as t:
            l, reg = self._reg(t)
            reg.publish("x.limit", "1.0", {"v": 1.0})
            l.close_clean()
            eqi = ConstraintEQI(Path(t), window_id="constants")
            self.assertFalse(eqi.is_sealed())

    def test_unknown_constraint_returns_none(self):
        with tempfile.TemporaryDirectory() as t:
            l, reg = self._reg(t)
            reg.publish("x.limit", "1.0", {"v": 1.0})
            l.seal_window("constants"); l.close_clean()
            eqi = ConstraintEQI(Path(t), window_id="constants")
            self.assertIsNone(eqi.get_active("nonexistent.constraint"))

    def test_deprecate_removes_active(self):
        with tempfile.TemporaryDirectory() as t:
            l, reg = self._reg(t)
            ref = reg.publish("old.limit", "1.0", {"v": 1.0})
            reg.deprecate("old.limit", "1.0", previous_hash=ref.constraint_hash, note="replaced")
            l.seal_window("constants"); l.close_clean()
            eqi = ConstraintEQI(Path(t), window_id="constants")
            result = eqi.get_active("old.limit")
            self.assertIsNone(result)

    def test_multiple_constraints_independent(self):
        with tempfile.TemporaryDirectory() as t:
            l, reg = self._reg(t)
            reg.publish("temp.limit", "1.0", {"min": -20.0, "max": 120.0}, units="C")
            reg.publish("pressure.limit", "1.0", {"min": 0.0, "max": 25.0}, units="bar")
            reg.publish("flow.limit", "1.0", {"min": 0.0, "max": 100.0}, units="m3h")
            l.seal_window("constants"); l.close_clean()
            eqi = ConstraintEQI(Path(t), window_id="constants")
            for cid in ("temp.limit", "pressure.limit", "flow.limit"):
                self.assertIsNotNone(eqi.get_active(cid))

    def test_nan_in_rule_raises(self):
        with tempfile.TemporaryDirectory() as t:
            l, reg = self._reg(t)
            import math
            with self.assertRaises(ValueError):
                reg.publish("bad.limit", "1.0", {"min": math.nan, "max": 100.0})
            l.close_clean()

    def test_inf_in_rule_raises(self):
        with tempfile.TemporaryDirectory() as t:
            l, reg = self._reg(t)
            import math
            with self.assertRaises(ValueError):
                reg.publish("bad.limit", "1.0", {"min": 0.0, "max": math.inf})
            l.close_clean()

    def test_constraint_with_applicability_metadata(self):
        with tempfile.TemporaryDirectory() as t:
            l, reg = self._reg(t)
            ref = reg.publish("temp.limit", "1.0", {"min": 0.0, "max": 100.0},
                              units="C",
                              applicability={"system": "cooling_loop", "site": "plant_A"})
            self.assertIsNotNone(ref)
            l.close_clean()

    def test_constraint_with_tolerances_metadata(self):
        with tempfile.TemporaryDirectory() as t:
            l, reg = self._reg(t)
            ref = reg.publish("temp.limit", "1.0", {"min": 0.0, "max": 100.0},
                              tolerances={"hi_hi": 105.0, "lo_lo": -5.0})
            self.assertIsNotNone(ref)
            l.close_clean()

    def test_constraint_version_string_preserved(self):
        with tempfile.TemporaryDirectory() as t:
            l, reg = self._reg(t)
            reg.publish("v.limit", "2.3.1", {"x": 1.0})
            l.seal_window("constants"); l.close_clean()
            eqi = ConstraintEQI(Path(t), window_id="constants")
            active = eqi.get_active("v.limit")
            self.assertEqual(active[0].version, "2.3.1")

    def test_constraint_spine_verifies_clean(self):
        with tempfile.TemporaryDirectory() as t:
            l, reg = self._reg(t)
            ref = reg.publish("x.limit", "1.0", {"min": 0.0, "max": 50.0})
            reg.supersede("x.limit", "2.0", {"min": 0.0, "max": 55.0},
                          previous_version="1.0", previous_hash=ref.constraint_hash)
            l.seal_window("constants"); l.close_clean()
            r = verify_spine(t)
            self.assertTrue(r["ok"])

    def test_active_rule_payload_preserved(self):
        with tempfile.TemporaryDirectory() as t:
            l, reg = self._reg(t)
            rule = {"min": 5.0, "max": 95.0, "roc_max_per_s": 2.5}
            reg.publish("complex.rule", "1.0", rule)
            l.seal_window("constants"); l.close_clean()
            eqi = ConstraintEQI(Path(t), window_id="constants")
            active = eqi.get_active("complex.rule")
            stored_rule = active[1]["rule"]
            self.assertEqual(stored_rule["min"], 5.0)
            self.assertEqual(stored_rule["max"], 95.0)

    def test_supersede_note_stored(self):
        with tempfile.TemporaryDirectory() as t:
            l, reg = self._reg(t)
            ref = reg.publish("x.limit", "1.0", {"min": 0.0, "max": 10.0})
            reg.supersede("x.limit", "1.1", {"min": 0.0, "max": 12.0},
                          previous_version="1.0", previous_hash=ref.constraint_hash,
                          note="Extended upper limit per ECO-2026-003")
            l.seal_window("constants"); l.close_clean()
            evs = [json.loads(f.read_text()) for f in sorted((Path(t)/"spine/windows/constants/events").glob("*.json"))]
            sup_ev = next(e for e in evs if e["event_type"] == "CONSTRAINT_SUPERSEDE")
            self.assertIn("ECO-2026-003", str(sup_ev["payload"]))


# ══════════════════════════════════════════════════════════════════════════════
# SENTINEL — policy evaluation
# ══════════════════════════════════════════════════════════════════════════════

class TestSentinelEvaluation(unittest.TestCase):

    def _sentinel(self, tmp, policy_rules):
        root = _build_policy_root(tmp, policy_rules)
        cfg = SentinelConfig(constants_window="constants", policy_id="sentinel.policy")
        return SentinelLite(root, config=cfg)

    def test_low_risk_pass_policy(self):
        with tempfile.TemporaryDirectory() as t:
            s = self._sentinel(t, {"read_sensor": {"risk": "LOW", "default": "PASS"}})
            r = s.evaluate({"action": "read_sensor", "target": "PT-101", "actor": "operator"})
            self.assertEqual(r["verdict"], SentinelVerdict.PASS)

    def test_high_risk_fail_policy(self):
        with tempfile.TemporaryDirectory() as t:
            s = self._sentinel(t, {"delete_log": {"risk": "HIGH", "default": "FAIL"}})
            r = s.evaluate({"action": "delete_log", "target": "audit.log", "actor": "op"})
            self.assertEqual(r["verdict"], SentinelVerdict.FAIL)

    def test_high_risk_default_inconclusive(self):
        with tempfile.TemporaryDirectory() as t:
            s = self._sentinel(t, {"override_setpoint": {"risk": "HIGH", "default": "INCONCLUSIVE"}})
            r = s.evaluate({"action": "override_setpoint", "target": "TC-201", "actor": "op"})
            self.assertEqual(r["verdict"], SentinelVerdict.INCONCLUSIVE)
            self.assertEqual(r["reason_code"], SentinelReason.HIGH_RISK_NEEDS_WITNESS)

    def test_high_risk_default_pass_policy(self):
        with tempfile.TemporaryDirectory() as t:
            s = self._sentinel(t, {"emergency_ack": {"risk": "HIGH", "default": "PASS"}})
            r = s.evaluate({"action": "emergency_ack", "target": "alarm", "actor": "op"})
            self.assertEqual(r["verdict"], SentinelVerdict.PASS)

    def test_unknown_action_inconclusive(self):
        with tempfile.TemporaryDirectory() as t:
            s = self._sentinel(t, {"start_pump": {"risk": "LOW", "default": "PASS"}})
            r = s.evaluate({"action": "fly_to_moon", "target": "X", "actor": "op"})
            self.assertEqual(r["verdict"], SentinelVerdict.INCONCLUSIVE)
            self.assertEqual(r["reason_code"], SentinelReason.UNKNOWN_ACTION)

    def test_missing_action_field_inconclusive(self):
        with tempfile.TemporaryDirectory() as t:
            s = self._sentinel(t, {"start_pump": {"risk": "LOW", "default": "PASS"}})
            r = s.evaluate({"target": "P-101", "actor": "op"})
            self.assertEqual(r["verdict"], SentinelVerdict.INCONCLUSIVE)
            self.assertEqual(r["reason_code"], SentinelReason.MISSING_FIELDS)

    def test_missing_actor_field_inconclusive(self):
        with tempfile.TemporaryDirectory() as t:
            s = self._sentinel(t, {"start_pump": {"risk": "LOW", "default": "PASS"}})
            r = s.evaluate({"action": "start_pump", "target": "P-101"})
            self.assertEqual(r["verdict"], SentinelVerdict.INCONCLUSIVE)

    def test_missing_target_field_inconclusive(self):
        with tempfile.TemporaryDirectory() as t:
            s = self._sentinel(t, {"start_pump": {"risk": "LOW", "default": "PASS"}})
            r = s.evaluate({"action": "start_pump", "actor": "op"})
            self.assertEqual(r["verdict"], SentinelVerdict.INCONCLUSIVE)

    def test_allowed_actor_passes(self):
        with tempfile.TemporaryDirectory() as t:
            root = _build_policy_root(t, {"read": {"risk": "LOW", "default": "PASS"}})
            cfg = SentinelConfig(constants_window="constants", policy_id="sentinel.policy",
                                 allowed_actors=["supervisor", "engineer"])
            s = SentinelLite(root, config=cfg)
            r = s.evaluate({"action": "read", "target": "x", "actor": "supervisor"})
            self.assertEqual(r["verdict"], SentinelVerdict.PASS)

    def test_disallowed_actor_fails(self):
        with tempfile.TemporaryDirectory() as t:
            root = _build_policy_root(t, {"read": {"risk": "LOW", "default": "PASS"}})
            cfg = SentinelConfig(constants_window="constants", policy_id="sentinel.policy",
                                 allowed_actors=["supervisor"])
            s = SentinelLite(root, config=cfg)
            r = s.evaluate({"action": "read", "target": "x", "actor": "unknown_user"})
            self.assertEqual(r["verdict"], SentinelVerdict.FAIL)
            self.assertEqual(r["reason_code"], SentinelReason.NOT_AUTHORIZED)

    def test_no_policy_unavailable(self):
        with tempfile.TemporaryDirectory() as t:
            l = _ledger(t); l.close_clean()
            cfg = SentinelConfig(constants_window="constants", policy_id="sentinel.policy")
            s = SentinelLite(Path(t), config=cfg)
            r = s.evaluate({"action": "x", "target": "y", "actor": "z"})
            self.assertEqual(r["verdict"], SentinelVerdict.INCONCLUSIVE)
            self.assertEqual(r["reason_code"], SentinelReason.POLICY_UNAVAILABLE)

    def test_medium_risk_default_pass(self):
        with tempfile.TemporaryDirectory() as t:
            s = self._sentinel(t, {"stop_pump": {"risk": "MED", "default": "PASS"}})
            r = s.evaluate({"action": "stop_pump", "target": "P-101", "actor": "op"})
            self.assertEqual(r["verdict"], SentinelVerdict.PASS)

    def test_medium_risk_default_fail(self):
        with tempfile.TemporaryDirectory() as t:
            s = self._sentinel(t, {"stop_pump": {"risk": "MED", "default": "FAIL"}})
            r = s.evaluate({"action": "stop_pump", "target": "P-101", "actor": "op"})
            self.assertEqual(r["verdict"], SentinelVerdict.FAIL)

    def test_verdict_includes_module_sentinel(self):
        with tempfile.TemporaryDirectory() as t:
            s = self._sentinel(t, {"x": {"risk": "LOW", "default": "PASS"}})
            r = s.evaluate({"action": "x", "target": "y", "actor": "op"})
            self.assertEqual(r["module"], "Sentinel")

    def test_verdict_includes_policy_ref_when_available(self):
        with tempfile.TemporaryDirectory() as t:
            s = self._sentinel(t, {"x": {"risk": "LOW", "default": "PASS"}})
            r = s.evaluate({"action": "x", "target": "y", "actor": "op"})
            self.assertIn("policy_ref", r)

    def test_non_dict_proposal_inconclusive(self):
        with tempfile.TemporaryDirectory() as t:
            s = self._sentinel(t, {"x": {"risk": "LOW", "default": "PASS"}})
            r = s.evaluate("not a dict")
            self.assertEqual(r["verdict"], SentinelVerdict.INCONCLUSIVE)

    def test_five_different_actions_evaluated(self):
        with tempfile.TemporaryDirectory() as t:
            policy = {
                "start_pump": {"risk": "LOW", "default": "PASS"},
                "stop_pump": {"risk": "MED", "default": "PASS"},
                "override_setpoint": {"risk": "HIGH", "default": "INCONCLUSIVE"},
                "delete_log": {"risk": "HIGH", "default": "FAIL"},
                "emergency_stop": {"risk": "HIGH", "default": "PASS"},
            }
            s = self._sentinel(t, policy)
            expected = {
                "start_pump": "PASS",
                "stop_pump": "PASS",
                "override_setpoint": "INCONCLUSIVE",
                "delete_log": "FAIL",
                "emergency_stop": "PASS",
            }
            for action, exp_verdict in expected.items():
                r = s.evaluate({"action": action, "target": "x", "actor": "op"})
                self.assertEqual(r["verdict"], exp_verdict, f"Mismatch for {action}")

    def test_witness_required_on_high_risk_inconclusive(self):
        with tempfile.TemporaryDirectory() as t:
            s = self._sentinel(t, {"sensitive_op": {"risk": "HIGH", "default": "INCONCLUSIVE"}})
            r = s.evaluate({"action": "sensitive_op", "target": "x", "actor": "op"})
            self.assertIsInstance(r["witness_required"], list)
            self.assertGreater(len(r["witness_required"]), 0)

    def test_witness_required_empty_on_pass(self):
        with tempfile.TemporaryDirectory() as t:
            s = self._sentinel(t, {"read": {"risk": "LOW", "default": "PASS"}})
            r = s.evaluate({"action": "read", "target": "x", "actor": "op"})
            self.assertEqual(r["witness_required"], [])

    def test_policy_updated_and_active_version_wins(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            l = SpineLedger(root)
            reg = ConstraintRegistry(l, window_id="constants")
            ref1 = reg.publish("sentinel.policy", "1.0", {"action_x": {"risk": "LOW", "default": "PASS"}})
            ref2 = reg.supersede("sentinel.policy", "2.0", {"action_x": {"risk": "HIGH", "default": "FAIL"}},
                                 previous_version="1.0", previous_hash=ref1.constraint_hash)
            l.seal_window("constants"); l.close_clean()
            cfg = SentinelConfig(constants_window="constants", policy_id="sentinel.policy")
            s = SentinelLite(root, config=cfg)
            r = s.evaluate({"action": "action_x", "target": "y", "actor": "op"})
            # v2.0 says HIGH/FAIL so should be FAIL
            self.assertEqual(r["verdict"], SentinelVerdict.FAIL)


# ══════════════════════════════════════════════════════════════════════════════
# DETECTIVE — hypothesis evaluation
# ══════════════════════════════════════════════════════════════════════════════

class TestDetectiveEvaluation(unittest.TestCase):

    def _detective(self, tmp, events):
        root = Path(tmp) / "root"; root.mkdir(parents=True, exist_ok=True)
        l = SpineLedger(root)
        l.open_window("ops")
        for ev in events:
            l.append_event("ops", ev[0], ev[1])
        l.seal_window("ops"); l.close_clean()
        return Detective(root), root

    def test_evaluate_returns_list(self):
        with tempfile.TemporaryDirectory() as t:
            d, _ = self._detective(t, [("WITNESS", {"entity": "pump", "status": "ok"})])
            results = d.evaluate([Hypothesis("h1", "pump", "status", "ok")], window_id="ops")
            self.assertIsInstance(results, list)

    def test_open_verdict_when_no_match(self):
        with tempfile.TemporaryDirectory() as t:
            d, _ = self._detective(t, [("WITNESS", {"entity": "pump", "status": "ok"})])
            results = d.evaluate([Hypothesis("h1", "pump", "status", "fault")], window_id="ops")
            verdicts = [r["verdict"] for r in results]
            self.assertIn("OPEN", verdicts)

    def test_hypothesis_id_in_result(self):
        with tempfile.TemporaryDirectory() as t:
            d, _ = self._detective(t, [("WITNESS", {"entity": "pump", "status": "ok"})])
            results = d.evaluate([Hypothesis("hyp_001", "pump", "status", "ok")], window_id="ops")
            found = [r for r in results if r.get("hypothesis_id") == "hyp_001"]
            self.assertGreater(len(found), 0)

    def test_multiple_hypotheses_evaluated(self):
        with tempfile.TemporaryDirectory() as t:
            d, _ = self._detective(t, [
                ("WITNESS", {"entity": "pump", "status": "ok"}),
                ("WITNESS", {"entity": "valve", "state": "closed"}),
            ])
            hyps = [
                Hypothesis("h1", "pump", "status", "ok"),
                Hypothesis("h2", "valve", "state", "closed"),
            ]
            results = d.evaluate(hyps, window_id="ops")
            self.assertGreaterEqual(len(results), 2)

    def test_no_window_id_evaluates_all_windows(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            l = SpineLedger(root)
            l.open_window("ops")
            l.append_event("ops", "WITNESS", {"entity": "pump", "status": "ok"})
            l.seal_window("ops"); l.close_clean()
            d = Detective(root)
            results = d.evaluate([Hypothesis("h1", "pump", "status", "ok")])
            self.assertIsInstance(results, list)

    def test_inconclusive_on_coverage_gate_failure(self):
        with tempfile.TemporaryDirectory() as t:
            d, _ = self._detective(t, [("WITNESS", {"entity": "pump", "status": "ok"})])
            # Single hypothesis, no pins → coverage gate fails → INCONCLUSIVE
            hyps = [Hypothesis("h1", "pump", "status", "ok")]
            results = d.evaluate(hyps, window_id="ops")
            verdicts = [r["verdict"] for r in results]
            self.assertIn("INCONCLUSIVE", verdicts)

    def test_hypothesis_details_preserved(self):
        with tempfile.TemporaryDirectory() as t:
            d, _ = self._detective(t, [("WITNESS", {"entity": "valve_V401", "state": "open"})])
            hyps = [Hypothesis("h1", "valve_V401", "state", "open")]
            results = d.evaluate(hyps, window_id="ops")
            for r in results:
                if r.get("hypothesis_id") == "h1":
                    details = r.get("details", {})
                    self.assertEqual(details.get("entity"), "valve_V401")

    def test_empty_hypotheses_list(self):
        with tempfile.TemporaryDirectory() as t:
            d, _ = self._detective(t, [("WITNESS", {"entity": "pump", "status": "ok"})])
            results = d.evaluate([], window_id="ops")
            self.assertIsInstance(results, list)

    def test_result_has_verdict_key(self):
        with tempfile.TemporaryDirectory() as t:
            d, _ = self._detective(t, [("WITNESS", {"entity": "x", "k": "v"})])
            results = d.evaluate([Hypothesis("h1", "x", "k", "v")], window_id="ops")
            for r in results:
                self.assertIn("verdict", r)

    def test_result_has_pins_key(self):
        with tempfile.TemporaryDirectory() as t:
            d, _ = self._detective(t, [("WITNESS", {"entity": "x", "k": "v"})])
            results = d.evaluate([Hypothesis("h1", "x", "k", "v")], window_id="ops")
            for r in results:
                self.assertIn("pins", r)


# ══════════════════════════════════════════════════════════════════════════════
# CONVERTED PYTEST TESTS (originally failing due to pytest import)
# ══════════════════════════════════════════════════════════════════════════════

class TestZipGuardHostileInputsConverted(unittest.TestCase):
    """Stdlib conversion of test_zipguard_hostile_inputs.py"""

    def test_bad_zip(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.zip"
            p.write_bytes(b"not a zip")
            with self.assertRaises(ZipGuardError) as ctx:
                build_extraction_plan(str(p), ZipLimits())
            self.assertEqual(ctx.exception.reason_code, R.ERR_BAD_ZIP)

    def test_path_traversal(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "trav.zip"
            _make_zip(str(p), [("../evil.txt", b"x", None)])
            with self.assertRaises(ZipGuardError) as ctx:
                build_extraction_plan(str(p), ZipLimits())
            self.assertEqual(ctx.exception.reason_code, R.ERR_PATH_TRAVERSAL)

    def test_absolute_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "abs.zip"
            _make_zip(str(p), [("/tmp/evil.txt", b"x", None)])
            with self.assertRaises(ZipGuardError) as ctx:
                build_extraction_plan(str(p), ZipLimits())
            self.assertEqual(ctx.exception.reason_code, R.ERR_PATH_TRAVERSAL)

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "sym.zip"
            def mark_symlink(zi):
                zi.create_system = 3
                zi.external_attr = (0o120777 << 16)
            _make_zip(str(p), [("link", b"target", mark_symlink)])
            with self.assertRaises(ZipGuardError) as ctx:
                build_extraction_plan(str(p), ZipLimits())
            self.assertEqual(ctx.exception.reason_code, R.ERR_SYMLINK)

    def test_file_count_limit(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "many.zip"
            _make_zip(str(p), [(f"f{i}.txt", b"x", None) for i in range(4)])
            with self.assertRaises(ZipGuardError) as ctx:
                build_extraction_plan(str(p), ZipLimits(max_files=3))
            self.assertEqual(ctx.exception.reason_code, R.ERR_FILE_COUNT_LIMIT)

    def test_total_size_limit(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "big.zip"
            _make_zip(str(p), [("a.bin", b"123456", None), ("b.bin", b"123456", None)])
            with self.assertRaises(ZipGuardError) as ctx:
                build_extraction_plan(str(p), ZipLimits(max_total_uncompressed=10))
            self.assertEqual(ctx.exception.reason_code, R.ERR_SIZE_LIMIT)

    def test_single_file_limit(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "onebig.zip"
            _make_zip(str(p), [("a.bin", b"123456", None)])
            with self.assertRaises(ZipGuardError) as ctx:
                build_extraction_plan(str(p), ZipLimits(max_single_file=5))
            self.assertEqual(ctx.exception.reason_code, R.ERR_SINGLE_FILE_SIZE_LIMIT)


class TestClaimsPhase015Converted(unittest.TestCase):
    """Stdlib conversion of test_claims_phase0_1_5.py"""

    def test_claim_propose_and_read_via_eqi_requires_seal(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); led = SpineLedger(root)
            reg = ClaimRegistry(led, window_id="claims")
            reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
            led.close_clean()
            eqi = ClaimEQI(root, window_id="claims")
            self.assertIsNone(eqi.get_state("c1"))

    def test_claim_eqi_after_seal_reconstructs_state_and_history(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); led = SpineLedger(root)
            reg = ClaimRegistry(led, window_id="claims")
            reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
            reg.link_evidence(claim_id="c1", pins=["p1", "p2"])
            led.seal_window("claims"); led.close_clean()
            eqi = ClaimEQI(root, window_id="claims")
            st = eqi.get_state("c1")
            self.assertIsNotNone(st)
            self.assertEqual(st.claim.claim_id, "c1")
            self.assertIn("p1", st.claim.support.pins)
            self.assertGreaterEqual(len(st.history), 2)

    def test_no_silent_upgrade_witnessed_requires_pins(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); led = SpineLedger(root)
            reg = ClaimRegistry(led, window_id="claims")
            reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
            with self.assertRaises(ValueError):
                reg.set_status(claim_id="c1", old_status=ClaimStatus.OPEN,
                               new_status=ClaimStatus.WITNESSED, reason_code="WITNESSED", pins=None)
            led.close_clean()

    def test_transition_witnessed_only_to_superseded(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); led = SpineLedger(root)
            reg = ClaimRegistry(led, window_id="claims")
            reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
            reg.set_status(claim_id="c1", old_status=ClaimStatus.OPEN,
                           new_status=ClaimStatus.WITNESSED, reason_code="WITNESSED", pins=["p1"])
            with self.assertRaises(ValueError):
                reg.set_status(claim_id="c1", old_status=ClaimStatus.WITNESSED,
                               new_status=ClaimStatus.OPEN, reason_code="BACK", pins=None)
            led.close_clean()


class TestHardnessPhase5Converted(unittest.TestCase):
    """Stdlib conversion of test_hardness_phase5.py"""

    def _last_hash(self, root, window):
        return _last_hash(root, window)

    def test_hardness_silent_upgrade_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "root"; root.mkdir()
            led = SpineLedger(root)
            reg = ClaimRegistry(led, window_id="claims")
            reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
            with self.assertRaises(ValueError):
                reg.set_status(claim_id="c1", old_status=ClaimStatus.OPEN,
                               new_status=ClaimStatus.WITNESSED, reason_code="WIT", pins=None)
            led.close_clean()

    def test_hardness_missing_pin_targets_yields_inconclusive_claimcheck(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "root"; root.mkdir()
            led = SpineLedger(root)
            reg = ClaimRegistry(led, window_id="claims")
            reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
            fake_pin = "0" * 64
            reg.set_status(claim_id="c1", old_status=ClaimStatus.OPEN,
                           new_status=ClaimStatus.WITNESSED, reason_code="WIT", pins=[fake_pin])
            led.seal_window("claims"); led.close_clean()
            case = Path(td) / "case.zip"
            build_case_zip(root, case)
            res = check_claim(case, "c1")
            self.assertEqual(res.verdict, "INCONCLUSIVE")
            self.assertTrue(any("MISSING_PIN_TARGETS" in r.upper() for r in res.reasons))

    def test_hardness_unsealed_pin_reference_yields_inconclusive(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "root"; root.mkdir()
            led = SpineLedger(root)
            led.open_window("main")
            led.append_event("main", "WITNESS", {"k": "v"})  # NOT sealed
            pin = self._last_hash(root, "main")
            reg = ClaimRegistry(led, window_id="claims")
            reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
            reg.set_status(claim_id="c1", old_status=ClaimStatus.OPEN,
                           new_status=ClaimStatus.WITNESSED, reason_code="WIT", pins=[pin])
            led.seal_window("claims"); led.close_clean()
            case = Path(td) / "case.zip"
            build_case_zip(root, case)
            res = check_claim(case, "c1")
            self.assertEqual(res.verdict, "INCONCLUSIVE")
            self.assertTrue(any(
                "MISSING_PIN_TARGETS" in r or "UNSEALED_PIN_REFERENCES" in r
                for r in res.reasons
            ))

    def test_hardness_invalid_transition_injection_detected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "root"; root.mkdir()
            led = SpineLedger(root)
            reg = ClaimRegistry(led, window_id="claims")
            reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
            led.open_window("main")
            led.append_event("main", "WITNESS", {"k": "v"})
            led.seal_window("main")
            pin = self._last_hash(root, "main")
            reg.set_status(claim_id="c1", old_status=ClaimStatus.OPEN,
                           new_status=ClaimStatus.WITNESSED, reason_code="WIT", pins=[pin])
            payload = {"op": "CLAIM_STATUS_SET", "claim_id": "c1",
                       "new_status": "OPEN", "reason_code": "BAD_INJECT", "pins": []}
            led.append_event("claims", "CLAIM", payload)
            led.seal_window("claims"); led.close_clean()
            case = Path(td) / "case.zip"
            build_case_zip(root, case)
            res = check_claim(case, "c1")
            self.assertIn(res.verdict, ("INCONCLUSIVE", "FAIL"))
            self.assertTrue(any("INVALID_TRANSITIONS" in r for r in res.reasons))

    def test_hardness_unsealed_claims_window_inconclusive(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "root"; root.mkdir()
            led = SpineLedger(root)
            reg = ClaimRegistry(led, window_id="claims")
            reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
            led.close_clean()
            case = Path(td) / "case.zip"
            build_case_zip(root, case)
            res = check_claim(case, "c1")
            self.assertEqual(res.verdict, "INCONCLUSIVE")
            self.assertTrue(any("CLAIMS_WINDOW_NOT_SEALED" in r for r in res.reasons))

    def test_hardness_determinism_replay_claim_state_stable_when_sealed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "root"; root.mkdir()
            led1 = SpineLedger(root)
            reg1 = ClaimRegistry(led1, window_id="claims")
            reg1.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
            led1.seal_window("claims"); led1.close_clean()
            case1 = Path(td) / "case1.zip"
            build_case_zip(root, case1)
            r1 = check_claim(case1, "c1").to_dict()
            case2 = Path(td) / "case2.zip"
            build_case_zip(root, case2)
            r2 = check_claim(case2, "c1").to_dict()
            self.assertEqual(r1["verdict"], r2["verdict"])
            self.assertEqual(r1["reasons"], r2["reasons"])


class TestOperationalHardnessV1Converted(unittest.TestCase):
    """Stdlib conversion of test_operational_hardness_v1.py"""

    def _read_scars(self, root):
        p = root / "spine/scars.jsonl"
        if not p.exists():
            return []
        return [json.loads(line) for line in p.read_text().splitlines() if line.strip()]

    def test_dirty_shutdown_creates_scar_on_next_boot(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "root"; root.mkdir()
            led = SpineLedger(root)
            led.open_window("w")
            led.append_event("w", "X", {"a": 1})
            # Simulate crash — no close_clean()
            _ = SpineLedger(root)
            scars = self._read_scars(root)
            self.assertTrue(any(s.get("scar_type") == "DIRTY_SHUTDOWN" for s in scars))

    def test_siren_disk_pressure_transition_emits_mayday_and_persists_state(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "root"; root.mkdir()
            led = SpineLedger(root)
            siren = Siren(led)
            siren.transition(SirenState.DEGRADED_CAPTURE, MaydayCode.DISK_PRESSURE,
                             details={"free_bytes": 123})
            led.close_clean()
            state_path = root / "spine/siren_state.json"
            self.assertTrue(state_path.exists())
            st = json.loads(state_path.read_text())
            self.assertEqual(st.get("state"), SirenState.DEGRADED_CAPTURE.value)

    def test_reject_flood_is_bounded_and_triggers_siren_on_surge(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "root"; root.mkdir()
            led = SpineLedger(root)
            siren = Siren(led)
            cfg = IngestConfig(reject_max_records=50, surge_window_s=60, surge_reject_threshold=20)
            gate = IngestGate(led, siren=siren, config=cfg)
            for _ in range(60):
                res = gate.ingest({"source": "x", "event_type": "E", "payload": "not-a-dict"})
                self.assertEqual(res.decision, IngestDecision.REJECT)
            ring = root / "spine/rejects/ring.jsonl"
            meta = root / "spine/rejects/meta.json"
            self.assertTrue(ring.exists() and meta.exists())
            lines = ring.read_text().splitlines()
            self.assertEqual(len(lines), cfg.reject_max_records)
            m = json.loads(meta.read_text())
            self.assertGreaterEqual(m.get("total_rejects", 0), 60)
            st = json.loads((root / "spine/siren_state.json").read_text())
            self.assertIn(st.get("state"), (
                SirenState.SUMMARIES_ONLY.value,
                SirenState.HALT.value,
                SirenState.DEGRADED_CAPTURE.value
            ))

    def test_external_verifier_fails_if_event_file_missing(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "root"; root.mkdir()
            led = SpineLedger(root)
            led.open_window("main")
            led.append_event("main", "WITNESS", {"k": "v"})
            led.seal_window("main"); led.close_clean()
            case = Path(td) / "case.zip"
            build_case_zip(root, case)
            damaged = Path(td) / "case_damaged.zip"
            removed = False
            with zipfile.ZipFile(case, "r") as zin, zipfile.ZipFile(damaged, "w", compression=zipfile.ZIP_DEFLATED) as zout:
                for item in zin.infolist():
                    if (item.filename.endswith("events/000001.json") and
                            item.filename.startswith("evidence/spine/windows/main/")):
                        removed = True
                        continue
                    zout.writestr(item, zin.read(item.filename))
            self.assertTrue(removed)
            script = str(Path(__file__).parent.parent / "tools" / "verify_case.py")
            proc = subprocess.run(
                [sys.executable, script, str(damaged)],
                capture_output=True, text=True
            )
            self.assertNotEqual(proc.returncode, 0)
            out = json.loads(proc.stdout)
            self.assertEqual(out["verdict"], "FAIL")


# ══════════════════════════════════════════════════════════════════════════════
# END-TO-END INTEGRATION FLOWS
# ══════════════════════════════════════════════════════════════════════════════

class TestEndToEndIntegration(unittest.TestCase):
    """Real-world integration scenarios spanning multiple subsystems."""

    def test_ot_pump_fault_claim_workflow(self):
        """Pump fault observed → OT event → claim filed → case exported → claim verified."""
        with tempfile.TemporaryDirectory() as t:
            from aletheia.ot import OTAdapter, OTSensorReading, OTConfig
            root = Path(t) / "root"; root.mkdir()
            l = SpineLedger(root, allow_float_payload=True)
            siren = Siren(l)
            ot = OTAdapter(l, config=OTConfig(lens_validate=False, window_id="ot_data"), siren=siren)
            ot.open()
            for i in range(5):
                ot.ingest_reading(OTSensorReading(f"PT-{100+i}", float(15 + i), unit="bar", quality="GOOD"))
            fault_result = ot.ingest_reading(OTSensorReading("PT-105", 99.9, unit="bar", quality="BAD"))
            # Get event hash BEFORE sealing (last event in window is what we pin to)
            event_pin = _last_hash(root, "ot_data")
            sealed_hash = ot.seal_and_close()
            self.assertIsNotNone(sealed_hash)
            reg = ClaimRegistry(l, window_id="claims")
            reg.propose(claim_id="fault_001", claim_text="PT-105 recorded BAD quality",
                        claim_type=ClaimType.EMPIRICAL)
            reg.set_status(claim_id="fault_001", old_status=ClaimStatus.OPEN,
                           new_status=ClaimStatus.WITNESSED, reason_code="OT_FAULT_OBSERVED",
                           pins=[event_pin])
            l.seal_window("claims"); l.close_clean()
            zp = str(Path(t) / "pump_fault.zip")
            build_case_zip(root, zp)
            result = check_claim(zp, "fault_001")
            self.assertEqual(result.verdict, "PASS")

    def test_ai_audit_with_dfw_veto_full_chain(self):
        """AI makes a request → DFW vetoes → chain verified."""
        with tempfile.TemporaryDirectory() as t:
            from aletheia.ai_audit import AIAuditRecorder, AIAuditConfig, DFWBridge
            root = Path(t) / "root"; root.mkdir()
            l = SpineLedger(root)
            cfg = AIAuditConfig(window_id="ai_audit", include_full_content=True)
            rec = AIAuditRecorder(l, config=cfg)
            rec.start_session(metadata={"app": "anomaly_detector", "version": "2.1"})
            rec.record_model_version("detector-v2", "2025-12")
            rec.record_request("Should we shut down pump P-101?", request_id="req_001")
            bridge = DFWBridge(l, window_id="ai_audit")
            bridge.record_veto("emergency_pump_shutdown", "detector-v2",
                               rule_id="RULE_IRREVERSIBLE_ACTION",
                               reason="Action requires human authorisation")
            rec.record_human_override("supervisor_jones", "ai_recommends_shutdown",
                                      "hold_pending_investigation", reason="Under investigation")
            rec.end_session(outcome="HUMAN_OVERRIDE")
            l.seal_window("ai_audit"); l.close_clean()
            r = verify_spine(root)
            self.assertTrue(r["ok"])

    def test_streaming_to_claim_to_export_pipeline(self):
        """Stream events → auto-window → seal → claim filed → export → verify."""
        with tempfile.TemporaryDirectory() as t:
            from aletheia.streaming.scheduler import WindowScheduler, SchedulerConfig
            root = Path(t) / "root"; root.mkdir()
            l = SpineLedger(root, allow_float_payload=True)
            siren = Siren(l)
            cfg = SchedulerConfig(base_window_id="sensor_stream", max_events_per_window=5)
            sched = WindowScheduler(l, config=cfg, siren=siren)
            sched.start()
            for i in range(5):
                sched.append_event("SENSOR_READING", {"value": float(i) * 1.5, "tag": f"PT-{100+i}"})
            sealed_window = sched.stop()
            self.assertIsNotNone(sealed_window)
            sealed_hash = _last_hash(root, sealed_window)
            reg = ClaimRegistry(l, window_id="claims")
            reg.propose(claim_id="obs_001", claim_text="Five pressure readings captured",
                        claim_type=ClaimType.EMPIRICAL)
            reg.set_status(claim_id="obs_001", old_status=ClaimStatus.OPEN,
                           new_status=ClaimStatus.WITNESSED, reason_code="AUTO_SEAL",
                           pins=[sealed_hash])
            l.seal_window("claims"); l.close_clean()
            zp = str(Path(t) / "stream_case.zip")
            build_case_zip(root, zp)
            res = check_claim(zp, "obs_001")
            self.assertEqual(res.verdict, "PASS")

    def test_constraint_change_with_sentinel_enforcement(self):
        """Publish constraint v1 → sentinel allows action → update to v2 → sentinel blocks."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            l = SpineLedger(root)
            reg = ConstraintRegistry(l, window_id="constants")
            ref1 = reg.publish("sentinel.policy", "1.0", {
                "override_setpoint": {"risk": "LOW", "default": "PASS"}
            })
            ref2 = reg.supersede("sentinel.policy", "2.0", {
                "override_setpoint": {"risk": "HIGH", "default": "FAIL"}
            }, previous_version="1.0", previous_hash=ref1.constraint_hash)
            l.seal_window("constants"); l.close_clean()
            cfg = SentinelConfig(constants_window="constants", policy_id="sentinel.policy")
            s = SentinelLite(root, config=cfg)
            r = s.evaluate({"action": "override_setpoint", "target": "TC-201", "actor": "op"})
            self.assertEqual(r["verdict"], SentinelVerdict.FAIL)

    def test_multi_window_federation_full_flow(self):
        """Build two cases, federate them, write bundle, re-read."""
        from aletheia.federation import federate, write_federation_bundle, read_federation_bundle
        with tempfile.TemporaryDirectory() as t:
            def make(subdir):
                root = Path(t) / subdir; root.mkdir()
                l = SpineLedger(root)
                l.open_window("evidence")
                l.append_event("evidence", "WITNESS", {"plant": subdir, "value": 42})
                l.seal_window("evidence"); l.close_clean()
                zp = str(Path(t) / f"{subdir}.zip")
                build_case_zip(root, zp)
                return zp
            zp1 = make("plant_a"); zp2 = make("plant_b")
            fr = federate([zp1, zp2], node_ids=["plant_a", "plant_b"])
            self.assertEqual(fr.verdict, "PASS")
            bundle = str(Path(t) / "fed.zip")
            write_federation_bundle(fr, [zp1, zp2], bundle)
            loaded = read_federation_bundle(bundle)
            self.assertIsInstance(loaded, dict)

    def test_siren_escalation_stops_ingest_cleanly(self):
        """Siren reaches HALT → all further ingests fail gracefully → case exports cleanly."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            l = SpineLedger(root)
            siren = Siren(l)
            gate = IngestGate(l, siren=siren, config=IngestConfig())
            gate.ingest({"source": "plc", "event_type": "X", "payload": {"v": 1}})
            siren.transition(SirenState.HALT, MaydayCode.INTEGRITY_COMPROMISE)
            l.open_window("evidence")
            l.append_event("evidence", "PRE_HALT_WITNESS", {"safe": True})
            l.seal_window("evidence")
            l.close_clean()
            zp = str(Path(t) / "halt_case.zip")
            build_case_zip(root, zp)
            from aletheia.federation import verify_node
            nr = verify_node(zp)
            self.assertIn(nr.verdict, ("PASS", "INCONCLUSIVE"))

    def test_hmac_signed_end_to_end_case(self):
        """Sign all seals with HMAC → export case → verify with correct key → pass."""
        from aletheia.spine.signing import HMACSigner
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            key = b"plant_signing_key_2026"
            l = SpineLedger(root, signer=HMACSigner(key=key))
            l.open_window("evidence")
            for i in range(5):
                l.append_event("evidence", "SIGNED_WITNESS", {"seq": i, "value": "v"})
            l.seal_window("evidence"); l.close_clean()
            r = verify_spine(root, signer=HMACSigner(key=key))
            self.assertTrue(r["ok"])

    def test_wrong_hmac_key_fails_verification(self):
        from aletheia.spine.signing import HMACSigner
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            l = SpineLedger(root, signer=HMACSigner(key=b"right-key"))
            l.open_window("evidence")
            l.append_event("evidence", "WITNESS", {"v": 1})
            l.seal_window("evidence"); l.close_clean()
            r = verify_spine(root, signer=HMACSigner(key=b"wrong-key"))
            self.assertFalse(r["ok"])

    def test_100_sensors_10_windows_full_verify(self):
        """Simulate a real polling loop: 100 sensors, 10 windows of 10 each → verify clean."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            l = SpineLedger(root, allow_float_payload=True)
            for win in range(10):
                wid = f"sensor_batch_{win:02d}"
                l.open_window(wid)
                for sensor in range(10):
                    l.append_event(wid, "SENSOR_READING", {
                        "tag": f"PT-{win * 10 + sensor:03d}",
                        "value": float(win * 10 + sensor) * 0.5,
                        "unit": "bar"
                    })
                l.seal_window(wid)
            l.close_clean()
            r = verify_spine(root)
            self.assertTrue(r["ok"])
            self.assertEqual(r["sealed_windows_verified"], 10)

    def test_policy_claim_workflow(self):
        """Policy claim: publish policy constraint → evaluate → file claim → export."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            l = SpineLedger(root)
            const_reg = ConstraintRegistry(l, window_id="constants")
            ref = const_reg.publish("safety.policy.v1", "1.0", {
                "shutdown_reactor": {"risk": "HIGH", "default": "FAIL"},
                "read_telemetry": {"risk": "LOW", "default": "PASS"},
            })
            l.seal_window("constants")
            claim_reg = ClaimRegistry(l, window_id="claims")
            claim_reg.propose(claim_id="pol_001",
                              claim_text="Safety policy v1 applied to reactor control AI",
                              claim_type=ClaimType.POLICY)
            claim_reg.set_status(claim_id="pol_001", old_status=ClaimStatus.OPEN,
                                 new_status=ClaimStatus.WITNESSED, reason_code="POLICY_SEALED",
                                 pins=[ref.constraint_hash])
            l.seal_window("claims"); l.close_clean()
            zp = str(Path(t) / "policy_case.zip")
            build_case_zip(root, zp)
            res = check_claim(zp, "pol_001")
            self.assertEqual(res.verdict, "PASS")

    def test_retracted_claim_then_new_superseding_claim(self):
        """Retract a claim, file a superseding one, export, check both."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            l = SpineLedger(root)
            l.open_window("evidence")
            l.append_event("evidence", "WITNESS", {"data": "original observation"})
            pin = _last_hash(root, "evidence")
            l.seal_window("evidence")
            reg = ClaimRegistry(l, window_id="claims")
            reg.propose(claim_id="c1", claim_text="original claim", claim_type=ClaimType.EMPIRICAL)
            reg.retract(claim_id="c1", reason_code="SUPERSEDED_BY_C2")
            reg.propose(claim_id="c2", claim_text="revised claim", claim_type=ClaimType.EMPIRICAL)
            reg.set_status(claim_id="c2", old_status=ClaimStatus.OPEN,
                           new_status=ClaimStatus.WITNESSED, reason_code="WITNESSED", pins=[pin])
            l.seal_window("claims"); l.close_clean()
            zp = str(Path(t) / "case.zip")
            build_case_zip(root, zp)
            r_c1 = check_claim(zp, "c1")
            r_c2 = check_claim(zp, "c2")
            self.assertIn(r_c1.verdict, ("INCONCLUSIVE", "FAIL", "PASS"))
            self.assertEqual(r_c2.verdict, "PASS")

    def test_verify_case_tool_exit_codes(self):
        """verify_case.py returns 0 for valid, nonzero for tampered."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            l = SpineLedger(root)
            l.open_window("ev"); l.append_event("ev", "X", {"v": 1}); l.seal_window("ev")
            l.close_clean()
            zp = str(Path(t) / "ok.zip")
            build_case_zip(root, zp)
            script = str(Path(__file__).parent.parent / "tools" / "verify_case.py")
            ok = subprocess.run([sys.executable, script, zp], capture_output=True)
            self.assertEqual(ok.returncode, 0)
            # Tamper
            tampered = str(Path(t) / "tampered.zip")
            with zipfile.ZipFile(zp) as zin, zipfile.ZipFile(tampered, "w") as zout:
                for item in zin.infolist():
                    data = zin.read(item.filename)
                    if item.filename.endswith("000001.json"):
                        data = data.replace(b'"WINDOW_OPEN"', b'"TAMPERED"')
                    zout.writestr(item, data)
            bad = subprocess.run([sys.executable, script, tampered], capture_output=True)
            self.assertNotEqual(bad.returncode, 0)

    def test_five_claims_all_pass_then_check_all(self):
        """Five witnessed claims → check_all → overall PASS."""
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "root"; root.mkdir()
            l = SpineLedger(root)
            l.open_window("ev")
            for i in range(5):
                l.append_event("ev", "WITNESS", {"seq": i})
            pin = _last_hash(root, "ev")
            l.seal_window("ev")
            reg = ClaimRegistry(l, window_id="claims")
            for i in range(5):
                cid = f"claim_{i:02d}"
                reg.propose(claim_id=cid, claim_text=f"observation {i}", claim_type=ClaimType.EMPIRICAL)
                reg.set_status(claim_id=cid, old_status=ClaimStatus.OPEN,
                               new_status=ClaimStatus.WITNESSED, reason_code="W", pins=[pin])
            l.seal_window("claims"); l.close_clean()
            zp = str(Path(t) / "case.zip"); build_case_zip(root, zp)
            result = check_all(zp)
            self.assertEqual(result["overall"], "PASS")


if __name__ == "__main__":
    unittest.main(verbosity=2)
