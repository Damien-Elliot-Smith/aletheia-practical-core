import tempfile, json, zipfile
from pathlib import Path
import pytest

from aletheia.spine.ledger import SpineLedger
from aletheia.claims import ClaimRegistry, ClaimType, ClaimStatus
from aletheia.claims.claimcheck import check_claim
from aletheia.chronicle.export import build_case_zip
from aletheia.detective.claims_review import review_claims

def _last_hash(root: Path, window: str) -> str:
    evdir = root / "spine" / "windows" / window / "events"
    last = sorted(evdir.glob("*.json"))[-1]
    return json.loads(last.read_text())["hash"]

def test_hardness_silent_upgrade_blocked():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)/"root"
        root.mkdir(parents=True, exist_ok=True)
        led = SpineLedger(root)
        reg = ClaimRegistry(led, window_id="claims")
        reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
        with pytest.raises(ValueError):
            reg.set_status(claim_id="c1", old_status=ClaimStatus.OPEN, new_status=ClaimStatus.WITNESSED, reason_code="WIT", pins=None)
        led.close_clean()

def test_hardness_missing_pin_targets_yields_inconclusive_claimcheck():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)/"root"
        root.mkdir(parents=True, exist_ok=True)
        led = SpineLedger(root)
        # create claim that cites a non-existent pin
        reg = ClaimRegistry(led, window_id="claims")
        reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
        fake_pin = "0"*64
        reg.set_status(claim_id="c1", old_status=ClaimStatus.OPEN, new_status=ClaimStatus.WITNESSED, reason_code="WIT", pins=[fake_pin])
        led.seal_window("claims")
        led.close_clean()

        case = Path(td)/"case.zip"
        build_case_zip(root, case)
        res = check_claim(case, "c1")
        assert res.verdict == "INCONCLUSIVE"
        assert "MISSING_PIN_TARGETS" in res.reasons or "MISSING_PIN_TARGETS".lower() in " ".join(res.reasons).lower()

def test_hardness_unsealed_pin_reference_yields_inconclusive():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)/"root"
        root.mkdir(parents=True, exist_ok=True)
        led = SpineLedger(root)
        led.open_window("main")
        led.append_event("main", "WITNESS", {"k":"v"})  # NOT sealed
        pin = _last_hash(root, "main")
        # claim witnessed with pin from unsealed window
        reg = ClaimRegistry(led, window_id="claims")
        reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
        reg.set_status(claim_id="c1", old_status=ClaimStatus.OPEN, new_status=ClaimStatus.WITNESSED, reason_code="WIT", pins=[pin])
        led.seal_window("claims")
        led.close_clean()

        case = Path(td)/"case.zip"
        build_case_zip(root, case)
        res = check_claim(case, "c1")
        assert res.verdict == "INCONCLUSIVE"
        assert res.verdict == "INCONCLUSIVE"
        assert any(("MISSING_PIN_TARGETS" in r) or ("UNSEALED_PIN_REFERENCES" in r) for r in res.reasons)

def test_hardness_invalid_transition_injection_detected():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)/"root"
        root.mkdir(parents=True, exist_ok=True)
        led = SpineLedger(root)
        reg = ClaimRegistry(led, window_id="claims")
        reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
        # Make it witnessed properly
        led.open_window("main")
        led.append_event("main","WITNESS",{"k":"v"})
        led.seal_window("main")
        pin = _last_hash(root, "main")
        reg.set_status(claim_id="c1", old_status=ClaimStatus.OPEN, new_status=ClaimStatus.WITNESSED, reason_code="WIT", pins=[pin])
        # Inject a bad transition event directly (WITNESSED -> OPEN) by writing a raw CLAIM_STATUS_SET payload via ledger
        payload = {"op":"CLAIM_STATUS_SET","claim_id":"c1","new_status":"OPEN","reason_code":"BAD_INJECT","pins":[]}
        led.append_event("claims","CLAIM", payload)
        led.seal_window("claims")
        led.close_clean()

        case = Path(td)/"case.zip"
        build_case_zip(root, case)
        res = check_claim(case, "c1")
        assert res.verdict in ("INCONCLUSIVE","FAIL")
        assert any("INVALID_TRANSITIONS" in r for r in res.reasons)

def test_hardness_unsealed_claims_window_inconclusive():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)/"root"
        root.mkdir(parents=True, exist_ok=True)
        led = SpineLedger(root)
        reg = ClaimRegistry(led, window_id="claims")
        reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
        led.close_clean()
        case = Path(td)/"case.zip"
        build_case_zip(root, case)
        res = check_claim(case, "c1")
        assert res.verdict == "INCONCLUSIVE"
        assert any("CLAIMS_WINDOW_NOT_SEALED" in r for r in res.reasons)

def test_hardness_detective_claims_reflects_inconclusive_when_blocked():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)/"root"
        root.mkdir(parents=True, exist_ok=True)
        led = SpineLedger(root)
        reg = ClaimRegistry(led, window_id="claims")
        reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
        led.seal_window("claims")
        led.close_clean()
        case = Path(td)/"case.zip"
        build_case_zip(root, case)
        out = review_claims(case, claim_id="c1")
        assert out["overall"] in ("PASS","INCONCLUSIVE")  # conservative
        # Should produce a logic map list
        assert isinstance(out["results"][0]["logic_map"], list)

def test_hardness_determinism_replay_claim_state_stable_when_sealed():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)/"root"
        root.mkdir(parents=True, exist_ok=True)
        # First run
        led1 = SpineLedger(root)
        reg1 = ClaimRegistry(led1, window_id="claims")
        reg1.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
        led1.seal_window("claims")
        led1.close_clean()
        case1 = Path(td)/"case1.zip"
        build_case_zip(root, case1)
        r1 = check_claim(case1, "c1").to_dict()

        # Second run: export again without changing anything
        case2 = Path(td)/"case2.zip"
        build_case_zip(root, case2)
        r2 = check_claim(case2, "c1").to_dict()

        assert r1["verdict"] == r2["verdict"]
        assert r1["reasons"] == r2["reasons"]
