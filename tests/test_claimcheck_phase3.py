import tempfile, zipfile, json
from pathlib import Path
from aletheia.spine.ledger import SpineLedger
from aletheia.claims import ClaimRegistry, ClaimType, ClaimStatus, ClaimEQI
from aletheia.chronicle.export import build_case_zip
from aletheia.claims.claimcheck import check_claim

def test_claimcheck_pass_when_pins_exist_and_sealed():
    with tempfile.TemporaryDirectory() as td:
        root=Path(td)/"root"
        root.mkdir(parents=True, exist_ok=True)
        led=SpineLedger(root)
        led.open_window("main")
        # create a witness event to pin
        led.append_event("main","WITNESS",{"k":"v"})
        led.seal_window("main")
        # find witness pin
        ev_path = root/"spine/windows/main/events"
        last = sorted(ev_path.glob("*.json"))[-1]
        pin = json.loads(last.read_text())["hash"]
        # claims
        reg=ClaimRegistry(led, window_id="claims")
        reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
        reg.set_status(claim_id="c1", old_status=ClaimStatus.OPEN, new_status=ClaimStatus.WITNESSED, reason_code="WIT", pins=[pin])
        led.seal_window("claims")
        led.close_clean()
        case = Path(td)/"case.zip"
        build_case_zip(root, case)
        res = check_claim(case, "c1")
        assert res.verdict == "PASS"

def test_claimcheck_inconclusive_when_claims_not_sealed():
    with tempfile.TemporaryDirectory() as td:
        root=Path(td)/"root"
        root.mkdir(parents=True, exist_ok=True)
        led=SpineLedger(root)
        led.open_window("main")
        led.append_event("main","WITNESS",{"k":"v"})
        led.seal_window("main")
        reg=ClaimRegistry(led, window_id="claims")
        reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
        led.close_clean()
        case = Path(td)/"case.zip"
        build_case_zip(root, case)
        res = check_claim(case, "c1")
        assert res.verdict in ("INCONCLUSIVE","FAIL")
