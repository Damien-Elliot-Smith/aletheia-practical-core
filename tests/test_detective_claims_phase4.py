import tempfile, json
from pathlib import Path
from aletheia.spine.ledger import SpineLedger
from aletheia.claims import ClaimRegistry, ClaimType, ClaimStatus
from aletheia.chronicle.export import build_case_zip
from aletheia.detective.claims_review import review_claims

def test_detective_claims_review_produces_valid_logic_map():
    with tempfile.TemporaryDirectory() as td:
        root=Path(td)/"root"
        root.mkdir(parents=True, exist_ok=True)
        led=SpineLedger(root)
        led.open_window("main")
        led.append_event("main","WITNESS",{"k":"v"})
        led.seal_window("main")
        ev_path = root/"spine/windows/main/events"
        last = sorted(ev_path.glob("*.json"))[-1]
        pin = json.loads(last.read_text())["hash"]

        reg=ClaimRegistry(led, window_id="claims")
        reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
        reg.set_status(claim_id="c1", old_status=ClaimStatus.OPEN, new_status=ClaimStatus.WITNESSED, reason_code="WIT", pins=[pin])
        led.seal_window("claims")
        led.close_clean()

        case=Path(td)/"case.zip"
        build_case_zip(root, case)
        out = review_claims(case, claim_id="c1")
        assert out["overall"] == "PASS"
        assert out["results"][0]["claim_id"] == "c1"
        lm = out["results"][0]["logic_map"]
        assert isinstance(lm, list) and len(lm) >= 1
