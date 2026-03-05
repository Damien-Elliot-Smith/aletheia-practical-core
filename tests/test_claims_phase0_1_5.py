import tempfile
from pathlib import Path
import pytest
from aletheia.spine.ledger import SpineLedger
from aletheia.claims import ClaimRegistry, ClaimEQI, ClaimType, ClaimStatus

def test_claim_propose_and_read_via_eqi_requires_seal():
    with tempfile.TemporaryDirectory() as td:
        root=Path(td); led=SpineLedger(root)
        reg=ClaimRegistry(led, window_id="claims")
        reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
        # not sealed => eqi unavailable
        led.close_clean()
        eqi=ClaimEQI(root, window_id="claims")
        assert eqi.get_state("c1") is None

def test_claim_eqi_after_seal_reconstructs_state_and_history():
    with tempfile.TemporaryDirectory() as td:
        root=Path(td); led=SpineLedger(root)
        reg=ClaimRegistry(led, window_id="claims")
        reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
        reg.link_evidence(claim_id="c1", pins=["p1","p2"])
        led.seal_window("claims")
        led.close_clean()
        eqi=ClaimEQI(root, window_id="claims")
        st=eqi.get_state("c1")
        assert st is not None
        assert st.claim.claim_id=="c1"
        assert "p1" in st.claim.support.pins
        assert len(st.history) >= 2

def test_no_silent_upgrade_witnessed_requires_pins():
    with tempfile.TemporaryDirectory() as td:
        root=Path(td); led=SpineLedger(root)
        reg=ClaimRegistry(led, window_id="claims")
        reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
        # cannot set witnessed without pins
        with pytest.raises(ValueError):
            reg.set_status(claim_id="c1", old_status=ClaimStatus.OPEN, new_status=ClaimStatus.WITNESSED, reason_code="WITNESSED", pins=None)
        led.close_clean()

def test_transition_witnessed_only_to_superseded():
    with tempfile.TemporaryDirectory() as td:
        root=Path(td); led=SpineLedger(root)
        reg=ClaimRegistry(led, window_id="claims")
        reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
        reg.set_status(claim_id="c1", old_status=ClaimStatus.OPEN, new_status=ClaimStatus.WITNESSED, reason_code="WITNESSED", pins=["p1"])
        with pytest.raises(ValueError):
            reg.set_status(claim_id="c1", old_status=ClaimStatus.WITNESSED, new_status=ClaimStatus.OPEN, reason_code="BACK", pins=None)
        led.close_clean()
