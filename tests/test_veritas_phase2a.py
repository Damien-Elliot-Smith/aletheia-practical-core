import tempfile
from pathlib import Path
from aletheia.spine.ledger import SpineLedger
from aletheia.veritas.session import VeritasSession
from aletheia.claims import ClaimEQI

def test_veritas_session_writes_session_events_and_claim_flow():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        SpineLedger(root).close_clean()  # init root structure if needed
        vs = VeritasSession(root)
        sid = vs.start()
        assert sid
        vs.claim_propose("c1","EMPIRICAL","temp stable")
        vs.claim_link("c1",["p1"])
        vs.seal_claims()
        st = ClaimEQI(root).get_state("c1")
        assert st is not None
        vs.end(seal_sessions=True)
