import tempfile
from pathlib import Path
import json

from aletheia.spine.ledger import SpineLedger
from aletheia.detective import Detective, DetectiveConfig
from aletheia.detective.sieve import Hypothesis


def test_detective_witnessed_and_refuted_and_open():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        led = SpineLedger(root)
        led.open_window("w1")
        # witness: entity A key k value 1
        led.append_event("w1", "WITNESS", {"entity": "A", "key": "k", "value": 1})
        # contradicting witness: entity B key k value 9 (for other hypothesis)
        led.append_event("w1", "WITNESS", {"entity": "B", "key": "k", "value": 9})
        led.seal_window("w1")
        led.close_clean()

        det = Detective(str(root))
        hyps = [
            Hypothesis("h1", "A", "k", 1),   # witnessed
            Hypothesis("h2", "B", "k", 1),   # refuted (contradiction exists)
            Hypothesis("h3", "C", "k", 1),   # open (no witness)
        ]
        lines = det.evaluate(hyps)
        # find verdicts by hypothesis_id
        verdicts = {ln.get("hypothesis_id"): ln.get("verdict") for ln in lines if "hypothesis_id" in ln}
        assert verdicts["h1"] == "WITNESSED"
        assert verdicts["h2"] == "REFUTED"
        assert verdicts["h3"] == "OPEN"


def test_detective_conflict_inconclusive():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        led = SpineLedger(root)
        led.open_window("w1")
        led.append_event("w1", "WITNESS", {"entity": "A", "key": "k", "value": 1})
        led.append_event("w1", "WITNESS", {"entity": "A", "key": "k", "value": 2})
        led.seal_window("w1")
        led.close_clean()

        det = Detective(str(root))
        hyps = [Hypothesis("h1", "A", "k", 1)]
        lines = det.evaluate(hyps)
        # Should include an INCONCLUSIVE conflict line for h1
        assert any(ln["line_type"] == "INCONCLUSIVE" and ln.get("hypothesis_id") == "h1" for ln in lines)


def test_detective_verification_failure_blocks_reasoning():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        led = SpineLedger(root)
        led.open_window("w1")
        led.append_event("w1", "WITNESS", {"entity": "A", "key": "k", "value": 1})
        led.seal_window("w1")
        led.close_clean()

        # Tamper with an event file to break hash
        ev_path = root / "spine" / "windows" / "w1" / "events" / "000001.json"
        obj = json.loads(ev_path.read_text(encoding="utf-8"))
        obj["payload"]["value"] = 999  # tamper
        ev_path.write_text(json.dumps(obj), encoding="utf-8")

        det = Detective(str(root))
        lines = det.evaluate([Hypothesis("h1", "A", "k", 1)])
        assert lines[0]["line_type"] == "INCONCLUSIVE"
        assert "verification failed" in lines[0]["text"].lower()
