import tempfile
from pathlib import Path
import json

from aletheia.spine.ledger import SpineLedger
from aletheia.spine.verify import verify_spine


def test_spine_write_seal_verify_ok():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        led = SpineLedger(root)
        led.open_window("w1")
        led.append_event("w1", "SENSOR", {"sensor": "temp", "value": 42})
        seal = led.seal_window("w1")
        led.close_clean()

        rep = verify_spine(root)
        assert rep["ok"] is True
        assert rep["sealed_windows_verified"] == 1
        assert rep["sealed_windows_failed"] == 0
        assert "w1" not in rep["open_windows"]
        assert seal["window_id"] if isinstance(seal, dict) else True  # not used; ensure seal exists


def test_dirty_shutdown_creates_scar():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        # First run - do not close_clean
        led1 = SpineLedger(root)
        led1.open_window("w1")
        led1.append_event("w1", "SENSOR", {"sensor": "p", "value": 1})
        led1.seal_window("w1")
        # crash simulated by not calling close_clean()

        # Second boot should record SCAR in scars.jsonl
        led2 = SpineLedger(root)
        scars = (root / "spine" / "scars.jsonl").read_text(encoding="utf-8").strip().splitlines()
        assert len(scars) >= 1
        obj = json.loads(scars[-1])
        assert obj["scar_type"] == "DIRTY_SHUTDOWN"
        led2.close_clean()


def test_open_window_reported_untrusted():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        led = SpineLedger(root)
        led.open_window("w_open")
        led.append_event("w_open", "SENSOR", {"sensor": "x", "value": 2})
        # not sealed
        rep = verify_spine(root)
        assert "w_open" in rep["open_windows"]
        assert rep["sealed_windows_verified"] == 0
        led.close_clean()
