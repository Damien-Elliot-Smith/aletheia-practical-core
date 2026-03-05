import tempfile
from pathlib import Path
import json
import time

from aletheia.spine.ledger import SpineLedger
from aletheia.siren.state_machine import Siren, SirenState, MaydayCode, SirenConfig


def _load_last_event(root: Path, window_id: str):
    events_dir = root / "spine" / "windows" / window_id / "events"
    files = sorted(events_dir.glob("*.json"))
    assert files, "no events found"
    return json.loads(files[-1].read_text(encoding="utf-8"))


def test_siren_transition_emits_mayday_and_persists():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        led = SpineLedger(root)
        siren = Siren(led, SirenConfig(window_id="siren", heartbeat_interval_s=1000))

        siren.transition(SirenState.DEGRADED_CAPTURE, MaydayCode.DISK_PRESSURE, {"free_bytes": 123})
        last = _load_last_event(root, "siren")
        assert last["event_type"] == "MAYDAY"
        assert last["payload"]["to_state"] == "DEGRADED_CAPTURE"
        assert last["payload"]["reason_code"] == "DISK_PRESSURE"

        state_obj = json.loads((root / "spine" / "siren_state.json").read_text(encoding="utf-8"))
        assert state_obj["state"] == "DEGRADED_CAPTURE"

        led.close_clean()


def test_siren_heartbeat_emits_while_degraded():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        led = SpineLedger(root)
        siren = Siren(led, SirenConfig(window_id="siren", heartbeat_interval_s=1))

        siren.transition(SirenState.SUMMARIES_ONLY, MaydayCode.VERIFY_FAIL)
        # Force tick after >1s using monotonic_ns arithmetic
        now = time.monotonic_ns()
        siren.tick(now_ns=now + 2_000_000_000)

        last = _load_last_event(root, "siren")
        assert last["event_type"] == "MAYDAY_HEARTBEAT"
        assert last["payload"]["state"] == "SUMMARIES_ONLY"

        led.close_clean()


def test_siren_recover_to_normal_stops_heartbeat():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        led = SpineLedger(root)
        siren = Siren(led, SirenConfig(window_id="siren", heartbeat_interval_s=1))

        siren.transition(SirenState.SUMMARIES_ONLY, MaydayCode.MANUAL)
        siren.recover_to_normal()
        last = _load_last_event(root, "siren")
        assert last["event_type"] == "MAYDAY"
        assert last["payload"]["to_state"] == "NORMAL"
        assert siren.state == SirenState.NORMAL

        # tick should not emit heartbeat when NORMAL
        before_count = len(list((root / "spine" / "windows" / "siren" / "events").glob("*.json")))
        siren.tick(now_ns=time.monotonic_ns() + 2_000_000_000)
        after_count = len(list((root / "spine" / "windows" / "siren" / "events").glob("*.json")))
        assert before_count == after_count

        led.close_clean()
