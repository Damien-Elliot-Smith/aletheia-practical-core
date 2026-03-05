import tempfile
from pathlib import Path
import json
import time

from aletheia.spine.ledger import SpineLedger
from aletheia.siren.state_machine import Siren, SirenConfig
from aletheia.ingest.gate import IngestGate, IngestConfig, IngestDecision, RejectReason


def _count_events(root: Path, window_id: str) -> int:
    events_dir = root / "spine" / "windows" / window_id / "events"
    return len(list(events_dir.glob("*.json"))) if events_dir.exists() else 0


def test_ingest_accept_writes_spine_event():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        led = SpineLedger(root)
        gate = IngestGate(led, config=IngestConfig(window_id="ingest", max_accepts_per_sec=1000))

        before = _count_events(root, "ingest")
        res = gate.ingest({"source": "syslog", "event_type": "SENSOR", "payload": {"k": "v"}})
        after = _count_events(root, "ingest")

        assert res.decision == IngestDecision.ACCEPT
        assert after == before + 1

        led.close_clean()


def test_ingest_reject_invalid_payload():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        led = SpineLedger(root)
        gate = IngestGate(led)

        res = gate.ingest({"source": "syslog", "event_type": "SENSOR", "payload": "not-a-dict"})
        assert res.decision == IngestDecision.REJECT
        assert res.reason == RejectReason.PAYLOAD_NOT_DICT

        # reject ring exists and is bounded
        ring = (root / "spine" / "rejects" / "ring.jsonl").read_text(encoding="utf-8").splitlines()
        assert len(ring) == gate.config.reject_max_records

        led.close_clean()


def test_ingest_rate_limit_rejects():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        led = SpineLedger(root)
        gate = IngestGate(led, config=IngestConfig(max_accepts_per_sec=1.0))  # low
        # First accept likely allowed
        r1 = gate.ingest({"source": "a", "event_type": "E", "payload": {}})
        # Immediate second should be rate limited
        r2 = gate.ingest({"source": "a", "event_type": "E", "payload": {}})
        assert r2.decision == IngestDecision.REJECT
        assert r2.reason == RejectReason.RATE_LIMIT
        led.close_clean()


def test_reject_surge_triggers_siren_optional():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        led = SpineLedger(root)
        siren = Siren(led, SirenConfig(window_id="siren", heartbeat_interval_s=999))
        gate = IngestGate(led, siren=siren, config=IngestConfig(surge_window_s=10, surge_reject_threshold=5))

        # generate 5 rejects quickly
        for _ in range(5):
            gate.ingest({"source": "x", "event_type": "E", "payload": "bad"})

        # siren should have transitioned to SUMMARIES_ONLY at least once
        events_dir = root / "spine" / "windows" / "siren" / "events"
        maydays = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(events_dir.glob("*.json"))]
        assert any(e["event_type"] == "MAYDAY" and e["payload"]["to_state"] == "SUMMARIES_ONLY" for e in maydays)

        led.close_clean()
