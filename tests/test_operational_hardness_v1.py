import tempfile, json, os, subprocess, sys, zipfile
from pathlib import Path
import pytest

from aletheia.spine.ledger import SpineLedger
from aletheia.siren.state_machine import Siren, SirenState, MaydayCode
from aletheia.ingest.gate import IngestGate, IngestConfig, IngestDecision
from aletheia.chronicle.export import build_case_zip

def _read_scars(root: Path):
    p = root/"spine/scars.jsonl"
    if not p.exists():
        return []
    out=[]
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        out.append(json.loads(line))
    return out

def test_dirty_shutdown_creates_scar_on_next_boot():
    with tempfile.TemporaryDirectory() as td:
        root=Path(td)/"root"; root.mkdir(parents=True, exist_ok=True)
        # Start ledger but do not close_clean -> leaves dirty.marker
        led=SpineLedger(root)
        led.open_window("w")
        led.append_event("w","X",{"a":1})
        # simulate crash: no close_clean()
        # Next boot should record SCAR
        _ = SpineLedger(root)  # boot check runs in __init__
        scars=_read_scars(root)
        assert any(s.get("scar_type")=="DIRTY_SHUTDOWN" for s in scars)

def test_siren_disk_pressure_transition_emits_mayday_and_persists_state():
    with tempfile.TemporaryDirectory() as td:
        root=Path(td)/"root"; root.mkdir(parents=True, exist_ok=True)
        led=SpineLedger(root)
        siren=Siren(led)
        siren.transition(SirenState.DEGRADED_CAPTURE, MaydayCode.DISK_PRESSURE, details={"free_bytes":123})
        led.close_clean()
        # verify state persisted
        state_path=root/"spine/siren_state.json"
        assert state_path.exists()
        st=json.loads(state_path.read_text(encoding="utf-8"))
        assert st.get("state")==SirenState.DEGRADED_CAPTURE.value

def test_reject_flood_is_bounded_and_triggers_siren_on_surge():
    with tempfile.TemporaryDirectory() as td:
        root=Path(td)/"root"; root.mkdir(parents=True, exist_ok=True)
        led=SpineLedger(root)
        siren=Siren(led)
        cfg=IngestConfig(reject_max_records=50, surge_window_s=60, surge_reject_threshold=20)
        gate=IngestGate(led, siren=siren, config=cfg)
        # Send invalid records (payload not dict) to force rejects
        for _ in range(60):
            res=gate.ingest({"source":"x","event_type":"E","payload":"not-a-dict"})
            assert res.decision==IngestDecision.REJECT
        # bounded ring must have fixed line count
        ring = root/"spine/rejects/ring.jsonl"
        meta = root/"spine/rejects/meta.json"
        assert ring.exists() and meta.exists()
        lines=ring.read_text(encoding="utf-8").splitlines()
        assert len(lines)==cfg.reject_max_records
        m=json.loads(meta.read_text(encoding="utf-8"))
        assert m.get("total_rejects",0) >= 60
        # siren should have escalated (surge detection)
        st=json.loads((root/"spine/siren_state.json").read_text(encoding="utf-8"))
        assert st.get("state") in (SirenState.SUMMARIES_ONLY.value, SirenState.HALT.value, SirenState.DEGRADED_CAPTURE.value)

def test_external_verifier_fails_if_event_file_missing():
    with tempfile.TemporaryDirectory() as td:
        root=Path(td)/"root"; root.mkdir(parents=True, exist_ok=True)
        led=SpineLedger(root)
        led.open_window("main")
        led.append_event("main","WITNESS",{"k":"v"})
        led.seal_window("main")
        led.close_clean()
        case=Path(td)/"case.zip"
        build_case_zip(root, case)
        # remove an event file from the zip
        damaged=Path(td)/"case_damaged.zip"
        removed=False
        with zipfile.ZipFile(case,"r") as zin, zipfile.ZipFile(damaged,"w",compression=zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                if item.filename.endswith("events/000001.json") and item.filename.startswith("evidence/spine/windows/main/"):
                    removed=True
                    continue
                zout.writestr(item, zin.read(item.filename))
        assert removed
        proc=subprocess.run([sys.executable, str(Path(__file__).resolve().parents[1]/"tools/verify_case.py"), str(damaged)], capture_output=True, text=True)
        assert proc.returncode != 0
        out=json.loads(proc.stdout)
        assert out["verdict"]=="FAIL"
