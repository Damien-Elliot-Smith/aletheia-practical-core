import tempfile, json, zipfile, shutil, subprocess, sys
from pathlib import Path
from aletheia.spine.ledger import SpineLedger
from aletheia.claims import ClaimRegistry, ClaimType
from aletheia.chronicle.export import build_case_zip

def test_case_manifest_present_and_external_verifier_passes():
    with tempfile.TemporaryDirectory() as td:
        root=Path(td)/"root"; root.mkdir(parents=True, exist_ok=True)
        led=SpineLedger(root)
        led.open_window("main")
        led.append_event("main","WITNESS",{"k":"v"})
        led.seal_window("main")
        reg=ClaimRegistry(led, window_id="claims")
        reg.propose(claim_id="c1", claim_text="x", claim_type=ClaimType.EMPIRICAL)
        led.seal_window("claims")
        led.close_clean()
        case=Path(td)/"case.zip"
        build_case_zip(root, case)
        with zipfile.ZipFile(case,"r") as z:
            assert "case_manifest.json" in z.namelist()
        # run external verifier
        proc=subprocess.run([sys.executable, str(Path(__file__).resolve().parents[1]/"tools/verify_case.py"), str(case)], capture_output=True, text=True)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        out=json.loads(proc.stdout)
        assert out["verdict"]=="PASS"

def test_external_verifier_detects_tamper():
    with tempfile.TemporaryDirectory() as td:
        root=Path(td)/"root"; root.mkdir(parents=True, exist_ok=True)
        led=SpineLedger(root)
        led.open_window("main")
        led.append_event("main","WITNESS",{"k":"v"})
        led.seal_window("main")
        led.close_clean()
        case=Path(td)/"case.zip"
        build_case_zip(root, case)
        # tamper: rewrite a json file inside zip (change payload) -> hash mismatch
        tampered=Path(td)/"case_tampered.zip"
        with zipfile.ZipFile(case,"r") as zin, zipfile.ZipFile(tampered,"w",compression=zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                data=zin.read(item.filename)
                if item.filename.endswith("events/000001.json") and item.filename.startswith("evidence/spine/windows/main/"):
                    obj=json.loads(data.decode("utf-8"))
                    obj["payload"]={"k":"tampered"}
                    data=json.dumps(obj, sort_keys=True, indent=2).encode("utf-8")
                zout.writestr(item, data)
        proc=subprocess.run([sys.executable, str(Path(__file__).resolve().parents[1]/"tools/verify_case.py"), str(tampered)], capture_output=True, text=True)
        assert proc.returncode != 0
        out=json.loads(proc.stdout)
        assert out["verdict"]=="FAIL"
        assert "FILE_HASH_MISMATCH" in out["reasons"] or "WINDOW_VERIFY_FAILED" in out["reasons"]
