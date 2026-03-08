import os
import tempfile, subprocess, sys, json
from pathlib import Path

def test_demo_ot_generates_verifiable_case():
    with tempfile.TemporaryDirectory() as td:
        root=Path(td)/"demo_root"
        case=Path(td)/"demo_case.zip"
        proc=subprocess.run([sys.executable,"ag.py","demo-ot","--root",str(root),"--out",str(case)], cwd=str(Path(__file__).resolve().parents[1]), capture_output=True, text=True, env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])})
        assert proc.returncode==0, proc.stdout+proc.stderr
        vproc=subprocess.run([sys.executable, str(Path(__file__).resolve().parents[1]/"tools/verify_case.py"), str(case)], capture_output=True, text=True, env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])})
        assert vproc.returncode==0, vproc.stdout+vproc.stderr
        out=json.loads(vproc.stdout)
        assert out["verdict"]=="PASS"
