#!/usr/bin/env python3
from __future__ import annotations

import argparse, json, subprocess, sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from tools._diag_lib import make_trace

def run_cmd(cmd: List[str], cwd: Optional[str]=None) -> Dict[str, Any]:
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    out = p.stdout.strip()
    err = p.stderr.strip()
    j = None
    if out:
        try:
            j = json.loads(out)
        except Exception:
            j = None
    return {"rc": p.returncode, "stdout": out, "stderr": err, "json": j}

def verdict_from_checks(checks: List[Dict[str, Any]]) -> str:
    # precedence: ERROR > FAIL > INCONCLUSIVE > PASS
    vset = {c.get("verdict") for c in checks}
    if "ERROR" in vset: return "ERROR"
    if "FAIL" in vset: return "FAIL"
    if "INCONCLUSIVE" in vset: return "INCONCLUSIVE"
    return "PASS"

def emit(out_path: Path, trace: Dict[str, Any]) -> None:
    out_path.write_text(json.dumps(trace, indent=2, sort_keys=True), encoding="utf-8")

def diag_answer(core_dir: Path, answer_path: Path, compiled_path: Path) -> Dict[str, Any]:
    checks: List[Dict[str, Any]] = []

    # 1) schema validation (StructuredAnswer)
    cmd1 = [sys.executable, str(core_dir/"tools/validate_structured_answer.py"), str(answer_path)]
    r1 = run_cmd(cmd1, cwd=str(core_dir))
    j1 = r1["json"] if isinstance(r1["json"], dict) else {}
    checks.append({
        "check_id": "CHK_SCHEMA_STRUCTURED_ANSWER",
        "verdict": (j1.get("verdict") or ("PASS" if r1["rc"]==0 else "FAIL")),
        "errors": j1.get("errors", []) if isinstance(j1.get("errors"), list) else ([] if r1["rc"]==0 else ["SCHEMA_VALIDATOR_NO_JSON"]),
        "details": {"rc": r1["rc"]}
    })

    # 2) constraints
    cmd2 = [sys.executable, str(core_dir/"tools/run_constraints.py"), "--compiled", str(compiled_path), "--answer", str(answer_path)]
    r2 = run_cmd(cmd2, cwd=str(core_dir))
    j2 = r2["json"] if isinstance(r2["json"], dict) else {}
    checks.append({
        "check_id": "CHK_CONSTRAINTS_COMPILED",
        "verdict": (j2.get("verdict") or ("PASS" if r2["rc"]==0 else "FAIL")),
        "errors": j2.get("errors", []) if isinstance(j2.get("errors"), list) else ([] if r2["rc"]==0 else ["CONSTRAINT_RUNNER_NO_JSON"]),
        "details": {"ruleset_id": j2.get("ruleset_id"), "rc": r2["rc"]}
    })

    return {"checks": checks}

def diag_envelope(core_dir: Path, env_path: Path) -> Dict[str, Any]:
    checks: List[Dict[str, Any]] = []
    cmd = [sys.executable, str(core_dir/"tools/validate_envelope.py"), str(env_path)]
    r = run_cmd(cmd, cwd=str(core_dir))
    j = r["json"] if isinstance(r["json"], dict) else {}
    checks.append({
        "check_id": "CHK_SCHEMA_PROVENANCE_ENVELOPE",
        "verdict": (j.get("verdict") or ("PASS" if r["rc"]==0 else "FAIL")),
        "errors": j.get("errors", []) if isinstance(j.get("errors"), list) else ([] if r["rc"]==0 else ["ENVELOPE_VALIDATOR_NO_JSON"]),
        "details": {"rc": r["rc"]}
    })
    return {"checks": checks}

def diag_case(core_dir: Path, case_path: Path, enforce_drift: bool) -> Dict[str, Any]:
    checks: List[Dict[str, Any]] = []
    cmd = [sys.executable, str(core_dir/"tools/verify_case.py")]
    if enforce_drift:
        cmd.append("--enforce-drift")
    cmd.append(str(case_path))
    r = run_cmd(cmd, cwd=str(core_dir))
    j = r["json"] if isinstance(r["json"], dict) else {}
    # verify_case returns verdict PASS/FAIL/ERROR and reasons
    checks.append({
        "check_id": "CHK_CASE_VERIFY",
        "verdict": j.get("verdict") or ("PASS" if r["rc"]==0 else "FAIL"),
        "errors": j.get("reasons", []) if isinstance(j.get("reasons"), list) else ([] if r["rc"]==0 else ["CASE_VERIFY_NO_JSON"]),
        "details": {
            "rc": r["rc"],
            "case_id": j.get("case_id"),
            "driftlock": j.get("driftlock"),
        }
    })
    return {"checks": checks}

def main() -> None:
    ap = argparse.ArgumentParser(description="Self-diagnostic wrapper producing trace IDs.")
    sub = ap.add_subparsers(dest="mode", required=True)

    ap_a = sub.add_parser("answer", help="Diagnose a StructuredAnswer (schema + constraints)")
    ap_a.add_argument("--core-dir", default=".", help="Core directory (default .)")
    ap_a.add_argument("--answer", required=True)
    ap_a.add_argument("--compiled", required=True)
    ap_a.add_argument("--out", required=True)

    ap_e = sub.add_parser("envelope", help="Diagnose a Provenance Envelope (schema/hashes)")
    ap_e.add_argument("--core-dir", default=".")
    ap_e.add_argument("--env", required=True)
    ap_e.add_argument("--out", required=True)

    ap_c = sub.add_parser("case", help="Diagnose a case.zip verification")
    ap_c.add_argument("--core-dir", default=".")
    ap_c.add_argument("--case", required=True)
    ap_c.add_argument("--enforce-drift", action="store_true")
    ap_c.add_argument("--out", required=True)

    args = ap.parse_args()
    core_dir = Path(args.core_dir).resolve()

    if args.mode == "answer":
        payload = diag_answer(core_dir, Path(args.answer), Path(args.compiled))
    elif args.mode == "envelope":
        payload = diag_envelope(core_dir, Path(args.env))
    elif args.mode == "case":
        payload = diag_case(core_dir, Path(args.case), bool(args.enforce_drift))
    else:
        raise SystemExit("BAD_MODE")

    trace = {
        "schema_version": "1",
        "verdict": "PASS",
        "checks": payload["checks"],
    }
    trace["verdict"] = "PASS" if all(c.get("verdict")=="PASS" for c in trace["checks"]) else verdict_from_checks(trace["checks"])
    trace = make_trace(trace)

    out_path = Path(getattr(args, "out")).resolve()
    emit(out_path, trace)
    print(json.dumps({"verdict": trace["verdict"], "trace_id": trace["trace_id"], "out": str(out_path)}, indent=2, sort_keys=True))
    raise SystemExit(0 if trace["verdict"]=="PASS" else 2)

if __name__ == "__main__":
    main()
