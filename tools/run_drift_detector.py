#!/usr/bin/env python3
from __future__ import annotations

import argparse, json, subprocess, sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from tools._drift_lib import now_utc_iso, stable_id

def run_json(cmd: List[str], cwd: Path) -> Dict[str, Any]:
    p = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)
    out = p.stdout.strip()
    j: Dict[str, Any] = {}
    if out:
        try:
            j = json.loads(out)
        except Exception:
            j = {}
    return {"rc": p.returncode, "json": j, "stderr": p.stderr.strip(), "cmd": cmd}

def verdict_from_rc(rc: int) -> str:
    return "PASS" if rc == 0 else "FAIL"

def drift_detector(core_dir: Path, manifest: Path, calibration_pack: Optional[Path], redteam_pack: Optional[Path],
                   compiled_constraints: Optional[Path], sample_answer: Optional[Path], sample_env: Optional[Path]) -> Dict[str, Any]:
    results: List[Dict[str, Any]] = []

    # 1) manifest validation (identity pinned)
    r = run_json([sys.executable, str(core_dir/"tools/validate_manifest.py"), str(manifest)], core_dir)
    j = r["json"] if isinstance(r["json"], dict) else {}
    results.append({
        "check_id":"DRIFT_VALIDATE_MANIFEST",
        "verdict": j.get("verdict") or verdict_from_rc(r["rc"]),
        "errors": j.get("errors", []) if isinstance(j.get("errors"), list) else ([] if r["rc"]==0 else ["MANIFEST_VALIDATOR_NO_JSON"]),
        "details":{"rc": r["rc"]}
    })

    # 2) calibration pack run (if provided)
    if calibration_pack is not None:
        r = run_json([sys.executable, str(core_dir/"tools/run_calibration.py"),
                      "--core-dir", str(core_dir), "--pack", str(calibration_pack), "--out", str(core_dir/"_drift_calibration_report.json")], core_dir)
        j = r["json"] if isinstance(r["json"], dict) else {}
        results.append({
            "check_id":"DRIFT_CALIBRATION_PACK",
            "verdict": j.get("verdict") or verdict_from_rc(r["rc"]),
            "errors": [] if (j.get("verdict")=="PASS" or r["rc"]==0) else ["CALIBRATION_PACK_FAILED"],
            "details":{"rc": r["rc"], "out": j.get("out")}
        })

    # 3) redteam pack run (if provided)
    if redteam_pack is not None:
        r = run_json([sys.executable, str(core_dir/"tools/run_redteam.py"),
                      "--core-dir", str(core_dir), "--pack", str(redteam_pack), "--out", str(core_dir/"_drift_redteam_report.json")], core_dir)
        j = r["json"] if isinstance(r["json"], dict) else {}
        results.append({
            "check_id":"DRIFT_REDTEAM_PACK",
            "verdict": j.get("verdict") or verdict_from_rc(r["rc"]),
            "errors": [] if (j.get("verdict")=="PASS" or r["rc"]==0) else ["REDTEAM_PACK_FAILED"],
            "details":{"rc": r["rc"], "out": j.get("out")}
        })

    # 4) constraints run (if provided)
    if compiled_constraints is not None and sample_answer is not None:
        r = run_json([sys.executable, str(core_dir/"tools/run_constraints.py"),
                      "--compiled", str(compiled_constraints), "--answer", str(sample_answer)], core_dir)
        j = r["json"] if isinstance(r["json"], dict) else {}
        results.append({
            "check_id":"DRIFT_CONSTRAINTS_ON_SAMPLE_ANSWER",
            "verdict": j.get("verdict") or verdict_from_rc(r["rc"]),
            "errors": j.get("errors", []) if isinstance(j.get("errors"), list) else ([] if r["rc"]==0 else ["CONSTRAINTS_NO_JSON"]),
            "details":{"rc": r["rc"], "ruleset_id": j.get("ruleset_id")}
        })

    # 5) envelope replay (if provided)
    if sample_env is not None and (core_dir/"tools/replay_envelope.py").exists():
        r = run_json([sys.executable, str(core_dir/"tools/replay_envelope.py"),
                      "--core-dir", str(core_dir), "--env", str(sample_env), "--out", str(core_dir/"_drift_replay_report.json")], core_dir)
        j = r["json"] if isinstance(r["json"], dict) else {}
        results.append({
            "check_id":"DRIFT_REPLAY_SAMPLE_ENV",
            "verdict": j.get("verdict") or verdict_from_rc(r["rc"]),
            "errors": [] if (j.get("verdict")=="PASS" or r["rc"]==0) else ["REPLAY_FAILED"],
            "details":{"rc": r["rc"], "out": j.get("out"), "replay_id": j.get("replay_id")}
        })

    # Summarize
    verdict = "PASS"
    for it in results:
        if it["verdict"] == "FAIL":
            verdict = "FAIL"
            break
        if it["verdict"] == "ERROR":
            verdict = "ERROR"
            break

    summary = {
        "checks_total": len(results),
        "checks_pass": sum(1 for x in results if x["verdict"]=="PASS"),
        "checks_fail": sum(1 for x in results if x["verdict"]=="FAIL"),
        "checks_error": sum(1 for x in results if x["verdict"]=="ERROR"),
    }

    report = {
        "schema_version":"1",
        "created_utc": now_utc_iso(),
        "verdict": verdict,
        "results": results,
        "summary": summary,
    }
    report["drift_id"] = stable_id(report, drop_keys=["created_utc","drift_id"])
    return report

def main() -> None:
    ap = argparse.ArgumentParser(description="Step 14 Drift Detector: run regression + schema checks and emit drift report.")
    ap.add_argument("--core-dir", default=".", help="Core directory")
    ap.add_argument("--manifest", default="Provenance_Manifest.json")
    ap.add_argument("--calibration-pack", default=None)
    ap.add_argument("--redteam-pack", default=None)
    ap.add_argument("--compiled-constraints", default=None)
    ap.add_argument("--sample-answer", default=None)
    ap.add_argument("--sample-env", default=None)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    core_dir = Path(args.core_dir).resolve()
    manifest = Path(args.manifest).resolve()

    cal = Path(args.calibration_pack).resolve() if args.calibration_pack else None
    rt = Path(args.redteam_pack).resolve() if args.redteam_pack else None
    cc = Path(args.compiled_constraints).resolve() if args.compiled_constraints else None
    sa = Path(args.sample_answer).resolve() if args.sample_answer else None
    se = Path(args.sample_env).resolve() if args.sample_env else None

    report = drift_detector(core_dir, manifest, cal, rt, cc, sa, se)
    outp = Path(args.out).resolve()
    outp.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"verdict": report["verdict"], "drift_id": report["drift_id"], "out": str(outp)}, indent=2, sort_keys=True))
    raise SystemExit(0 if report["verdict"]=="PASS" else 2)

if __name__ == "__main__":
    main()
