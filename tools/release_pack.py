#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, os, subprocess, sys, zipfile, hashlib, time
from pathlib import Path
from typing import Any, Dict, List, Optional
from tools._zip_write import write_zip_from_tree, ZipWritePolicy

def now_utc_iso() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z")

def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def run(cmd: List[str], cwd: Path, env: Optional[Dict[str,str]] = None) -> Dict[str, Any]:
    p = subprocess.run(cmd, cwd=str(cwd), env=env, capture_output=True, text=True)
    return {
        "cmd": cmd,
        "rc": p.returncode,
        "stdout": p.stdout.strip(),
        "stderr": p.stderr.strip(),
    }

def write_json(p: Path, obj: Any) -> None:
    p.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")

def add_tree(z: zipfile.ZipFile, root: Path, arc_prefix: str, exclude_dirs: List[str]) -> int:
    count = 0
    for p in sorted(root.rglob("*")):
        if p.is_dir():
            continue
        rel = p.relative_to(root).as_posix()
        # exclude build artifacts and sessions/dist by default
        if rel.split("/")[0] in exclude_dirs:
            continue
        z.write(p, f"{arc_prefix}/{rel}")
        count += 1
    return count

def main() -> int:
    ap = argparse.ArgumentParser(description="Step 17: release hardening packer (deterministic checks + snapshot zip).")
    ap.add_argument("--core-dir", default=".", help="Core directory root")
    ap.add_argument("--version", default="local", help="Release version label (e.g., v1_16)")
    ap.add_argument("--out-dir", default="dist", help="Output directory for zip + sha256 + report")
    ap.add_argument("--manifest", default="Provenance_Manifest.json", help="Manifest filename in core dir")
    ap.add_argument("--exclude-dir", action="append", default=[], help="Top-level dirs to exclude (repeatable)")
    args = ap.parse_args()

    core = Path(args.core_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    exclude = set(["dist", "sessions", "__pycache__", ".pytest_cache"])
    exclude.update(args.exclude_dir or [])

    report: Dict[str, Any] = {
        "schema_version": "1",
        "created_utc": now_utc_iso(),
        "core_dir": str(core),
        "version": args.version,
        "checks": [],
        "artifacts": {},
        "verdict": "PASS",
    }

    env = dict(os.environ)
    env["PYTHONPATH"] = str(core)

    # 1) validate manifest
    manifest_path = core / args.manifest
    if not manifest_path.exists():
        report["checks"].append({"check_id":"REL_MANIFEST_PRESENT","verdict":"FAIL","errors":[f"MISSING:{args.manifest}"]})
        report["verdict"] = "FAIL"
    else:
        r = run([sys.executable, str(core/"tools/validate_manifest.py"), str(manifest_path)], cwd=core, env=env)
        chk = {"check_id":"REL_VALIDATE_MANIFEST","details":r,"verdict":"PASS" if r["rc"]==0 else "FAIL"}
        if r["rc"] != 0:
            chk["errors"] = ["MANIFEST_INVALID"]
            report["verdict"] = "FAIL"
        report["checks"].append(chk)

    # 2) run calibration pack if present
    pack = core / "calibration/pack_v1/tests.json"
    if pack.exists() and (core/"tools/run_calibration.py").exists():
        r = run([sys.executable, str(core/"tools/run_calibration.py"),
                 "--core-dir", str(core),
                 "--pack", str(pack),
                 "--out", str(out_dir/"_release_calibration_report.json")], cwd=core, env=env)
        chk = {"check_id":"REL_CALIBRATION_PACK","details":r,"verdict":"PASS" if r["rc"]==0 else "FAIL"}
        if r["rc"] != 0:
            chk["errors"] = ["CALIBRATION_FAIL"]
            report["verdict"] = "FAIL"
        report["checks"].append(chk)
        report["artifacts"]["calibration_report"] = str(out_dir/"_release_calibration_report.json")
    else:
        report["checks"].append({"check_id":"REL_CALIBRATION_PACK","verdict":"INCONCLUSIVE","errors":["MISSING_PACK_OR_RUNNER"]})

    # 3) run redteam pack if present
    rpack = core / "redteam/pack_v1/tests.json"
    if rpack.exists() and (core/"tools/run_redteam.py").exists():
        r = run([sys.executable, str(core/"tools/run_redteam.py"),
                 "--core-dir", str(core),
                 "--pack", str(rpack),
                 "--out", str(out_dir/"_release_redteam_report.json")], cwd=core, env=env)
        chk = {"check_id":"REL_REDTEAM_PACK","details":r,"verdict":"PASS" if r["rc"]==0 else "FAIL"}
        if r["rc"] != 0:
            chk["errors"] = ["REDTEAM_FAIL"]
            report["verdict"] = "FAIL"
        report["checks"].append(chk)
        report["artifacts"]["redteam_report"] = str(out_dir/"_release_redteam_report.json")
    else:
        report["checks"].append({"check_id":"REL_REDTEAM_PACK","verdict":"INCONCLUSIVE","errors":["MISSING_PACK_OR_RUNNER"]})

    # 4) run drift detector if present
    drift = core / "tools/run_drift_detector.py"
    if drift.exists():
        r = run([sys.executable, str(drift),
                 "--core-dir", str(core),
                 "--out", str(out_dir/"_release_drift_report.json")], cwd=core, env=env)
        chk = {"check_id":"REL_DRIFT_DETECTOR","details":r,"verdict":"PASS" if r["rc"]==0 else "FAIL"}
        if r["rc"] != 0:
            chk["errors"] = ["DRIFT_FAIL"]
            report["verdict"] = "FAIL"
        report["checks"].append(chk)
        report["artifacts"]["drift_report"] = str(out_dir/"_release_drift_report.json")
    else:
        report["checks"].append({"check_id":"REL_DRIFT_DETECTOR","verdict":"INCONCLUSIVE","errors":["MISSING_RUNNER"]})

    # 5) pack snapshot zip (always)
    zip_name = f"Provenance_FULL_SNAPSHOT_{args.version}.zip"
    zip_path = out_dir / zip_name
    if zip_path.exists():
        zip_path.unlink()

    # Route through _zip_write.py: enforces fixed timestamps, deterministic ordering,
    # and centralised zip-writing policy. Same source tree -> same zip bytes.
    file_count = write_zip_from_tree(
        str(zip_path),
        str(core),
        "Aletheia_v1_Practical_Core",
        exclude_dirs=sorted(exclude),
        policy=ZipWritePolicy(),
    )

    sha = sha256_file(zip_path)
    sha_path = out_dir / f"{zip_name}.sha256"
    sha_path.write_text(f"{sha}  {zip_name}\n", encoding="utf-8")

    report["artifacts"]["snapshot_zip"] = str(zip_path)
    report["artifacts"]["snapshot_sha256"] = str(sha_path)
    report["artifacts"]["snapshot_file_count"] = file_count
    report["artifacts"]["snapshot_sha256_value"] = sha

    report_path = out_dir / f"release_report_{args.version}.json"
    write_json(report_path, report)
    report["artifacts"]["release_report"] = str(report_path)

    # echo summary
    print(json.dumps({
        "verdict": report["verdict"],
        "out_zip": str(zip_path),
        "sha256": sha,
        "sha256_file": str(sha_path),
        "release_report": str(report_path),
        "file_count": file_count
    }, indent=2, sort_keys=True))

    return 0 if report["verdict"] == "PASS" else 2

if __name__ == "__main__":
    raise SystemExit(main())
