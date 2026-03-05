#!/usr/bin/env python3
from __future__ import annotations

import argparse, json, subprocess, sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from tools._replay_lib import canonical_json_bytes, sha256_hex, now_utc_iso, stable_id

def run_json(cmd: List[str], cwd: Path) -> Dict[str, Any]:
    p = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)
    out = p.stdout.strip()
    j: Dict[str, Any] = {}
    if out:
        try:
            j = json.loads(out)
        except Exception:
            j = {}
    return {"rc": p.returncode, "json": j, "stderr": p.stderr.strip()}

def recompute_envelope_hash(env: Dict[str, Any]) -> str:
    base = dict(env)
    base.pop("envelope_hash", None)
    return sha256_hex(canonical_json_bytes(base))

def replay_one(core_dir: Path, env_path: Path) -> Dict[str, Any]:
    checks: List[Dict[str, Any]] = []

    # 1) validate envelope using existing validator (schema + hash checks)
    vcmd = [sys.executable, str(core_dir/"tools/validate_envelope.py"), str(env_path)]
    r1 = run_json(vcmd, core_dir)
    vj = r1["json"] if isinstance(r1["json"], dict) else {}
    checks.append({
        "check_id":"CHK_VALIDATE_ENVELOPE",
        "verdict": vj.get("verdict") or ("PASS" if r1["rc"]==0 else "FAIL"),
        "errors": vj.get("errors", []) if isinstance(vj.get("errors"), list) else ([] if r1["rc"]==0 else ["VALIDATOR_NO_JSON"]),
        "details": {"rc": r1["rc"]}
    })

    # 2) recompute envelope_hash deterministically
    env = json.loads(env_path.read_text(encoding="utf-8"))
    got = env.get("envelope_hash")
    exp = recompute_envelope_hash(env)
    if got != exp:
        checks.append({
            "check_id":"CHK_ENVELOPE_HASH_RECOMPUTE",
            "verdict":"FAIL",
            "errors":["ENVELOPE_HASH_MISMATCH"],
            "details":{"expected":exp,"got":got}
        })
    else:
        checks.append({
            "check_id":"CHK_ENVELOPE_HASH_RECOMPUTE",
            "verdict":"PASS",
            "errors":[],
            "details":{"envelope_hash":exp}
        })

    verdict = "PASS"
    if any(c["verdict"]=="FAIL" for c in checks): verdict = "FAIL"
    if any(c["verdict"]=="ERROR" for c in checks): verdict = "ERROR"

    report = {
        "schema_version":"1",
        "created_utc": now_utc_iso(),
        "verdict": verdict,
        "checks": checks,
        "env_path": str(env_path),
    }
    report["replay_id"] = stable_id(report)
    return report

def replay_chain(core_dir: Path, env_paths: List[Path]) -> Dict[str, Any]:
    checks: List[Dict[str, Any]] = []
    # ensure deterministic order
    env_paths = list(env_paths)
    # Validate each + recompute hash; also check parent_hash linkage
    prev_hash: Optional[str] = None
    for p in env_paths:
        rep = replay_one(core_dir, p)
        checks.append({
            "check_id":"CHK_REPLAY_ONE",
            "verdict": rep["verdict"],
            "errors": [e for c in rep["checks"] for e in c.get("errors", [])],
            "details":{"env": str(p), "replay_id": rep["replay_id"]}
        })
        env = json.loads(p.read_text(encoding="utf-8"))
        ph = env.get("parent_hash")
        if prev_hash is None:
            # first may be null
            pass
        else:
            if ph != prev_hash:
                checks.append({
                    "check_id":"CHK_PARENT_HASH_CHAIN",
                    "verdict":"FAIL",
                    "errors":["PARENT_HASH_MISMATCH"],
                    "details":{"env": str(p), "expected_parent": prev_hash, "got_parent": ph}
                })
        prev_hash = env.get("envelope_hash")

    verdict = "PASS"
    if any(c["verdict"]=="FAIL" for c in checks): verdict = "FAIL"
    if any(c["verdict"]=="ERROR" for c in checks): verdict = "ERROR"

    report = {
        "schema_version":"1",
        "created_utc": now_utc_iso(),
        "verdict": verdict,
        "checks": checks,
        "count": len(env_paths),
    }
    report["replay_id"] = stable_id(report)
    return report

def main() -> None:
    ap = argparse.ArgumentParser(description="Replay engine: deterministically re-validate and re-hash envelopes.")
    ap.add_argument("--core-dir", default=".", help="Core directory containing tools/validate_envelope.py")
    ap.add_argument("--env", help="Single envelope path")
    ap.add_argument("--env-list", help="Text file listing envelope paths (one per line) for chain replay")
    ap.add_argument("--out", required=True, help="Output replay report json")
    args = ap.parse_args()

    core_dir = Path(args.core_dir).resolve()
    out_path = Path(args.out).resolve()

    if args.env and args.env_list:
        raise SystemExit("CHOOSE_ENV_OR_ENV_LIST")
    if not args.env and not args.env_list:
        raise SystemExit("MISSING_INPUT")

    if args.env:
        report = replay_one(core_dir, Path(args.env).resolve())
    else:
        lines = [ln.strip() for ln in Path(args.env_list).read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.strip().startswith("#")]
        report = replay_chain(core_dir, [Path(x).resolve() for x in lines])

    out_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"verdict": report["verdict"], "replay_id": report["replay_id"], "out": str(out_path)}, indent=2, sort_keys=True))
    raise SystemExit(0 if report["verdict"]=="PASS" else 2)

if __name__ == "__main__":
    main()
