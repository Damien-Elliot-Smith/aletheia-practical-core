#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

from tools.validate_structured_answer import validate_structured_answer


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def run_py(args: List[str], cwd: Path) -> Tuple[int, str, str]:
    p = subprocess.run(
        [sys.executable] + args,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        env={**dict(**{"PYTHONPATH": "."}), **dict()},
    )
    return p.returncode, p.stdout, p.stderr


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    ap = argparse.ArgumentParser(description="Run RedTeam Pack v1 (stdlib-only, offline).")
    ap.add_argument("--core-dir", default=".", help="Core directory")
    ap.add_argument("--pack", default="redteam/pack_v1/tests.json", help="Path to tests.json (relative to core)")
    ap.add_argument("--out", default="redteam_report.json", help="Output report path")
    args = ap.parse_args()

    core = Path(args.core_dir).resolve()
    pack_path = (core / args.pack).resolve()
    spec = load_json(pack_path)
    tests = spec.get("tests", [])

    results: List[Dict[str, Any]] = []
    any_fail = False

    for t in tests:
        tid = t.get("id", "UNKNOWN")
        entry: Dict[str, Any] = {"id": tid}
        qtext = t.get("question_text", "")
        fixture = (pack_path.parent / t.get("answer_fixture")).resolve()
        sa = load_json(fixture)

        # 1) Question -> StructuredQuestion
        rc_q, out_q, err_q = run_py(["tools/structure_question.py", "--text", qtext], cwd=core)
        entry["question_rc"] = rc_q
        entry["question_stderr"] = err_q.strip()
        if rc_q != 0:
            entry["verdict"] = "FAIL"
            entry["reason"] = "STRUCTURE_QUESTION_ERROR"
            any_fail = True
            results.append(entry)
            continue

        sq = json.loads(out_q)
        entry["question_fingerprint"] = sq.get("question_fingerprint")

        # 2) Validate answer fixture using library function (fail-closed)
        errs = validate_structured_answer(sa)
        verdict = "PASS" if not errs else "FAIL"
        entry["validate_answer"] = {"verdict": verdict, "errors": errs}

        exp = t.get("expects", {})
        if exp.get("validate_answer") and verdict != exp["validate_answer"]:
            entry["verdict"] = "FAIL"
            entry["reason"] = "ANSWER_VALIDATION_MISMATCH"
            any_fail = True
            results.append(entry)
            continue

        if verdict == "PASS":
            # extra expectations
            if exp.get("proof_status") and sa.get("proof_status") != exp["proof_status"]:
                entry["verdict"] = "FAIL"
                entry["reason"] = "PROOF_STATUS_MISMATCH"
                any_fail = True
                results.append(entry)
                continue
            if exp.get("constraints_contains"):
                got = sa.get("constraints", [])
                missing = [c for c in exp["constraints_contains"] if c not in got]
                if missing:
                    entry["verdict"] = "FAIL"
                    entry["reason"] = "MISSING_CONSTRAINTS"
                    entry["missing_constraints"] = missing
                    any_fail = True
                    results.append(entry)
                    continue

        # 3) If answer is valid, make envelope then validate it
        if verdict == "PASS":
            sq_path = core / "_rt_sq.json"
            sa_path = core / "_rt_sa.json"
            env_path = core / "_rt_env.json"
            sq_path.write_text(json.dumps(sq, indent=2, sort_keys=True), encoding="utf-8")
            sa_path.write_text(json.dumps(sa, indent=2, sort_keys=True), encoding="utf-8")

            rc_e, out_e, err_e = run_py([
                "tools/make_envelope.py",
                "--question", str(sq_path),
                "--answer", str(sa_path),
                "--manifest", "Provenance_Manifest.json",
                "--out", str(env_path),
                "--parent-hash", "null",
            ], cwd=core)
            entry["make_envelope_rc"] = rc_e
            entry["make_envelope_stderr"] = err_e.strip()
            if rc_e != 0:
                entry["verdict"] = "FAIL"
                entry["reason"] = "MAKE_ENVELOPE_ERROR"
                any_fail = True
                results.append(entry)
                continue

            rc_v, out_v, err_v = run_py(["tools/validate_envelope.py", str(env_path)], cwd=core)
            entry["validate_envelope_rc"] = rc_v
            entry["validate_envelope_stderr"] = err_v.strip()
            try:
                vobj = json.loads(out_v)
            except Exception:
                vobj = {"verdict": "FAIL", "errors": ["BAD_VALIDATOR_OUTPUT"]}
            entry["validate_envelope"] = vobj

            if vobj.get("verdict") != "PASS":
                entry["verdict"] = "FAIL"
                entry["reason"] = "ENVELOPE_VALIDATE_FAIL"
                any_fail = True
                results.append(entry)
                continue

            # 4) Tamper test (RT_005): modify env.json then expect validate FAIL
            if exp.get("envelope_validate_after_tamper"):
                tampered = json.loads(env_path.read_text(encoding="utf-8"))
                tampered["output"]["output_hash"] = "0"*64  # corrupt hash
                env_path.write_text(json.dumps(tampered, indent=2, sort_keys=True), encoding="utf-8")
                rc_v2, out_v2, err_v2 = run_py(["tools/validate_envelope.py", str(env_path)], cwd=core)
                try:
                    v2 = json.loads(out_v2)
                except Exception:
                    v2 = {"verdict":"FAIL","errors":["BAD_VALIDATOR_OUTPUT"]}
                entry["tamper_validate"] = v2
                if v2.get("verdict") != exp["envelope_validate_after_tamper"]:
                    entry["verdict"] = "FAIL"
                    entry["reason"] = "TAMPER_EXPECTATION_MISMATCH"
                    any_fail = True
                    results.append(entry)
                    continue

        entry["verdict"] = "PASS"
        entry["drift"] = sha256_hex(canonical_json_bytes(entry))
        results.append(entry)

    report = {
        "schema_version": "1",
        "pack": str(pack_path),
        "verdict": "PASS" if not any_fail else "FAIL",
        "results": results,
        "drift_signature": sha256_hex(canonical_json_bytes(results)),
    }

    out_path = (core / args.out).resolve()
    out_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"verdict": report["verdict"], "out": str(out_path), "drift_signature": report["drift_signature"]}, indent=2, sort_keys=True))
    sys.exit(0 if not any_fail else 2)


if __name__ == "__main__":
    main()
