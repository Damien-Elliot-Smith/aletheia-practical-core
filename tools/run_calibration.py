#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

# stdlib-only runner. It calls local python scripts using the current PYTHONPATH.


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
    ap = argparse.ArgumentParser(description="Run Calibration Pack v1 (stdlib-only).")
    ap.add_argument("--core-dir", default=".", help="Core directory (where tools/ lives)")
    ap.add_argument("--pack", default="calibration/pack_v1/tests.json", help="Path to tests.json (relative to core-dir)")
    ap.add_argument("--out", default="calibration_report.json", help="Output report path")
    args = ap.parse_args()

    core = Path(args.core_dir).resolve()
    pack_path = (core / args.pack).resolve()
    spec = load_json(pack_path)
    tests = spec.get("tests", [])

    results: List[Dict[str, Any]] = []
    any_fail = False

    for t in tests:
        tid = t.get("id", "UNKNOWN")
        kind = t.get("kind")
        entry: Dict[str, Any] = {"id": tid, "kind": kind}

        try:
            if kind == "structure_question":
                q = t["input"]
                rc, out, err = run_py(["tools/structure_question.py", "--text", q], cwd=core)
                entry["rc"] = rc
                entry["stderr"] = err.strip()
                if rc != 0:
                    entry["verdict"] = "FAIL"
                    entry["reason"] = "RUN_ERROR"
                    any_fail = True
                else:
                    obj = json.loads(out)
                    entry["output_sha256"] = sha256_hex(canonical_json_bytes(obj))
                    exp = t.get("expected", {})
                    if "ambiguity_triggers" in exp and obj.get("ambiguity_triggers") != exp["ambiguity_triggers"]:
                        entry["verdict"] = "FAIL"
                        entry["reason"] = "MISMATCH_TRIGGERS"
                        entry["got"] = obj.get("ambiguity_triggers")
                        entry["expected"] = exp["ambiguity_triggers"]
                        any_fail = True
                    elif "max_triggers" in exp and len(obj.get("ambiguity_triggers", [])) > int(exp["max_triggers"]):
                        entry["verdict"] = "FAIL"
                        entry["reason"] = "TOO_MANY_TRIGGERS"
                        any_fail = True
                    else:
                        entry["verdict"] = "PASS"

            elif kind == "make_envelope":
                # create temp files in core dir (deterministic names)
                qtext = t["question_text"]
                sa_path = core / t["answer_path"]
                man_path = core / t["manifest_path"]

                sq_json = core / "_cal_sq.json"
                env_json = core / "_cal_env.json"

                rc, out, err = run_py(["tools/structure_question.py", "--text", qtext], cwd=core)
                if rc != 0:
                    entry["verdict"] = "FAIL"
                    entry["reason"] = "SQ_RUN_ERROR"
                    entry["stderr"] = err.strip()
                    any_fail = True
                else:
                    sq_json.write_text(out, encoding="utf-8")
                    rc2, out2, err2 = run_py([
                        "tools/make_envelope.py",
                        "--question", str(sq_json),
                        "--answer", str(sa_path),
                        "--manifest", str(man_path),
                        "--out", str(env_json),
                        "--parent-hash", "null"
                    ], cwd=core)
                    entry["make_rc"] = rc2
                    entry["make_stderr"] = err2.strip()
                    if rc2 != 0:
                        entry["verdict"] = "FAIL"
                        entry["reason"] = "MAKE_ENVELOPE_ERROR"
                        any_fail = True
                    else:
                        rc3, out3, err3 = run_py(["tools/validate_envelope.py", str(env_json)], cwd=core)
                        entry["validate_rc"] = rc3
                        entry["validate_stderr"] = err3.strip()
                        try:
                            vobj = json.loads(out3)
                        except Exception:
                            vobj = {"verdict": "FAIL", "errors": ["BAD_VALIDATOR_OUTPUT"]}
                        entry["validate"] = vobj
                        entry["output_sha256"] = sha256_hex(env_json.read_bytes())
                        expv = t.get("expected", {}).get("validate_envelope")
                        if expv and vobj.get("verdict") != expv:
                            entry["verdict"] = "FAIL"
                            entry["reason"] = "VALIDATION_MISMATCH"
                            any_fail = True
                        else:
                            entry["verdict"] = "PASS"

            else:
                entry["verdict"] = "FAIL"
                entry["reason"] = "UNKNOWN_TEST_KIND"
                any_fail = True

        except Exception as ex:
            entry["verdict"] = "FAIL"
            entry["reason"] = "EXCEPTION"
            entry["detail"] = str(ex)
            any_fail = True

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
