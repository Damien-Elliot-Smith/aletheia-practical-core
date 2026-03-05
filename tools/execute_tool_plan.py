#!/usr/bin/env python3
from __future__ import annotations

import argparse, json, shutil, time
from pathlib import Path
from typing import Any, Dict, List

from tools._toolrunner_helpers import load_json, save_json, safe_resolve, utc_now_iso, canonical_json_bytes, sha256_hex, file_size

ALLOWED_OPS = {"COPY","MOVE","DELETE","MKDIR"}

def _fail(code: str, detail: str="") -> Dict[str, Any]:
    out = {"verdict":"FAIL","error":code}
    if detail:
        out["detail"] = detail
    return out

def main() -> None:
    ap = argparse.ArgumentParser(description="Execute an approved ToolPlan (workspace-only, stdlib-only).")
    ap.add_argument("--plan", required=True, help="tool_plan.json")
    ap.add_argument("--approval", required=True, help="tool_approval.json")
    ap.add_argument("--out", default="tool_run.json", help="Run report output")
    args = ap.parse_args()

    t0 = time.time()
    plan = load_json(Path(args.plan))
    appr = load_json(Path(args.approval))

    if appr.get("decision") != "APPROVE":
        print(json.dumps(_fail("NOT_APPROVED"), indent=2, sort_keys=True))
        raise SystemExit(2)

    if appr.get("plan_hash") != plan.get("plan_hash"):
        print(json.dumps(_fail("PLAN_HASH_MISMATCH"), indent=2, sort_keys=True))
        raise SystemExit(2)

    ws = Path(plan["workspace_root"])
    budgets = plan["budgets"]
    max_files = int(budgets["max_files_touched"])
    max_bytes = int(budgets["max_total_bytes"])
    max_secs = int(budgets["max_runtime_seconds"])

    files_touched = 0
    bytes_touched = 0
    actions: List[Dict[str, Any]] = []

    for step in plan["steps"]:
        if time.time() - t0 > max_secs:
            print(json.dumps(_fail("BUDGET_RUNTIME_EXCEEDED"), indent=2, sort_keys=True))
            raise SystemExit(2)

        op = step.get("op")
        if op not in ALLOWED_OPS:
            print(json.dumps(_fail("OP_NOT_ALLOWED", str(op)), indent=2, sort_keys=True))
            raise SystemExit(2)

        src_rel = step.get("src")
        dst_rel = step.get("dst")

        if op == "MKDIR":
            if not dst_rel:
                print(json.dumps(_fail("BAD_STEP_MKDIR"), indent=2, sort_keys=True))
                raise SystemExit(2)
            dst = safe_resolve(ws, dst_rel)
            dst.mkdir(parents=True, exist_ok=True)
            actions.append({"op":"MKDIR","dst":dst_rel,"ok":True})
            continue

        if not src_rel:
            print(json.dumps(_fail("BAD_STEP_NO_SRC", op), indent=2, sort_keys=True))
            raise SystemExit(2)
        src = safe_resolve(ws, src_rel)

        if op in ("COPY","MOVE"):
            if not dst_rel:
                print(json.dumps(_fail("BAD_STEP_NO_DST", op), indent=2, sort_keys=True))
                raise SystemExit(2)
            dst = safe_resolve(ws, dst_rel)
            dst.parent.mkdir(parents=True, exist_ok=True)

            if not src.exists():
                print(json.dumps(_fail("SRC_MISSING", src_rel), indent=2, sort_keys=True))
                raise SystemExit(2)

            sz = file_size(src) if src.is_file() else 0
            if files_touched + 1 > max_files:
                print(json.dumps(_fail("BUDGET_FILES_EXCEEDED"), indent=2, sort_keys=True))
                raise SystemExit(2)
            if bytes_touched + sz > max_bytes:
                print(json.dumps(_fail("BUDGET_BYTES_EXCEEDED"), indent=2, sort_keys=True))
                raise SystemExit(2)

            if op == "COPY":
                if src.is_dir():
                    shutil.copytree(src, dst, dirs_exist_ok=True)
                else:
                    shutil.copy2(src, dst)
            else:
                shutil.move(str(src), str(dst))

            files_touched += 1
            bytes_touched += sz
            actions.append({"op":op,"src":src_rel,"dst":dst_rel,"bytes":sz,"ok":True})
            continue

        if op == "DELETE":
            if not src.exists():
                actions.append({"op":"DELETE","src":src_rel,"ok":True,"note":"already_missing"})
                continue
            sz = file_size(src) if src.is_file() else 0
            if files_touched + 1 > max_files:
                print(json.dumps(_fail("BUDGET_FILES_EXCEEDED"), indent=2, sort_keys=True))
                raise SystemExit(2)
            if bytes_touched + sz > max_bytes:
                print(json.dumps(_fail("BUDGET_BYTES_EXCEEDED"), indent=2, sort_keys=True))
                raise SystemExit(2)
            if src.is_dir():
                shutil.rmtree(src)
            else:
                src.unlink()
            files_touched += 1
            bytes_touched += sz
            actions.append({"op":"DELETE","src":src_rel,"bytes":sz,"ok":True})
            continue

    report = {
        "schema_version": "1",
        "created_utc": utc_now_iso(),
        "plan_hash": plan["plan_hash"],
        "approval_hash": appr["approval_hash"],
        "budgets": budgets,
        "files_touched": files_touched,
        "bytes_touched": bytes_touched,
        "actions": actions,
        "verdict": "PASS",
    }
    report["run_hash"] = sha256_hex(canonical_json_bytes(report))

    save_json(Path(args.out), report)
    print(json.dumps({"verdict":"PASS","out":args.out,"run_hash":report["run_hash"]}, indent=2, sort_keys=True))

if __name__ == "__main__":
    main()
