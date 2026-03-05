#!/usr/bin/env python3
from __future__ import annotations

import argparse, os, json
from pathlib import Path
from typing import Any, Dict

from tools._toolrunner_helpers import utc_now_iso, canonical_json_bytes, sha256_hex, load_json, save_json

def main() -> None:
    ap = argparse.ArgumentParser(description="Approve or reject a ToolPlan v1 (creates ToolApproval v1).")
    ap.add_argument("--plan", required=True, help="Path to tool_plan.json")
    ap.add_argument("--approver", required=True, help="Human approver name/id")
    ap.add_argument("--decision", choices=["APPROVE","REJECT"], required=True)
    ap.add_argument("--comment", default="")
    ap.add_argument("--out", default="tool_approval.json")
    args = ap.parse_args()

    plan = load_json(Path(args.plan))
    plan_hash = plan.get("plan_hash")

    approval: Dict[str, Any] = {
        "schema_version": "1",
        "approval_id": sha256_hex(os.urandom(16)),
        "created_utc": utc_now_iso(),
        "approver": args.approver,
        "plan_hash": str(plan_hash),
        "decision": args.decision,
        "comment": args.comment,
    }

    body = dict(approval)
    approval_hash = sha256_hex(canonical_json_bytes(body))
    approval["approval_hash"] = approval_hash

    save_json(Path(args.out), approval)
    print(json.dumps({"verdict":"PASS","decision":args.decision,"approval_hash":approval_hash,"out":args.out}, indent=2, sort_keys=True))

if __name__ == "__main__":
    main()
