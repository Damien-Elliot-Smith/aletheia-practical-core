#!/usr/bin/env python3
from __future__ import annotations

import argparse, os, json
from pathlib import Path
from typing import Any, Dict, List

from tools._toolrunner_helpers import utc_now_iso, canonical_json_bytes, sha256_hex, save_json

def main() -> None:
    ap = argparse.ArgumentParser(description="Create a ToolPlan v1 (stdlib-only, deterministic).")
    ap.add_argument("--workspace-root", required=True, help="Absolute path to workspace root (everything constrained inside).")
    ap.add_argument("--out", default="tool_plan.json", help="Output plan path")
    ap.add_argument("--max-files", type=int, default=20)
    ap.add_argument("--max-bytes", type=int, default=10_000_000)
    ap.add_argument("--max-seconds", type=int, default=10)
    ap.add_argument("--step", action="append", required=True,
                    help="Step format: OP:src:dst  (DELETE uses OP:src:; MKDIR uses OP::dst)")
    ap.add_argument("--notes", default="")
    args = ap.parse_args()

    steps: List[Dict[str, Any]] = []
    for s in args.step:
        parts = s.split(":", 2)
        if len(parts) != 3:
            raise SystemExit(f"Bad --step: {s}")
        op, src, dst = parts[0], parts[1] or None, parts[2] or None
        steps.append({"op": op, "src": src, "dst": dst})

    plan: Dict[str, Any] = {
        "schema_version": "1",
        "plan_id": sha256_hex(os.urandom(16)),
        "created_utc": utc_now_iso(),
        "workspace_root": str(Path(args.workspace_root)),
        "budgets": {
            "max_files_touched": int(args.max_files),
            "max_total_bytes": int(args.max_bytes),
            "max_runtime_seconds": int(args.max_seconds),
        },
        "steps": steps,
        "notes": args.notes,
    }

    body = dict(plan)
    plan_hash = sha256_hex(canonical_json_bytes(body))
    plan["plan_hash"] = plan_hash

    save_json(Path(args.out), plan)
    print(json.dumps({"verdict":"PASS","plan_hash":plan_hash,"out":args.out}, indent=2, sort_keys=True))

if __name__ == "__main__":
    main()
