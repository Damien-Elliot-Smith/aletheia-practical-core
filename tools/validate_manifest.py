#!/usr/bin/env python3
from __future__ import annotations

import argparse, json
from pathlib import Path
from typing import Any, Dict, List

ALLOWED_TOP = {
    "schema_version",
    "core",
    "constraint_sets",
    "packs",
    "tooling",
    "created_utc",
    "schemas",
    "tool_policy",
    "model_adapter",
}

REQUIRED_TOP = {"schema_version","core","constraint_sets","packs"}
CORE_REQUIRED = {"name","version","sha256"}

TOOLING_ALLOWED = {"tool_runner", "self_diagnostic", "replay_engine", "drift_detector", "ui_shell"}

def validate_manifest(obj: Dict[str, Any]) -> List[str]:
    errs: List[str] = []
    if not isinstance(obj, dict):
        return ["NOT_AN_OBJECT"]

    unknown = sorted([k for k in obj.keys() if k not in ALLOWED_TOP])
    if unknown:
        errs.append("UNKNOWN_TOP_LEVEL_KEYS:" + ",".join(unknown))

    missing = sorted([k for k in REQUIRED_TOP if k not in obj])
    if missing:
        errs.append("MISSING_TOP_LEVEL_KEYS:" + ",".join(missing))

    if obj.get("schema_version") != "1":
        errs.append("BAD_SCHEMA_VERSION")

    core = obj.get("core")
    if not isinstance(core, dict):
        errs.append("CORE_NOT_OBJECT")
    else:
        miss_core = sorted([k for k in CORE_REQUIRED if k not in core])
        if miss_core:
            errs.append("CORE_MISSING_KEYS:" + ",".join(miss_core))

    if "tooling" in obj:
        tooling = obj.get("tooling")
        if not isinstance(tooling, dict):
            errs.append("TOOLING_NOT_OBJECT")
        else:
            unknown_t = sorted([k for k in tooling.keys() if k not in TOOLING_ALLOWED])
            if unknown_t:
                errs.append("TOOLING_UNKNOWN_KEYS:" + ",".join(unknown_t))

            def req_obj(name: str, req: List[str]) -> None:
                if name not in tooling:
                    return
                v = tooling.get(name)
                if not isinstance(v, dict):
                    errs.append(f"{name.upper()}_NOT_OBJECT")
                    return
                miss = [k for k in req if k not in v]
                if miss:
                    errs.append(f"{name.upper()}_MISSING_KEYS:" + ",".join(miss))

            req_obj("tool_runner", ["version","ops_allowlist","workspace_only","budgets_enforced","requires_approval"])
            req_obj("self_diagnostic", ["version","trace_schema_version","checks"])
            if "self_diagnostic" in tooling and isinstance(tooling.get("self_diagnostic"), dict):
                if "checks" in tooling["self_diagnostic"] and not isinstance(tooling["self_diagnostic"].get("checks"), list):
                    errs.append("SELF_DIAGNOSTIC_CHECKS_NOT_LIST")

            req_obj("replay_engine", ["version","replay_report_schema_version","supports_chain"])
            req_obj("drift_detector", ["version","drift_report_schema_version","checks"])
            if "drift_detector" in tooling and isinstance(tooling.get("drift_detector"), dict):
                if "checks" in tooling["drift_detector"] and not isinstance(tooling["drift_detector"].get("checks"), list):
                    errs.append("DRIFT_DETECTOR_CHECKS_NOT_LIST")

            req_obj("ui_shell", ["version","modes","session_export","stores_mode_in_envelope"])
            if "ui_shell" in tooling and isinstance(tooling.get("ui_shell"), dict):
                if "modes" in tooling["ui_shell"] and not isinstance(tooling["ui_shell"].get("modes"), list):
                    errs.append("UI_SHELL_MODES_NOT_LIST")

    return errs

def main() -> None:
    ap = argparse.ArgumentParser(description="Validate Provenance_Manifest.json (stdlib-only, fail-closed).")
    ap.add_argument("path")
    args = ap.parse_args()
    obj = json.loads(Path(args.path).read_text(encoding="utf-8"))
    errs = validate_manifest(obj)
    print(json.dumps({"verdict":"PASS" if not errs else "FAIL", "errors": errs}, indent=2, sort_keys=True))

if __name__ == "__main__":
    main()
