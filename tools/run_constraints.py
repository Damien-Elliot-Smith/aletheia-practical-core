#!/usr/bin/env python3
from __future__ import annotations

import argparse, json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

def get_field(obj: Any, path: str) -> Any:
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur

def cmp(op: str, a: Any, b: Any) -> bool:
    if op == "==": return a == b
    if op == "!=": return a != b
    if op == "<": return a < b
    if op == "<=": return a <= b
    if op == ">": return a > b
    if op == ">=": return a >= b
    raise ValueError(f"BAD_OP:{op}")

def when_holds(sa: Dict[str, Any], when: Optional[Dict[str, Any]]) -> bool:
    if not when:
        return True
    wf = when.get("field")
    op = when.get("op")
    val = when.get("value")
    got = get_field(sa, wf) if isinstance(wf, str) else None
    try:
        return cmp(str(op), got, val)
    except Exception:
        return False

def check_rule(sa: Dict[str, Any], rule: Dict[str, Any]) -> Optional[str]:
    if rule.get("applies_to") != "StructuredAnswer":
        return None
    if not when_holds(sa, rule.get("when")):
        return None

    rtype = rule.get("type")
    field = rule.get("field")
    msg = rule.get("message","RULE_FAILED")

    if rtype == "numeric_bound":
        got = get_field(sa, str(field))
        try:
            got_f = float(got)
            val_f = float(rule.get("value"))
            if not cmp(str(rule.get("op")), got_f, val_f):
                return msg
        except Exception:
            return "BAD_NUMERIC_FIELD"
        return None

    if rtype == "min_len":
        got = get_field(sa, str(field))
        m = int(rule.get("min", 0))
        if not isinstance(got, list) or len(got) < m:
            return msg
        return None

    return "UNKNOWN_RULE_TYPE"

def main() -> None:
    ap = argparse.ArgumentParser(description="Run compiled constraints against a StructuredAnswer JSON.")
    ap.add_argument("--compiled", default="constraints/compiled_constraints.json")
    ap.add_argument("--answer", required=True)
    args = ap.parse_args()

    bundle = json.loads(Path(args.compiled).read_text(encoding="utf-8"))
    sa = json.loads(Path(args.answer).read_text(encoding="utf-8"))

    errors: List[str] = []
    for rule in bundle.get("compiled_rules", []):
        err = check_rule(sa, rule)
        if err:
            errors.append(f"{rule.get('id')}:{err}")

    print(json.dumps({"verdict":"PASS" if not errors else "FAIL", "errors": errors, "ruleset_id": bundle.get("ruleset_id")}, indent=2, sort_keys=True))
    raise SystemExit(0 if not errors else 2)

if __name__ == "__main__":
    main()
