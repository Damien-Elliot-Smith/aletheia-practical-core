#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List


ALLOWED_PROOF = {"PROVEN","DISPROVEN","UNPROVEN","INCONCLUSIVE"}


class ValidationError(Exception):
    pass


def _fail(msg: str) -> None:
    raise ValidationError(msg)


def _is_obj(x: Any) -> bool:
    return isinstance(x, dict)


def _is_list(x: Any) -> bool:
    return isinstance(x, list)


def _req(obj: Dict[str, Any], key: str) -> Any:
    if key not in obj:
        _fail(f"MISSING_KEY:{key}")
    return obj[key]


def validate_structured_answer(a: Dict[str, Any]) -> List[str]:
    errors: List[str] = []

    def chk(fn):
        try:
            fn()
        except ValidationError as e:
            errors.append(str(e))

    def root():
        if not _is_obj(a):
            _fail("NOT_OBJECT")
        if a.get("schema_version") != "1":
            _fail("BAD_SCHEMA_VERSION")
        for k in ("answer_version","proof_status","merit","confidence_bound","evidence_chain","inference_path",
                  "counterarguments","constraints","what_would_change","final_answer"):
            _req(a, k)

        extra = sorted(set(a.keys()) - {
            "schema_version","answer_version","proof_status","merit","confidence_bound","evidence_chain",
            "inference_path","counterarguments","constraints","what_would_change","final_answer"
        })
        if extra:
            _fail("UNKNOWN_KEYS:" + ",".join(extra))

    def proof():
        ps = a.get("proof_status")
        if ps not in ALLOWED_PROOF:
            _fail("BAD_PROOF_STATUS")

    def merit():
        m = a.get("merit")
        if not _is_obj(m):
            _fail("BAD_MERIT_TYPE")
        for k in ("helpfulness","honesty","safety"):
            v = _req(m, k)
            if not isinstance(v, int) or v < 0 or v > 5:
                _fail(f"BAD_MERIT_{k}")

    def conf():
        c = a.get("confidence_bound")
        if not _is_obj(c):
            _fail("BAD_CONF_TYPE")
        lo = _req(c, "lower")
        hi = _req(c, "upper")
        _req(c, "notes")
        if not (isinstance(lo,(int,float)) and isinstance(hi,(int,float))):
            _fail("BAD_CONF_NUM")
        if lo < 0 or hi > 1 or lo > hi:
            _fail("BAD_CONF_RANGE")

    def lists():
        for k in ("evidence_chain","inference_path","counterarguments","constraints","what_would_change"):
            v = a.get(k)
            if not _is_list(v):
                _fail(f"BAD_LIST_TYPE:{k}")

    chk(root)
    chk(proof)
    chk(merit)
    chk(conf)
    chk(lists)

    return errors


def main() -> None:
    ap = argparse.ArgumentParser(description="Fail-closed validator for StructuredAnswer v1 (stdlib-only).")
    ap.add_argument("path", help="Path to StructuredAnswer JSON")
    args = ap.parse_args()

    p = Path(args.path)
    a = json.loads(p.read_text(encoding="utf-8"))
    errs = validate_structured_answer(a)
    out = {"verdict": "PASS" if not errs else "FAIL", "errors": errs}
    print(json.dumps(out, indent=2, sort_keys=True))
    sys.exit(0 if not errs else 2)


if __name__ == "__main__":
    main()
