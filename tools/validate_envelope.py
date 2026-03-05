#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ValidationError(Exception):
    pass


def _fail(msg: str) -> None:
    raise ValidationError(msg)


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_envelope(e: Dict[str, Any]) -> List[str]:
    errs: List[str] = []

    def chk(fn):
        try:
            fn()
        except ValidationError as ex:
            errs.append(str(ex))

    def root():
        if not isinstance(e, dict):
            _fail("NOT_OBJECT")
        if e.get("schema_version") != "1":
            _fail("BAD_SCHEMA_VERSION")
        for k in ("envelope_id","created_utc","manifest_ref","core_ref","input","output","envelope_hash"):
            if k not in e:
                _fail(f"MISSING_KEY:{k}")
        ph = e.get("parent_hash")
        if ph is not None and ph != "null":
            if not isinstance(ph, str) or not HEX64.match(ph):
                _fail("BAD_PARENT_HASH")

    def hashes():
        # recompute input/output/envelope hashes deterministically
        inp = e["input"]["question_structured"]
        outp = e["output"]["answer_structured"]
        got_in = e["input"].get("input_hash")
        got_out = e["output"].get("output_hash")
        if not (isinstance(got_in,str) and HEX64.match(got_in)):
            _fail("BAD_INPUT_HASH")
        if not (isinstance(got_out,str) and HEX64.match(got_out)):
            _fail("BAD_OUTPUT_HASH")
        exp_in = sha256_hex(canonical_json_bytes(inp))
        exp_out = sha256_hex(canonical_json_bytes(outp))
        if exp_in != got_in:
            _fail("INPUT_HASH_MISMATCH")
        if exp_out != got_out:
            _fail("OUTPUT_HASH_MISMATCH")

        got_env = e.get("envelope_hash")
        if not (isinstance(got_env,str) and HEX64.match(got_env)):
            _fail("BAD_ENVELOPE_HASH")
        body = dict(e)
        body.pop("envelope_hash", None)
        exp_env = sha256_hex(canonical_json_bytes(body))
        if exp_env != got_env:
            _fail("ENVELOPE_HASH_MISMATCH")

    chk(root)
    chk(hashes)
    return errs


def main() -> None:
    ap = argparse.ArgumentParser(description="Validate ProvenanceEnvelope v1 (stdlib-only, fail-closed).")
    ap.add_argument("path", help="Path to envelope JSON")
    args = ap.parse_args()
    e = load_json(Path(args.path))
    errs = validate_envelope(e)
    out = {"verdict": "PASS" if not errs else "FAIL", "errors": errs}
    print(json.dumps(out, indent=2, sort_keys=True))
    sys.exit(0 if not errs else 2)


if __name__ == "__main__":
    main()
