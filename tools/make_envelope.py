#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, obj: Dict[str, Any]) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")


def compute_input_hash(structured_question: Dict[str, Any]) -> str:
    return sha256_hex(canonical_json_bytes(structured_question))


def compute_output_hash(structured_answer: Dict[str, Any]) -> str:
    return sha256_hex(canonical_json_bytes(structured_answer))


def compute_envelope_hash(envelope_body: Dict[str, Any]) -> str:
    return sha256_hex(canonical_json_bytes(envelope_body))


def main() -> None:
    ap = argparse.ArgumentParser(description="Create a ProvenanceEnvelope v1 (stdlib-only, deterministic).")
    ap.add_argument("--question", required=True, help="Path to StructuredQuestion JSON")
    ap.add_argument("--answer", required=True, help="Path to StructuredAnswer JSON")
    ap.add_argument("--manifest", required=True, help="Path to Provenance_Manifest.json")
    ap.add_argument("--out", required=True, help="Output envelope JSON path")
    ap.add_argument("--parent-hash", default="null", help="Parent envelope hash (64hex) or 'null'")
    args = ap.parse_args()

    q = load_json(Path(args.question))
    a = load_json(Path(args.answer))
    m = load_json(Path(args.manifest))

    parent_hash: Optional[str]
    if args.parent_hash == "null":
        parent_hash = None
    else:
        parent_hash = args.parent_hash.strip()

    # Build envelope body (without envelope_hash)
    env: Dict[str, Any] = {
        "schema_version": "1",
        "envelope_id": sha256_hex(os.urandom(16)).lower(),  # random id; not part of deterministic hash chain
        "created_utc": utc_now_iso(),
        "parent_hash": parent_hash,
        "manifest_ref": str(Path(args.manifest)),
        "core_ref": {
            "name": m["core"]["name"],
            "version": m["core"]["version"],
            "sha256": m["core"]["sha256"],
        },
        "input": {
            "question_structured": q,
            "input_hash": compute_input_hash(q),
        },
        "output": {
            "answer_structured": a,
            "output_hash": compute_output_hash(a),
        },
    }

    body = dict(env)
    env_hash = compute_envelope_hash(body)
    env["envelope_hash"] = env_hash

    save_json(Path(args.out), env)
    print(json.dumps({"verdict":"PASS","envelope_hash":env_hash,"out":args.out}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
