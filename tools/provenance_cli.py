#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

# Reuse existing tools as libraries by importing their core functions where possible.
# Keep stdlib-only. No side effects besides files you explicitly pass in.

from tools.structure_question import build_structured_question
from tools.validate_manifest import validate_manifest
from tools.validate_structured_answer import validate_structured_answer
from tools.make_envelope import (
    compute_envelope_hash,
    compute_input_hash,
    compute_output_hash,
    load_json,
    save_json,
    utc_now_iso,
)


def _die(msg: str, code: int = 2) -> None:
    print(json.dumps({"verdict": "FAIL", "error": msg}, indent=2, sort_keys=True))
    raise SystemExit(code)


def cmd_question(args: argparse.Namespace) -> int:
    sq = build_structured_question(args.text)
    print(json.dumps(sq, indent=2, sort_keys=True))
    return 0


def cmd_validate_manifest(args: argparse.Namespace) -> int:
    data = json.loads(Path(args.path).read_text(encoding="utf-8"))
    errs = validate_manifest(data)
    out = {"verdict": "PASS" if not errs else "FAIL", "errors": errs}
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0 if not errs else 2


def cmd_validate_answer(args: argparse.Namespace) -> int:
    data = json.loads(Path(args.path).read_text(encoding="utf-8"))
    errs = validate_structured_answer(data)
    out = {"verdict": "PASS" if not errs else "FAIL", "errors": errs}
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0 if not errs else 2


def cmd_envelope(args: argparse.Namespace) -> int:
    # Load or build question
    if args.question_json:
        q = load_json(Path(args.question_json))
    else:
        q = build_structured_question(args.question_text)

    a = load_json(Path(args.answer_json))
    m = load_json(Path(args.manifest_json))

    # Fail-closed manifest + answer validation before producing envelope
    m_errs = validate_manifest(m)
    if m_errs:
        _die("MANIFEST_INVALID:" + ";".join(m_errs))

    a_errs = validate_structured_answer(a)
    if a_errs:
        _die("ANSWER_INVALID:" + ";".join(a_errs))

    parent_hash: Optional[str] = None if args.parent_hash == "null" else args.parent_hash.strip()

    env: Dict[str, Any] = {
        "schema_version": "1",
        "envelope_id": args.envelope_id or "manual",   # deterministic default unless user supplies
        "created_utc": utc_now_iso(),
        "parent_hash": parent_hash,
        "manifest_ref": str(Path(args.manifest_json)),
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
    print(json.dumps({"verdict": "PASS", "envelope_hash": env_hash, "out": args.out}, indent=2, sort_keys=True))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    # End-to-end offline run: question text -> sq.json, take SA json -> env.json
    core = Path(args.core_dir).resolve()
    manifest = core / "Provenance_Manifest.json"
    if not manifest.exists():
        _die(f"MISSING_MANIFEST:{manifest}")

    sq_path = Path(args.out_dir) / "sq.json"
    env_path = Path(args.out_dir) / "env.json"

    sq = build_structured_question(args.question)
    sq_path.parent.mkdir(parents=True, exist_ok=True)
    sq_path.write_text(json.dumps(sq, indent=2, sort_keys=True), encoding="utf-8")

    # envelope command
    ns = argparse.Namespace(
        question_json=str(sq_path),
        question_text=None,
        answer_json=args.answer_json,
        manifest_json=str(manifest),
        out=str(env_path),
        parent_hash=args.parent_hash,
        envelope_id=args.envelope_id,
    )
    rc = cmd_envelope(ns)
    if rc != 0:
        return rc
    print(json.dumps({"verdict": "PASS", "sq": str(sq_path), "env": str(env_path)}, indent=2, sort_keys=True))
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(prog="provenance", description="Offline Companion v1 (stdlib-only).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("question", help="Raw -> StructuredQuestion")
    p.add_argument("--text", required=True)
    p.set_defaults(fn=cmd_question)

    p = sub.add_parser("validate-manifest", help="Validate Provenance_Manifest.json")
    p.add_argument("path")
    p.set_defaults(fn=cmd_validate_manifest)

    p = sub.add_parser("validate-answer", help="Validate StructuredAnswer JSON")
    p.add_argument("path")
    p.set_defaults(fn=cmd_validate_answer)

    p = sub.add_parser("envelope", help="Make ProvenanceEnvelope from SQ + SA + Manifest")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--question-json", help="Path to StructuredQuestion JSON")
    g.add_argument("--question-text", help="Raw question text (will be structured)")
    p.add_argument("--answer-json", required=True, help="Path to StructuredAnswer JSON")
    p.add_argument("--manifest-json", required=True, help="Path to Provenance_Manifest.json")
    p.add_argument("--out", required=True, help="Output envelope path")
    p.add_argument("--parent-hash", default="null", help="64hex or 'null'")
    p.add_argument("--envelope-id", default=None, help="Optional deterministic id string")
    p.set_defaults(fn=cmd_envelope)

    p = sub.add_parser("run", help="End-to-end: question text -> sq.json + env.json (offline)")
    p.add_argument("--core-dir", default=".", help="Core dir containing Provenance_Manifest.json")
    p.add_argument("--out-dir", default=".", help="Where to write sq.json and env.json")
    p.add_argument("--question", required=True, help="Raw question text")
    p.add_argument("--answer-json", required=True, help="Path to StructuredAnswer JSON")
    p.add_argument("--parent-hash", default="null", help="64hex or 'null'")
    p.add_argument("--envelope-id", default=None)
    p.set_defaults(fn=cmd_run)

    args = ap.parse_args()
    rc = args.fn(args)
    raise SystemExit(rc)


if __name__ == "__main__":
    main()
