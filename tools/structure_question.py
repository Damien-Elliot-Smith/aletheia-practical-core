#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


_WS = re.compile(r"\s+")


def canonicalize_text(s: str) -> str:
    # Deterministic canonicalization: trim + collapse whitespace
    s = s.strip()
    s = _WS.sub(" ", s)
    return s


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


@dataclass(frozen=True)
class Trigger:
    code: str
    question: str


def detect_ambiguity(canonical: str) -> List[Trigger]:
    s = canonical.lower()
    triggers: List[Trigger] = []

    # 1) Deictic / pronoun-heavy without clear referent (heuristic)
    if re.search(r"\b(it|this|that|they|them|those|these)\b", s) and len(s.split()) < 18:
        triggers.append(Trigger(
            "AMBIG_PRONOUN_REFERENT",
            "What exactly does 'it/this/that/they' refer to here?"
        ))

    # 2) Vague evaluation without criteria
    if re.search(r"\b(best|better|good|bad|safe|unsafe|worth|should)\b", s) and not re.search(r"\b(criteria|metric|constraints|requirements)\b", s):
        triggers.append(Trigger(
            "AMBIG_CRITERIA_MISSING",
            "What criteria should I optimize for (e.g., cost, speed, risk, simplicity)?"
        ))

    # 3) Missing context about scope / environment
    if re.search(r"\b(set up|install|run|build|fix|configure)\b", s) and not re.search(r"\b(android|termux|windows|linux|mac|python)\b", s):
        triggers.append(Trigger(
            "AMBIG_ENVIRONMENT",
            "What environment are you running this on (OS/device), and what exact folder/path?"
        ))

    # 4) Missing target artifact
    if re.search(r"\b(this|that)\b", s) and re.search(r"\b(zip|file|repo|script|code)\b", s) is None:
        triggers.append(Trigger(
            "AMBIG_TARGET_ARTIFACT",
            "What exact file/repo/command are you referring to (name + path), and what output did you get?"
        ))

    # Deterministic order, cap at 3
    # Preserve order added (already deterministic)
    return triggers[:3]


def build_structured_question(raw: str) -> Dict[str, Any]:
    canonical = canonicalize_text(raw)

    triggers = detect_ambiguity(canonical)
    ambiguity_codes = [t.code for t in triggers]
    clarifying_questions = [t.question for t in triggers]

    sq_obj = {
        "schema_version": "1",
        "raw": raw,
        "canonical": canonical,
        "ambiguity_triggers": ambiguity_codes,
        "clarifying_questions": clarifying_questions,
        "term_definitions": [],
    }

    # fingerprint is over canonical form + trigger codes (so it changes when ambiguity changes)
    fp_material = {
        "schema_version": "1",
        "canonical": canonical,
        "ambiguity_triggers": ambiguity_codes,
    }
    sq_obj["question_fingerprint"] = sha256_hex(canonical_json_bytes(fp_material))
    return sq_obj


def main() -> None:
    ap = argparse.ArgumentParser(description="Raw -> StructuredQuestion (deterministic, stdlib-only).")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--text", help="Question text as a single argument.")
    g.add_argument("--file", help="Path to a UTF-8 text file containing the question.")
    args = ap.parse_args()

    if args.text is not None:
        raw = args.text
    else:
        with open(args.file, "r", encoding="utf-8") as f:
            raw = f.read()

    out = build_structured_question(raw)
    print(json.dumps(out, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
