#!/usr/bin/env python3
"""aletheia_selfcheck.py — Engine integrity self-check.

Verifies that the core engine modules are importable and internally consistent.
Does not verify any external bundle — only the engine itself.

Output is human-readable. Exit 0 = all clear, Exit 2 = something wrong.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

_USE_COLOR = sys.stdout.isatty()
def _c(code, t): return f"\033[{code}m{t}\033[0m" if _USE_COLOR else t
def green(t):  return _c("32", t)
def red(t):    return _c("31;1", t)
def yellow(t): return _c("33", t)
def dim(t):    return _c("2", t)
def bold(t):   return _c("1", t)


CHECKS = [
    ("aletheia.detective.reasons",   "Reason code registry"),
    ("aletheia.detective.zipguard",  "ZipGuard (hostile input filter)"),
    ("aletheia.detective.canon",     "Canonical JSON determinism"),
    ("aletheia.detective.hashutil",  "Streaming hash utilities"),
    ("aletheia.detective.limits",    "Input size limits"),
    ("aletheia.detective.case_reader","Case reader"),
    ("aletheia.spine.ledger",        "Spine ledger"),
    ("aletheia.chronicle.export",    "Case zip builder"),
    ("tools.verify_case",            "Core verifier"),
    ("tools.verify_bundle",          "Bundle verifier"),
    ("tools._zip_io",                "Zip I/O guard layer"),
]


def run_selfcheck() -> int:
    W = 62
    print(f"\n  {'═' * W}")
    print(f"  {bold('Aletheia Engine Self-Check')}")
    print(f"  {dim('Checking that all core modules are importable and consistent.')}")
    print(f"  {'─' * W}\n")

    results = []
    for module, label in CHECKS:
        try:
            __import__(module)
            results.append((label, True, None))
            print(f"  {green('✓')}  {label}")
        except Exception as e:
            results.append((label, False, str(e)))
            print(f"  {red('✗')}  {label}")
            print(f"       {dim(str(e)[:80])}")

    # Semantic checks beyond import
    print()
    try:
        from aletheia.detective import reasons as R
        # Outcomes must be exactly this set
        expected = frozenset({"PASS", "FAIL", "ERROR", "INCONCLUSIVE"})
        if R.OUTCOMES == expected:
            print(f"  {green('✓')}  Verdict vocabulary bounded: {sorted(R.OUTCOMES)}")
            results.append(("Verdict vocabulary", True, None))
        else:
            print(f"  {red('✗')}  Verdict vocabulary wrong: {R.OUTCOMES}")
            results.append(("Verdict vocabulary", False, f"got {R.OUTCOMES}"))
    except Exception as e:
        results.append(("Verdict vocabulary", False, str(e)))
        print(f"  {red('✗')}  Could not check verdict vocabulary: {e}")

    try:
        from aletheia.detective.canon import canonical_json_bytes
        a = canonical_json_bytes({"b": 2, "a": 1})
        b = canonical_json_bytes({"a": 1, "b": 2})
        if a == b:
            print(f"  {green('✓')}  canonical_json_bytes is deterministic across key orderings")
            results.append(("Canonical JSON determinism", True, None))
        else:
            print(f"  {red('✗')}  canonical_json_bytes is NOT deterministic")
            results.append(("Canonical JSON determinism", False, "key ordering affects output"))
    except Exception as e:
        results.append(("Canonical JSON determinism", False, str(e)))

    # Summary
    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    failed = [(label, err) for label, ok, err in results if not ok]

    print(f"\n  {'─' * W}")
    if not failed:
        print(f"  {green(bold('PASS'))}  {passed}/{total} checks passed. Engine is intact.")
    else:
        print(f"  {red(bold('FAIL'))}  {passed}/{total} checks passed. {len(failed)} failed:")
        for label, err in failed:
            print(f"       {red('✗')} {label}: {dim(str(err)[:70])}")
    print(f"  {'═' * W}\n")

    return 0 if not failed else 2


if __name__ == "__main__":
    raise SystemExit(run_selfcheck())
