#!/usr/bin/env python3
"""
tools/validate_repo.py — One-command repository validation.

Runs the full validation sequence:
  1. Engine self-check (all core modules importable and consistent)
  2. Core test suite (257 tests)
  3. Adversarial test suite (461 tests)
  4. Example case verification (known-good, tampered, corrupt)

Exit 0 = all passed. Exit 1 = something failed.

Usage:
    python tools/validate_repo.py
    python tools/validate_repo.py --quick   # skip adversarial suite
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYTHON = sys.executable

_USE_COLOR = sys.stdout.isatty()
def _c(code, t): return f"\033[{code}m{t}\033[0m" if _USE_COLOR else t
def green(t):  return _c("32", t)
def red(t):    return _c("31;1", t)
def bold(t):   return _c("1", t)
def dim(t):    return _c("2", t)


def run(label: str, cmd: list, cwd=ROOT) -> bool:
    """Run a command, print status. Returns True on success."""
    print(f"\n  {dim('▸')} {label}...", flush=True)
    t0 = time.monotonic()
    r = subprocess.run(cmd, cwd=str(cwd))
    elapsed = time.monotonic() - t0
    if r.returncode == 0:
        print(f"    {green('✓')} {label}  {dim(f'({elapsed:.1f}s)')}")
        return True
    else:
        print(f"    {red('✗')} {label} FAILED  (exit {r.returncode})")
        return False


def run_verify(label: str, path: str, expected: str) -> bool:
    """Run aletheia_verify and check the expected verdict appears in output."""
    print(f"\n  {dim('▸')} {label}...", flush=True)
    r = subprocess.run(
        [PYTHON, str(ROOT / "aletheia_verify.py"), path],
        cwd=str(ROOT), capture_output=True, text=True,
    )
    output = r.stdout + r.stderr
    if expected in output:
        print(f"    {green('✓')} {label}  ({expected})")
        return True
    else:
        print(f"    {red('✗')} {label}  expected {expected!r}, got:\n{output[:400]}")
        return False


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Aletheia repository validator")
    ap.add_argument("--quick", action="store_true",
                    help="Skip adversarial suite (faster)")
    args = ap.parse_args(argv)

    W = 62
    print(f"\n  {'═' * W}")
    print(f"  {bold('Aletheia Repository Validation')}")
    print(f"  {dim('Runs selfcheck → tests → examples → PASS/FAIL')}")
    print(f"  {'─' * W}")

    steps = []

    # 1. Engine self-check
    steps.append(run(
        "Engine self-check",
        [PYTHON, str(ROOT / "aletheia_selfcheck.py")],
    ))

    # 2. Core test suite
    steps.append(run(
        "Core tests (tests/)",
        [PYTHON, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v"],
    ))

    # 3. Adversarial suite (optional)
    if not args.quick:
        steps.append(run(
            "Adversarial tests (tests_adversarial/)",
            [PYTHON, "-m", "unittest", "discover",
             "-s", "tests_adversarial", "-p", "test_*.py"],
        ))

    # 4. Example verification
    examples = ROOT / "examples"
    if (examples / "case_boundary_test.zip").exists():
        steps.append(run_verify(
            "Example: case_boundary_test.zip",
            str(examples / "case_boundary_test.zip"),
            "PASS",
        ))
    if (examples / "case_boundary_test_TAMPER2.zip").exists():
        steps.append(run_verify(
            "Example: case_boundary_test_TAMPER2.zip (expect FAIL)",
            str(examples / "case_boundary_test_TAMPER2.zip"),
            "FAIL",
        ))

    # Summary
    passed = sum(steps)
    total = len(steps)
    print(f"\n  {'─' * W}")
    if passed == total:
        print(f"  {green(bold('PASS'))}  {passed}/{total} steps passed.")
        print(f"  {dim('Repository is handoff-ready.')}")
    else:
        print(f"  {red(bold('FAIL'))}  {passed}/{total} steps passed. "
              f"{total - passed} step(s) failed.")
    print(f"  {'═' * W}\n")

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
