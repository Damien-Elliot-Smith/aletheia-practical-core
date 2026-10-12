#!/usr/bin/env python3
"""
tools/gen_sha256sums.py — Regenerate SHA256SUMS.txt from the tracked files.

Lists every file tracked by git (except SHA256SUMS.txt itself), sorted, in
`sha256sum` format, so the result can be checked with `sha256sum -c`.
Untracked files, caches and build output are never listed.

Usage:
    python tools/gen_sha256sums.py           # rewrite SHA256SUMS.txt
    python tools/gen_sha256sums.py --check   # exit 1 if it is out of date
"""
from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SUMS = "SHA256SUMS.txt"


def tracked_files(root: Path = ROOT) -> list[str]:
    out = subprocess.check_output(["git", "ls-files", "-z"], cwd=root)
    return sorted(p for p in out.decode("utf-8").split("\0") if p and p != SUMS)


def render(root: Path = ROOT) -> str:
    lines = []
    for rel in tracked_files(root):
        digest = hashlib.sha256((root / rel).read_bytes()).hexdigest()
        lines.append(f"{digest}  {rel}\n")
    return "".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--check", action="store_true", help="only check, do not write")
    args = ap.parse_args()
    expected = render()
    path = ROOT / SUMS
    if args.check:
        if path.read_text(encoding="utf-8") != expected:
            print(f"{SUMS} is out of date; run: python tools/gen_sha256sums.py", file=sys.stderr)
            return 1
        return 0
    path.write_text(expected, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
