#!/usr/bin/env python3
"""aletheia.py — The one command you need.

Usage:
    python aletheia.py verify  <bundle.zip>
    python aletheia.py demo
    python aletheia.py selfcheck

That's it. Start with 'demo' if this is your first time.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Make the repo importable from any working directory
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


def main() -> None:
    ap = argparse.ArgumentParser(
        prog="aletheia",
        description="Aletheia — deterministic bundle verifier.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python aletheia.py verify  bundle.zip           # verify a bundle
  python aletheia.py verify  bundle.zip --json    # machine-readable JSON
  python aletheia.py demo                         # run the built-in demo
  python aletheia.py selfcheck                    # check the engine is intact
""",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("verify", help="Verify a case bundle zip")
    p.add_argument("bundle", help="Path to bundle.zip")
    p.add_argument("--json", action="store_true", help="Emit raw JSON instead of human report")
    p.add_argument("--strict", action="store_true", help="Enforce driftlock (rejects bundles with unsealed windows)")

    sub.add_parser("demo",      help="Run the built-in demo (good + tampered + hostile cases)")
    sub.add_parser("selfcheck", help="Check that the Aletheia engine itself is intact")

    args = ap.parse_args()

    if args.cmd == "verify":
        from aletheia_verify import run_verify
        rc = run_verify(args.bundle, emit_json=args.json, strict=args.strict)
    elif args.cmd == "demo":
        from aletheia_demo import run_demo
        rc = run_demo()
    elif args.cmd == "selfcheck":
        from aletheia_selfcheck import run_selfcheck
        rc = run_selfcheck()
    else:
        ap.print_help()
        rc = 2

    raise SystemExit(rc)


if __name__ == "__main__":
    main()
