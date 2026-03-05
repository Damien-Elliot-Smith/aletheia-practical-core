import argparse
import json
from pathlib import Path

from .case_reader import CaseReader


def cmd_verify(args: argparse.Namespace) -> int:
    cr = CaseReader(case_zip_path=Path(args.case_zip))
    report = cr.verify(drift_lock=bool(args.drift_lock))

    if args.pretty:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(json.dumps(report, separators=(",", ":"), sort_keys=True))

    return 0 if report.get("status") == "OK" else 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aletheia.detective",
        description="Aletheia Detective (Phase 1+2): read-only case.zip verifier + manifest checks + optional drift-lock.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("verify", help="Verify a case.zip (hashes + manifest + structure)")
    v.add_argument("case_zip", help="Path to a case zip file (case.zip)")
    v.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    v.add_argument(
        "--drift-lock",
        action="store_true",
        help="FAIL if the case is not locked to the same FREEZE.json as this core",
    )
    v.set_defaults(func=cmd_verify)

    return p


def main(argv=None) -> int:
    p = build_parser()
    args = p.parse_args(argv)
    return args.func(args)
