#!/usr/bin/env python3
"""verify_bundle.py

One-command verifier for Aletheia case zips.

Phase B1: ZIP IO must be structurally verified before reads (tools._zip_io).
Phase A2: Output is schema-locked: report_type/report_version/overall_verdict.
Phone-friendly: no subprocess, no heavy scanning.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from aletheia.detective.case_reader import CaseReader
from aletheia.detective import reasons as R
from tools._zip_io import open_zip_verified


def _first_reason(reasons: Any) -> str:
    if isinstance(reasons, list) and reasons:
        return str(reasons[0])
    return "OK"


def _reason_for_verdict(verdict: str, reasons: Any) -> str:
    r0 = _first_reason(reasons)
    if verdict in ("FAIL", "ERROR") and r0 == "OK":
        return R.ERR_INTERNAL
    return r0


def _emit(report: Dict[str, Any], pretty: bool) -> None:
    if pretty:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(json.dumps(report, sort_keys=True))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="One-command verifier for Aletheia case zips (bundle = case.zip)."
    )
    ap.add_argument("case_zip", help="Path to case zip (case.zip)")
    ap.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    ap.add_argument(
        "--strict",
        action="store_true",
        help="Enable drift-lock policy (enforce driftlock when sealed windows exist).",
    )
    args = ap.parse_args(argv)

    case_path = str(Path(args.case_zip).expanduser())

    report: Dict[str, Any] = {
        "report_type": "verify_bundle_report",
        "report_version": "1.0",
        "bundle_path": case_path,
        "overall_verdict": "ERROR",
        "checks": [],
    }

    # ---- Phase B1: ZIP_GUARD (REQUIRED) ----
    zg = open_zip_verified(case_path)
    report["checks"].append(
        {
            "check_id": "ZIP_GUARD",
            "verdict": zg.verdict,
            "reason": zg.reason,
            "details": {"members": zg.members, **({"detail": zg.detail} if zg.detail else {})},
        }
    )

    if zg.verdict != "PASS":
        # Hard stop: do not read anything else.
        report["checks"].append(
            {
                "check_id": "ZIP_GUARD_REQUIRED",
                "verdict": "ERROR",
                "reason": zg.reason if zg.reason else R.ERR_BAD_ZIP,
                "details": {"zip_guard_verdict": zg.verdict},
            }
        )
        report["overall_verdict"] = "ERROR"
        _emit(report, pretty=args.pretty)
        return 2

    # ---- Detective verify (core) ----
    cr = CaseReader(case_zip_path=Path(case_path))
    raw = cr.verify(drift_lock=False)  # we apply strict policy below, not inside core call

    got_verdict = raw.get("verdict") or "ERROR"
    report["checks"].append(
        {
            "check_id": "DETECTIVE_VERIFY",
            "verdict": got_verdict,
            "reason": _reason_for_verdict(got_verdict, raw.get("reasons")),
            "details": {
                "case_id": raw.get("case_id"),
                "status": raw.get("status"),
            "detail": raw.get("reason"),
                "missing_files": raw.get("missing_files", []),
                "hash_mismatches": raw.get("hash_mismatches", []),
                "window_failures": raw.get("window_failures", []),
            },
        }
    )

    # ---- Driftlock info (derived) ----
    drift = raw.get("driftlock") or {}
    sealed = drift.get("sealed_windows") or []
    drift_verdict = drift.get("verdict", "INCONCLUSIVE")
    drift_reason = _reason_for_verdict(str(drift_verdict), drift.get("reasons"))
    report["checks"].append(
        {
            "check_id": "DRIFTLOCK",
            "verdict": drift_verdict,
            "reason": drift_reason,
            "details": {
                "sealed_windows_count": len(sealed),
                "drift_signature": drift.get("drift_signature"),
            },
        }
    )

    # ---- Overall verdict policy ----
    overall = got_verdict

    # Strict policy: ONLY enforce driftlock when windows exist.
    if args.strict and len(sealed) > 0 and drift_verdict != "PASS":
        overall = "FAIL"
        report["checks"].append(
            {
                "check_id": "STRICT_POLICY",
                "verdict": "FAIL",
                "reason": "STRICT_DRIFTLOCK_REQUIRED",
                "details": {"sealed_windows_count": len(sealed), "driftlock_verdict": drift_verdict},
            }
        )

    report["overall_verdict"] = overall
    # A2: reclassify detective ERROR detail
    for c in report.get('checks', []) or []:
        if c.get('check_id') != 'DETECTIVE_VERIFY':
            continue
        if c.get('verdict') != 'ERROR':
            continue
        det = c.get('details') or {}
        detail = str(det.get('detail') or det.get('reason') or '')
        low = detail.lower()
        if ('zip corruption' in low) or ('badzipfile' in low) or ('crc' in low):
            c['reason'] = 'ERR_BAD_ZIP'

    _emit(report, pretty=args.pretty)

    return 0 if report["overall_verdict"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
