#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

def _classify_corruption(text: str | None) -> str | None:
    if not text:
        return None
    low = text.lower()
    if "zip corruption" in low or "badzipfile" in low or "crc" in low:
        return "ERR_BAD_ZIP"
    return None



def _run_verify_bundle(core_dir: Path, case_zip: Path, strict: bool) -> dict:
    cmd = [sys.executable, str(core_dir / "tools" / "verify_bundle.py"), str(case_zip)]
    if strict:
        cmd.append("--strict")
    p = subprocess.run(cmd, capture_output=True, text=True)
    out = (p.stdout or "").strip()
    if not out:
        raise SystemExit(
            f"[ui_verify] verify_bundle produced no output. rc={p.returncode}\n{p.stderr}"
        )
    try:
        return json.loads(out)
    except Exception:
        raise SystemExit(
            f"[ui_verify] verify_bundle output was not JSON:\n{out}\n\nstderr:\n{p.stderr}"
        )



def _peek_detective_reason(case_zip: str) -> str | None:
    """
    If verify_bundle loses the underlying reason, we peek detective directly.
    This is only used for the ERROR/ERR_INTERNAL case.
    """
    try:
        cmd = [sys.executable, "-m", "aletheia.detective", "verify", case_zip]
        p = subprocess.run(cmd, capture_output=True, text=True)
        out = (p.stdout or "").strip()
        if not out:
            return None
        data = json.loads(out)
        r = data.get("reason")
        return str(r) if r else None
    except Exception:
        return None

def _pick(checks: list[dict], check_id: str) -> dict | None:
    for c in checks:
        if c.get("check_id") == check_id:
            return c
    return None


def _print_summary(report: dict) -> None:
    overall = report.get("overall_verdict", "ERROR")
    bundle = report.get("bundle_path", "")
    checks = report.get("checks", []) or []

    zg = _pick(checks, "ZIP_GUARD")
    dv = _pick(checks, "DETECTIVE_VERIFY")
    dl = _pick(checks, "DRIFTLOCK")

    def fmt(c: dict | None) -> str:
        if not c:
            return "MISSING"
        v = c.get("verdict", "ERROR")
        r = c.get("reason", "")
        return f"{v}" + (f" ({r})" if r else "")

    print("Aletheia Verify (UI)")
    print(f"  bundle:  {bundle}")
    print(f"  overall: {overall}")
    print("")
    print("Checks:")
    print(f"  ZIP_GUARD:        {fmt(zg)}")
    print(f"  DETECTIVE_VERIFY: {fmt(dv)}")
    print(f"  DRIFTLOCK:        {fmt(dl)}")

    if dv and dv.get("verdict") in ("FAIL", "ERROR"):
        det = dv.get("details") or {}
        hm = det.get("hash_mismatches") or []
        mf = det.get("missing_files") or []

        print("")
        print("Top issue:")

        if hm:
            one = hm[0]
            print(f"  HASH_MISMATCH: {one.get('zip_path')}")
            return

        if mf:
            print(f"  MISSING_FILE: {mf[0]}")
            return

        # Try corruption classification from the detective detail string
        detail_text = str(det.get("detail") or "")
        corr = _classify_corruption(detail_text)
        if corr:
            print(f"  {corr}: {detail_text}".rstrip())
            return

        # Final fallback
        print(f"  {dv.get('reason','ERR')}")
        return
    return



def main() -> int:
    ap = argparse.ArgumentParser(description="Friendly UI wrapper for tools/verify_bundle.py")
    ap.add_argument("case_zip", help="Path to case.zip")
    ap.add_argument("--strict", action="store_true", help="Enable drift-lock enforcement")
    ap.add_argument("--json", action="store_true", help="Print full JSON (pretty)")
    args = ap.parse_args()

    core_dir = Path(__file__).resolve().parents[1]
    case_zip = Path(args.case_zip).resolve()

    report = _run_verify_bundle(core_dir, case_zip, strict=bool(args.strict))

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        _print_summary(report)

    ov = report.get("overall_verdict", "ERROR")
    return 0 if ov == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
