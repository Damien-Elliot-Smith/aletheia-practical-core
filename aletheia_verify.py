#!/usr/bin/env python3
"""aletheia_verify.py — Human-readable verify output.

A tired operator can understand the result in 30 seconds.

Design rules:
  - Verdict on line 1, always
  - Blocking reasons immediately after verdict
  - Warnings separated from failures
  - "What was checked" section — no surprises
  - "What was NOT checked" — trust boundary visible
  - Next action stated explicitly
  - JSON mode available for machines
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


# ── Terminal colours (disabled if not a tty) ─────────────────────────────────
_USE_COLOR = sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"

def green(t):  return _c("32", t)
def red(t):    return _c("31;1", t)
def yellow(t): return _c("33", t)
def dim(t):    return _c("2", t)
def bold(t):   return _c("1", t)
def cyan(t):   return _c("36", t)


# ── Verdict rendering ─────────────────────────────────────────────────────────

VERDICT_DISPLAY = {
    "PASS":         ("✓  PASS",         green),
    "FAIL":         ("✗  FAIL",         red),
    "ERROR":        ("⚠  ERROR",        yellow),
    "INCONCLUSIVE": ("?  INCONCLUSIVE", yellow),
}

VERDICT_MEANING = {
    "PASS": "All checks passed. The bundle is intact as captured.",
    "FAIL": "A check failed. The bundle has been tampered with or is corrupted.",
    "ERROR": "The verifier could not complete. The input may be malformed.",
    "INCONCLUSIVE": "Checks could not produce a definitive result.",
}

CHECK_LABELS = {
    "ZIP_GUARD":          "Zip structure safety",
    "DETECTIVE_VERIFY":   "Manifest + hash integrity",
    "DRIFTLOCK":          "Drift lock (engine version)",
    "REPLAY":             "Replay integrity",
    "CONSTRAINTS_LINKAGE":"Constraint linkage",
    "ZIP_GUARD_REQUIRED": "Zip guard gate",
    "STRICT_POLICY":      "Strict mode policy",
}

REASON_EXPLANATIONS = {
    "ERR_BAD_ZIP":              "The zip file is corrupt or truncated.",
    "ERR_PATH_TRAVERSAL":       "The zip contains an unsafe path (path traversal attack).",
    "ERR_SYMLINK":              "The zip contains a symlink, which is not permitted.",
    "ERR_FILE_COUNT_LIMIT":     "The zip contains too many files.",
    "ERR_SIZE_LIMIT":           "A file in the zip exceeds the size limit.",
    "ERR_HASH_MISMATCH":        "A file's content does not match its recorded hash.",
    "ERR_CHAIN_BREAK":          "The hash chain is broken — events are not contiguous.",
    "ERR_MANIFEST_MISSING":     "The case manifest is missing from the bundle.",
    "ERR_DRIFT_NO_WINDOWS":     "No sealed windows found — drift check could not run.",
    "FILE_HASH_MISMATCH":       "One or more files do not match their recorded hashes.",
    "MISSING_FILES":            "Files listed in the manifest are absent from the bundle.",
    "WINDOW_VERIFY_FAILED":     "A sealed event window failed its chain verification.",
    "NO_MANIFEST":              "No case_manifest.json found in the bundle.",
    "MISSING_verify_report_sha256": "The manifest is missing the verify_report hash.",
    "MISSING_VERIFY_REPORT":    "evidence/verify_report.json is missing from the bundle.",
    "VERIFY_REPORT_HASH_MISMATCH": "The verify report has been altered since capture.",
}


def _explain_reason(reason: str) -> str:
    return REASON_EXPLANATIONS.get(reason, f"Reason code: {reason}")


def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ── Core render ───────────────────────────────────────────────────────────────

def render_human_report(raw: Dict[str, Any], bundle_path: str) -> str:
    """Render a verify_bundle report as a human-readable 30-second decision surface."""
    lines: List[str] = []
    W = 62

    def rule(char="─"): lines.append(dim(char * W))
    def blank(): lines.append("")

    overall = raw.get("overall_verdict", "ERROR")
    checks = raw.get("checks", [])

    # ── Header ────────────────────────────────────────────────────────────────
    blank()
    rule("═")
    label, colour_fn = VERDICT_DISPLAY.get(overall, ("?  UNKNOWN", yellow))
    lines.append(f"  {colour_fn(bold(label))}")
    lines.append(f"  {dim(VERDICT_MEANING.get(overall, ''))}")
    rule("═")
    blank()

    # ── Bundle info ───────────────────────────────────────────────────────────
    lines.append(f"  {dim('Bundle')}   {Path(bundle_path).name}")
    case_id = None
    for c in checks:
        ci = (c.get("details") or {}).get("case_id")
        if ci:
            case_id = ci
            break
    if case_id:
        lines.append(f"  {dim('Case ID')}  {case_id}")
    lines.append(f"  {dim('Verified')} {_now_utc()}")
    blank()

    # ── Blocking failures ─────────────────────────────────────────────────────
    failures = [c for c in checks if c.get("verdict") in ("FAIL", "ERROR")]
    if failures:
        rule()
        lines.append(f"  {red('BLOCKING ISSUES')}")
        blank()
        for c in failures:
            cid = c.get("check_id", "?")
            reason = c.get("reason", "")
            label_str = CHECK_LABELS.get(cid, cid)
            v = c.get("verdict")
            verdict_str = red("FAIL") if v == "FAIL" else yellow("ERROR")
            lines.append(f"  {verdict_str}  {bold(label_str)}")
            lines.append(f"       {_explain_reason(reason)}")
            # Surface specific detail (hash mismatches, missing files)
            det = c.get("details") or {}
            mismatches = det.get("hash_mismatches") or []
            missing = det.get("missing_files") or []
            wfails = det.get("window_failures") or []
            for m in mismatches[:3]:
                lines.append(f"       {dim('file:')} {m.get('zip_path', '?')}")
                lines.append(f"       {dim('  expected:')} {str(m.get('expected_sha256',''))[:16]}…")
                lines.append(f"       {dim('  got:     ')} {str(m.get('got_sha256',''))[:16]}…")
            if len(mismatches) > 3:
                lines.append(f"       {dim(f'  … and {len(mismatches)-3} more')}")
            for mf in missing[:3]:
                lines.append(f"       {dim('missing:')} {mf}")
            for wf in wfails[:2]:
                lines.append(f"       {dim('window:')} {wf.get('window_id','?')} — {wf.get('error','?')}")
            blank()

    # ── Warnings (INCONCLUSIVE) ────────────────────────────────────────────────
    warnings = [c for c in checks if c.get("verdict") == "INCONCLUSIVE"]
    if warnings:
        rule()
        lines.append(f"  {yellow('WARNINGS')}")
        blank()
        for c in warnings:
            cid = c.get("check_id", "?")
            reason = c.get("reason", "")
            label_str = CHECK_LABELS.get(cid, cid)
            lines.append(f"  {yellow('?')}  {label_str}")
            lines.append(f"       {_explain_reason(reason)}")
            blank()

    # ── What was checked ──────────────────────────────────────────────────────
    rule()
    lines.append(f"  {dim('WHAT WAS CHECKED')}")
    blank()
    passed = [c for c in checks if c.get("verdict") == "PASS"]
    for c in passed:
        cid = c.get("check_id", "?")
        lines.append(f"  {green('✓')}  {CHECK_LABELS.get(cid, cid)}")
    for c in failures:
        cid = c.get("check_id", "?")
        lines.append(f"  {red('✗')}  {CHECK_LABELS.get(cid, cid)}")
    for c in warnings:
        cid = c.get("check_id", "?")
        lines.append(f"  {yellow('?')}  {CHECK_LABELS.get(cid, cid)} (inconclusive)")
    blank()

    # ── What was NOT checked ──────────────────────────────────────────────────
    rule()
    lines.append(f"  {dim('WHAT THIS DOES NOT VERIFY')}")
    blank()
    lines.append(f"  {dim('·')}  Whether the original content was true or accurate")
    lines.append(f"  {dim('·')}  Whether the operator who captured it was honest")
    lines.append(f"  {dim('·')}  Whether the capturing machine was compromised")
    lines.append(f"  {dim('·')}  Whether all relevant evidence was captured")
    lines.append(f"  {dim('·')}  Legal chain of custody before ingestion")
    blank()

    # ── Next action ───────────────────────────────────────────────────────────
    rule()
    if overall == "PASS":
        lines.append(f"  {green('NEXT')}  Bundle is intact. Safe to use.")
    elif overall == "FAIL":
        lines.append(f"  {red('NEXT')}  Do not use this bundle. Investigate the issues above.")
    elif overall == "ERROR":
        lines.append(f"  {yellow('NEXT')}  Check that the input file is a valid Aletheia bundle.")
    else:
        lines.append(f"  {yellow('NEXT')}  Retry verification or escalate for manual inspection.")
    blank()

    # ── Independent re-check ─────────────────────────────────────────────────
    lines.append(f"  {dim('To independently re-check:')}")
    lines.append(f"  {dim('  python aletheia.py verify ' + bundle_path)}")
    lines.append(f"  {dim('  python tools/verify_case.py ' + bundle_path + '  (stdlib only)')}")
    blank()
    rule("═")
    blank()

    return "\n".join(lines)


# ── Entry ─────────────────────────────────────────────────────────────────────

def run_verify(bundle_path: str, emit_json: bool = False, strict: bool = False) -> int:
    """Run verify and return exit code. 0=PASS, 2=FAIL/ERROR."""
    p = Path(bundle_path)
    if not p.exists():
        if emit_json:
            print(json.dumps({"overall_verdict": "ERROR", "error": f"File not found: {bundle_path}",
                               "report_type": "verify_bundle_report", "report_version": "1.1",
                               "checks": []}, indent=2, sort_keys=True))
        else:
            print(f"\n  {red('ERROR')}  File not found: {bundle_path}\n")
        return 2

    # Delegate to existing verify_bundle
    from tools.verify_bundle import main as _vb_main
    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    try:
        argv = [str(p), "--pretty"]
        if strict:
            argv.append("--strict")
        with redirect_stdout(buf):
            _rc = _vb_main(argv)
    except SystemExit as e:
        _rc = int(e.code) if e.code is not None else 0

    raw_output = buf.getvalue().strip()

    try:
        raw = json.loads(raw_output)
    except json.JSONDecodeError:
        raw = {"overall_verdict": "ERROR", "checks": [], "report_type": "verify_bundle_report",
               "report_version": "1.1", "error": "verify produced unparseable output"}
        _rc = 2

    if emit_json:
        print(json.dumps(raw, indent=2, sort_keys=True))
    else:
        print(render_human_report(raw, bundle_path))

    overall = raw.get("overall_verdict", "ERROR")
    return 0 if overall == "PASS" else 2


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("bundle")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args()
    raise SystemExit(run_verify(args.bundle, emit_json=args.json, strict=args.strict))
