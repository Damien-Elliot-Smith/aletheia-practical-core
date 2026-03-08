#!/usr/bin/env python3
"""aletheia_demo.py — Built-in evaluator demo.

Runs three cases in sequence:
  1. Good bundle    → expects PASS
  2. Tampered bundle → expects FAIL
  3. Corrupt bundle  → expects ERROR

A stranger can run this cold and understand the system in under 5 minutes.
Exit 0 = all outcomes matched. Exit 2 = something unexpected happened.
"""
from __future__ import annotations

import io
import json
import sys
import tempfile
import zipfile
import hashlib
from contextlib import redirect_stdout
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
def cyan(t):   return _c("36", t)


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _make_good_case(td: Path) -> Path:
    """Build a clean valid case from the live stack."""
    from aletheia.spine.ledger import SpineLedger
    from aletheia.chronicle.export import build_case_zip
    root = td / "root_good"; root.mkdir()
    led = SpineLedger(root)
    led.open_window("main")
    led.append_event("main", "WITNESS", {"content": "Example evidence payload"})
    led.seal_window("main")
    led.close_clean()
    out = td / "demo_good.zip"
    build_case_zip(root, out)
    return out


def _make_tampered_case(td: Path, good_zip: Path) -> Path:
    """Flip a single byte in an evidence file — simulates post-capture tampering."""
    out = td / "demo_tampered.zip"
    with zipfile.ZipFile(str(good_zip), "r") as zin, \
         zipfile.ZipFile(str(out), "w", compression=zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if (item.filename.endswith(".json")
                    and "events" in item.filename
                    and len(data) > 20):
                try:
                    obj = json.loads(data.decode("utf-8"))
                    if "payload" in obj:
                        obj["payload"]["content"] = "TAMPERED — content altered after capture"
                        data = json.dumps(obj, sort_keys=True).encode("utf-8")
                except (json.JSONDecodeError, TypeError):
                    data = data[:-4] + b"XXXX"  # fallback: flip last bytes
            zout.writestr(item, data)
    return out


def _make_corrupt_case(td: Path) -> Path:
    """Write a file that looks like a zip but isn't."""
    out = td / "demo_corrupt.zip"
    out.write_bytes(b"PK\x03\x04" + b"\x00" * 50 + b"this is not a real zip file")
    return out


def _run_verify_json(zip_path: str) -> dict:
    buf = io.StringIO()
    from tools.verify_bundle import main as vb_main
    with redirect_stdout(buf):
        try:
            vb_main([zip_path, "--pretty"])
        except SystemExit:
            pass
    try:
        return json.loads(buf.getvalue())
    except json.JSONDecodeError:
        return {"overall_verdict": "ERROR", "checks": [], "error": "unparseable output"}


def _print_case_result(label: str, description: str, zip_path: str,
                       expected: str, result: dict) -> bool:
    W = 62
    actual = result.get("overall_verdict", "ERROR")
    matched = actual == expected

    # Header
    print(f"\n  {bold(label)}")
    print(f"  {dim(description)}")
    print(f"  {dim('─' * (W - 2))}")

    # Result
    verdict_colours = {"PASS": green, "FAIL": red, "ERROR": yellow, "INCONCLUSIVE": yellow}
    vfn = verdict_colours.get(actual, yellow)
    efn = verdict_colours.get(expected, yellow)

    print(f"  Expected   {efn(expected)}")
    print(f"  Got        {vfn(actual)}", end="")

    if matched:
        print(f"  {green('✓ correct')}")
    else:
        print(f"  {red('✗ UNEXPECTED')}")

    # Show blocking issues if any
    failures = [c for c in result.get("checks", []) if c.get("verdict") in ("FAIL", "ERROR")]
    if failures:
        from aletheia_verify import REASON_EXPLANATIONS, CHECK_LABELS
        for c in failures[:2]:
            cid = CHECK_LABELS.get(c.get("check_id", "?"), c.get("check_id", "?"))
            reason = c.get("reason", "")
            explanation = REASON_EXPLANATIONS.get(reason, reason)
            print(f"  {dim('Issue')}     {cid}: {explanation}")

    return matched


def run_demo() -> int:
    W = 62
    print(f"\n  {'═' * W}")
    print(f"  {bold('Aletheia Demo — Three Cases')}")
    print(f"  {dim('Each case tests a different scenario.')}")
    print(f"  {dim('A correct result means the expected outcome was produced.')}")
    print(f"  {'═' * W}")

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        all_pass = True

        # ── Case 1: Good bundle ───────────────────────────────────────────────
        print(f"\n  {cyan('Case 1 of 3 — Known-good bundle')}")
        try:
            good_zip = _make_good_case(td)
            result = _run_verify_json(str(good_zip))
            ok = _print_case_result(
                "Case 1: Known-good",
                "A freshly built bundle — nothing touched after capture.",
                str(good_zip), "PASS", result,
            )
            if not ok:
                all_pass = False
        except Exception as e:
            print(f"  {red('ERROR')} building good case: {e}")
            all_pass = False

        # ── Case 2: Tampered bundle ───────────────────────────────────────────
        print(f"\n  {cyan('Case 2 of 3 — Tampered bundle')}")
        try:
            from aletheia.spine.ledger import SpineLedger
            from aletheia.chronicle.export import build_case_zip
            root2 = td / "root_tamper"; root2.mkdir(exist_ok=True)
            led2 = SpineLedger(root2)
            led2.open_window("main")
            led2.append_event("main", "WITNESS", {"content": "Evidence payload for tamper test"})
            led2.seal_window("main")
            led2.close_clean()
            good_zip_for_tamper = td / "good2.zip"
            build_case_zip(root2, good_zip_for_tamper)
            tampered_zip = _make_tampered_case(td, good_zip_for_tamper)
            result = _run_verify_json(str(tampered_zip))
            ok = _print_case_result(
                "Case 2: Tampered",
                "An evidence file was modified after the bundle was sealed.",
                str(tampered_zip), "FAIL", result,
            )
            if not ok:
                all_pass = False
        except Exception as e:
            print(f"  {red('ERROR')} building tampered case: {e}")
            all_pass = False

        # ── Case 3: Corrupt bundle ────────────────────────────────────────────
        print(f"\n  {cyan('Case 3 of 3 — Corrupt/malformed bundle')}")
        try:
            corrupt_zip = _make_corrupt_case(td)
            result = _run_verify_json(str(corrupt_zip))
            ok = _print_case_result(
                "Case 3: Corrupt input",
                "A truncated file that isn't a valid zip.",
                str(corrupt_zip), "ERROR", result,
            )
            if not ok:
                all_pass = False
        except Exception as e:
            print(f"  {red('ERROR')} building corrupt case: {e}")
            all_pass = False

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n  {'─' * W}")
    if all_pass:
        print(f"  {green('All three cases produced the expected outcome.')}")
        print(f"  {dim('Aletheia is working correctly.')}")
    else:
        print(f"  {red('One or more cases did not produce the expected outcome.')}")
        print(f"  {dim('Run: python aletheia.py selfcheck to inspect the engine.')}")

    # ── What this demo proves and doesn't prove ───────────────────────────────
    print(f"\n  {'─' * W}")
    print(f"  {dim('What this demo shows:')}")
    print(f"  {dim('  · Aletheia detects when a bundle is intact')}")
    print(f"  {dim('  · Aletheia detects tampering after capture')}")
    print(f"  {dim('  · Aletheia handles corrupt inputs without crashing')}")
    print(f"\n  {dim('What this demo does not show:')}")
    print(f"  {dim('  · Whether the content captured was originally true')}")
    print(f"  {dim('  · Whether the operator who built the bundle was honest')}")
    print(f"  {dim('  · Whether the machine that ran Aletheia was compromised')}")

    print(f"\n  {'═' * W}\n")

    return 0 if all_pass else 2


if __name__ == "__main__":
    raise SystemExit(run_demo())
