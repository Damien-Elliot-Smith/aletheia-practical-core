"""
tools/adapter_selfcheck.py — Adapter Self-Check and Version Fingerprint (Phase 10)

Runs a known-answer test for each registered adapter to verify:
  - The adapter is registered and importable.
  - The adapter version matches the expected value.
  - A clean input produces the expected status (ACCEPTED or ACCEPTED_WITH_LOSS).
  - A hostile input produces REJECTED / HOSTILE.
  - The input_hash is a 64-char hex string (SHA256 format).

Usage:
  python tools/adapter_selfcheck.py
  python tools/adapter_selfcheck.py --json

Exit codes:
  0  All checks passed.
  1  One or more checks failed.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

_HERE = Path(__file__).resolve().parent.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import aletheia.adapters.json_adapter
import aletheia.adapters.file_adapter
import aletheia.adapters.ai_audit_adapter
import aletheia.adapters.ot_adapter
import aletheia.adapters.ai_audit_causal

from aletheia.adapters.registry import get_adapter, list_adapters
from aletheia.adapters.taxonomy import STATUS_REJECTED

_CHECKS = [
    # (adapter_name, expected_version, clean_input_bytes, dirty_input_bytes)
    (
        "json_adapter", "1.0.0",
        b'{"source":"selfcheck","event_type":"PING","payload":{"ok":true}}',
        b"{not json at all",
    ),
    (
        "file_adapter", "1.0.0",
        b'{"event_type":"LINE","payload":{"n":1}}\n{"event_type":"LINE","payload":{"n":2}}',
        b"\xff\xfe not utf-8",
    ),
    (
        "ai_audit_adapter", "1.0.0",
        b'{"record_type":"inference_request","model":"test-model","source":"selfcheck"}',
        b"null",
    ),
    (
        "ot_adapter", "1.0.0",
        b'{"record_type":"sensor_reading","device_id":"SC-01","value":1.0,"quality":"GOOD"}',
        b'{"record_type":"sensor_reading"}',  # missing device_id + value
    ),
    (
        "ai_audit_causal", "1.0.0",
        b'[{"record_type":"tool_link","tool_name":"calculator","chain_id":"c1"}]',
        b"{bad",
    ),
]


def _run_check(adapter_name: str, expected_version: str,
               clean: bytes, dirty: bytes) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "adapter":  adapter_name,
        "checks":   [],
        "passed":   True,
    }

    def check(name: str, ok: bool, note: str = "") -> None:
        result["checks"].append({"check": name, "ok": ok, "note": note})
        if not ok:
            result["passed"] = False

    # 1. Registration
    try:
        adapter = get_adapter(adapter_name)
        check("registered", True)
    except KeyError as e:
        check("registered", False, str(e))
        return result

    # 2. Version
    actual_version = getattr(adapter, "VERSION", "?")
    check("version_match",
          actual_version == expected_version,
          f"expected {expected_version!r}, got {actual_version!r}")

    # 3. Clean input → not REJECTED
    clean_result = adapter.adapt(clean)
    check("clean_input_not_rejected",
          clean_result.status != STATUS_REJECTED,
          f"status={clean_result.status}")

    # 4. input_hash format
    h = clean_result.input_hash
    check("input_hash_format",
          isinstance(h, str) and len(h) == 64 and all(c in "0123456789abcdef" for c in h),
          f"hash={h!r}")

    # 5. Dirty input → REJECTED
    dirty_result = adapter.adapt(dirty)
    check("dirty_input_rejected",
          dirty_result.status == STATUS_REJECTED,
          f"status={dirty_result.status}")

    # 6. Determinism: same input = same hash
    clean_result2 = adapter.adapt(clean)
    check("hash_deterministic",
          clean_result.input_hash == clean_result2.input_hash)

    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Adapter self-check (Phase 10)")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args(argv)

    all_results = []
    for check_args in _CHECKS:
        all_results.append(_run_check(*check_args))

    # Also check that all registered adapters are covered
    registered = set(list_adapters())
    covered = {c[0] for c in _CHECKS}
    uncovered = registered - covered
    if uncovered:
        all_results.append({
            "adapter": "_coverage",
            "passed": False,
            "checks": [{"check": "all_adapters_have_selfcheck", "ok": False,
                         "note": f"Uncovered: {sorted(uncovered)}"}],
        })

    overall_pass = all(r["passed"] for r in all_results)

    if args.json:
        print(json.dumps({"passed": overall_pass, "results": all_results}, indent=2))
    else:
        _print_results(all_results, overall_pass)

    return 0 if overall_pass else 1


def _print_results(results: List[Dict], overall: bool) -> None:
    print("\n=== Adapter Self-Check ===\n")
    for r in results:
        status = "PASS" if r["passed"] else "FAIL"
        print(f"  [{status}] {r['adapter']}")
        for c in r["checks"]:
            icon = "  ✓" if c["ok"] else "  ✗"
            note = f"  ({c['note']})" if c["note"] else ""
            print(f"      {icon} {c['check']}{note}")
    print()
    print(f"Overall: {'PASS' if overall else 'FAIL'}")
    print()


if __name__ == "__main__":
    sys.exit(main())
