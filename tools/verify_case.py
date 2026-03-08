#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, hashlib, zipfile, sys
from pathlib import Path
from typing import Any, Dict, List, Tuple, Set

# Self-bootstrap: ensure the project root is on sys.path regardless of how this
# script is invoked (direct run, subprocess, pytest, Termux, cron, etc.)
_HERE = Path(__file__).resolve().parent.parent  # tools/ -> project root
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

# v1_3 hostile-input gating + limits/reasons
from aletheia.detective.zipguard import build_extraction_plan, ZipGuardError
from aletheia.detective.limits import ZipLimits
from aletheia.detective import reasons as R

# v1_4 DriftLock
from aletheia.detective.drift_lock import driftlock_check


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def canonicalize_json(obj: Any) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_json_from_zip(z: zipfile.ZipFile, name: str) -> Dict[str, Any]:
    with z.open(name) as f:
        return json.loads(f.read().decode("utf-8"))


def _read_bytes(z: zipfile.ZipFile, name: str) -> bytes:
    with z.open(name) as f:
        return f.read()


def _zip_sha256(z: zipfile.ZipFile, name: str) -> Tuple[str, int]:
    # streaming hash to avoid slurping large files into RAM
    h = hashlib.sha256()
    size = 0
    with z.open(name) as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            h.update(chunk)
    return h.hexdigest(), size


def _sealed_windows(z: zipfile.ZipFile) -> Set[str]:
    out = set()
    for n in z.namelist():
        if n.startswith("evidence/spine/windows/") and n.endswith("/sealed.json"):
            parts = n.split("/")
            if len(parts) >= 5:
                out.add(parts[3])
    return out


def verify_sealed_window(events: List[Dict[str, Any]], seal: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    if not events:
        return False, {"error": "EMPTY_WINDOW"}
    seqs = [int(e.get("seq", -1)) for e in events]
    expected = list(range(seqs[0], seqs[0] + len(seqs)))
    if seqs != expected:
        return False, {"error": "SEQ_GAP"}
    prev_hash = None
    for e in events:
        base = dict(e)
        got_hash = base.pop("hash", None)
        if got_hash is None:
            return False, {"error": "MISSING_HASH", "seq": e.get("seq")}
        if base.get("prev_hash") != prev_hash:
            return False, {
                "error": "CHAIN_BREAK",
                "seq": e.get("seq"),
                "expected_prev": prev_hash,
                "got_prev": base.get("prev_hash"),
            }
        exp = sha256_hex(canonicalize_json(base))
        if exp != got_hash:
            return False, {
                "error": "HASH_MISMATCH",
                "seq": e.get("seq"),
                "expected": exp,
                "got": got_hash,
            }
        prev_hash = got_hash
    if int(seal.get("event_count", -1)) != len(events):
        return False, {"error": "SEAL_COUNT_MISMATCH"}
    if str(seal.get("first_hash")) != str(events[0].get("hash")):
        return False, {"error": "SEAL_FIRST_HASH_MISMATCH"}
    if str(seal.get("last_hash")) != str(events[-1].get("hash")):
        return False, {"error": "SEAL_LAST_HASH_MISMATCH"}
    root_bytes = ("\n".join(e["hash"] for e in events) + "\n").encode("utf-8")
    root_hash = hashlib.sha256(root_bytes).hexdigest()
    if str(seal.get("window_root_hash")) != root_hash:
        return False, {
            "error": "WINDOW_ROOT_MISMATCH",
            "expected": root_hash,
            "got": seal.get("window_root_hash"),
        }
    return True, {"ok": True}


def _error_result(case_zip: Path, reason: str, detail: str | None = None, case_id: Any = None) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "verdict": "ERROR",
        "reasons": [reason],
        "hash_mismatches": [],
        "missing_files": [],
        "window_failures": [],
        "case_id": case_id,
        "case_path": str(case_zip),
    }
    if detail:
        out["detail"] = detail
    return out


def verify_case(case_zip: Path, *, drift_lock: bool = True, enforce_drift: bool = False, strict_window_order: bool = False) -> Dict[str, Any]:
    # hostile-input preflight (even though we don't extract)
    try:
        build_extraction_plan(str(case_zip), ZipLimits())
    except ZipGuardError as e:
        return _error_result(case_zip, e.reason_code, getattr(e, "detail", None))

    try:
        with zipfile.ZipFile(case_zip, "r") as z:
            try:
                names = z.namelist()
            except zipfile.BadZipFile as e:
                return _error_result(case_zip, "ZIP_CORRUPT", str(e))

            # load manifest
            try:
                if "case_manifest.json" in names:
                    man = _load_json_from_zip(z, "case_manifest.json")
                elif "manifest.json" in names:
                    man = _load_json_from_zip(z, "manifest.json")
                else:
                    return {
                        "verdict": "FAIL",
                        "reasons": ["NO_MANIFEST"],
                        "hash_mismatches": [],
                        "missing_files": [],
                        "window_failures": [],
                        "case_id": None,
                    }
            except (zipfile.BadZipFile, KeyError, OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
                return _error_result(case_zip, "MANIFEST_UNREADABLE", str(e))

            # Guard: manifest must be a dict, not a list or other type
            if not isinstance(man, dict):
                return {
                    "verdict": "FAIL",
                    "reasons": ["MANIFEST_WRONG_TYPE"],
                    "hash_mismatches": [],
                    "missing_files": [],
                    "window_failures": [],
                    "case_id": None,
                }

            # ── Strict manifest schema validation (fail closed) ──────────────
            # A verifier must reject malformed structure, not silently skip work.
            # Every field is checked for presence AND type before any hash work begins.
            schema_errors = []

            for k in ("schema_version", "files", "windows", "verify_report_sha256"):
                if k not in man:
                    schema_errors.append(f"MISSING_{k}")

            if not schema_errors:
                # Type guards — wrong type is FAIL, not a skip
                if not isinstance(man["files"], list):
                    schema_errors.append("MANIFEST_FILES_NOT_LIST")
                if not isinstance(man["windows"], list):
                    schema_errors.append("MANIFEST_WINDOWS_NOT_LIST")
                if not isinstance(man.get("verify_report_sha256"), str):
                    schema_errors.append("MANIFEST_VERIFY_REPORT_SHA256_NOT_STRING")
                elif len(man["verify_report_sha256"]) != 64:
                    schema_errors.append("MANIFEST_VERIFY_REPORT_SHA256_BAD_LENGTH")

            if not schema_errors:
                # Per-file entry validation: every entry must be a dict with required string fields
                for i, entry in enumerate(man["files"]):
                    if not isinstance(entry, dict):
                        schema_errors.append(f"FILE_ENTRY_{i}_NOT_DICT")
                        break
                    for field in ("zip_path", "sha256"):
                        if field not in entry:
                            schema_errors.append(f"FILE_ENTRY_{i}_MISSING_{field}")
                        elif not isinstance(entry[field], str):
                            schema_errors.append(f"FILE_ENTRY_{i}_{field}_NOT_STRING")
                    if "bytes" in entry and not isinstance(entry["bytes"], int):
                        schema_errors.append(f"FILE_ENTRY_{i}_BYTES_NOT_INT")
                    if schema_errors:
                        break

            if not schema_errors:
                # Per-window entry validation
                for i, w in enumerate(man["windows"]):
                    if not isinstance(w, dict):
                        schema_errors.append(f"WINDOW_ENTRY_{i}_NOT_DICT")
                        break
                    if "window_id" in w and not isinstance(w["window_id"], str):
                        schema_errors.append(f"WINDOW_ENTRY_{i}_WINDOW_ID_NOT_STRING")
                    if schema_errors:
                        break

            if schema_errors:
                return {
                    "verdict": "FAIL",
                    "reasons": schema_errors,
                    "hash_mismatches": [],
                    "missing_files": [],
                    "window_failures": [],
                    "case_id": man.get("case_id"),
                }
            # ── End schema validation ─────────────────────────────────────────

            # reasons accumulates non-schema issues found during hash/window verification
            reasons = []

            # verify listed file hashes
            hash_mismatches = []
            missing_files = []
            for f in man["files"]:
                zp = f.get("zip_path")
                if not isinstance(zp, str):
                    continue
                if zp not in names:
                    missing_files.append(zp)
                    continue
                try:
                    got, size = _zip_sha256(z, zp)
                except (zipfile.BadZipFile, KeyError, OSError) as e:
                    return _error_result(case_zip, "ZIP_CORRUPT", f"{zp}: {e}", case_id=man.get("case_id"))
                if got != f.get("sha256") or size != f.get("bytes"):
                    hash_mismatches.append(
                        {
                            "zip_path": zp,
                            "expected_sha256": f.get("sha256"),
                            "got_sha256": got,
                            "expected_bytes": f.get("bytes"),
                            "got_bytes": size,
                        }
                    )
            if missing_files:
                reasons.append("MISSING_FILES")
            if hash_mismatches:
                reasons.append("FILE_HASH_MISMATCH")

            # verify verify_report hash
            if "evidence/verify_report.json" in names:
                try:
                    got, _ = _zip_sha256(z, "evidence/verify_report.json")
                except (zipfile.BadZipFile, KeyError, OSError) as e:
                    return _error_result(case_zip, "ZIP_CORRUPT", f"evidence/verify_report.json: {e}", case_id=man.get("case_id"))
                if got != man.get("verify_report_sha256"):
                    reasons.append("VERIFY_REPORT_HASH_MISMATCH")
            else:
                reasons.append("MISSING_VERIFY_REPORT")

            # verify each sealed window chain
            try:
                sealed = _sealed_windows(z)
            except zipfile.BadZipFile as e:
                return _error_result(case_zip, "ZIP_CORRUPT", str(e), case_id=man.get("case_id"))

            window_failures = []
            for w in sorted(sealed):
                try:
                    seal = _load_json_from_zip(z, f"evidence/spine/windows/{w}/sealed.json")
                except (zipfile.BadZipFile, KeyError, OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
                    return _error_result(case_zip, "WINDOW_DATA_UNREADABLE", f"{w}: {e}", case_id=man.get("case_id"))

                events = []
                prefix = f"evidence/spine/windows/{w}/events/"
                try:
                    event_names = sorted(
                        [n for n in names if n.startswith(prefix) and n.endswith(".json")]
                    )
                except zipfile.BadZipFile as e:
                    return _error_result(case_zip, "ZIP_CORRUPT", str(e), case_id=man.get("case_id"))

                for n in event_names:
                    try:
                        obj = _load_json_from_zip(z, n)
                    except (zipfile.BadZipFile, KeyError, OSError, UnicodeDecodeError, json.JSONDecodeError):
                        continue
                    if isinstance(obj, dict) and "seq" in obj:
                        events.append(obj)

                ok, details = verify_sealed_window(events, seal)
                if not ok:
                    window_failures.append({"window_id": w, **details})

            if window_failures:
                reasons.append("WINDOW_VERIFY_FAILED")

            verdict = "PASS" if not reasons else "FAIL"
            out = {
                "verdict": verdict,
                "reasons": reasons or ["OK"],
                "window_failures": window_failures,
                "hash_mismatches": hash_mismatches,
                "missing_files": missing_files,
                "case_id": man.get("case_id"),
            }

            # drift lock (default: run, but do not change overall verdict unless enforce_drift)
            if drift_lock:
                try:
                    dl = driftlock_check(z, man, strict_window_order=strict_window_order)
                except (zipfile.BadZipFile, KeyError, OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
                    out["driftlock"] = {
                        "verdict": "ERROR",
                        "reasons": ["DRIFTLOCK_ERROR"],
                        "detail": str(e),
                    }
                    if enforce_drift:
                        out["verdict"] = "FAIL"
                        if out.get("reasons") == ["OK"]:
                            out["reasons"] = []
                        out["reasons"].append("DRIFTLOCK_FAILED")
                else:
                    out["driftlock"] = dl
                    if enforce_drift and dl.get("verdict") != "PASS":
                        out["verdict"] = "FAIL"
                        if out.get("reasons") == ["OK"]:
                            out["reasons"] = []
                        out["reasons"].append("DRIFTLOCK_FAILED")

            return out

    except FileNotFoundError as e:
        return _error_result(case_zip, "CASE_NOT_FOUND", str(e))
    except zipfile.BadZipFile as e:
        return _error_result(case_zip, "ZIP_CORRUPT", str(e))
    except OSError as e:
        return _error_result(case_zip, "IO_ERROR", str(e))


def main():
    ap = argparse.ArgumentParser(description="Verify an Aletheia case.zip (stdlib-only verifier).")
    ap.add_argument("case_zip", help="Path to case.zip")
    ap.add_argument("--no-drift-lock", action="store_true", help="Disable DriftLock checks (v1_4).")
    ap.add_argument("--enforce-drift", action="store_true", help="If DriftLock fails, force overall verdict FAIL.")
    ap.add_argument("--strict-window-order", action="store_true", help="DriftLock: require manifest windows to be sorted.")
    args = ap.parse_args()

    out = verify_case(
        Path(args.case_zip),
        drift_lock=(not args.no_drift_lock),
        enforce_drift=args.enforce_drift,
        strict_window_order=args.strict_window_order,
    )
    print(json.dumps(out, indent=2, sort_keys=True))
    sys.exit(0 if out.get("verdict") == "PASS" else 2)


if __name__ == "__main__":
    main()
