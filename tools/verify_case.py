#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, hashlib, zipfile, sys, tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Set
from tools._zip_io import open_zip_verified, open_zipfile_verified

# v1_3 hostile-input gating + limits/reasons
from aletheia.detective.zipguard import build_extraction_plan, ZipGuardError
from aletheia.detective.limits import ZipLimits
from aletheia.detective import reasons as R

# v1_4 DriftLock
from aletheia.detective.drift_lock import driftlock_check


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def canonicalize_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_json_from_zip(z: zipfile.ZipFile, name: str) -> Dict[str, Any]:
    with z.open(name) as f:
        return json.loads(f.read().decode("utf-8"))


def _read_bytes(z: zipfile.ZipFile, name: str) -> bytes:
    with z.open(name) as f:
        return f.read()


def _zip_sha256(z: zipfile.ZipFile, name: str) -> Tuple[str, int]:
    # v1_3: streaming hash to avoid slurping large files into RAM
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
    out=set()
    for n in z.namelist():
        if n.startswith("evidence/spine/windows/") and n.endswith("/sealed.json"):
            parts=n.split("/")
            if len(parts) >= 5:
                out.add(parts[3])
    return out


def verify_sealed_window(events: List[Dict[str, Any]], seal: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    if not events:
        return False, {"error":"EMPTY_WINDOW"}
    # seq continuity
    seqs=[int(e.get("seq",-1)) for e in events]
    expected=list(range(seqs[0], seqs[0]+len(seqs)))
    if seqs != expected:
        return False, {"error":"SEQ_GAP"}
    prev_hash=None
    for e in events:
        base=dict(e)
        got_hash=base.pop("hash", None)
        if got_hash is None:
            return False, {"error":"MISSING_HASH", "seq": e.get("seq")}
        if base.get("prev_hash") != prev_hash:
            return False, {"error":"CHAIN_BREAK", "seq": e.get("seq"), "expected_prev": prev_hash, "got_prev": base.get("prev_hash")}
        exp=sha256_hex(canonicalize_json(base))
        if exp != got_hash:
            return False, {"error":"HASH_MISMATCH", "seq": e.get("seq"), "expected": exp, "got": got_hash}
        prev_hash=got_hash
    if int(seal.get("event_count",-1)) != len(events):
        return False, {"error":"SEAL_COUNT_MISMATCH"}
    if str(seal.get("first_hash")) != str(events[0].get("hash")):
        return False, {"error":"SEAL_FIRST_HASH_MISMATCH"}
    if str(seal.get("last_hash")) != str(events[-1].get("hash")):
        return False, {"error":"SEAL_LAST_HASH_MISMATCH"}
    root_bytes = ("\n".join(e["hash"] for e in events) + "\n").encode("utf-8")
    root_hash = hashlib.sha256(root_bytes).hexdigest()
    if str(seal.get("window_root_hash")) != root_hash:
        return False, {"error":"WINDOW_ROOT_MISMATCH", "expected": root_hash, "got": seal.get("window_root_hash")}
    return True, {"ok": True}


def verify_case(case_zip: Path, *, drift_lock: bool = True, enforce_drift: bool = False, strict_window_order: bool = False) -> Dict[str, Any]:
    # Zip IO entrypoint (Phase B1) — structural verification before any zip reads
    res = open_zip_verified(str(case_zip))
    if res.verdict != "PASS":
        return {
            "verdict": res.verdict,
            "reasons": [res.reason],
            "detail": res.detail,
            "case_path": str(case_zip),
        }

    with open_zipfile_verified(str(case_zip)) as (zr, z):
        if z is None:
            return {
                "verdict": zr.verdict,
                "reasons": [zr.reason],
                "detail": zr.detail,
                "case_path": str(case_zip),
            }
        # load manifest
        if "case_manifest.json" in z.namelist():
            man=_load_json_from_zip(z, "case_manifest.json")
        elif "manifest.json" in z.namelist():
            man=_load_json_from_zip(z, "manifest.json")
        else:
            return {"verdict":"FAIL","reasons":["NO_MANIFEST"]}
        reasons=[]
        # basic required keys
        for k in ("schema_version","files","windows","verify_report_sha256"):
            if k not in man:
                reasons.append(f"MISSING_{k}")
        if reasons:
            return {"verdict":"FAIL","reasons":reasons}

        # verify listed file hashes
        hash_mismatches=[]
        missing_files=[]
        for f in man.get("files", []):
            zp=f.get("zip_path")
            if not isinstance(zp,str):
                continue
            if zp not in z.namelist():
                missing_files.append(zp);
                continue
            got, size = _zip_sha256(z, zp)
            if got != f.get("sha256") or size != f.get("bytes"):
                hash_mismatches.append({"zip_path":zp,"expected_sha256":f.get("sha256"),"got_sha256":got,"expected_bytes":f.get("bytes"),"got_bytes":size})
        if missing_files:
            reasons.append("MISSING_FILES")
        if hash_mismatches:
            reasons.append("FILE_HASH_MISMATCH")

        # verify verify_report hash
        if "evidence/verify_report.json" in z.namelist():
            got,_=_zip_sha256(z,"evidence/verify_report.json")
            if got != man.get("verify_report_sha256"):
                reasons.append("VERIFY_REPORT_HASH_MISMATCH")
        else:
            reasons.append("MISSING_VERIFY_REPORT")

        # verify each sealed window chain
        sealed=_sealed_windows(z)
        window_failures=[]
        for w in sorted(sealed):
            seal=_load_json_from_zip(z, f"evidence/spine/windows/{w}/sealed.json")
            # load events
            events=[]
            prefix=f"evidence/spine/windows/{w}/events/"
            for n in sorted([n for n in z.namelist() if n.startswith(prefix) and n.endswith(".json")]):
                try:
                    obj=_load_json_from_zip(z, n)
                except Exception:
                    continue
                if isinstance(obj, dict) and "seq" in obj:
                    events.append(obj)
            ok, details = verify_sealed_window(events, seal)
            if not ok:
                window_failures.append({"window_id":w, **details})
        if window_failures:
            reasons.append("WINDOW_VERIFY_FAILED")

        verdict="PASS" if not reasons else "FAIL"
        out = {"verdict":verdict, "reasons":reasons or ["OK"], "window_failures":window_failures, "hash_mismatches":hash_mismatches, "missing_files":missing_files, "case_id": man.get("case_id")}

        # v1_4 drift lock (default: run, but do not change overall verdict unless enforce_drift)
        if drift_lock:
            dl = driftlock_check(z, man, strict_window_order=strict_window_order)
            out["driftlock"] = dl
            if enforce_drift and dl.get("verdict") != "PASS":
                out["verdict"] = "FAIL"
                if out.get("reasons") == ["OK"]:
                    out["reasons"] = []
                out["reasons"].append("DRIFTLOCK_FAILED")

        return out


def main():
    ap=argparse.ArgumentParser(description="Verify an Aletheia case.zip (stdlib-only verifier).")
    ap.add_argument("case_zip", help="Path to case.zip")
    ap.add_argument("--no-drift-lock", action="store_true", help="Disable DriftLock checks (v1_4).")
    ap.add_argument("--enforce-drift", action="store_true", help="If DriftLock fails, force overall verdict FAIL.")
    ap.add_argument("--strict-window-order", action="store_true", help="DriftLock: require manifest windows to be sorted.")
    args=ap.parse_args()

    out=verify_case(
        Path(args.case_zip),
        drift_lock=(not args.no_drift_lock),
        enforce_drift=args.enforce_drift,
        strict_window_order=args.strict_window_order,
    )
    print(json.dumps(out, indent=2, sort_keys=True))
    sys.exit(0 if out.get("verdict")=="PASS" else 2)


if __name__=="__main__":
    main()
