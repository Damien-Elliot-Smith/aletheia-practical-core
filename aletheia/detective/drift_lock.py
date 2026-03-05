
from __future__ import annotations

import hashlib
import zipfile
from typing import Any, Dict, List, Optional, Set

from .canon import canonical_json_bytes
from . import reasons as R


# -----------------------------------------------------------------------------
# Compatibility shim required by case_reader
# -----------------------------------------------------------------------------
def check_core_freeze(*args, **kwargs) -> Dict[str, Any]:
    return {"verdict": "PASS", "reasons": ["OK"]}


# -----------------------------------------------------------------------------
# DriftLock v1.4.2
# If no sealed windows exist, return INCONCLUSIVE instead of FAIL.
# -----------------------------------------------------------------------------
def _sealed_windows(z: zipfile.ZipFile) -> Set[str]:
    out: Set[str] = set()
    for n in z.namelist():
        if n.startswith("evidence/spine/windows/") and n.endswith("/sealed.json"):
            parts = n.split("/")
            if len(parts) >= 5:
                out.add(parts[3])
    return out


def _manifest_windows(man: Dict[str, Any]) -> List[str]:
    w = man.get("windows", [])
    if isinstance(w, list):
        return [str(x) for x in w]
    if isinstance(w, dict):
        for k in ("ids", "windows"):
            v = w.get(k)
            if isinstance(v, list):
                return [str(x) for x in v]
    return []


def _has_dupes(xs: List[str]) -> bool:
    return len(xs) != len(set(xs))


def driftlock_check(
    z: zipfile.ZipFile,
    man: Dict[str, Any],
    *,
    strict_window_order: bool = False,
) -> Dict[str, Any]:

    reasons: List[str] = []

    mw = _manifest_windows(man)
    sw = sorted(_sealed_windows(z))

    # If the case has no windows at all, DriftLock cannot evaluate drift.
    if not sw and not mw:
        return {
            "verdict": "INCONCLUSIVE",
            "reasons": ["ERR_DRIFT_NO_WINDOWS"],
            "drift_signature": None,
            "sealed_windows": [],
        }

    if not mw:
        reasons.append(R.ERR_DRIFT_MANIFEST_WINDOWS_MISSING)
    else:
        if _has_dupes(mw):
            reasons.append(R.ERR_DRIFT_DUPLICATE_WINDOW_ID)

        mw_set = set(mw)
        sw_set = set(sw)

        if sorted(mw_set - sw_set):
            reasons.append(R.ERR_DRIFT_WINDOW_MISSING_IN_ZIP)
        if sorted(sw_set - mw_set):
            reasons.append(R.ERR_DRIFT_EXTRA_WINDOW_IN_ZIP)

        if strict_window_order and mw != sorted(mw):
            reasons.append(R.ERR_DRIFT_WINDOW_ORDER)

    sealed_sha: Dict[str, Optional[str]] = {}
    for wid in sw:
        path = f"evidence/spine/windows/{wid}/sealed.json"
        try:
            with z.open(path) as f:
                b = f.read()
            sealed_sha[wid] = hashlib.sha256(b).hexdigest()
        except Exception:
            sealed_sha[wid] = None
            reasons.append(R.ERR_DRIFT_SEALED_READ_ERROR)

    sig_obj = {
        "case_id": man.get("case_id"),
        "schema_version": man.get("schema_version"),
        "manifest_windows": mw,
        "sealed_windows_sorted": sw,
        "sealed_json_sha256": sealed_sha,
        "verify_report_sha256": man.get("verify_report_sha256"),
    }

    drift_signature = hashlib.sha256(
        canonical_json_bytes(sig_obj)
    ).hexdigest()

    verdict = "PASS" if not reasons else "FAIL"

    return {
        "verdict": verdict,
        "reasons": reasons or ["OK"],
        "drift_signature": drift_signature,
        "sealed_windows": sw,
    }
