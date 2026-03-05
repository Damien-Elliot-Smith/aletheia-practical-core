from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from aletheia.detective.limits import ZipLimits
from aletheia.detective.zipguard import ZipGuardError, build_extraction_plan
from aletheia.detective import reasons as R


@dataclass(frozen=True)
class ZipOpenResult:
    verdict: str  # PASS|FAIL|INCONCLUSIVE|ERROR
    reason: str
    members: int = 0
    detail: str = ""


def open_zip_verified(zip_path: str, limits: Optional[ZipLimits] = None) -> ZipOpenResult:
    """
    Phase B1: Single zip IO entrypoint.

    This function performs ZipGuard structural verification BEFORE any other code
    attempts to read/extract zip contents.
    """
    try:
        lim = limits or ZipLimits()
        plans = build_extraction_plan(zip_path, lim)
        return ZipOpenResult(verdict="PASS", reason="OK", members=len(plans), detail="")
    except ZipGuardError as e:
        # canonical reason code carried by ZipGuardError
        rc = getattr(e, "reason_code", R.ERR_BAD_ZIP)
        detail = getattr(e, "detail", str(e))
        return ZipOpenResult(verdict="FAIL", reason=rc, members=0, detail=detail)
    except Exception as e:
        return ZipOpenResult(verdict="ERROR", reason=R.ERR_ZIP_GUARD_EXCEPTION, members=0, detail=f"{type(e).__name__}: {e}")

from contextlib import contextmanager
import zipfile


@contextmanager
def open_zipfile_verified(zip_path: str, limits: Optional[ZipLimits] = None):
    """
    Context manager: ZipGuard preflight + open ZipFile.
    This is the ONLY approved way for non-zipguard code to read zip contents.
    """
    res = open_zip_verified(zip_path, limits=limits)
    if res.verdict != "PASS":
        yield res, None
        return
    zf = zipfile.ZipFile(zip_path, "r")
    try:
        yield res, zf
    finally:
        zf.close()
