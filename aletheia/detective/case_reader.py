from __future__ import annotations

import json
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

from tools.verify_case import verify_case  # core verifier
from .drift_lock import check_core_freeze


@dataclass(frozen=True)
class CaseReader:
    case_zip_path: Path

    def verify(self, drift_lock: bool = False) -> Dict[str, Any]:
        """Read-only verification of a case.zip."""
        p = Path(self.case_zip_path)

        if not p.exists():
            return {"status": "ERROR", "reason": f"case zip not found: {str(p)}"}
        if not p.is_file():
            return {"status": "ERROR", "reason": f"case path is not a file: {str(p)}"}

        # Basic zip sanity
        try:
            with zipfile.ZipFile(p, "r") as zf:
                bad = zf.testzip()
                if bad is not None:
                    return {"status": "ERROR", "reason": f"zip corruption at: {bad}"}
        except Exception as e:
            return {"status": "ERROR", "reason": f"cannot open zip: {e!r}"}

        # Delegate to core verifier (hash chain / manifest / evidence integrity)
        try:
            report = verify_case(str(p))
        except Exception as e:
            return {"status": "ERROR", "reason": f"verify_case failed: {e!r}"}

        # Normalize: older verifier may omit status
        if isinstance(report, dict) and "status" not in report:
            errors = report.get("errors") or report.get("hash_mismatches") or []
            report = dict(report)
            report["status"] = "OK" if not errors else "ERROR"

        # Optional drift-lock: ensure case was produced by the same frozen core
        if drift_lock:
            try:
                with zipfile.ZipFile(p, "r") as zf:
                    manifest = json.loads(zf.read("case_manifest.json").decode("utf-8"))
            except Exception as e:
                report = dict(report) if isinstance(report, dict) else {"status": "ERROR"}
                report["status"] = "ERROR"
                report["verdict"] = "FAIL"
                report["reasons"] = list(report.get("reasons") or []) + ["MANIFEST_READ_ERROR"]
                report["reason"] = f"cannot read case_manifest.json: {e!r}"
                return report

            ok, code, details = check_core_freeze(manifest)
            report = dict(report) if isinstance(report, dict) else {"status": "ERROR"}
            report["drift_lock"] = {"ok": bool(ok), "code": code, "details": details}

            if not ok:
                report["status"] = "ERROR"
                report["verdict"] = "FAIL"
                report["reasons"] = list(report.get("reasons") or []) + ["DRIFT_LOCK_FAIL", code]
            else:
                # don't overwrite existing verdict/status if core verifier already failed
                pass

        return report
