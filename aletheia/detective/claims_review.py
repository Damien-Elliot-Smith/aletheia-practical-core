from __future__ import annotations
import json
import zipfile
from tools._zip_io import open_zipfile_verified
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from aletheia.claims.claimcheck import check_claim, check_all
from aletheia.claims.eqi import ClaimEQI
from aletheia.detective.schema import LineType, ReasonCode, VerdictState, validate_logic_map

def _extract_evidence_root(case_zip: str|Path) -> Path:
    """
    Extract evidence/spine/* from case.zip into a temp directory so existing EQIs can operate.
    Returns temp root path that contains `spine/`.
    Caller must manage lifetime via context manager.
    """
    raise RuntimeError("Use _evidence_root_cm() context manager")

class _EvidenceRootCM:
    def __init__(self, case_zip: str|Path):
        self.case_zip = Path(case_zip)
        self._td = None
        self.root: Optional[Path] = None

    def __enter__(self) -> Path:
        import tempfile
        self._td = tempfile.TemporaryDirectory()
        root = Path(self._td.name)
        with open_zipfile_verified(str(self.case_zip)) as (zr, z):
            if z is None:
                raise ValueError(f"case zip failed ZipGuard: {zr.reason} {zr.detail}")
            prefix = "evidence/spine/"
            for n in z.namelist():
                if n.startswith(prefix) and not n.endswith("/"):
                    rel = n[len(prefix):]
                    target = root / "spine" / rel
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with z.open(n) as src:
                        target.write_bytes(src.read())
        self.root = root
        return root

    def __exit__(self, exc_type, exc, tb):
        if self._td is not None:
            self._td.cleanup()
        self.root = None
        return False

def _evidence_root_cm(case_zip: str|Path) -> _EvidenceRootCM:
    return _EvidenceRootCM(case_zip)

def _logic_line(line_type: LineType, reason_code: str, text: str, pins: List[str], *, verdict: Optional[VerdictState]=None, details: Optional[Dict[str, Any]]=None) -> Dict[str, Any]:
    d = {
        "line_type": line_type.value,
        "reason_code": reason_code,
        "text": text,
        "pins": list(pins),
    }
    if verdict is not None:
        d["verdict"] = verdict.value
    if details is not None:
        d["details"] = details
    return d

def review_claims(case_zip: str|Path, *, claim_id: Optional[str]=None, all_claims: bool=False, claims_window_id: str="claims") -> Dict[str, Any]:
    """
    Phase 4: Read-only claim review that produces a schema-locked logic map.
    This is conservative v1:
    - First gate is ClaimCheck.
    - If PASS, emits witness-backed lines for the claim pins and a status line.
    - If not PASS, emits INCONCLUSIVE lines with reasons + REQUEST_EVIDENCE if applicable.
    """
    case_zip = Path(case_zip)
    if all_claims:
        checks = check_all(case_zip, claims_window_id=claims_window_id)["results"]
        claim_ids = [c["claim_id"] for c in checks]
    else:
        if not claim_id:
            raise ValueError("Provide claim_id or set all_claims=True")
        claim_ids = [claim_id]
        checks = [check_claim(case_zip, claim_id, claims_window_id=claims_window_id).to_dict()]

    out_results = []
    with _evidence_root_cm(case_zip) as root:
        eqi = ClaimEQI(root, window_id=claims_window_id)

        for chk in checks:
            cid = chk["claim_id"]
            lines: List[Dict[str, Any]] = []
            verdict = chk["verdict"]
            reasons = chk["reasons"]
            st = eqi.get_state(cid)

            if st is None:
                lines.append(_logic_line(LineType.INCONCLUSIVE, "CLAIM_NOT_FOUND", f"Claim '{cid}' not found in sealed claims window.", [], verdict=VerdictState.INCONCLUSIVE))
            else:
                # Always include a status summary line (not evidence)
                lines.append(_logic_line(
                    LineType.OPEN_HYPOTHESIS if st.claim.status.value in ("OPEN","INCONCLUSIVE") else LineType.CONSTRAINT_RULE,
                    "OK",
                    f"Claim '{cid}' status={st.claim.status.value} type={st.claim.type.value} reason={st.claim.reason_code}",
                    [],
                    details={"scope": st.claim.scope, "support_pins": list(st.claim.support.pins)}
                ))

                if verdict == "PASS":
                    # Emit witness facts for each pin (pins are already verified by claimcheck)
                    pins = list(st.claim.support.pins)
                    if pins:
                        lines.append(_logic_line(LineType.WITNESS_FACT, "OK", f"Evidence pins linked to claim '{cid}'.", pins, verdict=VerdictState.WITNESSED))
                    else:
                        # should not happen for witnessed/derived but handle gracefully
                        lines.append(_logic_line(LineType.INCONCLUSIVE, "NO_PINS", f"Claim '{cid}' has PASS check but no pins were present.", [], verdict=VerdictState.INCONCLUSIVE))
                else:
                    # Conservative: do not attempt refute/confirm beyond check. Provide reasons + evidence request.
                    rc = "INCONCLUSIVE_GATES" if verdict == "INCONCLUSIVE" else "FAIL"
                    lines.append(_logic_line(LineType.INCONCLUSIVE, rc, f"ClaimCheck verdict={verdict} reasons={reasons}", [], verdict=VerdictState.INCONCLUSIVE, details={"claimcheck": chk}))
                    # Evidence request hints based on common reasons
                    if "CLAIMS_WINDOW_NOT_SEALED" in reasons:
                        lines.append(_logic_line(LineType.REQUEST_EVIDENCE, "REQUEST_SEAL_CLAIMS", "Seal the claims window and re-export case.zip.", [], details={"action":"seal_window", "window_id": claims_window_id}))
                    if "MISSING_PIN_TARGETS" in reasons:
                        lines.append(_logic_line(LineType.REQUEST_EVIDENCE, "REQUEST_MISSING_PINS", "Linked pins were not found in case evidence; re-export with referenced witness bundles/windows.", [], details={"missing_pins": chk.get("missing_pins", 0)}))
                    if "UNSEALED_PIN_REFERENCES" in reasons:
                        lines.append(_logic_line(LineType.REQUEST_EVIDENCE, "REQUEST_SEALED_EVIDENCE", "Pins reference unsealed windows; seal the source windows before export.", [], details={"unsealed_pin_refs": chk.get("unsealed_pin_refs", 0)}))

            validate_logic_map(lines)
            out_results.append({"claim_id": cid, "logic_map": lines, "claimcheck": chk})

    overall = "PASS"
    for r in out_results:
        v = r["claimcheck"]["verdict"]
        if v == "FAIL":
            overall = "FAIL"; break
        if v == "INCONCLUSIVE":
            overall = "INCONCLUSIVE"
    return {"overall": overall, "results": out_results}
