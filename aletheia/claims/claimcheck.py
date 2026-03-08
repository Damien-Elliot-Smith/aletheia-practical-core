from __future__ import annotations
import json
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Set

from .eqi import ClaimEQI
from .model import ClaimStatus, is_transition_allowed

@dataclass
class CheckResult:
    claim_id: str
    verdict: str  # PASS/FAIL/INCONCLUSIVE
    reasons: List[str]
    pins_checked: int = 0
    missing_pins: int = 0
    unsealed_pin_refs: int = 0
    invalid_transitions: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "verdict": self.verdict,
            "reasons": list(self.reasons),
            "pins_checked": self.pins_checked,
            "missing_pins": self.missing_pins,
            "unsealed_pin_refs": self.unsealed_pin_refs,
            "invalid_transitions": self.invalid_transitions,
        }

def _load_json(z: zipfile.ZipFile, path: str) -> Optional[Dict[str, Any]]:
    try:
        with z.open(path) as f:
            return json.loads(f.read().decode("utf-8"))
    except KeyError:
        return None

def _list_json_paths(z: zipfile.ZipFile, prefix: str) -> List[str]:
    out=[]
    for n in z.namelist():
        if n.startswith(prefix) and n.endswith(".json"):
            out.append(n)
    return sorted(out)

def _sealed_windows_from_case(z: zipfile.ZipFile) -> Set[str]:
    # We consider a window sealed if evidence includes its sealed marker.
    sealed=set()
    for n in z.namelist():
        # evidence/spine/windows/<window_id>/sealed.json
        if n.startswith("evidence/spine/windows/") and n.endswith("/sealed.json"):
            parts=n.split("/")
            if len(parts) >= 5:
                sealed.add(parts[3])
    return sealed

def _pin_exists(z: zipfile.ZipFile, pin_hash: str) -> Tuple[bool, Optional[str]]:
    # Search for any event json containing "hash": "<pin_hash>"
    # Efficient enough for small bundles; deterministic.
    for n in z.namelist():
        if not (n.startswith("evidence/spine/windows/") and n.endswith(".json")):
            continue
        if "/events/" not in n:
            continue
        try:
            with z.open(n) as f:
                b=f.read()
        except Exception:
            continue
        # quick substring check
        if pin_hash.encode("utf-8") not in b:
            continue
        try:
            obj=json.loads(b.decode("utf-8"))
        except Exception:
            continue
        if obj.get("hash")==pin_hash:
            return True, n
    return False, None

def _pin_window(path_in_zip: str) -> Optional[str]:
    # evidence/spine/windows/<window_id>/events/000001.json
    parts=path_in_zip.split("/")
    if len(parts) >= 5 and parts[0]=="evidence" and parts[1]=="spine" and parts[2]=="windows":
        return parts[3]
    return None

def check_claim(case_zip: str|Path, claim_id: str, *, claims_window_id: str="claims") -> CheckResult:
    case_zip = Path(case_zip)
    reasons: List[str]=[]
    with zipfile.ZipFile(case_zip, "r") as z:
        # Ensure claims window sealed
        if f"evidence/spine/windows/{claims_window_id}/sealed.json" not in z.namelist():
            return CheckResult(claim_id, "INCONCLUSIVE", ["CLAIMS_WINDOW_NOT_SEALED"])

        # Reconstruct claim state/history using ClaimEQI on extracted evidence dir structure inside zip.
        # We'll extract only claims window to temp for EQI to operate on the same layout.
        import tempfile, shutil
        with tempfile.TemporaryDirectory() as td:
            td_path=Path(td)
            # extract evidence/spine/windows/<claims_window_id>/*
            prefix=f"evidence/spine/windows/{claims_window_id}/"
            for n in z.namelist():
                if n.startswith(prefix):
                    target=td_path / "spine" / "windows" / claims_window_id / "/".join(n.split("/")[4:])
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with z.open(n) as src:
                        target.write_bytes(src.read())
            eqi = ClaimEQI(td_path, window_id=claims_window_id)
            st = eqi.get_state(claim_id)
            if st is None:
                return CheckResult(claim_id, "FAIL", ["CLAIM_NOT_FOUND"])

            # validate transition history deterministically
            invalid_transitions=0
            prev_status=None
            # We'll derive statuses from history ops similarly to EQI, but EQI already computes final state;
            # Here we validate that any status_set op followed allowed transitions.
            # We'll replay status only on CLAIM_STATUS_SET ops.
            from .model import ClaimStatus
            status = ClaimStatus.OPEN
            for h in st.history:
                op=h.get("op")
                pl=h.get("payload") or {}
                if op=="CLAIM_PROPOSED":
                    status = ClaimStatus.OPEN
                elif op=="CLAIM_STATUS_SET":
                    ns=pl.get("new_status")
                    if isinstance(ns,str) and ns in [s.value for s in ClaimStatus]:
                        new_status=ClaimStatus(ns)
                        if not is_transition_allowed(status, new_status):
                            invalid_transitions += 1
                        else:
                            status = new_status
                elif op=="CLAIM_SUPERSEDED":
                    # supersede implies SUPERSEDED
                    if not is_transition_allowed(status, ClaimStatus.SUPERSEDED):
                        invalid_transitions += 1
                    status = ClaimStatus.SUPERSEDED
                elif op=="CLAIM_RETRACTED":
                    status = ClaimStatus.RETRACTED

            # pin checks
            sealed_windows=_sealed_windows_from_case(z)
            pins = list(st.claim.support.pins)
            pins_checked=0
            missing_pins=0
            unsealed_pin_refs=0
            for pin in pins:
                pins_checked += 1
                ok, path = _pin_exists(z, pin)
                if not ok:
                    missing_pins += 1
                    continue
                w=_pin_window(path or "")
                if w and w not in sealed_windows:
                    unsealed_pin_refs += 1

            # enforce no silent upgrade: witnessed/derived must have pins and pins must exist & be sealed
            if st.claim.status in (ClaimStatus.WITNESSED, ClaimStatus.DERIVED):
                if not pins:
                    reasons.append("MISSING_PINS_FOR_WITNESSED_OR_DERIVED")
                if missing_pins:
                    reasons.append("MISSING_PIN_TARGETS")
                if unsealed_pin_refs:
                    reasons.append("UNSEALED_PIN_REFERENCES")

            if invalid_transitions:
                reasons.append("INVALID_TRANSITIONS")

            # Decide verdict
            if reasons:
                # Fail only for hard violations; otherwise inconclusive for missing sealed evidence
                hard_fail = "INVALID_TRANSITIONS" in reasons or "CLAIM_NOT_FOUND" in reasons
                if "MISSING_PIN_TARGETS" in reasons or "UNSEALED_PIN_REFERENCES" in reasons or "CLAIMS_WINDOW_NOT_SEALED" in reasons:
                    verdict="INCONCLUSIVE"
                else:
                    verdict="FAIL" if hard_fail else "INCONCLUSIVE"
            else:
                verdict="PASS"
                reasons=["OK"]

            return CheckResult(
                claim_id=claim_id,
                verdict=verdict,
                reasons=reasons,
                pins_checked=pins_checked,
                missing_pins=missing_pins,
                unsealed_pin_refs=unsealed_pin_refs,
                invalid_transitions=invalid_transitions,
            )

def check_all(case_zip: str|Path, *, claims_window_id: str="claims") -> Dict[str, Any]:
    case_zip = Path(case_zip)
    with zipfile.ZipFile(case_zip, "r") as z:
        # list claim ids by scanning claims events payloads inside zip
        ids=set()
        prefix=f"evidence/spine/windows/{claims_window_id}/events/"
        for n in z.namelist():
            if not (n.startswith(prefix) and n.endswith(".json")):
                continue
            try:
                with z.open(n) as f:
                    obj=json.loads(f.read().decode("utf-8"))
            except Exception:
                continue
            pl=obj.get("payload") or {}
            cid=pl.get("claim_id")
            if isinstance(cid,str) and cid:
                ids.add(cid)
    results=[]
    for cid in sorted(ids):
        results.append(check_claim(case_zip, cid, claims_window_id=claims_window_id).to_dict())
    # overall
    overall="PASS"
    for r in results:
        if r["verdict"]=="FAIL":
            overall="FAIL"; break
        if r["verdict"]=="INCONCLUSIVE":
            overall="INCONCLUSIVE"
    return {"overall": overall, "results": results}
