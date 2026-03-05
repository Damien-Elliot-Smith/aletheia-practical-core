from __future__ import annotations
import json
from dataclasses import dataclass
from typing import Any, Dict, Optional, List, Tuple

from aletheia.spine.ledger import SpineLedger
from .model import ClaimType, ClaimStatus, is_transition_allowed

CLAIMS_WINDOW_DEFAULT = "claims"
CLAIM_EVENT_TYPE = "CLAIM"

@dataclass(frozen=True)
class ClaimRef:
    claim_id: str
    claim_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return {"claim_id": self.claim_id, "claim_hash": self.claim_hash}

class ClaimRegistry:
    def __init__(self, ledger: SpineLedger, *, window_id: str = CLAIMS_WINDOW_DEFAULT):
        self.ledger = ledger
        self.window_id = window_id
        self.ledger.open_window(window_id)

    def _assert_json_safe(self, obj: Any) -> None:
        # strict JSON only (reject NaN/Inf)
        try:
            json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        except Exception as e:
            raise ValueError(f"Claim payload is not strict-JSON-serializable: {e}") from e

    def _append(self, payload: Dict[str, Any]) -> str:
        self._assert_json_safe(payload)
        self.ledger.append_event(self.window_id, CLAIM_EVENT_TYPE, payload)
        # last written event hash is returned by append_event as part of stored record? Ledger writes file; we can resolve by reading last file.
        # To avoid filesystem dependence, resolve by scanning latest seq file.
        wdir = self.ledger.root_dir / "spine" / "windows" / self.window_id / "events"
        latest = sorted([p for p in wdir.glob("*.json") if p.name[:6].isdigit()])[-1]
        obj = json.loads(latest.read_text(encoding="utf-8"))
        return str(obj.get("hash"))

    def propose(self, *, claim_id: str, claim_text: str, claim_type: ClaimType, reason_code: str = "OPEN", scope: Optional[Dict[str, Any]] = None) -> ClaimRef:
        payload = {
            "op": "CLAIM_PROPOSED",
            "claim_id": claim_id,
            "claim_text": claim_text,
            "claim_type": claim_type.value,
            "new_status": ClaimStatus.OPEN.value,
            "reason_code": reason_code,
            "scope": scope or {},
            "pins": [],
        }
        h = self._append(payload)
        return ClaimRef(claim_id, h)

    def set_scope(self, *, claim_id: str, scope: Dict[str, Any], reason_code: str = "SCOPE_SET") -> ClaimRef:
        payload = {"op": "CLAIM_SCOPE_SET", "claim_id": claim_id, "scope": scope, "reason_code": reason_code}
        h = self._append(payload)
        return ClaimRef(claim_id, h)

    def link_evidence(self, *, claim_id: str, pins: List[str], reason_code: str = "EVIDENCE_LINKED") -> ClaimRef:
        if not pins or any((not isinstance(p, str) or not p) for p in pins):
            raise ValueError("pins must be a non-empty list of non-empty strings")
        payload = {"op": "CLAIM_LINKED_EVIDENCE", "claim_id": claim_id, "pins": list(pins), "reason_code": reason_code}
        h = self._append(payload)
        return ClaimRef(claim_id, h)

    def set_status(self, *, claim_id: str, old_status: ClaimStatus, new_status: ClaimStatus, reason_code: str, pins: Optional[List[str]] = None) -> ClaimRef:
        if not is_transition_allowed(old_status, new_status):
            raise ValueError(f"Transition not allowed: {old_status.value} -> {new_status.value}")
        # No silent upgrades: witnessed/derived require pins
        if new_status in (ClaimStatus.WITNESSED, ClaimStatus.DERIVED):
            if not pins or any((not isinstance(p, str) or not p) for p in pins):
                raise ValueError("WITNESSED/DERIVED require evidence pins")
        payload = {"op": "CLAIM_STATUS_SET", "claim_id": claim_id, "new_status": new_status.value, "reason_code": reason_code, "pins": list(pins or [])}
        h = self._append(payload)
        return ClaimRef(claim_id, h)

    def supersede(self, *, claim_id: str, supersedes_claim_id: str, reason_code: str = "SUPERSEDED") -> ClaimRef:
        if claim_id == supersedes_claim_id:
            raise ValueError("claim_id cannot supersede itself")
        payload = {"op": "CLAIM_SUPERSEDED", "claim_id": claim_id, "supersedes_claim_id": supersedes_claim_id, "reason_code": reason_code}
        h = self._append(payload)
        return ClaimRef(claim_id, h)

    def retract(self, *, claim_id: str, reason_code: str = "RETRACTED") -> ClaimRef:
        payload = {"op": "CLAIM_RETRACTED", "claim_id": claim_id, "reason_code": reason_code}
        h = self._append(payload)
        return ClaimRef(claim_id, h)
