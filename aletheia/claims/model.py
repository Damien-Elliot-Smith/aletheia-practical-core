from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

class ClaimType(str, Enum):
    LOGICAL="LOGICAL"
    EMPIRICAL="EMPIRICAL"
    HISTORICAL="HISTORICAL"
    POLICY="POLICY"
    OPERATIONAL="OPERATIONAL"

class ClaimStatus(str, Enum):
    OPEN="OPEN"
    WITNESSED="WITNESSED"
    DERIVED="DERIVED"
    REFUTED="REFUTED"
    SUPERSEDED="SUPERSEDED"
    RETRACTED="RETRACTED"
    INCONCLUSIVE="INCONCLUSIVE"

# Allowed status transitions (closed graph)
ALLOWED_TRANSITIONS = {
    ClaimStatus.OPEN: {ClaimStatus.OPEN, ClaimStatus.INCONCLUSIVE, ClaimStatus.WITNESSED, ClaimStatus.DERIVED, ClaimStatus.REFUTED, ClaimStatus.RETRACTED, ClaimStatus.SUPERSEDED},
    ClaimStatus.INCONCLUSIVE: {ClaimStatus.INCONCLUSIVE, ClaimStatus.WITNESSED, ClaimStatus.DERIVED, ClaimStatus.REFUTED, ClaimStatus.RETRACTED, ClaimStatus.SUPERSEDED},
    ClaimStatus.WITNESSED: {ClaimStatus.SUPERSEDED},
    ClaimStatus.DERIVED: {ClaimStatus.SUPERSEDED},
    ClaimStatus.REFUTED: {ClaimStatus.SUPERSEDED},
    ClaimStatus.SUPERSEDED: {ClaimStatus.SUPERSEDED},
    ClaimStatus.RETRACTED: {ClaimStatus.RETRACTED},
}

def is_transition_allowed(old: ClaimStatus, new: ClaimStatus) -> bool:
    return new in ALLOWED_TRANSITIONS.get(old, set())

@dataclass
class Support:
    pins: List[str] = field(default_factory=list)
    constraint_refs: List[Dict[str, Any]] = field(default_factory=list)
    policy_refs: List[Dict[str, Any]] = field(default_factory=list)
    citations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pins": list(self.pins),
            "constraint_refs": list(self.constraint_refs),
            "policy_refs": list(self.policy_refs),
            "citations": list(self.citations),
        }

@dataclass
class Claim:
    claim_id: str
    claim_text: str
    type: ClaimType
    status: ClaimStatus = ClaimStatus.OPEN
    scope: Dict[str, Any] = field(default_factory=dict)
    support: Support = field(default_factory=Support)
    reason_code: str = "OPEN"
    created_utc: Optional[str] = None
    updated_utc: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "claim_id": self.claim_id,
            "claim_text": self.claim_text,
            "type": self.type.value,
            "status": self.status.value,
            "scope": dict(self.scope),
            "support": self.support.to_dict(),
            "reason_code": self.reason_code,
        }
        if self.created_utc: d["created_utc"] = self.created_utc
        if self.updated_utc: d["updated_utc"] = self.updated_utc
        return d
