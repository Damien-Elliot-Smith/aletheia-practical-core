"""
Detective v1 Schema + Drift Lock

This module enforces the closed set of allowed line types and the mandatory pinning rules.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional


class LineType(str, Enum):
    WITNESS_FACT = "WITNESS_FACT"
    CONSTRAINT_RULE = "CONSTRAINT_RULE"
    ELIMINATION = "ELIMINATION"
    OPEN_HYPOTHESIS = "OPEN_HYPOTHESIS"
    REQUEST_EVIDENCE = "REQUEST_EVIDENCE"
    INCONCLUSIVE = "INCONCLUSIVE"


class VerdictState(str, Enum):
    WITNESSED = "WITNESSED"
    REFUTED = "REFUTED"
    OPEN = "OPEN"
    INCONCLUSIVE = "INCONCLUSIVE"


class ReasonCode(str, Enum):
    OK = "OK"
    INCONCLUSIVE_GATES = "INCONCLUSIVE_GATES"
    INCONCLUSIVE_SCAR = "INCONCLUSIVE_SCAR"
    INCONCLUSIVE_BUDGET = "INCONCLUSIVE_BUDGET"
    INCONCLUSIVE_CONFLICT = "INCONCLUSIVE_CONFLICT"
    NEED_EVIDENCE = "NEED_EVIDENCE"
    REFUTED_BY_WITNESS = "REFUTED_BY_WITNESS"
    WITNESSED_BY_MATCH = "WITNESSED_BY_MATCH"


@dataclass
class LogicLine:
    line_type: LineType
    reason_code: ReasonCode
    text: str
    pins: List[str]  # spine event hashes (pins)

    # Optional structured fields for UI
    hypothesis_id: Optional[str] = None
    verdict: Optional[VerdictState] = None
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "line_type": self.line_type.value,
            "reason_code": self.reason_code.value,
            "text": self.text,
            "pins": list(self.pins),
        }
        if self.hypothesis_id is not None:
            d["hypothesis_id"] = self.hypothesis_id
        if self.verdict is not None:
            d["verdict"] = self.verdict.value
        if self.details is not None:
            d["details"] = self.details
        return d


def validate_logic_map(lines: List[Dict[str, Any]]) -> None:
    """
    Drift lock validator for output.
    Raises ValueError on any contract violation.
    """
    allowed = set(lt.value for lt in LineType)
    for i, ln in enumerate(lines):
        if not isinstance(ln, dict):
            raise ValueError(f"Line {i} not dict")
        lt = ln.get("line_type")
        if lt not in allowed:
            raise ValueError(f"Line {i} invalid line_type: {lt}")
        pins = ln.get("pins")
        if not isinstance(pins, list) or not all(isinstance(p, str) and p for p in pins):
            raise ValueError(f"Line {i} pins invalid")
        # Mandatory pinning rules
        if lt in (LineType.WITNESS_FACT.value, LineType.ELIMINATION.value):
            if len(pins) == 0:
                raise ValueError(f"Line {i} {lt} requires pins")
        # Every line must have a reason code
        rc = ln.get("reason_code")
        if not isinstance(rc, str) or not rc:
            raise ValueError(f"Line {i} missing reason_code")
        # No freeform narrative fields enforced here; caller controls schemas.
