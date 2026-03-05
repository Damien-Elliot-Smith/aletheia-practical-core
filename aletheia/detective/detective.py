"""
Detective v1 – Practical Core

- Drift lock enforced via schema validator.
- Read-only EQI bridge to Spine (sealed-only evidence).
- Deterministic logic sieve (no narrative).
- Scar policy (pragmatic v1):
    If any SCAR exists, Detective includes an INCONCLUSIVE line noting scars,
    and never assumes continuity beyond sealed windows (enforced by EQI sealed-only fetch).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .eqi import EQI
from .sieve import Hypothesis, SieveConfig, run_sieve
from .schema import LogicLine, LineType, VerdictState, ReasonCode, validate_logic_map


@dataclass
class DetectiveConfig:
    from dataclasses import field
    sieve: SieveConfig = field(default_factory=SieveConfig)
    witness_event_type: str = "WITNESS"  # minimal witness event type for v1


class Detective:
    def __init__(self, root_dir: str, config: Optional[DetectiveConfig] = None):
        self.root_dir = root_dir
        self.config = config or DetectiveConfig()
        self.eqi = EQI(root_dir)

    def evaluate(self, hypotheses: List[Hypothesis], *, window_id: Optional[str] = None) -> List[Dict[str, Any]]:
        # Verify spine first
        v = self.eqi.verify_on_fetch()
        if not v.get("ok", False):
            lines = [LogicLine(LineType.INCONCLUSIVE, ReasonCode.INCONCLUSIVE_GATES,
                               "Spine verification failed; refusing to reason.",
                               pins=[],
                               verdict=VerdictState.INCONCLUSIVE,
                               details={"verify": v}).to_dict()]
            validate_logic_map(lines)
            return lines

        scars = self.eqi.get_scars()
        pre_lines: List[Dict[str, Any]] = []
        if scars.has_scar():
            pre_lines.append(LogicLine(
                LineType.INCONCLUSIVE,
                ReasonCode.INCONCLUSIVE_SCAR,
                "SCAR present; reasoning limited to sealed windows; continuity not assumed.",
                pins=[],
                verdict=VerdictState.INCONCLUSIVE,
                details={"scar_count": len(scars.scars)},
            ).to_dict())

        # Fetch sealed-only witness events
        witnesses = self.eqi.fetch_events(window_id=window_id, event_type=self.config.witness_event_type, limit=2000)
        logic = run_sieve(hypotheses, witnesses, cfg=self.config.sieve)

        lines = pre_lines + logic
        validate_logic_map(lines)
        return lines
