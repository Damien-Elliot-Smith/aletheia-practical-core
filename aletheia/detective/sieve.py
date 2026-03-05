"""
Deterministic Logic Sieve (PoE engine) – v1 minimal

Inputs:
- hypotheses (structured, bounded)
- EQI evidence (sealed-only, verified)
- optional constraints registry (not yet full; minimal support)

Outputs:
- Drift-locked "logic map" (schema validated)
- No narrative, no new entities, pins required for witnessed/refuted lines
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .schema import LogicLine, LineType, VerdictState, ReasonCode, validate_logic_map


@dataclass
class Hypothesis:
    hypothesis_id: str
    entity: str
    key: str
    value: Any
    window_id: Optional[str] = None  # optional scope restriction


@dataclass
class SieveConfig:
    max_hypotheses: int = 25
    max_steps: int = 1000
    max_lines: int = 200
    min_pinned_claim_ratio: float = 0.6
    max_inference_mass: float = 0.4  # fraction of OPEN claims allowed (pragmatic gate)


def _witness_matches(h: Hypothesis, witness_payload: Dict[str, Any]) -> Optional[Tuple[bool, str]]:
    """
    Minimal v1 witness model:
    Witness payload is expected to include:
      {"entity": str, "key": str, "value": Any}
    Returns (is_match, kind) where kind in {"MATCH","CONTRADICT","IRRELEVANT"}.
    """
    if witness_payload.get("entity") != h.entity:
        return None
    if witness_payload.get("key") != h.key:
        return None
    if witness_payload.get("value") == h.value:
        return (True, "MATCH")
    # same entity/key but different value => contradiction
    return (False, "CONTRADICT")


def run_sieve(hypotheses: List[Hypothesis], witnesses: List[Dict[str, Any]], cfg: Optional[SieveConfig] = None) -> List[Dict[str, Any]]:
    cfg = cfg or SieveConfig()

    lines: List[LogicLine] = []
    steps = 0

    if len(hypotheses) > cfg.max_hypotheses:
        lines.append(LogicLine(LineType.INCONCLUSIVE, ReasonCode.INCONCLUSIVE_BUDGET,
                               f"Budget: hypotheses {len(hypotheses)} exceeds max {cfg.max_hypotheses}.",
                               pins=[],
                               verdict=VerdictState.INCONCLUSIVE))
        out = [l.to_dict() for l in lines]
        validate_logic_map(out)
        return out

    # Index witnesses by quick scan (deterministic order preserved in iteration below)
    for h in hypotheses:
        steps += 1
        if steps > cfg.max_steps:
            lines.append(LogicLine(LineType.INCONCLUSIVE, ReasonCode.INCONCLUSIVE_BUDGET,
                                   "Budget: max steps exceeded.",
                                   pins=[],
                                   verdict=VerdictState.INCONCLUSIVE))
            break

        matched_pin: Optional[str] = None
        contradict_pins: List[str] = []
        conflict = False

        for e in witnesses:
            payload = e.get("payload") or {}
            if not isinstance(payload, dict):
                continue
            w = payload.get("payload") if isinstance(payload.get("payload"), dict) else payload
            # Support either direct witness payload or nested under payload.payload (from ingest sanitization)
            if not isinstance(w, dict):
                continue

            res = _witness_matches(h, w)
            if res is None:
                continue
            is_match, kind = res
            if kind == "MATCH":
                if matched_pin is None:
                    matched_pin = str(e.get("hash", ""))
                else:
                    # multiple matches are fine (redundant witnesses); keep deterministic by keeping first
                    pass
            elif kind == "CONTRADICT":
                contradict_pins.append(str(e.get("hash", "")))

        if matched_pin and contradict_pins:
            conflict = True

        if conflict:
            lines.append(LogicLine(
                LineType.INCONCLUSIVE,
                ReasonCode.INCONCLUSIVE_CONFLICT,
                f"Hypothesis {h.hypothesis_id} has conflicting pinned witnesses.",
                pins=[p for p in [matched_pin] + contradict_pins if p],
                hypothesis_id=h.hypothesis_id,
                verdict=VerdictState.INCONCLUSIVE,
                details={"entity": h.entity, "key": h.key, "value": h.value},
            ))
        elif matched_pin:
            lines.append(LogicLine(
                LineType.WITNESS_FACT,
                ReasonCode.WITNESSED_BY_MATCH,
                f"Hypothesis {h.hypothesis_id} WITNESSED by pinned witness.",
                pins=[matched_pin],
                hypothesis_id=h.hypothesis_id,
                verdict=VerdictState.WITNESSED,
                details={"entity": h.entity, "key": h.key, "value": h.value},
            ))
        elif contradict_pins:
            lines.append(LogicLine(
                LineType.ELIMINATION,
                ReasonCode.REFUTED_BY_WITNESS,
                f"Hypothesis {h.hypothesis_id} REFUTED by pinned contradiction.",
                pins=[p for p in contradict_pins if p],
                hypothesis_id=h.hypothesis_id,
                verdict=VerdictState.REFUTED,
                details={"entity": h.entity, "key": h.key, "value": h.value},
            ))
        else:
            lines.append(LogicLine(
                LineType.OPEN_HYPOTHESIS,
                ReasonCode.NEED_EVIDENCE,
                f"Hypothesis {h.hypothesis_id} OPEN (no pinned witness).",
                pins=[],
                hypothesis_id=h.hypothesis_id,
                verdict=VerdictState.OPEN,
                details={"entity": h.entity, "key": h.key, "value": h.value},
            ))

        if len(lines) >= cfg.max_lines:
            lines.append(LogicLine(LineType.INCONCLUSIVE, ReasonCode.INCONCLUSIVE_BUDGET,
                                   "Budget: max output lines reached.",
                                   pins=[],
                                   verdict=VerdictState.INCONCLUSIVE))
            break

    # Coverage gates: pinned claim ratio and inference mass
    total_claims = sum(1 for l in lines if l.line_type in (LineType.WITNESS_FACT, LineType.ELIMINATION, LineType.OPEN_HYPOTHESIS))
    pinned_claims = sum(1 for l in lines if l.line_type in (LineType.WITNESS_FACT, LineType.ELIMINATION))
    open_claims = sum(1 for l in lines if l.line_type == LineType.OPEN_HYPOTHESIS)

    if total_claims > 0:
        pinned_ratio = pinned_claims / total_claims
        open_ratio = open_claims / total_claims
        if pinned_ratio < cfg.min_pinned_claim_ratio or open_ratio > cfg.max_inference_mass:
            lines.append(LogicLine(
                LineType.INCONCLUSIVE,
                ReasonCode.INCONCLUSIVE_GATES,
                "Coverage gates failed (too few pinned claims / too much inference).",
                pins=[],
                verdict=VerdictState.INCONCLUSIVE,
                details={"pinned_ratio": pinned_ratio, "open_ratio": open_ratio,
                         "min_pinned": cfg.min_pinned_claim_ratio, "max_open": cfg.max_inference_mass},
            ))

    out = [l.to_dict() for l in lines]
    validate_logic_map(out)
    return out
