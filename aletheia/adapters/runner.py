"""
aletheia.adapters.runner — Deterministic Adapter Runner

Phase 2: Adapter Framework

The runner is the integration point between the adapter layer and the
Ingest Gate. It:
  1. Resolves the adapter by name.
  2. Calls adapt(raw) to get an AdapterResult.
  3. Passes each canonical event to IngestGate.ingest().
  4. Returns a RunnerReport with full adapter result and all gate decisions.

This is the only path by which external data reaches the Spine.

Design rules:
  - Every gate decision is recorded in the report.
  - Adapter failures never crash the runner — they are captured and reported.
  - The runner never modifies AdapterResult after the adapter returns it.
"""
from __future__ import annotations

import traceback
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from aletheia.adapters.base import AdapterResult, AdapterBase
from aletheia.adapters.registry import get_adapter
from aletheia.ingest.gate import IngestGate, IngestResult, IngestDecision


@dataclass
class GateDecision:
    """One Ingest Gate decision for one canonical event."""
    event_index: int
    event_type: str
    decision: str            # ACCEPT or REJECT
    reason: Optional[str]    # None on ACCEPT
    detail: Optional[Dict[str, Any]] = None


@dataclass
class RunnerReport:
    """Complete result of a runner.run() call."""
    adapter_name: str
    adapter_result: AdapterResult
    gate_decisions: List[GateDecision] = field(default_factory=list)
    runner_error: Optional[str] = None   # Set if adapter itself raised

    @property
    def events_accepted(self) -> int:
        return sum(1 for d in self.gate_decisions if d.decision == "ACCEPT")

    @property
    def events_rejected_by_gate(self) -> int:
        return sum(1 for d in self.gate_decisions if d.decision == "REJECT")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "adapter_name":          self.adapter_name,
            "adapter_status":        self.adapter_result.status,
            "adapter_input_hash":    self.adapter_result.input_hash,
            "events_produced":       len(self.adapter_result.canonical_events),
            "events_accepted":       self.events_accepted,
            "events_rejected_by_gate": self.events_rejected_by_gate,
            "losses":                len(self.adapter_result.losses),
            "rejections":            len(self.adapter_result.rejections),
            "gate_decisions":        [
                {
                    "event_index": d.event_index,
                    "event_type":  d.event_type,
                    "decision":    d.decision,
                    "reason":      d.reason,
                    "detail":      d.detail,
                }
                for d in self.gate_decisions
            ],
            "runner_error": self.runner_error,
        }


class AdapterRunner:
    """
    Runs a named adapter against raw bytes and feeds results to an IngestGate.

    Usage:
        runner = AdapterRunner(gate)
        report = runner.run("json_adapter", raw_bytes)
    """

    def __init__(self, gate: IngestGate) -> None:
        self.gate = gate

    def run(
        self,
        adapter_name: str,
        raw: bytes,
        profile: Optional[Dict[str, Any]] = None,
    ) -> RunnerReport:
        """
        Run the named adapter against raw bytes.

        Steps:
          1. Resolve adapter.
          2. adapt(raw) -> AdapterResult.
          3. For each canonical event, IngestGate.ingest().
          4. Return RunnerReport.
        """
        try:
            adapter = get_adapter(adapter_name)
        except KeyError as e:
            # Produce a minimal failed report
            from aletheia.adapters.base import hash_raw_bytes, AdapterResult as AR
            dummy = AR(
                adapter_name=adapter_name,
                adapter_version="unknown",
                trust_level="UNAUTHENTICATED_SOURCE",
                input_hash=hash_raw_bytes(raw),
            )
            dummy.add_rejection("UNSUPPORTED", f"Adapter not registered: {e}")
            return RunnerReport(adapter_name=adapter_name, adapter_result=dummy,
                                runner_error=str(e))

        try:
            result = adapter.adapt(raw, profile=profile)
        except Exception:
            from aletheia.adapters.base import hash_raw_bytes, AdapterResult as AR
            dummy = AR(
                adapter_name=adapter_name,
                adapter_version=getattr(adapter, "VERSION", "unknown"),
                trust_level=getattr(adapter, "DEFAULT_TRUST", "UNAUTHENTICATED_SOURCE"),
                input_hash=hash_raw_bytes(raw),
            )
            tb = traceback.format_exc()
            dummy.add_rejection("MALFORMED", f"Adapter raised exception: {tb[:500]}")
            return RunnerReport(adapter_name=adapter_name, adapter_result=dummy,
                                runner_error=tb)

        report = RunnerReport(adapter_name=adapter_name, adapter_result=result)

        # Feed each canonical event to the gate
        for i, event in enumerate(result.canonical_events):
            ingest_record = event.to_ingest_record()
            gate_result: IngestResult = self.gate.ingest(ingest_record)
            report.gate_decisions.append(GateDecision(
                event_index=i,
                event_type=event.event_type,
                decision=gate_result.decision.value,
                reason=gate_result.reason.value if gate_result.reason else None,
                detail=gate_result.detail,
            ))

        return report
