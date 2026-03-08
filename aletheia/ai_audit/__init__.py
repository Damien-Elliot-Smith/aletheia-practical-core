"""
aletheia.ai_audit — Phase 2.4: AI Agent Audit Trail

Provides a standard vocabulary and recording interface for AI system
audit events. Designed for EU AI Act Article 12 (record-keeping) and
Article 13 (transparency) compliance for high-risk AI systems.

AI event types (first-class Spine events):
  AI_INFERENCE_REQUEST    — question/prompt sent to a model
  AI_INFERENCE_RESPONSE   — model response received
  AI_MODEL_VERSION        — model identity/version anchored to record
  AI_CONSTRAINT_APPLIED   — a constraint rule was evaluated
  AI_HUMAN_OVERRIDE       — human operator overrode an AI decision
  AI_ESCALATION           — AI escalated a decision to a human
  AI_POLICY_VERDICT       — Sentinel-style policy gate result
  AI_AUDIT_SESSION_START  — audit session opened
  AI_AUDIT_SESSION_END    — audit session closed cleanly

Integration with DFW (Deontological Firewall):
  DFWBridge records DFW veto/approve decisions as AI_POLICY_VERDICT events.
  The DFW is Damien's separate project — this module provides the bridge
  interface so DFW decisions become part of the tamper-evident Spine record.

ProvenanceEnvelope integration:
  AuditRecorder.record_envelope() hashes an input+output pair, stores the
  hashes in a WITNESS event, and returns the envelope for downstream use.
  This implements the existing provenance_envelope.schema.json.

Compliance profile:
  AuditSession.export_case() adds compliance_profile="EU_AI_ACT_ART12_13"
  to the case manifest metadata.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from aletheia.spine.ledger import SpineLedger, canonicalize_json
from aletheia.ingest.gate import IngestGate, IngestConfig, IngestDecision
from aletheia.siren.state_machine import Siren


# ── AI Event Type constants ────────────────────────────────────────────────────

AI_INFERENCE_REQUEST  = "AI_INFERENCE_REQUEST"
AI_INFERENCE_RESPONSE = "AI_INFERENCE_RESPONSE"
AI_MODEL_VERSION      = "AI_MODEL_VERSION"
AI_CONSTRAINT_APPLIED = "AI_CONSTRAINT_APPLIED"
AI_HUMAN_OVERRIDE     = "AI_HUMAN_OVERRIDE"
AI_ESCALATION         = "AI_ESCALATION"
AI_POLICY_VERDICT     = "AI_POLICY_VERDICT"
AI_AUDIT_SESSION_START = "AI_AUDIT_SESSION_START"
AI_AUDIT_SESSION_END   = "AI_AUDIT_SESSION_END"

# DFW risk levels (mirrors DFW's own vocabulary)
DFW_RISK_LOW  = "LOW"
DFW_RISK_MED  = "MED"
DFW_RISK_HIGH = "HIGH"

# DFW dispositions
DFW_APPROVED = "APPROVED"
DFW_VETOED   = "VETOED"
DFW_DEFERRED = "DEFERRED"

COMPLIANCE_PROFILE_EU_AI_ACT = "EU_AI_ACT_ART12_13"


@dataclass
class AIAuditConfig:
    # Window where AI audit events are written
    window_id: str = "ai_audit"
    # Model identifier for this session
    model_id: str = "unknown"
    model_version: str = "unknown"
    # Deployment environment
    deployment_env: str = "production"
    # Hash algorithm for envelope content
    hash_algorithm: str = "sha256"
    # Whether to include full prompt/response text in payload
    # False = hash only (privacy-preserving), True = full text
    include_full_content: bool = False
    # Compliance profile to embed in case manifest metadata
    compliance_profile: str = COMPLIANCE_PROFILE_EU_AI_ACT


@dataclass
class EnvelopeRecord:
    """Result of recording a provenance envelope."""
    envelope_id: str
    input_hash: str
    output_hash: str
    event_hash: str   # Spine event hash that anchors this envelope
    window_id: str


class AIAuditRecorder:
    """
    Records AI system events to the Spine.

    Every event written here is subject to the same hash-chain integrity
    guarantees as all other Spine events: tamper-evident, append-only,
    verifiable in case.zip without the original system.

    Usage:
        recorder = AIAuditRecorder(ledger, config=AIAuditConfig(model_id="gpt-4o"))
        recorder.start_session()

        # Record a request/response pair
        req_ev = recorder.record_request("What is the capital of France?", context={})
        resp_ev = recorder.record_response("Paris.", request_event_hash=req_ev.hash)

        # Record a constraint evaluation
        recorder.record_constraint("C_NO_FALSE_CERTAINTY", "PASS", details={})

        recorder.end_session()
    """

    def __init__(
        self,
        ledger: SpineLedger,
        *,
        config: Optional[AIAuditConfig] = None,
        siren: Optional[Siren] = None,
    ) -> None:
        self.ledger = ledger
        self.config = config or AIAuditConfig()
        self.siren = siren
        self._session_id: Optional[str] = None

    def start_session(self, *, metadata: Optional[Dict[str, Any]] = None) -> str:
        """Open audit window and record session start. Returns session_id."""
        self._session_id = uuid.uuid4().hex[:16]

        try:
            self.ledger.open_window(self.config.window_id)
        except Exception:
            pass  # window may already be open from a previous call

        ev = self.ledger.append_event(self.config.window_id, AI_AUDIT_SESSION_START, {
            "session_id": self._session_id,
            "model_id": self.config.model_id,
            "model_version": self.config.model_version,
            "deployment_env": self.config.deployment_env,
            "compliance_profile": self.config.compliance_profile,
            "utc": _utc_now(),
            **(metadata or {}),
        })
        return self._session_id

    def end_session(self, *, outcome: str = "NORMAL", metadata: Optional[Dict[str, Any]] = None) -> None:
        """Record session end. Does NOT seal the window (caller controls that)."""
        self.ledger.append_event(self.config.window_id, AI_AUDIT_SESSION_END, {
            "session_id": self._session_id,
            "outcome": outcome,
            "utc": _utc_now(),
            **(metadata or {}),
        })

    def record_model_version(self, model_id: str, version: str, *, checksum: Optional[str] = None) -> Any:
        """Anchor model identity to the Spine. Returns the Spine event."""
        return self.ledger.append_event(self.config.window_id, AI_MODEL_VERSION, {
            "session_id": self._session_id,
            "model_id": model_id,
            "version": version,
            "checksum": checksum,
            "utc": _utc_now(),
        })

    def record_request(
        self,
        prompt: str,
        *,
        context: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None,
    ) -> Any:
        """
        Record an inference request.
        If include_full_content=False, stores SHA256 of prompt only.
        Returns the Spine event.
        """
        rid = request_id or uuid.uuid4().hex[:16]
        payload = {
            "session_id": self._session_id,
            "request_id": rid,
            "prompt_hash": _hash_content(prompt),
            "context_hash": _hash_content(json.dumps(context or {}, sort_keys=True)),
            "utc": _utc_now(),
        }
        if self.config.include_full_content:
            payload["prompt"] = prompt[:4096]  # cap at 4KiB
            payload["context"] = context or {}

        return self.ledger.append_event(self.config.window_id, AI_INFERENCE_REQUEST, payload)

    def record_response(
        self,
        response: str,
        *,
        request_event_hash: Optional[str] = None,
        request_id: Optional[str] = None,
        latency_ms: Optional[int] = None,
        tokens_used: Optional[int] = None,
    ) -> Any:
        """
        Record an inference response, pinned to its request event.
        Returns the Spine event.
        """
        payload = {
            "session_id": self._session_id,
            "request_id": request_id,
            "request_pin": request_event_hash,  # hash of request event
            "response_hash": _hash_content(response),
            "latency_ms": latency_ms,
            "tokens_used": tokens_used,
            "utc": _utc_now(),
        }
        if self.config.include_full_content:
            payload["response"] = response[:4096]

        return self.ledger.append_event(self.config.window_id, AI_INFERENCE_RESPONSE, payload)

    def record_envelope(
        self,
        input_data: Any,
        output_data: Any,
        *,
        envelope_id: Optional[str] = None,
        parent_hash: Optional[str] = None,
    ) -> EnvelopeRecord:
        """
        Record a provenance envelope (input + output hashes) to the Spine.
        Implements the provenance_envelope.schema.json workflow.
        Returns an EnvelopeRecord with the anchoring event hash.
        """
        eid = envelope_id or uuid.uuid4().hex[:16]
        input_hash = _hash_content(
            json.dumps(input_data, sort_keys=True, ensure_ascii=False)
            if not isinstance(input_data, str) else input_data
        )
        output_hash = _hash_content(
            json.dumps(output_data, sort_keys=True, ensure_ascii=False)
            if not isinstance(output_data, str) else output_data
        )

        ev = self.ledger.append_event(self.config.window_id, "PROVENANCE_ENVELOPE", {
            "envelope_id": eid,
            "parent_hash": parent_hash,
            "session_id": self._session_id,
            "input_hash": input_hash,
            "output_hash": output_hash,
            "utc": _utc_now(),
        })

        return EnvelopeRecord(
            envelope_id=eid,
            input_hash=input_hash,
            output_hash=output_hash,
            event_hash=ev.hash,
            window_id=self.config.window_id,
        )

    def record_constraint(
        self,
        constraint_id: str,
        verdict: str,
        *,
        details: Optional[Dict[str, Any]] = None,
        request_pin: Optional[str] = None,
    ) -> Any:
        """Record a constraint evaluation result. Returns Spine event."""
        return self.ledger.append_event(self.config.window_id, AI_CONSTRAINT_APPLIED, {
            "session_id": self._session_id,
            "constraint_id": constraint_id,
            "verdict": verdict,  # PASS / FAIL / INCONCLUSIVE
            "request_pin": request_pin,
            "details": _safe_details(details or {}),
            "utc": _utc_now(),
        })

    def record_human_override(
        self,
        operator_id: str,
        original_decision: str,
        override_decision: str,
        *,
        reason: Optional[str] = None,
        request_pin: Optional[str] = None,
    ) -> Any:
        """Record a human operator override. Returns Spine event."""
        return self.ledger.append_event(self.config.window_id, AI_HUMAN_OVERRIDE, {
            "session_id": self._session_id,
            "operator_id": operator_id,
            "original_decision": original_decision,
            "override_decision": override_decision,
            "reason": reason,
            "request_pin": request_pin,
            "utc": _utc_now(),
        })

    def record_escalation(
        self,
        reason: str,
        *,
        escalated_to: Optional[str] = None,
        request_pin: Optional[str] = None,
    ) -> Any:
        """Record an AI-to-human escalation. Returns Spine event."""
        return self.ledger.append_event(self.config.window_id, AI_ESCALATION, {
            "session_id": self._session_id,
            "reason": reason,
            "escalated_to": escalated_to,
            "request_pin": request_pin,
            "utc": _utc_now(),
        })


# ── DFW Bridge ─────────────────────────────────────────────────────────────────

class DFWBridge:
    """
    Bridge between the Deontological Firewall (DFW) and Aletheia.

    Every DFW veto/approve/defer decision becomes an AI_POLICY_VERDICT
    event in the Spine. The AI's ethical decision history is part of the
    tamper-evident record.

    The DFW is Damien's separate project. This bridge accepts verdicts
    from DFW in a standard dict format and records them to Spine without
    coupling to the DFW's internal implementation.

    DFW verdict dict expected:
        {
          "action": str,
          "actor": str,
          "target": str,
          "risk_level": "LOW" | "MED" | "HIGH",
          "disposition": "APPROVED" | "VETOED" | "DEFERRED",
          "rule_id": str (optional),
          "reason": str (optional),
        }
    """

    def __init__(self, ledger: SpineLedger, window_id: str = "ai_audit") -> None:
        self.ledger = ledger
        self.window_id = window_id

    def record_verdict(
        self,
        dfw_verdict: Dict[str, Any],
        *,
        session_id: Optional[str] = None,
        request_pin: Optional[str] = None,
    ) -> Any:
        """
        Record a DFW verdict to the Spine as an AI_POLICY_VERDICT event.
        Returns the Spine event.
        """
        payload = {
            "session_id": session_id,
            "action": dfw_verdict.get("action"),
            "actor": dfw_verdict.get("actor"),
            "target": dfw_verdict.get("target"),
            "risk_level": dfw_verdict.get("risk_level"),
            "disposition": dfw_verdict.get("disposition"),
            "rule_id": dfw_verdict.get("rule_id"),
            "reason": dfw_verdict.get("reason"),
            "request_pin": request_pin,
            "utc": _utc_now(),
            "source": "DFW",
        }
        return self.ledger.append_event(self.window_id, AI_POLICY_VERDICT, payload)

    def record_veto(
        self,
        action: str,
        actor: str,
        *,
        rule_id: Optional[str] = None,
        reason: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Any:
        """Convenience: record a DFW veto directly."""
        return self.record_verdict({
            "action": action,
            "actor": actor,
            "target": action,
            "risk_level": DFW_RISK_HIGH,
            "disposition": DFW_VETOED,
            "rule_id": rule_id,
            "reason": reason,
        }, session_id=session_id)

    def record_approval(
        self,
        action: str,
        actor: str,
        *,
        risk_level: str = DFW_RISK_LOW,
        rule_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Any:
        """Convenience: record a DFW approval."""
        return self.record_verdict({
            "action": action,
            "actor": actor,
            "target": action,
            "risk_level": risk_level,
            "disposition": DFW_APPROVED,
            "rule_id": rule_id,
        }, session_id=session_id)


# ── Helpers ─────────────────────────────────────────────────────────────────────

def _hash_content(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _safe_details(d: Dict[str, Any]) -> Dict[str, Any]:
    """Convert float values to strings so Spine (allow_float=False) accepts them."""
    result = {}
    for k, v in d.items():
        if isinstance(v, float):
            result[k] = str(v)
        elif isinstance(v, dict):
            result[k] = _safe_details(v)
        else:
            result[k] = v
    return result


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
