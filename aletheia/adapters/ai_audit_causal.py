"""
aletheia.adapters.ai_audit_causal — Advanced AI Audit Causal Chain Reconstruction

Phase 5B: Extend AI audit ingestion with causal chain reconstruction.

Capabilities:
  - tool call linkage (chains tool invocations to the inference request that triggered them)
  - multi-step reasoning chain reconstruction (CoT / scratchpad sequences)
  - override tracking (human or system overrides of model decisions)
  - moderation lineage (traces content from inference through moderation to outcome)

Rules (Phase 0):
  - Inferred relationships are marked as LOSS_OF_CAUSAL_LINKAGE, not silently invented.
  - Missing links remain explicit — we never fabricate a causal edge.
  - Every reconstructed chain event carries a chain_id to group related events.
  - An incomplete chain (missing start or end) produces LOSS_OF_COMPLETENESS.

Design note:
  CausalChainBuilder is stateful within a single adapt() call.
  It is NOT stateful across multiple calls — each raw input is self-contained.
  Cross-session causal linkage is handled by Veritas claims referencing event hashes,
  not by this adapter.

Event types produced:
  AI_CAUSAL_TOOL_LINK         — tool invocation linked to a specific inference request
  AI_REASONING_STEP           — one step in a multi-step reasoning chain
  AI_REASONING_CHAIN_COMPLETE — full chain reconstructed (all steps present)
  AI_OVERRIDE_RECORD          — a human or system override of a model decision
  AI_MODERATION_LINEAGE       — trace from content through moderation to outcome
  AI_CAUSAL_INCOMPLETE        — chain that could not be fully reconstructed
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional

from aletheia.adapters.base import AdapterBase, AdapterResult
from aletheia.adapters.determinism import (
    normalise_unicode, parse_timestamp, measure_depth, MAX_PAYLOAD_DEPTH,
)
from aletheia.adapters.taxonomy import (
    LOSS_OF_CAUSAL_LINKAGE, LOSS_OF_COMPLETENESS, LOSS_OF_STRUCTURE,
    LOSS_OF_AUTHENTICITY,
    REJECT_MALFORMED, REJECT_INCOMPLETE, REJECT_HOSTILE,
    TRUST_UNAUTHENTICATED,
)


class AIAuditCausalAdapter(AdapterBase):
    """
    Reconstructs causal chains from AI workflow record batches.

    Input: a JSON array of records, each with a record_type discriminator
    and linking fields (request_id, chain_id, step_index, etc.).

    The adapter attempts to reconstruct causal links within the batch.
    It never invents links that are absent from the input.

    Supported record_types for causal reconstruction:
      tool_link           — explicit tool call linked to a request
      reasoning_step      — one step in a reasoning chain (has step_index)
      override            — human/system override event
      moderation_lineage  — content -> moderation -> outcome trace
    """

    NAME = "ai_audit_causal"
    VERSION = "1.0.0"
    DEFAULT_TRUST = TRUST_UNAUTHENTICATED
    DEFAULT_RETENTION = "HASHED"

    MAX_INPUT_BYTES = 10 * 1024 * 1024  # 10 MiB
    MAX_CHAIN_STEPS = 200

    def adapt(self, raw: bytes, *, profile: Optional[Dict[str, Any]] = None) -> AdapterResult:
        result = self._start_result(raw)

        if len(raw) > self.MAX_INPUT_BYTES:
            result.add_rejection(REJECT_HOSTILE, "root",
                                 f"Input {len(raw)} bytes exceeds limit {self.MAX_INPUT_BYTES}")
            return result

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as e:
            result.add_rejection(REJECT_MALFORMED, "root", f"Not valid UTF-8: {e}")
            return result

        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            result.add_rejection(REJECT_MALFORMED, "root", f"JSON parse error: {e}")
            return result

        if measure_depth(data) > MAX_PAYLOAD_DEPTH:
            result.add_rejection(REJECT_HOSTILE, "root", "Payload nesting depth exceeded")
            return result

        records = data if isinstance(data, list) else [data]

        # ── Pass 1: index all records by linking fields ───────────────────────
        builder = CausalChainBuilder(records)

        # ── Pass 2: reconstruct and emit ──────────────────────────────────────
        self._reconstruct_tool_links(builder, result)
        self._reconstruct_reasoning_chains(builder, result)
        self._reconstruct_overrides(builder, result)
        self._reconstruct_moderation_lineage(builder, result)
        self._emit_unlinked_records(builder, result)

        return result

    # ── Tool call linkage ─────────────────────────────────────────────────────

    def _reconstruct_tool_links(self, builder: "CausalChainBuilder", result: AdapterResult) -> None:
        for rec in builder.by_type.get("tool_link", []):
            prefix = f"[{rec['_idx']}]."
            request_id = rec.get("request_id")
            tool_name  = rec.get("tool_name")
            chain_id   = rec.get("chain_id")

            if not tool_name:
                result.add_rejection(REJECT_INCOMPLETE, f"{prefix}tool_name",
                                     "tool_link requires tool_name")
                continue

            if request_id is None:
                result.add_loss(LOSS_OF_CAUSAL_LINKAGE, f"{prefix}request_id",
                                "tool_link has no request_id; link to inference request is inferred from chain_id only")

            # Verify the linked request exists in this batch
            linked = builder.by_request_id.get(request_id) if request_id else None
            link_verified = linked is not None

            payload: Dict[str, Any] = {
                "tool_name":       normalise_unicode(str(tool_name)),
                "request_id":      request_id,
                "chain_id":        chain_id,
                "link_verified":   link_verified,
                "tool_input":      rec.get("tool_input"),
                "tool_output_hash": _hash_field(rec.get("tool_output")),
            }
            if not link_verified and request_id is not None:
                result.add_loss(LOSS_OF_CAUSAL_LINKAGE, f"{prefix}request_id",
                                f"Linked request_id {request_id!r} not found in this batch; "
                                f"cross-session link must be verified via Veritas claim pin")

            ts, _ = _rec_ts(rec)
            self._make_event(result, self._source(rec), "AI_CAUSAL_TOOL_LINK", payload, ts)
            builder.mark_handled(rec["_idx"])

    # ── Reasoning chain reconstruction ────────────────────────────────────────

    def _reconstruct_reasoning_chains(self, builder: "CausalChainBuilder", result: AdapterResult) -> None:
        steps_by_chain: Dict[str, List[Dict]] = {}
        for rec in builder.by_type.get("reasoning_step", []):
            chain_id = rec.get("chain_id")
            if chain_id is None:
                result.add_loss(LOSS_OF_CAUSAL_LINKAGE, f"[{rec['_idx']}].chain_id",
                                "reasoning_step has no chain_id; cannot group into chain")
                # Emit as standalone
                self._emit_single_step(rec, result, complete=False)
                builder.mark_handled(rec["_idx"])
                continue
            steps_by_chain.setdefault(chain_id, []).append(rec)

        for chain_id, steps in steps_by_chain.items():
            # Sort by step_index; missing step_index = order preserved, LOSS recorded
            has_index = all("step_index" in s for s in steps)
            if has_index:
                steps = sorted(steps, key=lambda s: int(s["step_index"]))
            else:
                result.add_loss(LOSS_OF_CAUSAL_LINKAGE, f"chain:{chain_id}",
                                "One or more reasoning_steps lack step_index; ordering may be wrong")

            if len(steps) > self.MAX_CHAIN_STEPS:
                result.add_loss(LOSS_OF_COMPLETENESS, f"chain:{chain_id}",
                                f"Chain has {len(steps)} steps; truncated to {self.MAX_CHAIN_STEPS}")
                steps = steps[:self.MAX_CHAIN_STEPS]

            # Check for gaps in step_index sequence
            if has_index:
                indices = [int(s["step_index"]) for s in steps]
                expected = list(range(min(indices), min(indices) + len(indices)))
                if indices != expected:
                    result.add_loss(LOSS_OF_COMPLETENESS, f"chain:{chain_id}",
                                    f"Step indices have gaps: {indices} — chain is incomplete")
                    chain_complete = False
                else:
                    chain_complete = True
            else:
                chain_complete = False

            request_id = next((s.get("request_id") for s in steps if s.get("request_id")), None)

            chain_payload: Dict[str, Any] = {
                "chain_id":       chain_id,
                "request_id":     request_id,
                "step_count":     len(steps),
                "chain_complete": chain_complete,
                "steps": [
                    {
                        "step_index": s.get("step_index"),
                        "step_type":  s.get("step_type", "reasoning"),
                        "content_hash": _hash_field(s.get("content")),
                    }
                    for s in steps
                ],
            }

            event_type = "AI_REASONING_CHAIN_COMPLETE" if chain_complete else "AI_CAUSAL_INCOMPLETE"
            source = self._source(steps[0])
            ts, _ = _rec_ts(steps[0])
            self._make_event(result, source, event_type, chain_payload, ts)

            for s in steps:
                builder.mark_handled(s["_idx"])

    def _emit_single_step(self, rec: Dict, result: AdapterResult, complete: bool) -> None:
        payload = {
            "chain_id":    rec.get("chain_id"),
            "step_index":  rec.get("step_index"),
            "step_type":   rec.get("step_type", "reasoning"),
            "content_hash": _hash_field(rec.get("content")),
        }
        ts, _ = _rec_ts(rec)
        self._make_event(result, self._source(rec), "AI_REASONING_STEP", payload, ts)

    # ── Override tracking ─────────────────────────────────────────────────────

    def _reconstruct_overrides(self, builder: "CausalChainBuilder", result: AdapterResult) -> None:
        for rec in builder.by_type.get("override", []):
            prefix = f"[{rec['_idx']}]."
            override_type = rec.get("override_type")
            target_id     = rec.get("target_id")
            actor         = rec.get("actor")

            if not override_type:
                result.add_rejection(REJECT_INCOMPLETE, f"{prefix}override_type",
                                     "override requires override_type")
                continue

            if target_id is None:
                result.add_loss(LOSS_OF_CAUSAL_LINKAGE, f"{prefix}target_id",
                                "Override has no target_id; cannot link to overridden decision")

            target_verified = target_id in builder.by_request_id if target_id else False

            payload: Dict[str, Any] = {
                "override_type":    normalise_unicode(str(override_type)),
                "target_id":        target_id,
                "target_verified":  target_verified,
                "actor":            actor,
                "reason":           rec.get("reason"),
                "original_decision": rec.get("original_decision"),
                "new_decision":      rec.get("new_decision"),
            }
            ts, _ = _rec_ts(rec)
            self._make_event(result, self._source(rec), "AI_OVERRIDE_RECORD", payload, ts)
            builder.mark_handled(rec["_idx"])

    # ── Moderation lineage ────────────────────────────────────────────────────

    def _reconstruct_moderation_lineage(
        self, builder: "CausalChainBuilder", result: AdapterResult
    ) -> None:
        for rec in builder.by_type.get("moderation_lineage", []):
            prefix = f"[{rec['_idx']}]."
            request_id = rec.get("request_id")
            verdict    = rec.get("verdict")

            if verdict is None:
                result.add_rejection(REJECT_INCOMPLETE, f"{prefix}verdict",
                                     "moderation_lineage requires verdict")
                continue

            # Try to link to inference request
            linked_request = builder.by_request_id.get(request_id) if request_id else None
            # Try to link to moderation outcome record
            linked_outcome = builder.by_type.get("moderation_outcome", [])
            outcome_linked = any(o.get("request_id") == request_id for o in linked_outcome)

            if request_id is None:
                result.add_loss(LOSS_OF_CAUSAL_LINKAGE, f"{prefix}request_id",
                                "moderation_lineage has no request_id; lineage is unanchored")
            elif linked_request is None:
                result.add_loss(LOSS_OF_CAUSAL_LINKAGE, f"{prefix}request_id",
                                f"request_id {request_id!r} not found in batch; "
                                f"lineage continuity cannot be verified in this batch")

            payload: Dict[str, Any] = {
                "request_id":      request_id,
                "verdict":         normalise_unicode(str(verdict)),
                "request_linked":  linked_request is not None,
                "outcome_linked":  outcome_linked,
                "categories":      rec.get("categories"),
                "lineage_notes":   rec.get("lineage_notes"),
            }
            ts, _ = _rec_ts(rec)
            self._make_event(result, self._source(rec), "AI_MODERATION_LINEAGE", payload, ts)
            builder.mark_handled(rec["_idx"])

    # ── Unhandled records ─────────────────────────────────────────────────────

    def _emit_unlinked_records(self, builder: "CausalChainBuilder", result: AdapterResult) -> None:
        """Emit any records not handled by a causal reconstruction pass."""
        for i, rec in enumerate(builder.records):
            if i in builder.handled:
                continue
            if not isinstance(rec, dict):
                continue
            rt = rec.get("record_type", "unknown")
            result.add_loss(LOSS_OF_STRUCTURE, f"[{i}].record_type",
                            f"Record type {rt!r} not handled by causal reconstruction; "
                            f"forwarded as AI_UNLINKED_RECORD")
            payload = {"record_type": rt, "index": i}
            self._make_event(result, self._source(rec), "AI_UNLINKED_RECORD", payload)

    def _source(self, rec: Dict) -> str:
        return str(rec.get("source", "ai_causal"))[:64] or "ai_causal"


# ── Causal chain builder ──────────────────────────────────────────────────────

class CausalChainBuilder:
    """
    Indexes a batch of records by type and linking fields.
    Tracks which records have been handled during reconstruction.
    """

    def __init__(self, records: List[Any]) -> None:
        self.records = records
        self.handled: set = set()
        self.by_type: Dict[str, List[Dict]] = {}
        self.by_request_id: Dict[str, Dict] = {}

        for i, rec in enumerate(records):
            if not isinstance(rec, dict):
                continue
            rec = dict(rec)
            rec["_idx"] = i

            rt = normalise_unicode(str(rec.get("record_type", "unknown"))).lower()
            self.by_type.setdefault(rt, []).append(rec)

            req_id = rec.get("request_id")
            if req_id is not None:
                self.by_request_id[req_id] = rec

    def mark_handled(self, idx: int) -> None:
        self.handled.add(idx)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _hash_field(value: Any) -> Optional[str]:
    """SHA256 of the canonical JSON representation of a field value. None if value is None."""
    if value is None:
        return None
    try:
        raw = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()
    except Exception:
        return None


def _rec_ts(rec: Dict) -> tuple:
    for key in ("timestamp", "ts", "time", "created_at", "time_wall"):
        if key in rec:
            return parse_timestamp(rec[key])
    return None, False


# Auto-register
from aletheia.adapters.registry import register as _reg
_reg(AIAuditCausalAdapter())
