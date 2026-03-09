"""
aletheia.adapters.ai_audit_adapter — Minimal AI Audit Adapter

Phase 5A: Deterministic ingestion of AI workflow records.

Inputs: prompts, responses, model metadata, session identifiers,
        tool invocation summaries, moderation outcomes.

Rules:
  - Truncated content is marked as LOSS_OF_COMPLETENESS, not silently trimmed.
  - Missing causal links are explicitly reported as LOSS_OF_CAUSAL_LINKAGE.
  - Content hashing is optional but deterministic when enabled.
  - Redaction is explicitly recorded — no silent omission.
  - Model version must be preserved exactly as provided.

Event types produced:
  AI_INFERENCE_REQUEST    — a prompt sent to a model
  AI_INFERENCE_RESPONSE   — a model output
  AI_MODEL_VERSION        — model version metadata record
  AI_TOOL_INVOCATION      — a tool call summary
  AI_MODERATION_OUTCOME   — a content moderation result
  AI_SESSION_START        — session boundary
  AI_SESSION_END          — session boundary
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
    LOSS_OF_COMPLETENESS, LOSS_OF_CAUSAL_LINKAGE, LOSS_OF_AUTHENTICITY,
    LOSS_OF_STRUCTURE,
    REJECT_MALFORMED, REJECT_INCOMPLETE, REJECT_HOSTILE,
    TRUST_UNAUTHENTICATED,
)

# Content truncation threshold — longer content recorded as LOSS_OF_COMPLETENESS
CONTENT_TRUNCATE_CHARS = 8_192
# Max number of tool calls in one record before truncation is noted
MAX_TOOL_CALLS = 50


class AIAuditAdapter(AdapterBase):
    """
    Ingests AI workflow records as canonical Aletheia events.

    Input: a JSON object (or array of objects) with a 'record_type' discriminator.

    Supported record_types:
      inference_request, inference_response, model_version,
      tool_invocation, moderation_outcome, session_start, session_end.

    Unknown record_types produce LOSS_OF_STRUCTURE (not REJECTED) so that
    future record types don't silently break ingestion.
    """

    NAME = "ai_audit_adapter"
    VERSION = "1.0.0"
    DEFAULT_TRUST = TRUST_UNAUTHENTICATED
    DEFAULT_RETENTION = "HASHED"

    MAX_INPUT_BYTES = 5 * 1024 * 1024  # 5 MiB

    def __init__(self, hash_content: bool = False) -> None:
        """
        hash_content: if True, include SHA256 of prompt/response content
                      in payload for integrity linkage.
        """
        self.hash_content = hash_content

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

        for i, rec in enumerate(records):
            if not isinstance(rec, dict):
                result.add_rejection(REJECT_MALFORMED, f"[{i}]",
                                     f"Item {i} is not a JSON object")
                continue
            self._translate_record(rec, result, item_index=i)

        return result

    def _translate_record(
        self, rec: Dict[str, Any], result: AdapterResult, item_index: int = 0
    ) -> None:
        prefix = f"[{item_index}]."
        record_type = rec.get("record_type")

        if not isinstance(record_type, str):
            result.add_rejection(REJECT_INCOMPLETE, f"{prefix}record_type",
                                 "record_type must be a string")
            return

        rt = normalise_unicode(record_type).lower().strip()

        dispatch = {
            "inference_request":  self._inference_request,
            "inference_response": self._inference_response,
            "model_version":      self._model_version,
            "tool_invocation":    self._tool_invocation,
            "moderation_outcome": self._moderation_outcome,
            "session_start":      self._session_boundary,
            "session_end":        self._session_boundary,
        }

        handler = dispatch.get(rt)
        if handler is None:
            result.add_loss(LOSS_OF_STRUCTURE, f"{prefix}record_type",
                            f"Unknown record_type {record_type!r}; record preserved as AI_UNKNOWN_RECORD")
            payload = {"record_type": record_type, "raw": _safe_truncate_dict(rec, result, prefix)}
            source = self._source(rec)
            self._make_event(result, source, "AI_UNKNOWN_RECORD", payload)
            return

        handler(rec, result, prefix)

    # ── Record type handlers ──────────────────────────────────────────────────

    def _inference_request(self, rec: Dict, result: AdapterResult, prefix: str) -> None:
        source   = self._source(rec)
        session  = _optional_str(rec, "session_id", result, prefix)
        model    = _required_str(rec, "model", result, prefix)
        if model is None:
            return

        content, truncated = _extract_content(rec, "prompt", result, prefix, CONTENT_TRUNCATE_CHARS)
        if truncated:
            result.add_loss(LOSS_OF_COMPLETENESS, f"{prefix}prompt",
                            f"Prompt truncated to {CONTENT_TRUNCATE_CHARS} chars")

        payload: Dict[str, Any] = {
            "model":      normalise_unicode(model),
            "session_id": session,
            "has_content": content is not None,
        }
        if self.hash_content and content is not None:
            payload["content_hash"] = hashlib.sha256(content.encode("utf-8")).hexdigest()

        ts, ambiguous = _rec_timestamp(rec)
        if ambiguous:
            result.add_loss(LOSS_OF_AUTHENTICITY, f"{prefix}timestamp", "Timezone assumed UTC")

        self._make_event(result, source, "AI_INFERENCE_REQUEST", payload, ts)

    def _inference_response(self, rec: Dict, result: AdapterResult, prefix: str) -> None:
        source   = self._source(rec)
        session  = _optional_str(rec, "session_id", result, prefix)
        model    = _optional_str(rec, "model", result, prefix)
        req_id   = _optional_str(rec, "request_id", result, prefix)

        if req_id is None:
            result.add_loss(LOSS_OF_CAUSAL_LINKAGE, f"{prefix}request_id",
                            "No request_id; cannot link response to a specific request")

        content, truncated = _extract_content(rec, "response", result, prefix, CONTENT_TRUNCATE_CHARS)
        if truncated:
            result.add_loss(LOSS_OF_COMPLETENESS, f"{prefix}response",
                            f"Response truncated to {CONTENT_TRUNCATE_CHARS} chars")

        payload: Dict[str, Any] = {
            "model":       model,
            "session_id":  session,
            "request_id":  req_id,
            "has_content": content is not None,
            "finish_reason": rec.get("finish_reason"),
            "usage":         rec.get("usage"),
        }
        if self.hash_content and content is not None:
            payload["content_hash"] = hashlib.sha256(content.encode("utf-8")).hexdigest()

        ts, ambiguous = _rec_timestamp(rec)
        if ambiguous:
            result.add_loss(LOSS_OF_AUTHENTICITY, f"{prefix}timestamp", "Timezone assumed UTC")

        self._make_event(result, source, "AI_INFERENCE_RESPONSE", payload, ts)

    def _model_version(self, rec: Dict, result: AdapterResult, prefix: str) -> None:
        source = self._source(rec)
        model  = _required_str(rec, "model", result, prefix)
        if model is None:
            return
        payload: Dict[str, Any] = {
            "model":        normalise_unicode(model),
            "model_family": rec.get("model_family"),
            "provider":     rec.get("provider"),
            "context_window": rec.get("context_window"),
            "capabilities": rec.get("capabilities"),
        }
        self._make_event(result, source, "AI_MODEL_VERSION", payload)

    def _tool_invocation(self, rec: Dict, result: AdapterResult, prefix: str) -> None:
        source  = self._source(rec)
        session = _optional_str(rec, "session_id", result, prefix)
        tool    = _required_str(rec, "tool_name", result, prefix)
        if tool is None:
            return

        calls = rec.get("calls", [])
        if not isinstance(calls, list):
            calls = []
            result.add_loss(LOSS_OF_STRUCTURE, f"{prefix}calls",
                            "calls field is not a list; omitted")
        if len(calls) > MAX_TOOL_CALLS:
            result.add_loss(LOSS_OF_COMPLETENESS, f"{prefix}calls",
                            f"calls truncated from {len(calls)} to {MAX_TOOL_CALLS}")
            calls = calls[:MAX_TOOL_CALLS]

        req_id = _optional_str(rec, "request_id", result, prefix)
        if req_id is None:
            result.add_loss(LOSS_OF_CAUSAL_LINKAGE, f"{prefix}request_id",
                            "No request_id; cannot link tool call to inference request")

        payload: Dict[str, Any] = {
            "tool_name":  normalise_unicode(tool),
            "session_id": session,
            "request_id": req_id,
            "call_count": len(calls),
            "outcome":    rec.get("outcome"),
        }
        ts, ambiguous = _rec_timestamp(rec)
        if ambiguous:
            result.add_loss(LOSS_OF_AUTHENTICITY, f"{prefix}timestamp", "Timezone assumed UTC")
        self._make_event(result, source, "AI_TOOL_INVOCATION", payload, ts)

    def _moderation_outcome(self, rec: Dict, result: AdapterResult, prefix: str) -> None:
        source  = self._source(rec)
        verdict = _required_str(rec, "verdict", result, prefix)
        if verdict is None:
            return

        req_id = _optional_str(rec, "request_id", result, prefix)
        if req_id is None:
            result.add_loss(LOSS_OF_CAUSAL_LINKAGE, f"{prefix}request_id",
                            "No request_id; moderation outcome unlinked from inference")

        payload: Dict[str, Any] = {
            "verdict":     normalise_unicode(verdict),
            "request_id":  req_id,
            "categories":  rec.get("categories"),
            "scores":      rec.get("scores"),
        }
        ts, ambiguous = _rec_timestamp(rec)
        if ambiguous:
            result.add_loss(LOSS_OF_AUTHENTICITY, f"{prefix}timestamp", "Timezone assumed UTC")
        self._make_event(result, source, "AI_MODERATION_OUTCOME", payload, ts)

    def _session_boundary(self, rec: Dict, result: AdapterResult, prefix: str) -> None:
        source     = self._source(rec)
        session_id = _optional_str(rec, "session_id", result, prefix)
        rt         = rec.get("record_type", "session_start").upper()
        event_type = f"AI_{rt}" if rt in ("SESSION_START", "SESSION_END") else "AI_SESSION_START"

        payload: Dict[str, Any] = {
            "session_id": session_id,
            "metadata":   rec.get("metadata"),
        }
        ts, _ = _rec_timestamp(rec)
        self._make_event(result, source, event_type, payload, ts)

    def _source(self, rec: Dict) -> str:
        s = rec.get("source", "ai_audit")
        return normalise_unicode(str(s))[:64] or "ai_audit"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _required_str(rec: Dict, key: str, result: AdapterResult, prefix: str) -> Optional[str]:
    v = rec.get(key)
    if not isinstance(v, str) or not v.strip():
        result.add_rejection(REJECT_INCOMPLETE, f"{prefix}{key}",
                             f"Required field '{key}' is missing or empty")
        return None
    return normalise_unicode(v.strip())


def _optional_str(rec: Dict, key: str, result: AdapterResult, prefix: str) -> Optional[str]:
    v = rec.get(key)
    if v is None:
        return None
    if not isinstance(v, str):
        result.add_loss(LOSS_OF_STRUCTURE, f"{prefix}{key}",
                        f"Optional field '{key}' is not a string; omitted")
        return None
    return normalise_unicode(v.strip()) or None


def _extract_content(
    rec: Dict, key: str, result: AdapterResult, prefix: str, limit: int
) -> tuple[Optional[str], bool]:
    """Extract a text content field, returning (text_or_none, truncated)."""
    v = rec.get(key)
    if v is None:
        return None, False
    if not isinstance(v, str):
        v = json.dumps(v, ensure_ascii=False)
    if len(v) > limit:
        return v[:limit], True
    return v, False


def _rec_timestamp(rec: Dict) -> tuple[Optional[str], bool]:
    from aletheia.adapters.determinism import parse_timestamp
    for key in ("timestamp", "created_at", "time", "ts", "time_wall"):
        if key in rec:
            return parse_timestamp(rec[key])
    return None, False


def _safe_truncate_dict(rec: Dict, result: AdapterResult, prefix: str) -> Dict:
    """Return a truncated repr of a dict for UNKNOWN_RECORD payloads."""
    try:
        s = json.dumps(rec, ensure_ascii=False)
        if len(s) > 2048:
            result.add_loss(LOSS_OF_COMPLETENESS, f"{prefix}raw",
                            "Unknown record content truncated to 2048 chars for payload")
            return {"_truncated": s[:2048]}
        return rec
    except Exception:
        return {"_unserializable": True}


# Auto-register
from aletheia.adapters.registry import register as _reg
_reg(AIAuditAdapter())
