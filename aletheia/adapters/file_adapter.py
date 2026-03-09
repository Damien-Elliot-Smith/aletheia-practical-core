"""
aletheia.adapters.file_adapter — File and Log Adapter

Phase 4: Translate log files and line-based event feeds.

Inputs: log files, JSON-line streams, delimited files, exported system logs.

Modes:
  STRICT: one parse error rejects the entire file.
  MIXED:  valid lines accepted; invalid lines rejected individually.

Rules:
  - Line-level provenance: each line's position is recorded.
  - Raw file hash is always computed before parsing.
  - Structured parse failure reporting — never silently dropped.
  - Empty lines are skipped without recording a loss.

Phase 11 hardening:
  - Max file size enforced before parsing.
  - Max lines enforced.
  - Max events per input enforced.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from aletheia.adapters.base import AdapterBase, AdapterResult, build_raw_ref
from aletheia.adapters.determinism import (
    parse_timestamp, normalise_unicode, measure_depth,
    MAX_PAYLOAD_DEPTH, MAX_EVENTS_PER_INPUT,
)
from aletheia.adapters.profiles import load_profile, apply_profile
from aletheia.adapters.taxonomy import (
    LOSS_OF_COMPLETENESS, LOSS_OF_STRUCTURE, LOSS_OF_AUTHENTICITY,
    REJECT_MALFORMED, REJECT_INCOMPLETE, REJECT_HOSTILE,
    TRUST_UNAUTHENTICATED,
)

MODE_STRICT = "STRICT"
MODE_MIXED  = "MIXED"


class FileAdapter(AdapterBase):
    """
    Translates a line-based file (JSON-lines or plain text) into canonical events.

    Without a profile: each line must be a JSON object with source, event_type,
    and payload keys.

    With a profile: each JSON-line object is translated using the profile
    event_mappings.

    Mode:
      STRICT — first parse error rejects the entire file.
      MIXED  — each line handled independently; failures recorded per-line.
    """

    NAME = "file_adapter"
    VERSION = "1.0.0"
    DEFAULT_TRUST = TRUST_UNAUTHENTICATED
    DEFAULT_RETENTION = "HASHED"

    MAX_FILE_BYTES = 50 * 1024 * 1024   # 50 MiB
    MAX_LINES      = 100_000

    def adapt(self, raw: bytes, *, profile: Optional[Dict[str, Any]] = None) -> AdapterResult:
        result = self._start_result(raw)

        # Phase 11: size guard
        if len(raw) > self.MAX_FILE_BYTES:
            result.add_rejection(REJECT_HOSTILE, "root",
                                 f"File size {len(raw)} bytes exceeds limit {self.MAX_FILE_BYTES}")
            return result

        # Decode
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as e:
            result.add_rejection(REJECT_MALFORMED, "root", f"File is not valid UTF-8: {e}")
            return result

        lines = text.splitlines()

        # Phase 11: line count guard
        if len(lines) > self.MAX_LINES:
            result.add_rejection(REJECT_HOSTILE, "root",
                                 f"File has {len(lines)} lines, exceeds limit {self.MAX_LINES}")
            return result

        # Determine mode from profile or default to MIXED
        mode = MODE_MIXED
        source_name = "file_adapter"
        trust = self.DEFAULT_TRUST
        if profile is not None:
            mode = profile.get("mode", MODE_MIXED)
            source_name = profile.get("source_name", source_name)
            trust = profile.get("trust_level", trust)
        result.trust_level = trust

        event_count = 0

        for lineno, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line:
                continue  # empty lines silently skipped

            # Parse line as JSON
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                rec = RejectionRecord(
                    rejection_type=REJECT_MALFORMED,
                    field=f"line:{lineno}",
                    detail=f"Line {lineno}: JSON parse error: {e}",
                )
                if mode == MODE_STRICT:
                    result.add_rejection(REJECT_MALFORMED, f"line:{lineno}",
                                         f"STRICT mode: parse error at line {lineno}: {e}")
                    return result
                else:
                    result.rejections.append(rec)
                    continue

            if not isinstance(obj, dict):
                msg = f"Line {lineno}: expected JSON object, got {type(obj).__name__}"
                if mode == MODE_STRICT:
                    result.add_rejection(REJECT_MALFORMED, f"line:{lineno}", f"STRICT mode: {msg}")
                    return result
                else:
                    result.add_rejection(REJECT_MALFORMED, f"line:{lineno}", msg)
                    continue

            # Depth guard
            depth = measure_depth(obj)
            if depth > MAX_PAYLOAD_DEPTH:
                msg = f"Line {lineno}: nesting depth {depth} exceeds limit {MAX_PAYLOAD_DEPTH}"
                if mode == MODE_STRICT:
                    result.add_rejection(REJECT_HOSTILE, f"line:{lineno}", f"STRICT mode: {msg}")
                    return result
                else:
                    result.add_rejection(REJECT_HOSTILE, f"line:{lineno}", msg)
                    continue

            # Translate
            if profile is not None:
                pr = apply_profile(profile, obj)
                from aletheia.adapters.base import LossRecord, RejectionRecord as RR
                for l in pr.losses:
                    result.losses.append(LossRecord(**l))
                for r in pr.rejections:
                    rr = RR(**r)
                    if mode == MODE_STRICT:
                        result.rejections.append(rr)
                        return result
                    result.rejections.append(rr)
                for ev in pr.events:
                    if event_count >= MAX_EVENTS_PER_INPUT:
                        result.add_rejection(REJECT_HOSTILE, "root",
                                             f"Max events per input ({MAX_EVENTS_PER_INPUT}) reached")
                        return result
                    self._make_event(result, source_name, ev["event_type"], ev["payload"])
                    event_count += 1
            else:
                ok = self._translate_line(obj, result, lineno, source_name, mode)
                if not ok and mode == MODE_STRICT:
                    return result
                if ok:
                    event_count += 1
                    if event_count >= MAX_EVENTS_PER_INPUT:
                        result.add_rejection(REJECT_HOSTILE, "root",
                                             f"Max events per input ({MAX_EVENTS_PER_INPUT}) reached")
                        return result

        return result

    def _translate_line(
        self,
        obj: Dict[str, Any],
        result: AdapterResult,
        lineno: int,
        source_name: str,
        mode: str,
    ) -> bool:
        """Translate one JSON-object line in direct (no-profile) mode. Returns True on success."""
        source = obj.get("source", source_name)
        event_type = obj.get("event_type")
        payload = obj.get("payload")

        if not isinstance(event_type, str) or not event_type:
            msg = f"Line {lineno}: missing or invalid event_type"
            result.add_rejection(REJECT_INCOMPLETE, f"line:{lineno}", msg)
            return False

        if payload is None:
            # Allow payload-less lines: use entire object minus source/event_type as payload
            payload = {k: v for k, v in obj.items() if k not in ("source", "event_type", "time_wall")}
            result.add_loss(LOSS_OF_STRUCTURE, f"line:{lineno}",
                            "No payload key; using remaining fields as payload")
        elif not isinstance(payload, dict):
            msg = f"Line {lineno}: payload must be a JSON object"
            result.add_rejection(REJECT_MALFORMED, f"line:{lineno}", msg)
            return False

        # Timestamp
        ts, ambiguous = _line_timestamp(obj)
        if ambiguous:
            result.add_loss(LOSS_OF_AUTHENTICITY, f"line:{lineno}",
                            "Timestamp had no timezone; UTC assumed")

        source = normalise_unicode(str(source))
        event_type = normalise_unicode(event_type)

        self._make_event(result, source, event_type, payload, ts)
        return True


def _line_timestamp(obj: Dict[str, Any]):
    from aletheia.adapters.determinism import parse_timestamp
    for key in ("time_wall", "timestamp", "ts", "time", "@timestamp"):
        if key in obj:
            return parse_timestamp(obj[key])
    return None, False


# ── RejectionRecord import fix ────────────────────────────────────────────────
from aletheia.adapters.base import LossRecord, RejectionRecord


# Auto-register
from aletheia.adapters.registry import register as _reg
_reg(FileAdapter())
