"""
aletheia.adapters.profiles — Mapping Profile Engine

Phase 7: Mapping Profiles

Loads and validates adapter_profile.schema.json profiles.
Applies field mappings deterministically to a source dict.

Rules:
  - Profiles may map fields but cannot invent missing certainty.
  - A missing required field without a fallback -> REJECTED / INCOMPLETE.
  - A missing optional field without a fallback -> LOSS_OF_COMPLETENESS.
  - Coercion failures -> REJECTED / MALFORMED.
  - Unknown fields are preserved under _unknown if preserve_unknown=True.
  - Profiles are loaded once and cached (deterministic per profile_id).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from aletheia.adapters.determinism import get_dot_path, coerce_value, normalise_unicode
from aletheia.adapters.taxonomy import (
    LOSS_OF_COMPLETENESS,
    REJECT_INCOMPLETE,
    REJECT_MALFORMED,
)

_PROFILE_CACHE: Dict[str, Dict[str, Any]] = {}


def load_profile(profile_path: str | Path) -> Dict[str, Any]:
    """Load and cache a profile. Validates required top-level keys."""
    p = Path(profile_path)
    key = str(p.resolve())
    if key in _PROFILE_CACHE:
        return _PROFILE_CACHE[key]
    data = json.loads(p.read_text(encoding="utf-8"))
    for required in ("profile_id", "profile_version", "adapter_name", "source_name", "event_mappings"):
        if required not in data:
            raise ValueError(f"Profile missing required key: {required!r} in {profile_path}")
    _PROFILE_CACHE[key] = data
    return data


class ProfileApplyResult:
    """Result of applying a profile to a single source object."""
    __slots__ = ("events", "losses", "rejections", "matched")

    def __init__(self) -> None:
        self.events: List[Dict[str, Any]] = []     # list of (event_type, payload) dicts
        self.losses: List[Dict[str, Any]] = []
        self.rejections: List[Dict[str, Any]] = []
        self.matched: bool = False

    def add_loss(self, loss_type: str, field_path: str, detail: str) -> None:
        self.losses.append({"loss_type": loss_type, "field": field_path, "detail": detail})

    def add_rejection(self, rejection_type: str, field_path: Optional[str], detail: str) -> None:
        self.rejections.append({"rejection_type": rejection_type, "field": field_path, "detail": detail})

    @property
    def rejected(self) -> bool:
        return bool(self.rejections)


def apply_profile(profile: Dict[str, Any], source: Dict[str, Any]) -> ProfileApplyResult:
    """
    Apply a loaded profile to a source dict.

    For each event_mapping that matches (match_field/match_value or always):
      - Walk field_mappings, applying coercions and recording losses.
      - Emit a (event_type, payload) pair.

    Returns a ProfileApplyResult with all events and any losses/rejections.
    """
    result = ProfileApplyResult()
    source_name = profile.get("source_name", "unknown")
    preserve_default = False

    for mapping in profile.get("event_mappings", []):
        event_type = mapping["event_type"]
        match_field = mapping.get("match_field")
        match_value = mapping.get("match_value")
        preserve_unknown = mapping.get("preserve_unknown", preserve_default)

        # Check match condition
        if match_field is not None:
            val, found = get_dot_path(source, match_field)
            if not found or val != match_value:
                continue

        # Build canonical payload
        payload: Dict[str, Any] = {}
        mapped_source_fields: set = set()
        rejected = False

        for fm in mapping.get("field_mappings", []):
            src_field = fm["source_field"]
            tgt_field = fm["target_field"]
            required = fm.get("required", False)
            fallback = fm.get("fallback", _SENTINEL)
            transform = fm.get("transform")

            value, found = get_dot_path(source, src_field)
            mapped_source_fields.add(src_field.split(".")[0])

            if not found or value is None:
                if fallback is not _SENTINEL:
                    payload[tgt_field] = fallback
                    result.add_loss(LOSS_OF_COMPLETENESS, src_field,
                                    f"Field '{src_field}' absent; using fallback value")
                elif required:
                    result.add_rejection(REJECT_INCOMPLETE, src_field,
                                         f"Required field '{src_field}' is missing")
                    rejected = True
                else:
                    result.add_loss(LOSS_OF_COMPLETENESS, src_field,
                                    f"Optional field '{src_field}' absent; omitted from payload")
                continue

            # Apply transform
            if transform is not None:
                try:
                    value = coerce_value(value, transform)
                except (ValueError, TypeError) as exc:
                    result.add_rejection(REJECT_MALFORMED, src_field,
                                         f"Coercion of '{src_field}' to {transform!r} failed: {exc}")
                    rejected = True
                    continue

            # String field length guard (Phase 11)
            if isinstance(value, str) and len(value) > 4096:
                value = value[:4096]
                result.add_loss(
                    "LOSS_OF_PRECISION", src_field,
                    f"String field '{src_field}' truncated to 4096 chars"
                )

            payload[tgt_field] = value

        if rejected:
            # This mapping produced a rejection — skip event but record it
            continue

        # Preserve unknown fields if requested
        if preserve_unknown:
            unknown = {
                k: v for k, v in source.items()
                if k not in mapped_source_fields
            }
            if unknown:
                payload["_unknown"] = unknown
                result.add_loss("LOSS_OF_STRUCTURE", "_unknown",
                                 f"Unknown fields preserved under _unknown: {sorted(unknown.keys())}")

        result.events.append({"event_type": event_type, "payload": payload})
        result.matched = True

    if not result.matched and not result.rejected:
        result.add_loss("LOSS_OF_STRUCTURE", "root",
                         f"No event mapping matched this input from source '{source_name}'")

    return result


class _SentinelType:
    pass

_SENTINEL = _SentinelType()
