"""
aletheia.adapters.determinism — Deterministic field normalisation utilities

Phase 0: Determinism Rules

All adapters must use these functions for normalisation. Direct use of
str.strip(), str.lower() etc. inside adapters is permitted only when
the result is identical to what these functions produce.

Rules enforced here:
  - deterministic field normalisation (unicode NFC, strip, case)
  - deterministic timestamp fallback (UTC only, Z suffix always)
  - deterministic unicode normalisation (NFC before any comparison)
  - deterministic JSON serialisation (via canonicalize_json from Spine)
  - deterministic failure: every parse failure raises ValueError with
    a message that includes the offending value
"""
from __future__ import annotations

import unicodedata
import re
from datetime import datetime, timezone
from typing import Any, Optional


# ── Unicode normalisation (Phase 11) ─────────────────────────────────────────

def normalise_unicode(s: str) -> str:
    """
    NFC normalise a string. Called before any comparison or hashing of
    human-readable string fields. Prevents unicode confusion attacks.
    """
    return unicodedata.normalize("NFC", s)


def normalise_field_name(s: str) -> str:
    """
    Canonical field name: NFC, strip, lowercase, underscored.
    Used when mapping external field names to canonical names.
    """
    s = normalise_unicode(s).strip().lower()
    s = re.sub(r"[^a-z0-9_]", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s or "unknown_field"


# ── Timestamp policy (Phase 0) ────────────────────────────────────────────────

_TS_FORMATS = [
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%S+00:00",
    "%Y-%m-%dT%H:%M:%S.%f+00:00",
    "%Y-%m-%dT%H:%M:%S",       # assumed UTC, LOSS_OF_AUTHENTICITY if used
    "%Y-%m-%d %H:%M:%S",       # assumed UTC, LOSS_OF_AUTHENTICITY if used
]

_TS_AMBIGUOUS = {"%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"}

_TS_CANONICAL_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def parse_timestamp(raw_ts: Any) -> tuple[Optional[str], bool]:
    """
    Parse a raw timestamp value into canonical ISO8601 UTC (Z suffix, second precision).

    Returns:
      (canonical_str, is_ambiguous)
        canonical_str: ISO8601 UTC string or None if unparseable
        is_ambiguous:  True if timezone was assumed (caller should record LOSS_OF_AUTHENTICITY)

    Determinism rule: the same raw_ts always produces the same output.
    """
    if raw_ts is None:
        return None, False

    if isinstance(raw_ts, (int, float)):
        # Unix epoch seconds
        try:
            dt = datetime.fromtimestamp(float(raw_ts), tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ"), False
        except (OSError, OverflowError, ValueError):
            return None, False

    if isinstance(raw_ts, str):
        s = normalise_unicode(raw_ts).strip()
        if _TS_CANONICAL_RE.match(s):
            return s, False
        for fmt in _TS_FORMATS:
            try:
                dt = datetime.strptime(s, fmt)
                if fmt in _TS_AMBIGUOUS:
                    dt = dt.replace(tzinfo=timezone.utc)
                    return dt.strftime("%Y-%m-%dT%H:%M:%SZ"), True
                dt = dt.replace(tzinfo=timezone.utc)
                return dt.strftime("%Y-%m-%dT%H:%M:%SZ"), False
            except ValueError:
                continue

    return None, False


def current_utc_z() -> str:
    """Fallback timestamp: current UTC time as canonical ISO8601 Z string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Type coercions (used by profile field_mappings) ───────────────────────────

def coerce_value(value: Any, transform: Optional[str]) -> Any:
    """
    Apply a deterministic type coercion. Raises ValueError on failure.
    Used by the profile engine — never silently produces wrong types.
    """
    if transform is None:
        return value
    if transform == "str":
        return normalise_unicode(str(value))
    if transform == "int":
        if isinstance(value, bool):
            raise ValueError(f"bool cannot coerce to int: {value!r}")
        return int(value)
    if transform == "float":
        if isinstance(value, bool):
            raise ValueError(f"bool cannot coerce to float: {value!r}")
        v = float(value)
        if v != v or v in (float("inf"), float("-inf")):
            raise ValueError(f"NaN/Inf not permitted: {value!r}")
        return v
    if transform == "bool":
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            s = value.strip().lower()
            if s in ("true", "1", "yes", "on"):  return True
            if s in ("false", "0", "no", "off"): return False
            raise ValueError(f"Cannot coerce string to bool: {value!r}")
        if isinstance(value, int):
            return bool(value)
        raise ValueError(f"Cannot coerce {type(value).__name__} to bool: {value!r}")
    if transform == "iso_utc":
        ts, _ = parse_timestamp(value)
        if ts is None:
            raise ValueError(f"Cannot parse as ISO8601 UTC: {value!r}")
        return ts
    raise ValueError(f"Unknown transform: {transform!r}")


# ── Dot-path field access ─────────────────────────────────────────────────────

def get_dot_path(obj: Any, path: str, default: Any = None) -> tuple[Any, bool]:
    """
    Traverse a dot-separated path into a nested dict/list.
    Returns (value, found).
    List indices are supported: data.items.0.value
    """
    parts = path.split(".")
    cur = obj
    for part in parts:
        if cur is None:
            return default, False
        if isinstance(cur, dict):
            if part not in cur:
                return default, False
            cur = cur[part]
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return default, False
        else:
            return default, False
    return cur, True


# ── Payload size and depth guards (Phase 11) ──────────────────────────────────

MAX_PAYLOAD_BYTES: int = 65_536
MAX_PAYLOAD_DEPTH: int = 32
MAX_EVENTS_PER_INPUT: int = 500
MAX_STRING_FIELD_LEN: int = 4_096


def measure_depth(obj: Any, _d: int = 0) -> int:
    """Measure maximum nesting depth. Hard ceiling at 128."""
    if _d > 128:
        return _d
    if isinstance(obj, dict):
        if not obj:
            return _d
        return max(measure_depth(v, _d + 1) for v in obj.values())
    if isinstance(obj, list):
        if not obj:
            return _d
        return max(measure_depth(v, _d + 1) for v in obj)
    return _d
