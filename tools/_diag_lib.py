from __future__ import annotations

import json, hashlib, datetime
from typing import Any, Dict

def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def now_utc_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def make_trace(payload: Dict[str, Any]) -> Dict[str, Any]:
    # trace_id must not depend on wall-clock time
    base = {k: payload[k] for k in payload.keys() if k != "created_utc"}
    tid = sha256_hex(canonical_json_bytes(base))
    payload["trace_id"] = tid
    payload.setdefault("schema_version", "1")
    payload.setdefault("created_utc", now_utc_iso())
    return payload
