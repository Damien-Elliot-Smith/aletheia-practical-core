from __future__ import annotations

import json, hashlib, datetime
from typing import Any, Dict

def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def now_utc_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def stable_id(payload: Dict[str, Any]) -> str:
    # must not depend on created_utc
    base = {k: payload[k] for k in payload.keys() if k != "created_utc"}
    return sha256_hex(canonical_json_bytes(base))
