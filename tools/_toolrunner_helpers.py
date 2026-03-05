from __future__ import annotations

import hashlib, json, os, re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Tuple

HEX64 = re.compile(r"^[0-9a-f]{64}$")

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z")

def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def load_json(p: Path) -> Dict[str, Any]:
    return json.loads(p.read_text(encoding="utf-8"))

def save_json(p: Path, obj: Dict[str, Any]) -> None:
    p.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")

def safe_resolve(workspace: Path, rel: str) -> Path:
    # Resolve a path and ensure it stays within workspace_root
    rp = (workspace / rel).resolve()
    ws = workspace.resolve()
    if rp == ws or str(rp).startswith(str(ws) + os.sep):
        return rp
    raise ValueError(f"PATH_ESCAPE:{rel}")

def file_size(p: Path) -> int:
    return p.stat().st_size
