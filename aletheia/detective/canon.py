import json
from typing import Any

def canonical_json_bytes(obj: Any) -> bytes:
    s = json.dumps(
        obj,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return (s + "\n").encode("utf-8")
