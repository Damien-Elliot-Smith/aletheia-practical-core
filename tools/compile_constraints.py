#!/usr/bin/env python3
from __future__ import annotations

import argparse, json, hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional

def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def load_json(p: Path) -> Any:
    return json.loads(p.read_text(encoding="utf-8"))

def save_json(p: Path, obj: Any) -> None:
    p.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")

def main() -> None:
    ap = argparse.ArgumentParser(description="Compile declarative constraints into a deterministic runtime bundle.")
    ap.add_argument("--rules", default="constraints/rules_v1.json", help="Ruleset JSON path")
    ap.add_argument("--out", default="constraints/compiled_constraints.json", help="Output compiled JSON path")
    args = ap.parse_args()

    rules_path = Path(args.rules).resolve()
    spec = load_json(rules_path)

    if not isinstance(spec, dict) or spec.get("schema_version") != "1":
        raise SystemExit("BAD_RULESET_SCHEMA_VERSION")

    compiled_rules: List[Dict[str, Any]] = []
    for i, r in enumerate(spec.get("rules", [])):
        if not isinstance(r, dict) or "id" not in r:
            continue
        cr = dict(r)
        cr["source"] = {"path": str(rules_path), "index": i}
        compiled_rules.append(cr)

    bundle: Dict[str, Any] = {
        "schema_version": "1",
        "ruleset_id": spec.get("ruleset_id"),
        "rules_source_sha256": sha256_hex(canonical_json_bytes(spec)),
        "compiled_rules": compiled_rules,
    }
    bundle["compiled_sha256"] = sha256_hex(canonical_json_bytes(bundle))

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    save_json(out_path, bundle)

    print(json.dumps({"verdict":"PASS","out":str(out_path),"compiled_sha256":bundle["compiled_sha256"]}, indent=2, sort_keys=True))

if __name__ == "__main__":
    main()
