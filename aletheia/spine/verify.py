"""
Spine verification (segment-aware)

Verification philosophy:
- Only sealed windows are considered valid evidence segments.
- Open/unsealed windows are reported but NOT trusted as complete segments.
- Any gap in event sequence or hash chain yields FAIL for that window segment.
- SCAR log is separate and never silently "fixes" anything.
"""

from __future__ import annotations

import json
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .ledger import canonicalize_json, sha256_hex


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def verify_spine(root_dir: str | Path, *, signer=None) -> Dict[str, Any]:
    root = Path(root_dir)
    spine_dir = root / "spine"
    windows_dir = spine_dir / "windows"

    report: Dict[str, Any] = {
        "ok": True,
        "sealed_windows_verified": 0,
        "sealed_windows_failed": 0,
        "open_windows": [],
        "failures": [],
    }

    if not windows_dir.exists():
        report["ok"] = False
        report["failures"].append({"error": "NO_WINDOWS_DIR"})
        return report

    for wdir in sorted(p for p in windows_dir.iterdir() if p.is_dir()):
        sealed_path = wdir / "sealed.json"
        open_path = wdir / "open.json"
        events_dir = wdir / "events"

        if not open_path.exists():
            if sealed_path.exists():
                # Phase 1.3: sealed window with no open.json is structurally invalid.
                report["ok"] = False
                report["sealed_windows_failed"] += 1
                report["failures"].append({"window_id": wdir.name, "error": "SEALED_WITHOUT_OPEN"})
                continue
            # Skip unknown garbage directory
            continue

        if not sealed_path.exists():
            report["open_windows"].append(wdir.name)
            continue

        seal = _load_json(sealed_path)
        ok, details = _verify_sealed_window(events_dir, seal, signer=signer)
        if ok:
            report["sealed_windows_verified"] += 1
        else:
            report["ok"] = False
            report["sealed_windows_failed"] += 1
            report["failures"].append({"window_id": wdir.name, **details})

    return report


def _verify_sealed_window(events_dir: Path, seal: Dict[str, Any], *, signer=None) -> Tuple[bool, Dict[str, Any]]:
    # Load events in order
    files = sorted(events_dir.glob("*.json"))
    events: List[Dict[str, Any]] = []
    for f in files:
        if not f.name[:6].isdigit():
            continue
        events.append(_load_json(f))

    if not events:
        return False, {"error": "EMPTY_WINDOW"}

    # Sequence continuity
    seqs = [int(e.get("seq", -1)) for e in events]
    expected = list(range(seqs[0], seqs[0] + len(seqs)))
    if seqs != expected:
        return False, {"error": "SEQ_GAP", "seqs": seqs[:20], "expected_head": expected[:20]}

    # Hash chain and self-hash validity
    prev_hash = None
    for e in events:
        base = dict(e)
        got_hash = base.pop("hash", None)
        if got_hash is None:
            return False, {"error": "MISSING_HASH", "seq": e.get("seq")}

        if base.get("prev_hash") != prev_hash:
            return False, {"error": "CHAIN_BREAK", "seq": e.get("seq"), "expected_prev": prev_hash, "got_prev": base.get("prev_hash")}

        expected_hash = sha256_hex(canonicalize_json(base))
        if expected_hash != got_hash:
            return False, {"error": "HASH_MISMATCH", "seq": e.get("seq"), "expected": expected_hash, "got": got_hash}

        prev_hash = got_hash

    # Seal checks
    if int(seal.get("event_count", -1)) != len(events):
        return False, {"error": "SEAL_COUNT_MISMATCH", "seal_count": seal.get("event_count"), "actual": len(events)}

    if str(seal.get("first_hash")) != str(events[0].get("hash")):
        return False, {"error": "SEAL_FIRST_HASH_MISMATCH"}

    if str(seal.get("last_hash")) != str(events[-1].get("hash")):
        return False, {"error": "SEAL_LAST_HASH_MISMATCH"}

    # Root hash check
    root_bytes = ("\n".join(e["hash"] for e in events) + "\n").encode("utf-8")
    root_hash = hashlib.sha256(root_bytes).hexdigest()
    if str(seal.get("window_root_hash")) != root_hash:
        return False, {"error": "WINDOW_ROOT_MISMATCH", "expected": root_hash, "got": seal.get("window_root_hash")}

    # Phase 1.1 — HMAC signature verification
    if signer is not None:
        seal_mode = seal.get("signing_mode", "NONE")
        if seal_mode != signer.signing_mode and signer.signing_mode != "NONE":
            return False, {
                "error": "SIGNING_MODE_MISMATCH",
                "seal_mode": seal_mode,
                "verifier_mode": signer.signing_mode,
            }
        if signer.signing_mode != "NONE":
            sig_hex = seal.get("seal_signature")
            sig_bytes = bytes.fromhex(sig_hex) if sig_hex else None
            try:
                valid = signer.verify(root_hash, sig_bytes)
            except Exception as exc:
                return False, {"error": "SIGNATURE_VERIFY_ERROR", "detail": str(exc)}
            if not valid:
                return False, {"error": "SIGNATURE_INVALID", "detail": "HMAC comparison failed — forged chain or wrong key"}

    return True, {"ok": True}
