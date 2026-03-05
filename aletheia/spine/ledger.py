"""
Aletheia Spine v1 (Practical Core)

Design goals:
- Deterministic canonicalization: exact bytes hashed are well-defined.
- Append-only events stored as atomic per-event files (write -> fsync -> rename).
- Hash chaining within a window.
- Window sealing: produces an immutable sealed record per window.
- Dirty shutdown detection: a persistent marker triggers SCAR on next boot.

This is intentionally single-node and filesystem-backed for robustness and auditability.
"""

from __future__ import annotations

import os
import json
import uuid
import time
import hashlib
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List, Tuple


class SpineError(Exception):
    pass


class ValidationError(SpineError):
    pass


def iso_utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_json_safe(v: Any, *, allow_float: bool) -> bool:
    # Strict JSON-compatible primitives (with optional float ban).
    if v is None or isinstance(v, (bool, str, int)):
        return True
    if isinstance(v, float):
        return allow_float
    if isinstance(v, list):
        return all(_is_json_safe(x, allow_float=allow_float) for x in v)
    if isinstance(v, dict):
        return all(isinstance(k, str) and _is_json_safe(val, allow_float=allow_float) for k, val in v.items())
    return False


def canonicalize_json(obj: Any) -> bytes:
    """
    Deterministic canonicalization:
    - UTF-8
    - sorted keys
    - separators without whitespace
    - ensure_ascii=False
    - no NaN/Infinity allowed
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


@dataclass(frozen=True)
class Event:
    event_id: str
    timestamp_wall: str
    timestamp_mono_ns: int
    window_id: str
    seq: int
    event_type: str
    payload: Dict[str, Any]
    prev_hash: Optional[str]
    hash: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp_wall": self.timestamp_wall,
            "timestamp_mono_ns": self.timestamp_mono_ns,
            "window_id": self.window_id,
            "seq": self.seq,
            "event_type": self.event_type,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
            "hash": self.hash,
        }


@dataclass(frozen=True)
class SealRecord:
    window_id: str
    sealed_utc: str
    first_seq: int
    last_seq: int
    first_hash: str
    last_hash: str
    window_root_hash: str
    event_count: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "window_id": self.window_id,
            "sealed_utc": self.sealed_utc,
            "first_seq": self.first_seq,
            "last_seq": self.last_seq,
            "first_hash": self.first_hash,
            "last_hash": self.last_hash,
            "window_root_hash": self.window_root_hash,
            "event_count": self.event_count,
        }


class SpineLedger:
    """
    Filesystem layout (under root_dir):
      spine/
        dirty.marker
        windows/
          <window_id>/
            open.json
            events/
              000001.json
              000002.json
              ...
            sealed.json   (present only when sealed)
        witness_index.json   (optional map: pin->relative path)
        scars.jsonl          (append-only SCAR records)

    All writes are atomic per file: write temp -> fsync -> rename.
    """
    def __init__(self, root_dir: str | Path, *, allow_float_payload: bool = False):
        self.root_dir = Path(root_dir)
        self.allow_float_payload = allow_float_payload
        self.spine_dir = self.root_dir / "spine"
        self.windows_dir = self.spine_dir / "windows"
        self.dirty_marker = self.spine_dir / "dirty.marker"
        self.scars_log = self.spine_dir / "scars.jsonl"
        self.witness_index = self.spine_dir / "witness_index.json"

        self.windows_dir.mkdir(parents=True, exist_ok=True)
        self._boot_check_dirty_and_scar()
        # Mark dirty for this run; cleared by close_clean()
        self._atomic_write_bytes(self.dirty_marker, b"DIRTY\n")

    # ---------- Public API ----------

    def open_window(self, window_id: str) -> None:
        wdir = self._wdir(window_id)
        events_dir = wdir / "events"
        events_dir.mkdir(parents=True, exist_ok=True)

        open_meta = wdir / "open.json"
        sealed = wdir / "sealed.json"
        if sealed.exists():
            raise SpineError(f"Window already sealed: {window_id}")

        if not open_meta.exists():
            meta = {
                "window_id": window_id,
                "opened_utc": iso_utc_now(),
            }
            self._atomic_write_json(open_meta, meta)

        # Record WINDOW_OPEN as first event if empty
        if self._next_seq(window_id) == 1:
            self.append_event(window_id, "WINDOW_OPEN", {"window_id": window_id})

    def append_event(self, window_id: str, event_type: str, payload: Dict[str, Any]) -> Event:
        self._validate_payload(payload)
        wdir = self._wdir(window_id)
        if not (wdir / "open.json").exists():
            raise SpineError(f"Window not opened: {window_id}")
        if (wdir / "sealed.json").exists():
            raise SpineError(f"Window sealed (append forbidden): {window_id}")

        seq = self._next_seq(window_id)
        prev_hash = self._read_prev_hash(window_id, seq)

        base = {
            "event_id": str(uuid.uuid4()),
            "timestamp_wall": iso_utc_now(),
            "timestamp_mono_ns": time.monotonic_ns(),
            "window_id": window_id,
            "seq": seq,
            "event_type": event_type,
            "payload": payload,
            "prev_hash": prev_hash,
        }
        # Hash is over canonical bytes of base (no 'hash' field)
        h = sha256_hex(canonicalize_json(base))
        ev = Event(**base, hash=h)

        # Persist event as atomic file
        path = self._event_path(window_id, seq)
        self._atomic_write_json(path, ev.to_dict())

        return ev

    def seal_window(self, window_id: str) -> SealRecord:
        wdir = self._wdir(window_id)
        sealed_path = wdir / "sealed.json"
        if sealed_path.exists():
            raise SpineError(f"Already sealed: {window_id}")
        if not (wdir / "open.json").exists():
            raise SpineError(f"Window not opened: {window_id}")

        # Ensure we have a WINDOW_SEALED event (as last event before seal record)
        self.append_event(window_id, "WINDOW_SEALED", {"window_id": window_id})

        events = self._load_events(window_id)
        if not events:
            raise SpineError("Cannot seal empty window")

        first = events[0]
        last = events[-1]

        # Root hash over ordered event hashes (deterministic)
        root_bytes = ("\n".join(e["hash"] for e in events) + "\n").encode("utf-8")
        root_hash = sha256_hex(root_bytes)

        sr = SealRecord(
            window_id=window_id,
            sealed_utc=iso_utc_now(),
            first_seq=int(first["seq"]),
            last_seq=int(last["seq"]),
            first_hash=str(first["hash"]),
            last_hash=str(last["hash"]),
            window_root_hash=root_hash,
            event_count=len(events),
        )
        self._atomic_write_json(sealed_path, sr.to_dict())
        return sr

    def close_clean(self) -> None:
        # Clear dirty marker for clean shutdown
        if self.dirty_marker.exists():
            try:
                self.dirty_marker.unlink()
            except OSError:
                pass

    def resolve_pin(self, pin_hash: str) -> Optional[str]:
        """
        Optional: resolve a pin to a witness bundle path using witness_index.json.
        This is a pragmatic placeholder; witness capture/packing can come later.
        """
        if not self.witness_index.exists():
            return None
        try:
            data = json.loads(self.witness_index.read_text(encoding="utf-8"))
        except Exception:
            return None
        val = data.get(pin_hash)
        if isinstance(val, str):
            return val
        return None

    # ---------- Internal helpers ----------

    def _validate_payload(self, payload: Dict[str, Any]) -> None:
        if not isinstance(payload, dict):
            raise ValidationError("payload must be a dict")
        if not _is_json_safe(payload, allow_float=self.allow_float_payload):
            raise ValidationError("payload contains non-JSON-safe types (or floats disallowed)")

    def _wdir(self, window_id: str) -> Path:
        if not window_id or any(c in window_id for c in "/\\"):
            raise ValidationError("invalid window_id")
        return self.windows_dir / window_id

    def _event_path(self, window_id: str, seq: int) -> Path:
        return self._wdir(window_id) / "events" / f"{seq:06d}.json"

    def _next_seq(self, window_id: str) -> int:
        events_dir = self._wdir(window_id) / "events"
        events_dir.mkdir(parents=True, exist_ok=True)
        existing = sorted(p for p in events_dir.glob("*.json") if p.name[:6].isdigit())
        if not existing:
            return 1
        last = existing[-1].stem
        return int(last) + 1

    def _read_prev_hash(self, window_id: str, seq: int) -> Optional[str]:
        if seq <= 1:
            return None
        prev_path = self._event_path(window_id, seq - 1)
        if not prev_path.exists():
            # This is a gap (should be recorded as SCAR by verifier or boot)
            return None
        prev = json.loads(prev_path.read_text(encoding="utf-8"))
        return prev.get("hash")

    def _load_events(self, window_id: str) -> List[Dict[str, Any]]:
        events_dir = self._wdir(window_id) / "events"
        files = sorted(events_dir.glob("*.json"))
        events: List[Dict[str, Any]] = []
        for f in files:
            if not f.name[:6].isdigit():
                continue
            events.append(json.loads(f.read_text(encoding="utf-8")))
        return events

    def _atomic_write_json(self, path: Path, obj: Dict[str, Any]) -> None:
        data = canonicalize_json(obj)
        self._atomic_write_bytes(path, data + b"\n")

    def _atomic_write_bytes(self, path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)  # atomic on POSIX

        # fsync parent dir for rename durability (best effort)
        try:
            dir_fd = os.open(str(path.parent), os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except Exception:
            pass

    def _boot_check_dirty_and_scar(self) -> None:
        self.spine_dir.mkdir(parents=True, exist_ok=True)
        if self.dirty_marker.exists():
            # Record SCAR event to scars log (append-only jsonl)
            scar = {
                "scar_type": "DIRTY_SHUTDOWN",
                "detected_utc": iso_utc_now(),
                "note": "Previous run did not close_clean(); integrity beyond last sealed window is unknown.",
            }
            self._append_jsonl(self.scars_log, scar)

    def _append_jsonl(self, path: Path, obj: Dict[str, Any]) -> None:
        # Append-only with fsync
        path.parent.mkdir(parents=True, exist_ok=True)
        line = canonicalize_json(obj) + b"\n"
        fd = os.open(str(path), os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
        try:
            os.write(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)
