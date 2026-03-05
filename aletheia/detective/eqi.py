"""
EQI (Evidence Query Interface) – Read-only bridge to Spine

Rules:
- Only reads from Spine. Never writes.
- Only returns events from SEALED windows.
- Performs verification before serving evidence.
- Supports witness fetch by filters.
- Exposes scar summary (from scars.jsonl).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from aletheia.spine.verify import verify_spine


@dataclass
class ScarInfo:
    scars: List[Dict[str, Any]]

    def has_scar(self) -> bool:
        return len(self.scars) > 0


class EQI:
    def __init__(self, root_dir: str | Path):
        self.root = Path(root_dir)
        self.spine = self.root / "spine"
        self.windows = self.spine / "windows"
        self.scars_log = self.spine / "scars.jsonl"

    def verify_on_fetch(self) -> Dict[str, Any]:
        return verify_spine(self.root)

    def list_sealed_windows(self) -> List[str]:
        out: List[str] = []
        if not self.windows.exists():
            return out
        for wdir in sorted(p for p in self.windows.iterdir() if p.is_dir()):
            if (wdir / "sealed.json").exists() and (wdir / "open.json").exists():
                out.append(wdir.name)
        return out

    def get_scars(self) -> ScarInfo:
        scars: List[Dict[str, Any]] = []
        if self.scars_log.exists():
            for line in self.scars_log.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    scars.append(json.loads(line))
                except Exception:
                    scars.append({"scar_type": "UNREADABLE_SCAR_LINE"})
        return ScarInfo(scars=scars)

    def fetch_events(
        self,
        *,
        window_id: Optional[str] = None,
        event_type: Optional[str] = None,
        source: Optional[str] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        """
        Fetch events from SEALED windows only. Filters are ANDed.
        - window_id: restrict to a specific sealed window
        - event_type: match event_type exactly
        - source: match payload.source if present
        """
        sealed = set(self.list_sealed_windows())
        if window_id is not None:
            if window_id not in sealed:
                return []
            windows = [window_id]
        else:
            windows = sorted(sealed)

        out: List[Dict[str, Any]] = []
        for wid in windows:
            events_dir = self.windows / wid / "events"
            if not events_dir.exists():
                continue
            for p in sorted(events_dir.glob("*.json")):
                if not p.name[:6].isdigit():
                    continue
                try:
                    e = json.loads(p.read_text(encoding="utf-8"))
                except Exception:
                    continue
                if event_type is not None and e.get("event_type") != event_type:
                    continue
                if source is not None:
                    payload = e.get("payload") or {}
                    if not isinstance(payload, dict) or payload.get("source") != source:
                        continue
                out.append(e)
                if len(out) >= limit:
                    return out
        return out
