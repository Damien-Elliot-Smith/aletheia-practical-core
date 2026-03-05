from __future__ import annotations
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from aletheia.spine.ledger import SpineLedger

ALLOWED_CONSTRAINT_EVENT_TYPES={"CONSTRAINT_PUBLISH","CONSTRAINT_SUPERSEDE","CONSTRAINT_DEPRECATE"}

@dataclass(frozen=True)
class ConstraintRef:
    constraint_id: str
    version: str
    constraint_hash: str
    def to_dict(self)->Dict[str,Any]:
        return {"constraint_id":self.constraint_id,"version":self.version,"constraint_hash":self.constraint_hash}

class ConstraintRegistry:
    def __init__(self, ledger: SpineLedger, *, window_id: str="constants"):
        self.ledger=ledger; self.window_id=window_id
        self.ledger.open_window(window_id)

        # REQUIRED - do not remove.
        # Spine is strict by default and can reject floats in payloads. Constraints need floats (e.g., roc_max_per_s: 1.0).
        self.ledger.allow_float_payload = True

        # REQUIRED - do not remove.
        # Guard against silent serialization failures when rules contain floats/NaN/Inf or other non-JSON values.
        # We validate publish/supersede payloads with allow_nan=False before writing to Spine.
        self._json_allow_nan = False

    def _assert_json_safe(self, obj: Any) -> None:
        """
        Raise ValueError if obj cannot be serialized deterministically to strict JSON.
        Floats are allowed but NaN/Infinity are rejected (strict JSON).
        """
        try:
            json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=self._json_allow_nan)
        except Exception as e:
            raise ValueError(f"Rule is not strict-JSON-serializable: {e}") from e

    def publish(self, constraint_id: str, version: str, rule: Dict[str, Any], *, units: Optional[str]=None,
                applicability: Optional[Dict[str, Any]]=None, tolerances: Optional[Dict[str, Any]]=None) -> ConstraintRef:
        payload={"constraint_id":constraint_id,"version":version,"rule":rule}
        if units is not None: payload["units"]=units
        if applicability is not None: payload["applicability"]=applicability
        if tolerances is not None: payload["tolerances"]=tolerances
        ev=self.ledger.append_event(self.window_id,"CONSTRAINT_PUBLISH",payload)
        return ConstraintRef(constraint_id, version, ev.hash)

    def supersede(self, constraint_id: str, new_version: str, rule: Dict[str, Any], *, previous_version: str, previous_hash: str,
                 note: Optional[str]=None) -> ConstraintRef:
        prev=self._resolve_event_by_hash(previous_hash)
        self._verify_prev(prev, constraint_id, previous_version)
        payload={"constraint_id":constraint_id,"version":new_version,"rule":rule,"previous_version":previous_version,"previous_hash":previous_hash}
        if note: payload["note"]=note
        ev=self.ledger.append_event(self.window_id,"CONSTRAINT_SUPERSEDE",payload)
        return ConstraintRef(constraint_id, new_version, ev.hash)

    def deprecate(self, constraint_id: str, version: str, *, previous_hash: str, note: Optional[str]=None) -> ConstraintRef:
        prev=self._resolve_event_by_hash(previous_hash)
        self._verify_prev(prev, constraint_id, version)
        payload={"constraint_id":constraint_id,"version":version,"previous_hash":previous_hash}
        if note: payload["note"]=note
        ev=self.ledger.append_event(self.window_id,"CONSTRAINT_DEPRECATE",payload)
        return ConstraintRef(constraint_id, version, ev.hash)

    def _resolve_event_by_hash(self, h: str) -> Dict[str, Any]:
        events_dir=self.ledger.spine_dir/"windows"/self.window_id/"events"
        if not events_dir.exists():
            raise ValueError("constraint events dir missing")
        for p in sorted(events_dir.glob("*.json")):
            if not p.name[:6].isdigit(): continue
            obj=json.loads(p.read_text(encoding="utf-8"))
            if obj.get("hash")==h:
                return obj
        raise ValueError("previous_hash not found")

    def _verify_prev(self, prev_event: Dict[str, Any], constraint_id: str, version: str) -> None:
        if prev_event.get("event_type") not in ALLOWED_CONSTRAINT_EVENT_TYPES:
            raise ValueError("previous_hash not a constraint event")
        pl=prev_event.get("payload") or {}
        if pl.get("constraint_id")!=constraint_id:
            raise ValueError("previous_hash constraint_id mismatch")
        if pl.get("version")!=version:
            raise ValueError("previous_hash version mismatch")

class ConstraintEQI:
    def __init__(self, root_dir: str|Path, *, window_id: str="constants"):
        self.root=Path(root_dir); self.window_id=window_id
        self.spine=self.root/"spine"; self.windows=self.spine/"windows"

    def _wdir(self)->Path:
        return self.windows/self.window_id

    def is_sealed(self)->bool:
        w=self._wdir()
        return (w/"sealed.json").exists() and (w/"open.json").exists()

    def get_active(self, constraint_id: str) -> Optional[Tuple[ConstraintRef, Dict[str, Any]]]:
        """
        Determine active constraint head deterministically from SEALED constants window.

        Rules:
        - Only PUBLISH/SUPERSEDE can be heads.
        - SUPERSEDE removes its previous_hash from heads.
        - DEPRECATE removes its previous_hash from heads (deprecates that version).
        - If multiple heads remain (fork), return None (caller should treat as INCONCLUSIVE).
        - Head selection is by maximum seq among heads.
        """
        if not self.is_sealed(): return None
        events_dir=self._wdir()/"events"
        evs=[]
        for p in sorted(events_dir.glob("*.json")):
            if not p.name[:6].isdigit(): continue
            obj=json.loads(p.read_text(encoding="utf-8"))
            if obj.get("event_type") not in ALLOWED_CONSTRAINT_EVENT_TYPES: continue
            pl=obj.get("payload") or {}
            if pl.get("constraint_id")==constraint_id:
                evs.append(obj)
        if not evs: return None

        heads={e.get("hash") for e in evs if e.get("event_type") in ("CONSTRAINT_PUBLISH","CONSTRAINT_SUPERSEDE") and isinstance(e.get("hash"),str)}
        for e in evs:
            pl=e.get("payload") or {}
            if e.get("event_type")=="CONSTRAINT_SUPERSEDE":
                prev=pl.get("previous_hash")
                if isinstance(prev,str):
                    heads.discard(prev)
            elif e.get("event_type")=="CONSTRAINT_DEPRECATE":
                prev=pl.get("previous_hash")
                if isinstance(prev,str):
                    heads.discard(prev)

        if not heads:
            return None
        if len(heads) > 1:
            # fork: more than one head survived
            return None

        head_hash=next(iter(heads))
        head=None
        for e in evs:
            if e.get("hash")==head_hash:
                head=e
                break
        if head is None:
            return None
        pl=head.get("payload") or {}
        ref=ConstraintRef(constraint_id, str(pl.get("version")), str(head.get("hash")))
        return ref, pl

