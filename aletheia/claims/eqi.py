from __future__ import annotations
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .model import ClaimType, ClaimStatus, Claim, Support, is_transition_allowed

@dataclass
class ClaimState:
    claim: Claim
    history: List[Dict[str, Any]] = field(default_factory=list)

class ClaimEQI:
    def __init__(self, root_dir: str|Path, *, window_id: str="claims"):
        self.root = Path(root_dir)
        self.window_id = window_id

    def _wdir(self) -> Path:
        return self.root / "spine" / "windows" / self.window_id

    def is_sealed(self) -> bool:
        wdir = self._wdir()
        return (wdir/"sealed.json").exists() and (wdir/"open.json").exists()

    def _iter_events(self) -> List[Dict[str, Any]]:
        wdir = self._wdir()
        events_dir = wdir/"events"
        if not events_dir.exists():
            return []
        evs=[]
        for p in sorted(events_dir.glob("*.json")):
            if not p.name[:6].isdigit():
                continue
            try:
                obj=json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            if obj.get("event_type") != "CLAIM":
                continue
            evs.append(obj)
        return evs

    def list_claim_ids(self) -> Optional[List[str]]:
        if not self.is_sealed():
            return None
        evs=self._iter_events()
        ids=set()
        for e in evs:
            pl=e.get("payload") or {}
            cid=pl.get("claim_id")
            if isinstance(cid,str) and cid:
                ids.add(cid)
        return sorted(ids)

    def get_state(self, claim_id: str) -> Optional[ClaimState]:
        if not self.is_sealed():
            return None
        evs=[e for e in self._iter_events() if (e.get("payload") or {}).get("claim_id")==claim_id]
        if not evs:
            return None

        # base from first propose, else synthesize minimal
        claim_text=""
        ctype=ClaimType.OPERATIONAL
        status=ClaimStatus.OPEN
        reason="OPEN"
        scope: Dict[str,Any]={}
        support=Support()
        created=None
        updated=None
        history=[]

        for e in evs:
            pl=e.get("payload") or {}
            op=pl.get("op")
            ts=e.get("created_utc")
            if created is None:
                created=ts
            updated=ts
            history.append({"seq": e.get("seq"), "hash": e.get("hash"), "op": op, "payload": pl, "created_utc": ts})

            if op=="CLAIM_PROPOSED":
                claim_text=str(pl.get("claim_text",""))
                ct=pl.get("claim_type")
                if isinstance(ct,str) and ct in [t.value for t in ClaimType]:
                    ctype=ClaimType(ct)
                status=ClaimStatus.OPEN
                reason=str(pl.get("reason_code","OPEN"))
                if isinstance(pl.get("scope"), dict):
                    scope=dict(pl.get("scope"))
            elif op=="CLAIM_SCOPE_SET":
                if isinstance(pl.get("scope"), dict):
                    scope=dict(pl.get("scope"))
                reason=str(pl.get("reason_code","SCOPE_SET"))
            elif op=="CLAIM_LINKED_EVIDENCE":
                pins=pl.get("pins")
                if isinstance(pins,list):
                    for p in pins:
                        if isinstance(p,str) and p:
                            support.pins.append(p)
                reason=str(pl.get("reason_code","EVIDENCE_LINKED"))
            elif op=="CLAIM_STATUS_SET":
                ns=pl.get("new_status")
                if isinstance(ns,str) and ns in [s.value for s in ClaimStatus]:
                    new_status=ClaimStatus(ns)
                    if not is_transition_allowed(status, new_status):
                        # invalid evolution => treat as INCONCLUSIVE state
                        status=ClaimStatus.INCONCLUSIVE
                        reason="INVALID_TRANSITION"
                    else:
                        status=new_status
                        reason=str(pl.get("reason_code","STATUS_SET"))
                    pins=pl.get("pins")
                    if isinstance(pins,list):
                        for p in pins:
                            if isinstance(p,str) and p and p not in support.pins:
                                support.pins.append(p)
            elif op=="CLAIM_SUPERSEDED":
                status=ClaimStatus.SUPERSEDED
                reason=str(pl.get("reason_code","SUPERSEDED"))
            elif op=="CLAIM_RETRACTED":
                status=ClaimStatus.RETRACTED
                reason=str(pl.get("reason_code","RETRACTED"))

        c=Claim(
            claim_id=claim_id,
            claim_text=claim_text or claim_id,
            type=ctype,
            status=status,
            scope=scope,
            support=support,
            reason_code=reason,
            created_utc=created,
            updated_utc=updated,
        )
        return ClaimState(claim=c, history=history)
