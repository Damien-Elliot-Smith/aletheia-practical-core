from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from aletheia.constraints.registry import ConstraintEQI

class SentinelVerdict(str, Enum):
    PASS="PASS"; FAIL="FAIL"; INCONCLUSIVE="INCONCLUSIVE"

class SentinelReason(str, Enum):
    OK="OK"; UNKNOWN_ACTION="UNKNOWN_ACTION"; MISSING_FIELDS="MISSING_FIELDS"; NOT_AUTHORIZED="NOT_AUTHORIZED"
    HIGH_RISK_NEEDS_WITNESS="HIGH_RISK_NEEDS_WITNESS"; POLICY_DENY="POLICY_DENY"; POLICY_UNAVAILABLE="POLICY_UNAVAILABLE"

@dataclass
class SentinelConfig:
    constants_window: str="constants"
    policy_id: str="sentinel.policy"
    allowed_actors: Optional[List[str]]=None

class SentinelLite:
    def __init__(self, root_dir: str|Any, config: Optional[SentinelConfig]=None):
        self.cfg=config or SentinelConfig()
        self.eqi=ConstraintEQI(root_dir, window_id=self.cfg.constants_window)

    def _resolve(self)->Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        active=self.eqi.get_active(self.cfg.policy_id)
        if active is None: return None, None
        ref, pl = active
        rule=pl.get("rule")
        if not isinstance(rule, dict): return None, ref.to_dict()
        return rule, ref.to_dict()

    def evaluate(self, proposal: Dict[str, Any]) -> Dict[str, Any]:
        policy, pref = self._resolve()
        if policy is None:
            return self._out(SentinelVerdict.INCONCLUSIVE, SentinelReason.POLICY_UNAVAILABLE, ["POLICY_REGISTRY"], policy_ref=pref)
        if not isinstance(proposal, dict):
            return self._out(SentinelVerdict.INCONCLUSIVE, SentinelReason.MISSING_FIELDS, ["PROPOSAL"], policy_ref=pref)
        action=proposal.get("action"); target=proposal.get("target"); actor=proposal.get("actor")
        if not isinstance(action,str) or not isinstance(target,str) or not isinstance(actor,str):
            return self._out(SentinelVerdict.INCONCLUSIVE, SentinelReason.MISSING_FIELDS, ["ACTION","TARGET","ACTOR"], policy_ref=pref)
        pol=policy.get(action)
        if pol is None or not isinstance(pol, dict):
            return self._out(SentinelVerdict.INCONCLUSIVE, SentinelReason.UNKNOWN_ACTION, ["POLICY_REGISTRY"], {"action":action}, policy_ref=pref)
        if self.cfg.allowed_actors is not None and actor not in self.cfg.allowed_actors:
            return self._out(SentinelVerdict.FAIL, SentinelReason.NOT_AUTHORIZED, ["ACCESS_WITNESS"], {"actor":actor}, policy_ref=pref)
        risk=str(pol.get("risk","MED")).upper()
        default=str(pol.get("default","INCONCLUSIVE")).upper()
        if risk=="HIGH":
            if default=="FAIL":
                return self._out(SentinelVerdict.FAIL, SentinelReason.POLICY_DENY, ["POLICY_WITNESS"], {"action":action}, policy_ref=pref)
            if default=="PASS":
                return self._out(SentinelVerdict.PASS, SentinelReason.OK, [], policy_ref=pref)
            return self._out(SentinelVerdict.INCONCLUSIVE, SentinelReason.HIGH_RISK_NEEDS_WITNESS, ["DUAL_APPROVAL_WITNESS","CHANGE_TICKET_WITNESS"], {"action":action}, policy_ref=pref)
        if default=="PASS":
            return self._out(SentinelVerdict.PASS, SentinelReason.OK, [], policy_ref=pref)
        if default=="FAIL":
            return self._out(SentinelVerdict.FAIL, SentinelReason.POLICY_DENY, ["POLICY_WITNESS"], {"action":action}, policy_ref=pref)
        return self._out(SentinelVerdict.INCONCLUSIVE, SentinelReason.HIGH_RISK_NEEDS_WITNESS, ["OPERATOR_CONFIRM_WITNESS"], {"action":action}, policy_ref=pref)

    def _out(self, verdict: SentinelVerdict, reason: SentinelReason, witness_required: List[str], policy: Optional[Dict[str, Any]]=None, *, policy_ref: Optional[Dict[str, Any]]=None) -> Dict[str, Any]:
        out={"module":"Sentinel","verdict":verdict.value,"reason_code":reason.value,"witness_required":list(witness_required)}
        if policy: out["policy"]=policy
        if policy_ref is not None: out["policy_ref"]=policy_ref
        return out
