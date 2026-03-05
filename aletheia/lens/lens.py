from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from aletheia.constraints.registry import ConstraintEQI

class LensVerdict(str, Enum):
    PASS="PASS"; FAIL="FAIL"; INCONCLUSIVE="INCONCLUSIVE"

class LensReason(str, Enum):
    OK="OK"; MISSING_FIELDS="MISSING_FIELDS"; TYPE_INVALID="TYPE_INVALID"; OUT_OF_RANGE="OUT_OF_RANGE"
    RATE_OF_CHANGE="RATE_OF_CHANGE"; UNKNOWN_SENSOR="UNKNOWN_SENSOR"; NO_BASELINE="NO_BASELINE"
    CONSTRAINTS_UNAVAILABLE="CONSTRAINTS_UNAVAILABLE"; CONSTRAINTS_FORK="CONSTRAINTS_FORK"

@dataclass
class LensConfig:
    constants_window: str="constants"
    constraint_id: str="temp.constraints"
    require_baseline_for_roc: bool=True

class Lens:
    def __init__(self, root_dir: str|Any, config: Optional[LensConfig]=None):
        self.cfg=config or LensConfig()
        self.eqi=ConstraintEQI(root_dir, window_id=self.cfg.constants_window)

    def _resolve(self)->Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]], Optional[LensReason]]:
        active=self.eqi.get_active(self.cfg.constraint_id)
        if active is None:
            # could be unavailable or fork; in v1 we treat both as unavailable
            return None, None, LensReason.CONSTRAINTS_UNAVAILABLE
        ref, pl = active
        rule=pl.get("rule")
        if not isinstance(rule, dict):
            return None, ref.to_dict(), LensReason.CONSTRAINTS_UNAVAILABLE
        return rule, ref.to_dict(), None

    def evaluate(self, event: Dict[str, Any], *, last_value: Optional[float]=None, last_ts: Optional[float]=None) -> Dict[str, Any]:
        constraints, cref, err = self._resolve()
        if constraints is None:
            return self._out(LensVerdict.INCONCLUSIVE, err or LensReason.CONSTRAINTS_UNAVAILABLE, ["CONSTRAINTS_REGISTRY"], constraint_ref=cref)
        payload=event.get("payload")
        if not isinstance(payload, dict):
            return self._out(LensVerdict.INCONCLUSIVE, LensReason.TYPE_INVALID, ["RAW_EVENT"], constraint_ref=cref)
        sensor=payload.get("sensor"); value=payload.get("value"); ts=payload.get("ts")
        if not isinstance(sensor,str) or sensor=="":
            return self._out(LensVerdict.INCONCLUSIVE, LensReason.MISSING_FIELDS, ["SENSOR_ID"], constraint_ref=cref)
        if not isinstance(value,(int,float)):
            return self._out(LensVerdict.INCONCLUSIVE, LensReason.TYPE_INVALID, ["SENSOR_VALUE"], constraint_ref=cref)
        cons=constraints.get(sensor)
        if cons is None or not isinstance(cons, dict):
            return self._out(LensVerdict.INCONCLUSIVE, LensReason.UNKNOWN_SENSOR, ["CONSTRAINTS_REGISTRY"], {"sensor":sensor}, constraint_ref=cref)
        vmin=cons.get("min"); vmax=cons.get("max")
        if isinstance(vmin,(int,float)) and value < vmin:
            return self._out(LensVerdict.FAIL, LensReason.OUT_OF_RANGE, ["CALIBRATION_WITNESS"], {"min":vmin,"value":value}, constraint_ref=cref)
        if isinstance(vmax,(int,float)) and value > vmax:
            return self._out(LensVerdict.FAIL, LensReason.OUT_OF_RANGE, ["CALIBRATION_WITNESS"], {"max":vmax,"value":value}, constraint_ref=cref)
        roc_max=cons.get("roc_max_per_s")
        if isinstance(roc_max,(int,float)):
            if last_value is None or last_ts is None or not isinstance(ts,(int,float)):
                if self.cfg.require_baseline_for_roc:
                    return self._out(LensVerdict.INCONCLUSIVE, LensReason.NO_BASELINE, ["BASELINE_WITNESS"], {"need":"last_value,last_ts,ts"}, constraint_ref=cref)
            else:
                dt=float(ts)-float(last_ts)
                if dt<=0:
                    return self._out(LensVerdict.INCONCLUSIVE, LensReason.NO_BASELINE, ["TIMEBASE_WITNESS"], {"dt":dt}, constraint_ref=cref)
                roc=abs(float(value)-float(last_value))/dt
                if roc>float(roc_max):
                    return self._out(LensVerdict.FAIL, LensReason.RATE_OF_CHANGE, ["HIGH_FREQ_WITNESS"], {"roc":roc,"roc_max":roc_max,"dt":dt}, constraint_ref=cref)
        return self._out(LensVerdict.PASS, LensReason.OK, [], constraint_ref=cref)

    def _out(self, verdict: LensVerdict, reason: LensReason, witness_required: List[str], details: Optional[Dict[str, Any]]=None, *, constraint_ref: Optional[Dict[str, Any]]=None) -> Dict[str, Any]:
        out={"module":"Lens","verdict":verdict.value,"reason_code":reason.value,"witness_required":list(witness_required)}
        if details: out["details"]=details
        if constraint_ref is not None: out["constraint_ref"]=constraint_ref
        return out
