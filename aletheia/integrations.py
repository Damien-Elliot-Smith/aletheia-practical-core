from __future__ import annotations
from typing import Any, Dict, Optional
from aletheia.spine.ledger import SpineLedger

def emit_verdict(ledger: SpineLedger, *, window_id: str, module: str, subject_pin: Optional[str], verdict: Dict[str, Any]) -> None:
    payload={"module":module,"subject_pin":subject_pin,"verdict":verdict}
    ledger.open_window(window_id)
    ledger.append_event(window_id, "VERDICT", payload)
