from __future__ import annotations
import json
import shlex
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from aletheia.spine.ledger import SpineLedger
from aletheia.claims import ClaimRegistry, ClaimEQI, ClaimType, ClaimStatus

SESSIONS_WINDOW_DEFAULT = "sessions"
SESSION_EVENT_TYPE = "SESSION"

@dataclass(frozen=True)
class SessionInfo:
    session_id: str
    root: Path
    claims_window: str = "claims"
    sessions_window: str = SESSIONS_WINDOW_DEFAULT

class VeritasSession:
    """
    Deterministic session wrapper. No LLM.
    - Writes SESSION_START/SESSION_END events to Spine window `sessions`.
    - Claim operations go through ClaimRegistry/ClaimEQI.
    """
    def __init__(self, root: str|Path, *, claims_window: str="claims", sessions_window: str=SESSIONS_WINDOW_DEFAULT, session_id: Optional[str]=None):
        self.root = Path(root)
        self.claims_window = claims_window
        self.sessions_window = sessions_window
        self.session_id = session_id or uuid.uuid4().hex
        self._started = False

    def start(self) -> str:
        led = SpineLedger(self.root)
        led.open_window(self.sessions_window)
        payload = {"op":"SESSION_START","session_id": self.session_id}
        led.append_event(self.sessions_window, SESSION_EVENT_TYPE, payload)
        led.close_clean()
        self._started = True
        return self.session_id

    def end(self, *, seal_sessions: bool=False) -> None:
        led = SpineLedger(self.root)
        led.open_window(self.sessions_window)
        payload = {"op":"SESSION_END","session_id": self.session_id}
        led.append_event(self.sessions_window, SESSION_EVENT_TYPE, payload)
        if seal_sessions:
            led.seal_window(self.sessions_window)
        led.close_clean()

    def claim_propose(self, claim_id: str, claim_type: str, text: str, reason_code: str="OPEN", seal: bool=False) -> Dict[str, Any]:
        led = SpineLedger(self.root)
        reg = ClaimRegistry(led, window_id=self.claims_window)
        ref = reg.propose(claim_id=claim_id, claim_text=text, claim_type=ClaimType(claim_type), reason_code=reason_code)
        if seal:
            led.seal_window(self.claims_window)
        led.close_clean()
        return ref.to_dict()

    def claim_link(self, claim_id: str, pins: List[str], reason_code: str="EVIDENCE_LINKED", seal: bool=False) -> Dict[str, Any]:
        led = SpineLedger(self.root)
        reg = ClaimRegistry(led, window_id=self.claims_window)
        ref = reg.link_evidence(claim_id=claim_id, pins=pins, reason_code=reason_code)
        if seal:
            led.seal_window(self.claims_window)
        led.close_clean()
        return ref.to_dict()

    def claim_set(self, claim_id: str, new_status: str, reason_code: str, pins: Optional[List[str]]=None, seal: bool=False) -> Dict[str, Any]:
        eqi = ClaimEQI(self.root, window_id=self.claims_window)
        st = eqi.get_state(claim_id)
        if st is None:
            raise ValueError("Claim not found or claims window not sealed (seal before set to ensure stable read).")
        old_status = st.claim.status
        led = SpineLedger(self.root)
        reg = ClaimRegistry(led, window_id=self.claims_window)
        ref = reg.set_status(claim_id=claim_id, old_status=old_status, new_status=ClaimStatus(new_status), reason_code=reason_code, pins=pins)
        if seal:
            led.seal_window(self.claims_window)
        led.close_clean()
        return ref.to_dict()

    def claim_show(self, claim_id: str) -> Dict[str, Any]:
        eqi = ClaimEQI(self.root, window_id=self.claims_window)
        st = eqi.get_state(claim_id)
        if st is None:
            raise ValueError("Claim not found or claims window not sealed.")
        return {"claim": st.claim.to_dict(), "history": st.history}

    def claim_list(self) -> List[str]:
        eqi = ClaimEQI(self.root, window_id=self.claims_window)
        ids = eqi.list_claim_ids()
        if ids is None:
            raise ValueError("Claims window not sealed.")
        return ids

    def seal_claims(self) -> None:
        led = SpineLedger(self.root)
        led.seal_window(self.claims_window)
        led.close_clean()

class VeritasShell:
    """
    Simple deterministic REPL for ClaimRegistry/ClaimEQI.
    """
    def __init__(self, root: str|Path, *, claims_window: str="claims", sessions_window: str=SESSIONS_WINDOW_DEFAULT):
        self.session = VeritasSession(root, claims_window=claims_window, sessions_window=sessions_window)
        self.root = Path(root)

    def _print(self, obj: Any) -> None:
        print(json.dumps(obj, indent=2, sort_keys=True))

    def run(self) -> int:
        sid = self.session.start()
        print(f"VERITAS session_id={sid}")
        print("Type 'help' for commands. NOTE: claim-list/show require claims window sealed. Use 'seal'.")
        while True:
            try:
                line = input("> ").strip()
            except EOFError:
                line = "exit"
            if not line:
                continue
            if line in ("exit","quit"):
                self.session.end(seal_sessions=False)
                return 0
            if line in ("help","?"):
                print("Commands:")
                print("  propose <claim_id> <TYPE> <text...>")
                print("  link <claim_id> <pin> [<pin> ...]")
                print("  set <claim_id> <STATUS> <REASON_CODE> [--pin <pin> ...]")
                print("  show <claim_id>")
                print("  list")
                print("  seal   (seal claims window)")
                print("  exit")
                continue
            try:
                args = shlex.split(line)
            except Exception as e:
                print(f"ERR: {e}")
                continue
            cmd = args[0].lower()
            try:
                if cmd == "propose":
                    if len(args) < 4:
                        raise ValueError("usage: propose <claim_id> <TYPE> <text...>")
                    claim_id = args[1]
                    ctype = args[2].upper()
                    text = " ".join(args[3:])
                    out = self.session.claim_propose(claim_id, ctype, text, seal=False)
                    self._print(out)
                elif cmd == "link":
                    if len(args) < 3:
                        raise ValueError("usage: link <claim_id> <pin> [<pin> ...]")
                    claim_id = args[1]
                    pins = [p for p in args[2:] if p]
                    out = self.session.claim_link(claim_id, pins, seal=False)
                    self._print(out)
                elif cmd == "set":
                    # set <claim_id> <STATUS> <REASON_CODE> [--pin <pin> ...]
                    if len(args) < 4:
                        raise ValueError("usage: set <claim_id> <STATUS> <REASON_CODE> [--pin <pin> ...]")
                    claim_id = args[1]
                    status = args[2].upper()
                    reason = args[3]
                    pins=[]
                    i=4
                    while i < len(args):
                        if args[i] == "--pin":
                            i += 1
                            if i >= len(args): break
                            pins.append(args[i])
                        i += 1
                    out = self.session.claim_set(claim_id, status, reason, pins=pins or None, seal=False)
                    self._print(out)
                elif cmd == "show":
                    if len(args) != 2:
                        raise ValueError("usage: show <claim_id>")
                    out = self.session.claim_show(args[1])
                    self._print(out)
                elif cmd == "list":
                    out = {"claim_ids": self.session.claim_list()}
                    self._print(out)
                elif cmd == "seal":
                    self.session.seal_claims()
                    print("OK: claims window sealed")
                else:
                    print("ERR: unknown command (type 'help')")
            except Exception as e:
                print(f"ERR: {e}")
        # unreachable
