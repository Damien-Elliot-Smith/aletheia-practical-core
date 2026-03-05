#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from typing import Any, List, Optional

from aletheia.spine.ledger import SpineLedger
from aletheia.spine.verify import verify_spine
from aletheia.siren.state_machine import Siren, SirenConfig
from aletheia.ingest.gate import IngestGate, IngestConfig
from aletheia.constraints.registry import ConstraintRegistry
from aletheia.claims import ClaimRegistry, ClaimEQI, ClaimType, ClaimStatus
from aletheia.claims.claimcheck import check_claim, check_all
from aletheia.detective.claims_review import review_claims
from aletheia.lens import Lens, LensConfig
from aletheia.sentinel import SentinelLite, SentinelConfig
from aletheia.integrations import emit_verdict
from aletheia.chronicle.export import build_case_zip
from aletheia.detective import Detective
from aletheia.detective.sieve import Hypothesis

def _read_json(s: str)->Any:
    try: return json.loads(s)
    except Exception as e: raise SystemExit(f"Invalid JSON: {e}")

def _read_json_input(args)->Any:
    if getattr(args,"json",None) is not None: return _read_json(args.json)
    if getattr(args,"json_file",None) is not None: return json.loads(Path(args.json_file).read_text(encoding="utf-8"))
    data=sys.stdin.read()
    if not data.strip(): raise SystemExit("No JSON provided (use --json/--json-file/stdin).")
    return json.loads(data)

def _find_event_by_hash(root: Path, window_id: str, h: str):
    ed=root/"spine"/"windows"/window_id/"events"
    if not ed.exists(): return None
    for p in sorted(ed.glob("*.json")):
        if not p.name[:6].isdigit(): continue
        try: obj=json.loads(p.read_text(encoding="utf-8"))
        except Exception: continue
        if obj.get("hash")==h: return obj
    return None

def cmd_init(args)->int:
    root=Path(args.root); root.mkdir(parents=True, exist_ok=True)
    led=SpineLedger(root); led.close_clean()
    print(f"Initialized: {root}")
    return 0

def cmd_constraints_publish(args)->int:
    root=Path(args.root); led=SpineLedger(root)
    reg=ConstraintRegistry(led, window_id=args.window)
    rule=_read_json_input(args)
    ref=reg.publish(args.constraint_id, args.version, rule, units=args.units)
    if args.seal:
        led.seal_window(args.window)
    led.close_clean()
    print(json.dumps(ref.to_dict(), indent=2, sort_keys=True))
    return 0

def cmd_ingest(args)->int:
    root=Path(args.root); led=SpineLedger(root)
    siren = Siren(led, SirenConfig(window_id=args.siren_window, heartbeat_interval_s=args.heartbeat_s)) if args.with_siren else None
    gate=IngestGate(led, siren=siren, config=IngestConfig(window_id=args.window, reject_max_records=args.reject_max, max_accepts_per_sec=args.max_accepts_per_sec, surge_window_s=args.surge_window_s, surge_reject_threshold=args.surge_threshold))
    rec=_read_json_input(args)
    res=gate.ingest(rec)
    led.close_clean()
    print(json.dumps({"decision":res.decision.value,"reason":res.reason.value if res.reason else None,"detail":res.detail}, indent=2, sort_keys=True))
    return 0 if res.decision.value=="ACCEPT" else 2

def cmd_lens(args)->int:
    root=Path(args.root); led=SpineLedger(root)
    lens=Lens(root, LensConfig(constants_window=args.constants_window, constraint_id=args.constraint_id, require_baseline_for_roc=not args.roc_without_baseline))
    if args.subject_pin:
        ev=_find_event_by_hash(root, args.subject_window, args.subject_pin)
        if ev is None:
            led.close_clean(); raise SystemExit("subject_pin not found")
        verdict=lens.evaluate(ev.get("payload",{}), last_value=args.last_value, last_ts=args.last_ts)
        subject_pin=ev.get("hash")
    else:
        ev=_read_json_input(args)
        verdict=lens.evaluate(ev, last_value=args.last_value, last_ts=args.last_ts)
        subject_pin=None
    emit_verdict(led, window_id=args.verdict_window, module="Lens", subject_pin=subject_pin, verdict=verdict)
    led.close_clean()
    print(json.dumps(verdict, indent=2, sort_keys=True))
    return 0

def cmd_sentinel(args)->int:
    root=Path(args.root); led=SpineLedger(root)
    allowed=args.allowed_actor.split(",") if args.allowed_actor else None
    sent=SentinelLite(root, SentinelConfig(constants_window=args.constants_window, policy_id=args.policy_id, allowed_actors=allowed))
    proposal=_read_json_input(args)
    verdict=sent.evaluate(proposal)
    emit_verdict(led, window_id=args.verdict_window, module="Sentinel", subject_pin=args.subject_pin, verdict=verdict)
    led.close_clean()
    print(json.dumps(verdict, indent=2, sort_keys=True))
    return 0

def cmd_verify(args)->int:
    rep=verify_spine(args.root)
    print(json.dumps(rep, indent=2, sort_keys=True))
    return 0 if rep.get("ok") else 3

def cmd_detective(args)->int:
    det=Detective(str(Path(args.root)))
    obj=_read_json_input(args)
    if not isinstance(obj,list): raise SystemExit("Hypotheses JSON must be a list.")
    hyps=[]
    for i,h in enumerate(obj):
        if not isinstance(h,dict): raise SystemExit(f"Hypothesis {i} must be dict")
        hyps.append(Hypothesis(hypothesis_id=str(h.get("hypothesis_id",f"h{i+1}")), entity=str(h.get("entity")), key=str(h.get("key")), value=h.get("value"), window_id=h.get("window_id")))
    lines=det.evaluate(hyps, window_id=args.window_id)
    print(json.dumps(lines, indent=2, sort_keys=True))
    return 0


def cmd_claim_propose(args)->int:
    root=Path(args.root); led=SpineLedger(root)
    reg=ClaimRegistry(led, window_id=args.window)
    ct = ClaimType(args.type)
    ref=reg.propose(claim_id=args.claim_id, claim_text=args.text, claim_type=ct, reason_code=args.reason_code)
    if args.seal:
        led.seal_window(args.window)
    led.close_clean()
    print(json.dumps(ref.to_dict(), indent=2, sort_keys=True))
    return 0

def cmd_claim_link(args)->int:
    root=Path(args.root); led=SpineLedger(root)
    reg=ClaimRegistry(led, window_id=args.window)
    pins=args.pin if args.pin else []
    ref=reg.link_evidence(claim_id=args.claim_id, pins=pins, reason_code=args.reason_code)
    if args.seal:
        led.seal_window(args.window)
    led.close_clean()
    print(json.dumps(ref.to_dict(), indent=2, sort_keys=True))
    return 0

def cmd_claim_set(args)->int:
    root=Path(args.root); eqi=ClaimEQI(root, window_id=args.window)
    st=eqi.get_state(args.claim_id)
    if st is None:
        raise SystemExit("Claim not found (or claims window not sealed).")
    old_status=st.claim.status
    new_status=ClaimStatus(args.status)
    led=SpineLedger(root)
    reg=ClaimRegistry(led, window_id=args.window)
    pins=args.pin if args.pin else None
    ref=reg.set_status(claim_id=args.claim_id, old_status=old_status, new_status=new_status, reason_code=args.reason_code, pins=pins)
    if args.seal:
        led.seal_window(args.window)
    led.close_clean()
    print(json.dumps(ref.to_dict(), indent=2, sort_keys=True))
    return 0

def cmd_claim_show(args)->int:
    root=Path(args.root); eqi=ClaimEQI(root, window_id=args.window)
    st=eqi.get_state(args.claim_id)
    if st is None:
        raise SystemExit("Claim not found (or claims window not sealed).")
    out={"claim": st.claim.to_dict(), "history": st.history}
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0

def cmd_claim_list(args)->int:
    root=Path(args.root); eqi=ClaimEQI(root, window_id=args.window)
    ids=eqi.list_claim_ids()
    if ids is None:
        raise SystemExit("Claims window not sealed.")
    print(json.dumps({"claim_ids": ids}, indent=2, sort_keys=True))
    return 0


def cmd_claimcheck(args)->int:
    if args.all:
        out = check_all(args.case, claims_window_id=args.window)
    else:
        out = check_claim(args.case, args.claim_id, claims_window_id=args.window).to_dict()
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


def cmd_detective_claims(args)->int:
    out = review_claims(args.case, claim_id=args.claim_id, all_claims=args.all, claims_window_id=args.window)
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


def cmd_demo_ot(args)->int:
    root=Path(args.root)
    root.mkdir(parents=True, exist_ok=True)
    led=SpineLedger(root)
    # Evidence window
    led.open_window(args.window)
    events=[
        {"ts":"2026-03-02T12:00:00Z","facility":"local0","severity":"info","tag":"PLC1","msg":"pump start","pump_id":"P-101"},
        {"ts":"2026-03-02T12:00:10Z","facility":"local0","severity":"info","tag":"PLC1","msg":"temp reading","pump_id":"P-101","temp_c_x10":832,"vibration_x100":31},
        {"ts":"2026-03-02T12:00:20Z","facility":"local0","severity":"warning","tag":"PLC1","msg":"temp high","pump_id":"P-101","temp_c_x10":927,"vibration_x100":49},
        {"ts":"2026-03-02T12:00:30Z","facility":"local0","severity":"warning","tag":"PLC1","msg":"trip imminent","pump_id":"P-101","temp_c_x10":971,"vibration_x100":55},
    ]
    for e in events:
        led.append_event(args.window, "WITNESS", e)
    led.seal_window(args.window)

    # Pin last witness for claim evidence
    evdir = root/"spine/windows"/args.window/"events"
    last = sorted(evdir.glob("*.json"))[-1]
    last_pin = json.loads(last.read_text(encoding="utf-8"))["hash"]

    # Claims + pins
    reg=ClaimRegistry(led, window_id="claims")
    reg.propose(claim_id="c1", claim_text="Pump P-101 overheating condition observed", claim_type=ClaimType.EMPIRICAL)
    reg.set_status(claim_id="c1", old_status=ClaimStatus.OPEN, new_status=ClaimStatus.WITNESSED, reason_code="DEMO_WITNESS", pins=[last_pin])
    led.seal_window("claims")
    led.close_clean()

    out=Path(args.out)
    build_case_zip(root, out)
    print("OK: demo case written to", out.as_posix())
    print("Next:")
    print("  python tools/verify_case.py", out.as_posix())
    print("  python ag.py claimcheck --case", out.as_posix(), "--all")
    print("  python ag.py detective-claims --case", out.as_posix(), "--all")
    return 0

def cmd_export(args)->int:
    man=build_case_zip(args.root, args.out, include_open_windows=args.include_open)
    print(json.dumps(man, indent=2, sort_keys=True))
    return 0

def cmd_demo(args)->int:
    root=Path(args.root); root.mkdir(parents=True, exist_ok=True)
    led=SpineLedger(root)
    reg=ConstraintRegistry(led, window_id="constants")
    reg.publish("temp.constraints","1.0",{"temp":{"min":0,"max":100,"roc_max_per_s":10}})
    reg.publish("sentinel.policy","1.0",{"FIRMWARE_UPDATE":{"risk":"HIGH","default":"INCONCLUSIVE"},"START":{"risk":"LOW","default":"PASS"}})
    led.seal_window("constants")

    siren=Siren(led, SirenConfig(window_id="siren", heartbeat_interval_s=2))
    gate=IngestGate(led, siren=siren, config=IngestConfig(window_id="ingest", max_accepts_per_sec=1000))
    gate.ingest({"source":"demo","event_type":"SENSOR","payload":{"sensor":"temp","value":42,"ts":10}})

    lens=Lens(root, LensConfig(constants_window="constants", constraint_id="temp.constraints"))
    ingest_dir=root/"spine"/"windows"/"ingest"/"events"
    sensor_ev=None
    if ingest_dir.exists():
        for p in reversed(sorted([p for p in ingest_dir.glob("*.json") if p.name[:6].isdigit()])):
            o=json.loads(p.read_text(encoding="utf-8"))
            if o.get("event_type")=="SENSOR":
                sensor_ev=o; break
    if sensor_ev:
        v=lens.evaluate(sensor_ev["payload"])
        emit_verdict(led, window_id="verdicts", module="Lens", subject_pin=sensor_ev["hash"], verdict=v)

    sent=SentinelLite(root, SentinelConfig(constants_window="constants", policy_id="sentinel.policy", allowed_actors=["alice"]))
    sv=sent.evaluate({"action":"FIRMWARE_UPDATE","target":"plc1","actor":"alice"})
    emit_verdict(led, window_id="verdicts", module="Sentinel", subject_pin=None, verdict=sv)

    led.close_clean()
    rep=verify_spine(root)
    out=Path(args.out) if args.out else (root/"case.zip")
    build_case_zip(root, out, include_open_windows=False)
    print(json.dumps({"verify":rep,"case_zip":str(out)}, indent=2, sort_keys=True))
    return 0

def build_parser():
    p=argparse.ArgumentParser(prog="ag", description="Aletheia Practical Core CLI")
    sub=p.add_subparsers(dest="cmd", required=True)

    pi=sub.add_parser("init"); pi.add_argument("--root", required=True); pi.set_defaults(func=cmd_init)

    pc=sub.add_parser("constraints-publish"); pc.add_argument("--root", required=True); pc.add_argument("--window", default="constants")
    pc.add_argument("--constraint-id", required=True); pc.add_argument("--version", required=True); pc.add_argument("--units", default=None)
    pc.add_argument("--seal", action="store_true"); pc.add_argument("--json", default=None); pc.add_argument("--json-file", default=None)
    pc.set_defaults(func=cmd_constraints_publish)

    
    pcl=sub.add_parser("claim-propose"); pcl.add_argument("--root", required=True); pcl.add_argument("--window", default="claims")
    pcl.add_argument("--claim-id", required=True); pcl.add_argument("--type", required=True, choices=["LOGICAL","EMPIRICAL","HISTORICAL","POLICY","OPERATIONAL"])
    pcl.add_argument("--text", required=True); pcl.add_argument("--reason-code", default="OPEN"); pcl.add_argument("--seal", action="store_true")
    pcl.set_defaults(func=cmd_claim_propose)

    pclk=sub.add_parser("claim-link"); pclk.add_argument("--root", required=True); pclk.add_argument("--window", default="claims")
    pclk.add_argument("--claim-id", required=True); pclk.add_argument("--pin", action="append", default=[])
    pclk.add_argument("--reason-code", default="EVIDENCE_LINKED"); pclk.add_argument("--seal", action="store_true")
    pclk.set_defaults(func=cmd_claim_link)

    pcs=sub.add_parser("claim-set"); pcs.add_argument("--root", required=True); pcs.add_argument("--window", default="claims")
    pcs.add_argument("--claim-id", required=True); pcs.add_argument("--status", required=True, choices=["OPEN","INCONCLUSIVE","WITNESSED","DERIVED","REFUTED","SUPERSEDED","RETRACTED"])
    pcs.add_argument("--pin", action="append", default=[]); pcs.add_argument("--reason-code", required=True); pcs.add_argument("--seal", action="store_true")
    pcs.set_defaults(func=cmd_claim_set)

    pcsh=sub.add_parser("claim-show"); pcsh.add_argument("--root", required=True); pcsh.add_argument("--window", default="claims")
    pcsh.add_argument("--claim-id", required=True); pcsh.set_defaults(func=cmd_claim_show)

    pclist=sub.add_parser("claim-list"); pclist.add_argument("--root", required=True); pclist.add_argument("--window", default="claims")
    pclist.set_defaults(func=cmd_claim_list)


    pcc=sub.add_parser("claimcheck"); pcc.add_argument("--case", required=True, help="Path to case.zip exported by Chronicle")
    pcc.add_argument("--window", default="claims"); pcc.add_argument("--claim-id", default=None)
    pcc.add_argument("--all", action="store_true", help="Check all claims found in the case")
    pcc.set_defaults(func=cmd_claimcheck)

    pdc=sub.add_parser("detective-claims"); pdc.add_argument("--case", required=True, help="Path to case.zip")
    pdc.add_argument("--window", default="claims"); pdc.add_argument("--claim-id", default=None)
    pdc.add_argument("--all", action="store_true", help="Review all claims in the case")
    pdc.set_defaults(func=cmd_detective_claims)

    pdo=sub.add_parser("demo-ot"); pdo.add_argument("--root", required=True); pdo.add_argument("--out", required=True)
    pdo.add_argument("--window", default="main")
    pdo.set_defaults(func=cmd_demo_ot)
    ping=sub.add_parser("ingest"); ping.add_argument("--root", required=True); ping.add_argument("--window", default="ingest")
    ping.add_argument("--json", default=None); ping.add_argument("--json-file", default=None)
    ping.add_argument("--with-siren", action="store_true"); ping.add_argument("--siren-window", default="siren"); ping.add_argument("--heartbeat-s", type=int, default=10)
    ping.add_argument("--reject-max", type=int, default=500); ping.add_argument("--max-accepts-per-sec", type=float, default=50.0)
    ping.add_argument("--surge-window-s", type=int, default=10); ping.add_argument("--surge-threshold", type=int, default=200)
    ping.set_defaults(func=cmd_ingest)

    pl=sub.add_parser("lens"); pl.add_argument("--root", required=True)
    pl.add_argument("--constants-window", default="constants"); pl.add_argument("--constraint-id", default="temp.constraints")
    pl.add_argument("--roc-without-baseline", action="store_true"); pl.add_argument("--last-value", type=float, default=None); pl.add_argument("--last-ts", type=float, default=None)
    pl.add_argument("--verdict-window", default="verdicts"); pl.add_argument("--subject-window", default="ingest"); pl.add_argument("--subject-pin", default=None)
    pl.add_argument("--json", default=None); pl.add_argument("--json-file", default=None); pl.set_defaults(func=cmd_lens)

    ps=sub.add_parser("sentinel"); ps.add_argument("--root", required=True)
    ps.add_argument("--constants-window", default="constants"); ps.add_argument("--policy-id", default="sentinel.policy")
    ps.add_argument("--allowed-actor", default=None); ps.add_argument("--verdict-window", default="verdicts"); ps.add_argument("--subject-pin", default=None)
    ps.add_argument("--json", default=None); ps.add_argument("--json-file", default=None); ps.set_defaults(func=cmd_sentinel)

    pv=sub.add_parser("verify"); pv.add_argument("--root", required=True); pv.set_defaults(func=cmd_verify)

    pd=sub.add_parser("detective"); pd.add_argument("--root", required=True); pd.add_argument("--window-id", default=None)
    pd.add_argument("--json", default=None); pd.add_argument("--json-file", default=None); pd.set_defaults(func=cmd_detective)

    pe=sub.add_parser("export-case"); pe.add_argument("--root", required=True); pe.add_argument("--out", required=True); pe.add_argument("--include-open", action="store_true")
    pe.set_defaults(func=cmd_export)

    pde=sub.add_parser("demo"); pde.add_argument("--root", required=True); pde.add_argument("--out", default=None); pde.set_defaults(func=cmd_demo)

    return p

def main(argv: Optional[List[str]]=None)->int:
    args=build_parser().parse_args(argv)
    return int(args.func(args))

if __name__=="__main__":
    raise SystemExit(main())
