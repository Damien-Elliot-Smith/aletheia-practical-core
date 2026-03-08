from __future__ import annotations
import json, hashlib, zipfile
from pathlib import Path
from typing import Any, Dict, List, Tuple
from aletheia.spine.verify import verify_spine

def sha256_file(path: Path) -> str:
    h=hashlib.sha256()
    with open(path,"rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def build_case_zip(root_dir: str|Path, out_zip: str|Path, *, include_open_windows: bool=False) -> Dict[str, Any]:
    root=Path(root_dir)
    spine=root/"spine"
    windows=spine/"windows"
    report=verify_spine(root)

    sealed=[]; openw=[]
    if windows.exists():
        for wdir in sorted([p for p in windows.iterdir() if p.is_dir()]):
            if (wdir/"sealed.json").exists() and (wdir/"open.json").exists():
                sealed.append(wdir.name)
            elif (wdir/"open.json").exists():
                openw.append(wdir.name)
    omitted=[] if include_open_windows else list(openw)

    files: List[Tuple[Path,str]]=[]
    for wid in sealed:
        wdir=windows/wid
        for p in sorted((wdir/"events").glob("*.json")):
            if p.name[:6].isdigit():
                files.append((p,f"evidence/spine/windows/{wid}/events/{p.name}"))
        files.append((wdir/"open.json", f"evidence/spine/windows/{wid}/open.json"))
        files.append((wdir/"sealed.json", f"evidence/spine/windows/{wid}/sealed.json"))
    if include_open_windows:
        for wid in openw:
            wdir=windows/wid
            for p in sorted((wdir/"events").glob("*.json")):
                if p.name[:6].isdigit():
                    files.append((p,f"evidence/spine/windows/{wid}/events/{p.name}"))
            files.append((wdir/"open.json", f"evidence/spine/windows/{wid}/open.json"))

    for opt in ["scars.jsonl","witness_index.json","siren_state.json","clean_shutdown.json"]:
        p=spine/opt
        if p.exists():
            files.append((p,f"evidence/spine/{opt}"))
    rej=spine/"rejects"
    if rej.exists():
        for p in sorted(rej.glob("*")):
            if p.is_file():
                files.append((p,f"evidence/spine/rejects/{p.name}"))

    # Constraints snapshot (active + forks) if constants sealed
    constraints_snapshot=None
    const_dir=windows/"constants"
    if (const_dir/"sealed.json").exists():
        events_dir=const_dir/"events"
        const_events=[]
        for p in sorted(events_dir.glob("*.json")):
            if p.name[:6].isdigit():
                try: obj=json.loads(p.read_text(encoding="utf-8"))
                except Exception: continue
                if obj.get("event_type") in ("CONSTRAINT_PUBLISH","CONSTRAINT_SUPERSEDE","CONSTRAINT_DEPRECATE"):
                    const_events.append(obj)
        by_id={}
        for e in const_events:
            pl=e.get("payload") or {}
            cid=pl.get("constraint_id")
            if isinstance(cid,str):
                by_id.setdefault(cid, []).append(e)
        snap={"window_id":"constants","active":{}, "forks":{}}
        for cid, evs in by_id.items():
            heads={e.get("hash") for e in evs if e.get("event_type") in ("CONSTRAINT_PUBLISH","CONSTRAINT_SUPERSEDE") and isinstance(e.get("hash"),str)}
            for e in evs:
                pl=e.get("payload") or {}
                if e.get("event_type")=="CONSTRAINT_SUPERSEDE":
                    prev=pl.get("previous_hash")
                    if isinstance(prev,str): heads.discard(prev)
                elif e.get("event_type")=="CONSTRAINT_DEPRECATE":
                    prev=pl.get("previous_hash")
                    if isinstance(prev,str): heads.discard(prev)
            if not heads:
                continue
            if len(heads)>1:
                snap["forks"][cid]=sorted(list(heads))
                continue
            head_hash=next(iter(heads))
            head=None
            for e in evs:
                if e.get("hash")==head_hash:
                    head=e; break
            if not head:
                continue
            pl=head.get("payload") or {}
            snap["active"][cid] = {
                "version": pl.get("version"),
                "constraint_hash": head.get("hash"),
                "rule": pl.get("rule"),
                "units": pl.get("units"),
                "applicability": pl.get("applicability"),
                "tolerances": pl.get("tolerances"),
            }
        constraints_snapshot=snap

    verify_report={"verify":report,"sealed_windows":sealed,"open_windows":openw,"include_open_windows":include_open_windows}
    out_zip=Path(out_zip); out_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_zip,"w",compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("evidence/verify_report.json", json.dumps(verify_report, sort_keys=True, indent=2))
        if constraints_snapshot is not None:
            z.writestr("evidence/constraints_registry_snapshot.json", json.dumps(constraints_snapshot, sort_keys=True, indent=2))
        for src,zp in files:
            z.write(src,zp)

        manifest_files=[]
        for src,zp in files:
            manifest_files.append({"zip_path":zp,"src_rel":str(src.relative_to(root)),"sha256":sha256_file(src),"bytes":src.stat().st_size})
        vb=json.dumps(verify_report, sort_keys=True, indent=2).encode("utf-8")
        manifest_files.append({"zip_path":"evidence/verify_report.json","src_rel":None,"sha256":hashlib.sha256(vb).hexdigest(),"bytes":len(vb)})
        if constraints_snapshot is not None:
            sb=json.dumps(constraints_snapshot, sort_keys=True, indent=2).encode("utf-8")
            manifest_files.append({"zip_path":"evidence/constraints_registry_snapshot.json","src_rel":None,"sha256":hashlib.sha256(sb).hexdigest(),"bytes":len(sb)})
        manifest_files=[]
        for src,zp in files:
            manifest_files.append({"zip_path":zp,"sha256":sha256_file(src),"bytes":src.stat().st_size})
        vb=json.dumps(verify_report, sort_keys=True, indent=2).encode("utf-8")
        verify_sha=hashlib.sha256(vb).hexdigest()
        manifest_files.append({"zip_path":"evidence/verify_report.json","sha256":verify_sha,"bytes":len(vb)})
        constraints_sha=None
        if constraints_snapshot is not None:
            sb=json.dumps(constraints_snapshot, sort_keys=True, indent=2).encode("utf-8")
            constraints_sha=hashlib.sha256(sb).hexdigest()
            manifest_files.append({"zip_path":"evidence/constraints_registry_snapshot.json","sha256":constraints_sha,"bytes":len(sb)})

        # Window summary (seal records + content digests)
        window_summaries=[]
        for wid in sealed:
            wdir = windows/wid
            seal_obj = json.loads((wdir/"sealed.json").read_text(encoding="utf-8"))
            seal_bytes = json.dumps(seal_obj, sort_keys=True, separators=(",",":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
            seal_sha = hashlib.sha256(seal_bytes).hexdigest()
            # Content hash: sha256 over sorted event file sha256 list + seal/open markers
            sha_lines=[]
            for p in sorted((wdir/"events").glob("*.json")):
                if p.name[:6].isdigit():
                    sha_lines.append(sha256_file(p))
            sha_lines.append(sha256_file(wdir/"open.json"))
            sha_lines.append(sha256_file(wdir/"sealed.json"))
            content_sha = hashlib.sha256(("\n".join(sha_lines)+"\n").encode("utf-8")).hexdigest()
            window_summaries.append({
                "window_id": wid,
                "sealed": True,
                "seal_record_sha256": seal_sha,
                "window_root_hash": str(seal_obj.get("window_root_hash")),
                "event_count": int(seal_obj.get("event_count", 0)),
                "first_hash": str(seal_obj.get("first_hash")),
                "last_hash": str(seal_obj.get("last_hash")),
                "window_content_sha256": content_sha,
            })

        core_root = Path(__file__).resolve().parents[2]
        freeze_path = core_root / 'FREEZE.json'
        core_freeze_sha256 = sha256_file(freeze_path) if freeze_path.exists() else None
        case_manifest={
            "schema_version":"2",
            "core_freeze_sha256": core_freeze_sha256,
            "case_id": hashlib.sha256((str(root.resolve())+"|"+__import__("datetime").datetime.utcnow().isoformat()).encode("utf-8")).hexdigest()[:16],
            "created_utc": __import__("datetime").datetime.utcnow().replace(microsecond=0).isoformat()+"Z",
            "tool": {"name":"aletheia-practical-core","version":"v1"},
            "verify_ok": bool(report.get("ok",False)),
            "verify_report_sha256": verify_sha,
            "constraints_snapshot_sha256": constraints_sha,
            "claims_window_id": "claims",
            "sealed_windows_included": sealed,
            "open_windows_present": openw,
            "omitted_windows": omitted,
            "windows": window_summaries,
            "files": sorted(manifest_files, key=lambda x: x["zip_path"]),
        }
        z.writestr("case_manifest.json", json.dumps(case_manifest, sort_keys=True, indent=2))
        # Back-compat: keep old name
        z.writestr("manifest.json", json.dumps(case_manifest, sort_keys=True, indent=2))
    return case_manifest

# Backwards-compatible alias (older docs/examples used export_case_zip)
def export_case_zip(root_dir: str|Path, out_zip: str|Path, *, include_open_windows: bool=False):
    """Alias for build_case_zip."""
    return build_case_zip(root_dir, out_zip, include_open_windows=include_open_windows)
