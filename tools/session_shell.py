#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, os, shutil, sys, time, zipfile, hashlib
from pathlib import Path
from typing import Any, Dict, Optional, List, Tuple

def now_utc_iso() -> str:
    import datetime
    # Avoid the utcnow() deprecation warning on newer Python:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z")

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def read_json(p: Path) -> Dict[str, Any]:
    return json.loads(p.read_text(encoding="utf-8"))

def write_json(p: Path, obj: Any) -> None:
    p.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")

def mk_session_id() -> str:
    seed = f"{time.time_ns()}:{os.getpid()}:{os.urandom(8).hex()}".encode("utf-8")
    return sha256_hex(seed)[:16]

def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def extract_json_objects(text: str) -> List[Any]:
    """Extract JSON objects from an arbitrary stdout stream.
    Handles pretty-printed JSON (multi-line) by scanning with JSONDecoder.
    """
    dec = json.JSONDecoder()
    i = 0
    out: List[Any] = []
    n = len(text)
    while i < n:
        # skip whitespace
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            break
        # try decode at this position
        try:
            obj, j = dec.raw_decode(text, i)
            out.append(obj)
            i = j
        except json.JSONDecodeError:
            # move forward until next plausible JSON start
            i += 1
    return out

def cmd_init(args: argparse.Namespace) -> int:
    core = Path(args.core_dir).resolve()
    out_root = Path(args.out_root).resolve()
    ensure_dir(out_root)

    sid = args.session_id or mk_session_id()
    sdir = out_root / f"session_{sid}"
    ensure_dir(sdir / "envelopes")

    manifest = (core / args.manifest).resolve()
    if not manifest.exists():
        print(json.dumps({"verdict":"ERROR","error":"MANIFEST_NOT_FOUND","path":str(manifest)}, indent=2, sort_keys=True))
        return 2
    shutil.copy2(manifest, sdir / "Provenance_Manifest.json")

    meta = {
        "schema_version":"1",
        "created_utc": now_utc_iso(),
        "session_id": sid,
        "core_dir": str(core),
        "manifest": "Provenance_Manifest.json",
        "envelopes_dir": "envelopes",
        "last_envelope_hash": None,
        "count": 0
    }
    write_json(sdir / "session_meta.json", meta)
    print(json.dumps({"verdict":"PASS","session_dir":str(sdir),"session_id":sid}, indent=2, sort_keys=True))
    return 0

def run_provenance_cli(core: Path, out_dir: Path, question: str, answer_json: Path, parent_hash: Optional[str]) -> Dict[str, Any]:
    import subprocess
    cmd = [
        sys.executable, str(core/"tools/provenance_cli.py"),
        "run",
        "--core-dir", str(core),
        "--out-dir", str(out_dir),
        "--question", question,
        "--answer-json", str(answer_json),
    ]
    if parent_hash is not None:
        cmd += ["--parent-hash", parent_hash]
    p = subprocess.run(cmd, cwd=str(core), capture_output=True, text=True)
    objs = extract_json_objects(p.stdout)
    last = objs[-1] if objs else None
    return {"rc": p.returncode, "last": last, "stdout": p.stdout.strip(), "stderr": p.stderr.strip(), "cmd": cmd}

def cmd_add(args: argparse.Namespace) -> int:
    sdir = Path(args.session_dir).resolve()
    meta_p = sdir / "session_meta.json"
    if not meta_p.exists():
        print(json.dumps({"verdict":"ERROR","error":"SESSION_META_NOT_FOUND","path":str(meta_p)}, indent=2, sort_keys=True))
        return 2
    meta = read_json(meta_p)

    core = Path(args.core_dir).resolve()
    env_dir = sdir / "envelopes"
    ensure_dir(env_dir)

    parent = meta.get("last_envelope_hash")
    ans_path = Path(args.answer_json).resolve()
    if not ans_path.exists():
        print(json.dumps({"verdict":"ERROR","error":"ANSWER_JSON_NOT_FOUND","path":str(ans_path)}, indent=2, sort_keys=True))
        return 2

    r = run_provenance_cli(core, sdir, args.question, ans_path, parent)
    if r["rc"] != 0 or not isinstance(r["last"], dict) or r["last"].get("verdict") != "PASS":
        print(json.dumps({"verdict":"FAIL","rc":r["rc"],"stderr":r["stderr"],"stdout":r["stdout"]}, indent=2, sort_keys=True))
        return 2

    count = int(meta.get("count") or 0) + 1
    env_src = sdir / "env.json"
    sq_src = sdir / "sq.json"
    if not env_src.exists() or not sq_src.exists():
        print(json.dumps({"verdict":"ERROR","error":"MISSING_OUTPUT_FILES","details":{"env":str(env_src),"sq":str(sq_src)}}, indent=2, sort_keys=True))
        return 2

    env_obj = read_json(env_src)
    env_hash = env_obj.get("envelope_hash")
    if not isinstance(env_hash, str) or len(env_hash) != 64:
        print(json.dumps({"verdict":"ERROR","error":"BAD_ENVELOPE_HASH","got":env_hash}, indent=2, sort_keys=True))
        return 2

    env_dst = env_dir / f"{count:04d}_{env_hash}.env.json"
    sq_dst  = env_dir / f"{count:04d}_{env_hash}.sq.json"
    shutil.move(str(env_src), str(env_dst))
    shutil.move(str(sq_src), str(sq_dst))

    meta["count"] = count
    meta["last_envelope_hash"] = env_hash
    write_json(meta_p, meta)

    print(json.dumps({"verdict":"PASS","count":count,"envelope_hash":env_hash,"env":str(env_dst),"sq":str(sq_dst)}, indent=2, sort_keys=True))
    return 0

def cmd_list(args: argparse.Namespace) -> int:
    sdir = Path(args.session_dir).resolve()
    env_dir = sdir / "envelopes"
    if not env_dir.exists():
        print(json.dumps({"verdict":"ERROR","error":"NO_ENVELOPES_DIR","path":str(env_dir)}, indent=2, sort_keys=True))
        return 2
    envs = sorted([p.name for p in env_dir.glob("*.env.json")])
    print(json.dumps({"verdict":"PASS","count":len(envs),"envelopes":envs}, indent=2, sort_keys=True))
    return 0

def cmd_export(args: argparse.Namespace) -> int:
    sdir = Path(args.session_dir).resolve()
    out_zip = Path(args.out_zip).resolve()
    if out_zip.exists() and not args.overwrite:
        print(json.dumps({"verdict":"ERROR","error":"OUT_ZIP_EXISTS","path":str(out_zip)}, indent=2, sort_keys=True))
        return 2
    if out_zip.exists():
        out_zip.unlink()

    parent = sdir.parent.resolve()
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for p in sorted(sdir.rglob("*")):
            if p.is_dir():
                continue
            rel = p.relative_to(parent).as_posix()
            z.write(p, rel)

    sha = sha256_hex(out_zip.read_bytes())
    sha_path = out_zip.with_suffix(out_zip.suffix + ".sha256")
    sha_path.write_text(f"{sha}  {out_zip.name}\n", encoding="utf-8")
    print(json.dumps({"verdict":"PASS","out_zip":str(out_zip),"sha256":sha,"sha256_file":str(sha_path)}, indent=2, sort_keys=True))
    return 0

def main() -> int:
    ap = argparse.ArgumentParser(description="Step 15 UI Shell (minimal): session wrapper over deterministic provenance core.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="Create a new local session folder with pinned manifest copy.")
    p.add_argument("--core-dir", default=".", help="Core dir")
    p.add_argument("--manifest", default="Provenance_Manifest.json")
    p.add_argument("--out-root", default="sessions", help="Where to create session_* directories")
    p.add_argument("--session-id", default=None, help="Optional explicit session id")
    p.set_defaults(fn=cmd_init)

    p = sub.add_parser("add", help="Add one Q/A to session, producing a new envelope chained to the last.")
    p.add_argument("--core-dir", default=".", help="Core dir")
    p.add_argument("--session-dir", required=True, help="session_* directory")
    p.add_argument("--question", required=True)
    p.add_argument("--answer-json", required=True, help="Path to a StructuredAnswer JSON")
    p.set_defaults(fn=cmd_add)

    p = sub.add_parser("list", help="List envelopes in a session.")
    p.add_argument("--session-dir", required=True)
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser("export", help="Export the entire session as a zip bundle (+ sha256).")
    p.add_argument("--session-dir", required=True)
    p.add_argument("--out-zip", required=True)
    p.add_argument("--overwrite", action="store_true")
    p.set_defaults(fn=cmd_export)

    args = ap.parse_args()
    return int(args.fn(args))

if __name__ == "__main__":
    raise SystemExit(main())
