#!/usr/bin/env python3
"""
tools/release_build.py — Reproducible release bundle builder.

Steps:
  1. Clean runtime artifacts
  2. Run validation (selfcheck + core tests + example verification)
  3. Build deterministic zip
  4. Write SHA256 file

Output:
  dist/aletheia_core_v{VERSION}.zip
  dist/aletheia_core_v{VERSION}.sha256

Usage:
    python tools/release_build.py
    python tools/release_build.py --skip-tests   # for CI where tests already ran
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT   = Path(__file__).resolve().parent.parent
PYTHON = sys.executable

# ── read version from pyproject.toml ─────────────────────────────────────────
def _read_version() -> str:
    pp = ROOT / "pyproject.toml"
    for line in pp.read_text(encoding="utf-8").splitlines():
        if line.strip().startswith("version"):
            return line.split("=")[1].strip().strip('"').strip("'")
    return "0.0.0"

VERSION = _read_version()

# ── what to include in the release ───────────────────────────────────────────
INCLUDE_DIRS = [
    "aletheia",
    "tools",
    "tests",
    "tests_adversarial",
    "schemas",
    "profiles",
    "docs",
    "examples",
    "constraints",
]
INCLUDE_ROOT_FILES = [
    "README.md",
    "CHANGELOG.md",
    "pyproject.toml",
    ".gitignore",
    "aletheia.py",
    "aletheia_selfcheck.py",
    "aletheia_verify.py",
    "aletheia_demo.py",
    "veritas.py",
    "ag.py",
]
EXCLUDE_PATTERNS = {"__pycache__", ".pytest_cache", ".pyc", ".pyo", ".DS_Store"}


def _should_exclude(path: Path) -> bool:
    for part in path.parts:
        if part in EXCLUDE_PATTERNS:
            return True
    if path.suffix in {".pyc", ".pyo"}:
        return True
    return False


# Fixed timestamp for deterministic zips (release date)
_FIXED_TS = (2026, 3, 9, 12, 0, 0)


def _clean_artifacts():
    print("  Cleaning runtime artifacts...")
    patterns = [
        "drift_report.json", "redteam_report.json", "calibration_report.json",
        "replay_*.json", "_rt_*.json", "_cal_*.json", "_drift_*.json",
        "diag_*.json",
    ]
    removed = 0
    for pattern in patterns:
        for f in ROOT.glob(pattern):
            f.unlink()
            removed += 1
    for d in ROOT.rglob("__pycache__"):
        shutil.rmtree(d, ignore_errors=True)
    print(f"    Removed {removed} artifact(s) and __pycache__ dirs")


def _run_validation() -> bool:
    print("  Running validation...")
    r = subprocess.run(
        [PYTHON, "tools/validate_repo.py"],
        cwd=str(ROOT),
    )
    return r.returncode == 0


def _build_zip(out_path: Path) -> str:
    """Build a deterministic zip. Returns SHA256 of the zip file on disk.

    IMPORTANT: The hash is computed from the final zip file after it is fully
    written to disk, not from the raw content bytes during streaming.
    These are different values — the zip file hash is what a downloader
    can verify with sha256sum, which is the only hash that matters.
    """
    print(f"  Building {out_path.name}...")
    entries = []

    for d in INCLUDE_DIRS:
        dp = ROOT / d
        if not dp.exists():
            continue
        for f in sorted(dp.rglob("*")):
            if f.is_file() and not _should_exclude(f):
                entries.append(str(f.relative_to(ROOT)))

    for name in INCLUDE_ROOT_FILES:
        f = ROOT / name
        if f.exists():
            entries.append(name)

    entries = sorted(set(entries))

    out_path.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel in entries:
            info = zipfile.ZipInfo(rel)
            info.date_time = _FIXED_TS
            info.compress_type = zipfile.ZIP_DEFLATED
            data = (ROOT / rel).read_bytes()
            zf.writestr(info, data)

    # Hash the zip file itself — this is what sha256sum will verify.
    digest = hashlib.sha256(out_path.read_bytes()).hexdigest()
    size_kb = out_path.stat().st_size // 1024
    print(f"    {len(entries)} files  {size_kb} KB  SHA256: {digest[:16]}…")
    return digest


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Aletheia release builder")
    ap.add_argument("--skip-tests", action="store_true",
                    help="Skip validation (tests already ran upstream)")
    args = ap.parse_args(argv)

    print(f"\n  Building Aletheia Core v{VERSION} release\n")

    _clean_artifacts()

    if not args.skip_tests:
        ok = _run_validation()
        if not ok:
            print("\n  ABORT: Validation failed. Fix tests before releasing.\n")
            return 1

    from datetime import date as _date
    _today = _date.today().strftime("%Y%m%d")
    name = f"aletheia_core_v{VERSION.replace('.', '_')}_{_today}"
    dist = ROOT / "dist"
    zip_path  = dist / f"{name}.zip"
    sha_path  = dist / f"{name}.sha256"

    digest = _build_zip(zip_path)

    built_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat() + "Z"
    sha_path.write_text(
        f"{digest}  {zip_path.name}\n"
        f"\n"
        f"# Built:   {built_at}\n"
        f"# Version: {VERSION}\n"
        f"#\n"
        f"# To verify:\n"
        f"#   sha256sum -c {sha_path.name}\n"
        f"# Note: if your browser renamed the zip (e.g. appended -1),\n"
        f"#   rename it back to {zip_path.name} before running sha256sum -c\n",
        encoding="utf-8",
    )

    print(f"\n  Release artifacts:")
    print(f"    {zip_path.relative_to(ROOT)}")
    print(f"    {sha_path.relative_to(ROOT)}")
    print(f"\n  SHA256: {digest}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
