import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _in_git_checkout() -> bool:
    try:
        subprocess.check_output(["git", "rev-parse", "--is-inside-work-tree"], cwd=ROOT, stderr=subprocess.DEVNULL)
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


def test_sha256sums_lists_no_cache_files():
    names = [l.split("  ", 1)[1] for l in (ROOT / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines()]
    bad = [n for n in names if "__pycache__" in n or ".pytest_cache" in n or n.endswith((".pyc", ".pyo"))]
    assert bad == []


@pytest.mark.skipif(not _in_git_checkout(), reason="needs a git checkout to know the tracked files")
def test_sha256sums_matches_tracked_files():
    from tools.gen_sha256sums import render
    assert (ROOT / "SHA256SUMS.txt").read_text(encoding="utf-8") == render(), \
        "SHA256SUMS.txt is out of date; run: python tools/gen_sha256sums.py"
