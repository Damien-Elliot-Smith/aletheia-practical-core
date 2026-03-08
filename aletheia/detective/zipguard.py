from __future__ import annotations

import os
import posixpath
import zipfile
from dataclasses import dataclass
from typing import List

from .limits import ZipLimits
from . import reasons as R


@dataclass(frozen=True)
class ZipMemberPlan:
    zip_name: str
    rel_path: str
    file_size: int


class ZipGuardError(Exception):
    def __init__(self, reason_code: str, detail: str = ""):
        super().__init__(detail)
        self.reason_code = reason_code
        self.detail = detail


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    # Unix symlink bit lives in external_attr top 16 bits
    # S_IFLNK = 0o120000
    mode = (info.external_attr >> 16) & 0o170000
    return mode == 0o120000


def _normalize_zip_relpath(name: str, limits: ZipLimits) -> str:
    # Zip names are posix-style
    if not name or len(name) > limits.max_path_len:
        raise ZipGuardError(R.ERR_BAD_PATH, f"bad path length: {len(name)}")

    # reject absolute paths
    if name.startswith("/") or name.startswith("\\"):
        raise ZipGuardError(R.ERR_PATH_TRAVERSAL, f"absolute path: {name}")

    # reject drive letters like C:
    if len(name) >= 2 and name[1] == ":":
        raise ZipGuardError(R.ERR_PATH_TRAVERSAL, f"drive path: {name}")

    # Phase 1.3 — backslash traversal guard (RT-07)
    # Windows-style paths like ..\..\evil can bypass posixpath.normpath on some platforms.
    if "\\" in name:
        raise ZipGuardError(R.ERR_PATH_TRAVERSAL, f"backslash in path: {name}")

    norm = posixpath.normpath(name)
    if norm in (".", ""):
        raise ZipGuardError(R.ERR_BAD_PATH, f"empty path: {name}")

    parts = norm.split("/")
    if any(p == ".." for p in parts):
        raise ZipGuardError(R.ERR_PATH_TRAVERSAL, f"traversal: {name}")

    if any(p in ("", ".") for p in parts):
        raise ZipGuardError(R.ERR_BAD_PATH, f"weird segments: {name}")

    return norm


def build_extraction_plan(zip_path: str, limits: ZipLimits) -> List[ZipMemberPlan]:
    plans: List[ZipMemberPlan] = []
    total = 0
    count = 0

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            infos = zf.infolist()
            infos.sort(key=lambda i: i.filename)  # determinism

            # Duplicate entry detection: a zip with two entries sharing the same
            # name is structurally ambiguous. Python's zipfile silently picks the
            # last one — we reject it explicitly before that ambiguity can affect
            # verification. This also suppresses the stdlib UserWarning.
            seen_names: set = set()
            for info in infos:
                if info.filename in seen_names:
                    raise ZipGuardError(R.ERR_BAD_ZIP, f"duplicate entry: {info.filename}")
                seen_names.add(info.filename)

            for info in infos:
                name = info.filename

                # directory entries
                if name.endswith("/"):
                    continue

                count += 1
                if count > limits.max_files:
                    raise ZipGuardError(R.ERR_FILE_COUNT_LIMIT, f"count>{limits.max_files}")

                if _is_symlink(info):
                    raise ZipGuardError(R.ERR_SYMLINK, f"symlink: {name}")

                if info.file_size < 0:
                    raise ZipGuardError(R.ERR_BAD_ZIP, f"negative size: {name}")

                if info.file_size > limits.max_single_file:
                    raise ZipGuardError(R.ERR_SINGLE_FILE_SIZE_LIMIT, f"{name} too big")

                total += info.file_size
                if total > limits.max_total_uncompressed:
                    raise ZipGuardError(R.ERR_SIZE_LIMIT, f"total>{limits.max_total_uncompressed}")

                rel = _normalize_zip_relpath(name, limits)
                plans.append(ZipMemberPlan(zip_name=name, rel_path=rel, file_size=info.file_size))

    except zipfile.BadZipFile as e:
        raise ZipGuardError(R.ERR_BAD_ZIP, str(e))
    except zipfile.LargeZipFile as e:
        raise ZipGuardError(R.ERR_BAD_ZIP, str(e))

    return plans


def safe_extract(zip_path: str, extract_root: str, plans: List[ZipMemberPlan]) -> None:
    root_abs = os.path.abspath(extract_root)
    with zipfile.ZipFile(zip_path, "r") as zf:
        for p in plans:
            out_path = os.path.abspath(os.path.join(root_abs, p.rel_path))
            if not out_path.startswith(root_abs + os.sep):
                raise ZipGuardError(R.ERR_PATH_TRAVERSAL, f"escape: {p.rel_path}")

            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with zf.open(p.zip_name, "r") as src, open(out_path, "wb") as dst:
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    dst.write(chunk)
