from __future__ import annotations

import os
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Tuple


@dataclass(frozen=True)
class ZipWritePolicy:
    """
    Phase B2/C hooks live here later.
    For now: centralize zip writing so we can enforce ordering/timestamps next.
    """
    fixed_timestamp: Tuple[int, int, int, int, int, int] = (1980, 1, 1, 0, 0, 0)  # stable epoch for determinism later
    compression: int = zipfile.ZIP_DEFLATED


def write_zip_from_files(
    out_zip: str,
    files: Iterable[tuple[str, str]],
    policy: ZipWritePolicy | None = None,
) -> None:
    """
    Write a zip from (src_path, arcname) pairs.
    Sorting is enforced for determinism.
    """
    pol = policy or ZipWritePolicy()
    out_path = Path(out_zip)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    items = list(files)
    items.sort(key=lambda t: t[1])  # sort by arcname (deterministic)

    with zipfile.ZipFile(str(out_path), "w", compression=pol.compression) as z:
        for src, arc in items:
            srcp = Path(src)
            if not srcp.is_file():
                raise FileNotFoundError(f"missing file: {src}")

            info = zipfile.ZipInfo(filename=arc, date_time=pol.fixed_timestamp)
            # Normalize perms a bit (readable file). We keep it conservative.
            info.external_attr = (0o644 & 0xFFFF) << 16

            with open(srcp, "rb") as f:
                data = f.read()
            z.writestr(info, data)

def write_zip_from_tree(
    out_zip: str,
    root_dir: str,
    prefix: str,
    exclude_dirs: list[str] | None = None,
    policy: ZipWritePolicy | None = None,
) -> int:
    """
    Centralized tree writer used by release_pack.
    Uses release_pack.add_tree for existing exclusion logic.
    """
    pol = policy or ZipWritePolicy()
    out_path = Path(out_zip)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # late import avoids circular import at module load
    from tools.release_pack import add_tree  # type: ignore

    with zipfile.ZipFile(str(out_path), "w", compression=pol.compression) as z:
        return int(add_tree(z, Path(root_dir), prefix, exclude_dirs=sorted(exclude_dirs or [])))


def write_zip_mixed(
    out_zip: str,
    file_items: Iterable[tuple[str, str]],
    bytes_items: Iterable[tuple[str, bytes]],
    policy: ZipWritePolicy | None = None,
) -> None:
    """
    Write a zip containing both on-disk files and in-memory bytes.

    - file_items: (src_path, arcname)
    - bytes_items: (arcname, bytes)

    Deterministic ordering:
    - bytes entries sorted by arcname
    - file entries sorted by arcname
    """
    pol = policy or ZipWritePolicy()
    out_path = Path(out_zip)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    fi = list(file_items)
    bi = list(bytes_items)
    fi.sort(key=lambda t: t[1])
    bi.sort(key=lambda t: t[0])

    with zipfile.ZipFile(str(out_path), "w", compression=pol.compression) as z:
        # bytes first (stable)
        for arc, data in bi:
            info = zipfile.ZipInfo(filename=arc, date_time=pol.fixed_timestamp)
            info.external_attr = (0o644 & 0xFFFF) << 16
            z.writestr(info, data)

        # then files (stable order)
        for src, arc in fi:
            srcp = Path(src)
            if not srcp.is_file():
                raise FileNotFoundError(f"missing file: {src}")

            info = zipfile.ZipInfo(filename=arc, date_time=pol.fixed_timestamp)
            info.external_attr = (0o644 & 0xFFFF) << 16

            with open(srcp, "rb") as f:
                data = f.read()

            z.writestr(info, data)

def append_zip_bytes(
    out_zip: str,
    bytes_items: Iterable[tuple[str, bytes]],
    policy: ZipWritePolicy | None = None,
) -> None:
    """
    Append in-memory bytes entries to an existing zip (or create it if missing),
    using deterministic ordering + timestamps.

    This keeps all zipfile.ZipFile usage inside tools/_zip_write.py (zip IO gate).
    """
    pol = policy or ZipWritePolicy()
    out_path = Path(out_zip)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    bi = list(bytes_items)
    bi.sort(key=lambda t: t[0])  # deterministic

    # Append mode: add new members without rewriting the whole archive
    with zipfile.ZipFile(str(out_path), "a", compression=pol.compression) as z:
        for arc, data in bi:
            info = zipfile.ZipInfo(filename=arc, date_time=pol.fixed_timestamp)
            info.external_attr = (0o644 & 0xFFFF) << 16
            z.writestr(info, data)

