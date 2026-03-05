from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class ZipLimits:
    # Tune to your environment. These defaults are conservative.
    max_files: int = 1000
    max_total_uncompressed: int = 100 * 1024 * 1024  # 100 MiB
    max_single_file: int = 50 * 1024 * 1024          # 50 MiB
    max_path_len: int = 512
