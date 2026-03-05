"""
Public API re-exports for aletheia.detective.
Keep imports explicit and side-effect free.
"""
from .detective import Detective, DetectiveConfig

__all__ = ["Detective", "DetectiveConfig"]
