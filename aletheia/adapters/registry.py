"""
aletheia.adapters.registry — Adapter Registry

Phase 2: Adapter Framework

Central registry for all named adapters. Adapters register themselves
on import. The runner uses the registry to resolve adapter names to
instances.

Pattern:
  from aletheia.adapters.registry import register, get_adapter
  register(MyAdapter())
"""
from __future__ import annotations

from typing import Dict
from aletheia.adapters.base import AdapterBase

_REGISTRY: Dict[str, AdapterBase] = {}


def register(adapter: AdapterBase) -> None:
    """Register an adapter instance under its NAME."""
    if not isinstance(adapter, AdapterBase):
        raise TypeError(f"Expected AdapterBase, got {type(adapter).__name__}")
    _REGISTRY[adapter.NAME] = adapter


def get_adapter(name: str) -> AdapterBase:
    """Retrieve a registered adapter by name. Raises KeyError if not found."""
    if name not in _REGISTRY:
        available = sorted(_REGISTRY.keys())
        raise KeyError(f"Adapter {name!r} not registered. Available: {available}")
    return _REGISTRY[name]


def list_adapters() -> list:
    """Return list of registered adapter names, sorted."""
    return sorted(_REGISTRY.keys())
