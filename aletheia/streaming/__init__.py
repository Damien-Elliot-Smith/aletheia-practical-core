"""
aletheia.streaming — Phase 2.1: Streaming Ingest

Provides:
  WindowScheduler  — auto-seal + roll to new window on time/count trigger
  StreamAdapter    — base class for continuous evidence sources
  FileAdapter      — tail a log file, ingest each new line
  CallbackAdapter  — ingest from a caller-supplied generator/callback
"""
from .scheduler import WindowScheduler, SchedulerConfig, SchedulerState, SchedulerError
from .adapters import StreamAdapter, FileAdapter, CallbackAdapter

__all__ = [
    "WindowScheduler", "SchedulerConfig", "SchedulerState", "SchedulerError",
    "StreamAdapter", "FileAdapter", "CallbackAdapter",
]
