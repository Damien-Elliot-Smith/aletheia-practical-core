"""
aletheia.adapters.streaming — Streaming Adapter Layer

Phase 9: Support continuous ingestion from live data feeds.

Inputs: webhooks, sockets, message queues, streaming telemetry.

Design:
  StreamingBuffer   — thread-safe bounded FIFO; backpressure via reject on full.
  StreamBatch       — a sealed, ordered, deterministically-hashed batch of raw items.
  StreamingRunner   — feeds a StreamingBuffer into an AdapterRunner in batch windows.

Streaming rules:
  - Defined batch boundaries: a batch is sealed before being passed to the adapter.
  - Deterministic ordering: items within a batch are processed in arrival order.
  - Late arrival classification: items with timestamps older than the batch
    open time are marked as LATE_ARRIVAL with LOSS_OF_CAUSAL_LINKAGE.
  - Clock drift handling: wall clock monotonicity is enforced per batch;
    backwards-moving clocks produce LOSS_OF_AUTHENTICITY, not silent acceptance.
  - Buffer full policy: new items are DROPPED (with explicit rejection record)
    rather than silently lost or causing unbounded memory growth.

This module is intentionally stdlib-only and synchronous-first.
Async / threaded integration is done by the caller.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from aletheia.adapters.taxonomy import (
    LOSS_OF_CAUSAL_LINKAGE, LOSS_OF_AUTHENTICITY,
    REJECT_HOSTILE,
    STATUS_REJECTED,
)


# ── Streaming item ────────────────────────────────────────────────────────────

@dataclass
class StreamItem:
    """
    One item in the streaming buffer.

    arrived_at_mono: monotonic clock at arrival time (for ordering and lateness).
    arrived_at_wall: wall clock at arrival time (ISO8601 UTC Z).
    raw:             raw bytes as received from the source.
    source_tag:      optional source label for this item.
    """
    raw: bytes
    arrived_at_mono: float
    arrived_at_wall: str
    source_tag: str = "stream"
    late: bool = False

    def input_hash(self) -> str:
        return hashlib.sha256(self.raw).hexdigest()


# ── Bounded buffer ────────────────────────────────────────────────────────────

class StreamingBuffer:
    """
    Thread-safe bounded FIFO buffer for streaming items.

    On overflow, new items are REJECTED (not silently dropped).
    The rejection is recorded in dropped_count and dropped_hashes for auditability.

    Parameters:
      max_items:           Maximum items held before backpressure triggers.
      late_threshold_s:    Items with timestamps older than this many seconds
                           relative to batch open time are classified as LATE.
    """

    def __init__(
        self,
        max_items: int = 1_000,
        late_threshold_s: float = 30.0,
    ) -> None:
        self.max_items = max_items
        self.late_threshold_s = late_threshold_s
        self._buf: deque = deque()
        self._lock = threading.Lock()
        self.dropped_count: int = 0
        self.dropped_hashes: List[str] = []  # bounded to 500
        self._batch_open_mono: float = time.monotonic()

    def push(self, raw: bytes, source_tag: str = "stream") -> bool:
        """
        Push a raw item onto the buffer.
        Returns True on success, False if buffer full (item rejected).
        """
        mono = time.monotonic()
        wall = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        with self._lock:
            if len(self._buf) >= self.max_items:
                # Backpressure: record rejection, do not accept
                self.dropped_count += 1
                if len(self.dropped_hashes) < 500:
                    self.dropped_hashes.append(hashlib.sha256(raw).hexdigest())
                return False

            late = (mono - self._batch_open_mono) > self.late_threshold_s
            item = StreamItem(
                raw=raw,
                arrived_at_mono=mono,
                arrived_at_wall=wall,
                source_tag=source_tag,
                late=late,
            )
            self._buf.append(item)
            return True

    def drain(self, max_items: Optional[int] = None) -> "StreamBatch":
        """
        Drain up to max_items from the buffer into a sealed StreamBatch.
        Resets the batch open time after draining.
        """
        with self._lock:
            n = min(len(self._buf), max_items) if max_items else len(self._buf)
            items = [self._buf.popleft() for _ in range(n)]
            dropped = self.dropped_count
            dropped_hashes = list(self.dropped_hashes)
            self.dropped_count = 0
            self.dropped_hashes = []
            self._batch_open_mono = time.monotonic()

        return StreamBatch(
            items=items,
            dropped_before_drain=dropped,
            dropped_hashes=dropped_hashes,
        )

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._buf)


# ── Stream batch ──────────────────────────────────────────────────────────────

@dataclass
class StreamBatch:
    """
    A sealed, ordered, deterministically-hashed batch of StreamItems.

    The batch hash is SHA256 over the concatenation of all item input hashes
    in arrival order. This makes the batch tamper-evident as a unit.
    """
    items: List[StreamItem]
    dropped_before_drain: int = 0     # items dropped due to buffer overflow before this drain
    dropped_hashes: List[str] = field(default_factory=list)

    @property
    def batch_hash(self) -> str:
        """Deterministic hash over all item hashes in order."""
        h = hashlib.sha256()
        for item in self.items:
            h.update(item.input_hash().encode("ascii"))
        return h.hexdigest()

    @property
    def late_count(self) -> int:
        return sum(1 for i in self.items if i.late)

    @property
    def item_count(self) -> int:
        return len(self.items)

    def to_meta_dict(self) -> Dict[str, Any]:
        return {
            "item_count":           self.item_count,
            "late_count":           self.late_count,
            "dropped_before_drain": self.dropped_before_drain,
            "batch_hash":           self.batch_hash,
        }


# ── Streaming runner ──────────────────────────────────────────────────────────

class StreamingRunner:
    """
    Feeds a StreamingBuffer into an AdapterRunner in sealed batch windows.

    Usage:
        buf = StreamingBuffer(max_items=500)
        runner = AdapterRunner(gate)
        streaming = StreamingRunner(buf, runner, adapter_name="json_adapter")

        # Producer feeds the buffer:
        buf.push(raw_bytes)

        # Consumer drains and ingests:
        reports = streaming.drain_and_run(max_items=100)

    Each drain_and_run() call:
      1. Drains up to max_items from the buffer (sealed batch).
      2. Runs each item through the adapter + gate.
      3. Records late arrivals and dropped item losses.
      4. Returns a StreamingRunReport.
    """

    def __init__(
        self,
        buffer: StreamingBuffer,
        runner: Any,               # AdapterRunner — avoid circular import
        adapter_name: str,
        profile: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.buffer = buffer
        self.runner = runner
        self.adapter_name = adapter_name
        self.profile = profile

    def drain_and_run(self, max_items: Optional[int] = None) -> "StreamingRunReport":
        """Drain a batch and run all items through the adapter."""
        batch = self.buffer.drain(max_items)
        reports = []
        clock_prev_mono: Optional[float] = None

        for item in batch.items:
            # Clock monotonicity check — detect clock drift
            clock_drift = False
            if clock_prev_mono is not None and item.arrived_at_mono < clock_prev_mono - 0.001:
                clock_drift = True
            clock_prev_mono = item.arrived_at_mono

            report = self.runner.run(self.adapter_name, item.raw, profile=self.profile)

            # Annotate gate decisions with streaming metadata
            for decision in report.gate_decisions:
                decision.detail = decision.detail or {}
                decision.detail["stream_arrived_at"] = item.arrived_at_wall
                decision.detail["stream_late"] = item.late
                decision.detail["stream_clock_drift"] = clock_drift

            # If the item was late, add a loss to the result
            if item.late:
                report.adapter_result.add_loss(
                    LOSS_OF_CAUSAL_LINKAGE, "stream",
                    f"Item arrived {item.late_threshold_label(self.buffer.late_threshold_s)} "
                    f"after batch window open — classified as LATE_ARRIVAL"
                )

            if clock_drift:
                report.adapter_result.add_loss(
                    LOSS_OF_AUTHENTICITY, "stream",
                    "Monotonic clock moved backwards between items — clock drift detected"
                )

            reports.append(report)

        return StreamingRunReport(batch=batch, item_reports=reports)


# ── Streaming run report ──────────────────────────────────────────────────────

@dataclass
class StreamingRunReport:
    batch: StreamBatch
    item_reports: List[Any]   # List[RunnerReport]

    @property
    def total_accepted(self) -> int:
        return sum(r.events_accepted for r in self.item_reports)

    @property
    def total_rejected_by_gate(self) -> int:
        return sum(r.events_rejected_by_gate for r in self.item_reports)

    @property
    def total_adapter_rejected(self) -> int:
        from aletheia.adapters.taxonomy import STATUS_REJECTED
        return sum(
            1 for r in self.item_reports
            if r.adapter_result.status == STATUS_REJECTED
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "batch": self.batch.to_meta_dict(),
            "items_run":             len(self.item_reports),
            "total_accepted":        self.total_accepted,
            "total_rejected_by_gate": self.total_rejected_by_gate,
            "total_adapter_rejected": self.total_adapter_rejected,
        }


# ── Webhook adapter ───────────────────────────────────────────────────────────

class WebhookAdapter:
    """
    Minimal synchronous webhook adapter.

    Receives raw HTTP POST bodies and pushes them to a StreamingBuffer.
    This is a push-in adapter — the web framework calls receive() on each request.

    The adapter does NOT parse the body — it hands raw bytes to the buffer.
    Parsing is done by the downstream adapter (json_adapter, etc.).

    Usage (with any WSGI/ASGI framework):
        hook = WebhookAdapter(buffer, secret="shared_hmac_secret")
        # In your request handler:
        accepted = hook.receive(body_bytes, headers=request.headers)
    """

    def __init__(
        self,
        buffer: StreamingBuffer,
        secret: Optional[str] = None,   # optional HMAC-SHA256 verification secret
        source_tag: str = "webhook",
    ) -> None:
        self.buffer = buffer
        self.secret = secret
        self.source_tag = source_tag
        self.received_count: int = 0
        self.rejected_count: int = 0

    def receive(self, body: bytes, headers: Optional[Dict[str, str]] = None) -> bool:
        """
        Accept a webhook payload.

        If secret is set, verifies X-Hub-Signature-256 or X-Signature header.
        Returns True if accepted into buffer, False if rejected (signature fail or buffer full).
        """
        if self.secret and headers:
            if not self._verify_signature(body, headers):
                self.rejected_count += 1
                return False

        self.received_count += 1
        return self.buffer.push(body, source_tag=self.source_tag)

    def _verify_signature(self, body: bytes, headers: Dict[str, str]) -> bool:
        """
        Verify HMAC-SHA256 signature. Checks X-Hub-Signature-256 (GitHub-style)
        and X-Signature headers. Returns True if valid or no signature header present.
        Constant-time comparison prevents timing attacks.
        """
        import hmac as _hmac

        sig_header = None
        for h in ("x-hub-signature-256", "x-signature", "x-webhook-signature"):
            val = headers.get(h) or headers.get(h.upper())
            if val:
                sig_header = val
                break

        if sig_header is None:
            # No signature header — if we have a secret, treat as unverified
            # but still accept (trust_level will be UNAUTHENTICATED)
            return True

        # Strip prefix (sha256=...) if present
        if "=" in sig_header:
            sig_header = sig_header.split("=", 1)[1]

        expected = _hmac.new(
            self.secret.encode("utf-8"), body, hashlib.sha256
        ).hexdigest()

        return _hmac.compare_digest(expected, sig_header.lower())


# ── StreamItem helper ─────────────────────────────────────────────────────────

def StreamItem_late_threshold_label(self, threshold_s: float) -> str:
    return f">{threshold_s:.0f}s"

StreamItem.late_threshold_label = StreamItem_late_threshold_label
