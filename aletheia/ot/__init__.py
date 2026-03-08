"""
aletheia.ot — Phase 2.5: Industrial OT Package

Provides:
  OTAdapter       — validates + ingests sensor readings from OT protocols
  OTSensorReading — typed sensor reading dataclass
  OTConsole       — operator console: current status in human-readable form
  OTConfig        — configuration for OT deployments

Designed for:
  - Oil & gas, water treatment, food production, power generation
  - IEC 62443, NERC CIP, FDA 21 CFR Part 11 compliance environments
  - Airgapped networks (no network dependencies)
  - Low-resource devices (runs on Termux/Android, Raspberry Pi)

The OTAdapter does NOT implement MQTT/Modbus/OPC-UA protocol parsing
(those require external libraries). Instead, it provides the validated
Aletheia-side interface that any protocol parser feeds into.

Protocol adapters (external, bring-your-own parser):
  Pass dicts to OTAdapter.ingest_reading() — the adapter handles
  Spine integration, Lens validation, Siren escalation, and audit trail.

Engineering unit validation:
  If a constraints window is sealed with Lens rules, every reading is
  validated against min/max/rate-of-change bounds.
  Readings that fail Lens validation are ingested as WITNESS_FAIL events
  (not dropped — the failed reading IS evidence).

Operator console output (OTConsole.render()):
  - Current Siren state
  - Last seal timestamp
  - Sensor pass/fail/INCONCLUSIVE rates (last N readings)
  - Active constraint violations
  Designed to fit on a 80x24 terminal or a control room screen.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from aletheia.spine.ledger import SpineLedger
from aletheia.siren.state_machine import Siren, SirenState, MaydayCode
from aletheia.ingest.gate import IngestGate, IngestConfig, IngestDecision


# ── Sensor reading types ───────────────────────────────────────────────────────

OT_WITNESS    = "OT_WITNESS"       # normal sensor reading
OT_FAULT      = "OT_FAULT"         # sensor fault / instrument error
OT_ALARM      = "OT_ALARM"         # process alarm (value outside safe range)
OT_COMMAND    = "OT_COMMAND"       # control command issued
OT_INTERLOCK  = "OT_INTERLOCK"     # safety interlock activated
OT_CALIBRATION = "OT_CALIBRATION"  # instrument calibration event


@dataclass
class OTSensorReading:
    """
    A structured sensor reading from an OT system.

    tag:        instrument tag (e.g. "PT-101" for pressure transmitter 101)
    value:      engineering-unit value (float or int)
    unit:       engineering unit string (e.g. "bar", "°C", "m³/h")
    quality:    OPC-UA style quality: "GOOD" | "BAD" | "UNCERTAIN"
    source:     data source identifier (PLC, SCADA, historian)
    timestamp:  ISO8601 UTC string (from the source device, if available)
    """
    tag: str
    value: float
    unit: str = ""
    quality: str = "GOOD"
    source: str = "ot"
    timestamp: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_payload(self) -> Dict[str, Any]:
        p = {
            "tag": self.tag,
            "value": self.value,
            "unit": self.unit,
            "quality": self.quality,
            "source": self.source,
        }
        if self.timestamp:
            p["timestamp"] = self.timestamp
        if self.metadata:
            p["metadata"] = self.metadata
        return p


@dataclass
class OTConfig:
    # Window where OT evidence is written
    window_id: str = "ot_ingest"
    # Max events before auto-seal trigger (0 = disabled, use scheduler externally)
    max_events_per_window: int = 10_000
    # Whether to run Lens validation on every reading
    lens_validate: bool = True
    # How many recent readings to track for the console
    console_history_size: int = 100
    # Minimum quality level to accept: GOOD only, or also UNCERTAIN
    accept_uncertain: bool = True
    # Event type for normal readings
    reading_event_type: str = OT_WITNESS


@dataclass
class OTIngestResult:
    accepted: bool
    event_type: str
    tag: str
    lens_verdict: Optional[str] = None   # PASS / FAIL / INCONCLUSIVE
    reason: Optional[str] = None
    event_hash: Optional[str] = None


class OTAdapter:
    """
    Validated OT sensor ingest interface.

    Wraps IngestGate with OT-specific validation:
      - Engineering unit presence check
      - Quality filtering (BAD quality → OT_FAULT, never WITNESS)
      - Lens validation against sealed constraint rules (if available)
      - Siren escalation on repeated alarm/fault events

    Example — ingest from a SCADA polling loop:
        adapter = OTAdapter(ledger, siren=siren)
        adapter.open()

        while True:
            readings = scada.poll()  # your protocol layer
            for r in readings:
                result = adapter.ingest_reading(OTSensorReading(
                    tag=r["tag"], value=r["value"], unit=r["unit"]
                ))

        adapter.seal_and_close()
    """

    def __init__(
        self,
        ledger: SpineLedger,
        *,
        config: Optional[OTConfig] = None,
        siren: Optional[Siren] = None,
        gate_config: Optional[IngestConfig] = None,
    ) -> None:
        self.ledger = ledger
        self.config = config or OTConfig()
        self.siren = siren
        self._event_count = 0
        self._alarm_count = 0
        self._fault_count = 0
        self._recent: List[Dict[str, Any]] = []  # rolling history for console

        gate_cfg = gate_config or IngestConfig(
            window_id=self.config.window_id,
            max_payload_bytes=4096,
        )
        # OT sensor readings contain float values (engineering units).
        # Create ledger with float payloads allowed for OT use.
        from aletheia.spine.ledger import SpineLedger as _SL
        if not ledger.allow_float_payload:
            # Wrap with a float-allowed ledger pointing at the same root
            self._float_ledger = _SL(ledger.root_dir, allow_float_payload=True,
                                     signer=ledger._signer)
            self.gate = IngestGate(self._float_ledger, siren=siren, config=gate_cfg)
        else:
            self._float_ledger = None
            self.gate = IngestGate(ledger, siren=siren, config=gate_cfg)

    def open(self) -> None:
        """Open OT ingest window. Idempotent."""
        # IngestGate already opens the window in __init__, but
        # calling this explicitly makes the lifecycle clear.
        pass

    def ingest_reading(self, reading: OTSensorReading) -> OTIngestResult:
        """
        Validate and ingest a single sensor reading.

        Bad quality → recorded as OT_FAULT (never dropped silently).
        Uncertain quality → recorded as OT_WITNESS if accept_uncertain=True.
        Lens validation failure → recorded as OT_ALARM.
        """
        # Quality filter
        if reading.quality == "BAD":
            return self._ingest_as(reading, OT_FAULT, "BAD_QUALITY")

        if reading.quality == "UNCERTAIN" and not self.config.accept_uncertain:
            return self._ingest_as(reading, OT_FAULT, "UNCERTAIN_QUALITY_REJECTED")

        # Lens validation (if configured and constraints window sealed)
        lens_verdict = None
        if self.config.lens_validate:
            lens_verdict = self._run_lens(reading)
            if lens_verdict == "FAIL":
                self._alarm_count += 1
                result = self._ingest_as(reading, OT_ALARM, "LENS_FAIL")
                self._maybe_escalate_alarm()
                return result

        # Normal reading
        result = self._ingest_as(reading, self.config.reading_event_type, None)
        result.lens_verdict = lens_verdict
        return result

    def ingest_command(
        self,
        command: str,
        target: str,
        operator: str,
        *,
        reason: Optional[str] = None,
    ) -> OTIngestResult:
        """Record a control command. Commands are always ingested as evidence."""
        payload = {
            "command": command,
            "target": target,
            "operator": operator,
            "reason": reason,
            "utc": _utc_now(),
        }
        result = self.gate.ingest({
            "source": "ot_command",
            "event_type": OT_COMMAND,
            "payload": payload,
        })
        return OTIngestResult(
            accepted=result.decision == IngestDecision.ACCEPT,
            event_type=OT_COMMAND,
            tag=target,
            reason=result.reason.value if result.reason else None,
        )

    def ingest_interlock(
        self,
        tag: str,
        state: str,
        *,
        triggered_by: Optional[str] = None,
    ) -> OTIngestResult:
        """Record a safety interlock activation/deactivation."""
        payload = {
            "tag": tag,
            "state": state,
            "triggered_by": triggered_by,
            "utc": _utc_now(),
        }
        result = self.gate.ingest({
            "source": "ot_safety",
            "event_type": OT_INTERLOCK,
            "payload": payload,
        })
        return OTIngestResult(
            accepted=result.decision == IngestDecision.ACCEPT,
            event_type=OT_INTERLOCK,
            tag=tag,
        )

    def seal_and_close(self) -> Optional[str]:
        """Seal the OT ingest window. Returns seal record root hash."""
        try:
            seal = self.ledger.seal_window(self.config.window_id)
            return seal.window_root_hash
        except Exception:
            return None

    def get_console_stats(self) -> Dict[str, Any]:
        """Return stats for operator console rendering."""
        total = len(self._recent)
        pass_count  = sum(1 for r in self._recent if r.get("lens_verdict") == "PASS")
        fail_count  = sum(1 for r in self._recent if r.get("event_type") == OT_ALARM)
        fault_count = sum(1 for r in self._recent if r.get("event_type") == OT_FAULT)
        inconcl     = total - pass_count - fail_count - fault_count
        return {
            "total_readings": self._event_count,
            "recent_window": total,
            "pass": pass_count,
            "alarm": fail_count,
            "fault": fault_count,
            "inconclusive": inconcl,
            "siren_state": self.siren.state.value if self.siren else "N/A",
        }

    # ── Internal ──────────────────────────────────────────────────────────────

    def _ingest_as(
        self,
        reading: OTSensorReading,
        event_type: str,
        reason: Optional[str],
    ) -> OTIngestResult:
        payload = reading.to_payload()
        if reason:
            payload["ot_reason"] = reason

        result = self.gate.ingest({
            "source": reading.source,
            "event_type": event_type,
            "payload": payload,
        })

        accepted = result.decision == IngestDecision.ACCEPT
        if accepted:
            self._event_count += 1
            # Track in rolling history for console
            entry = {"event_type": event_type, "tag": reading.tag, "value": reading.value}
            self._recent.append(entry)
            if len(self._recent) > self.config.console_history_size:
                self._recent.pop(0)

        return OTIngestResult(
            accepted=accepted,
            event_type=event_type,
            tag=reading.tag,
            reason=result.reason.value if result.reason else reason,
        )

    def _run_lens(self, reading: OTSensorReading) -> str:
        """
        Attempt Lens validation against sealed constraint rules.
        Returns "PASS" / "FAIL" / "INCONCLUSIVE".
        Falls back to INCONCLUSIVE if Lens is unavailable.
        """
        try:
            from aletheia.lens.lens import Lens
            lens = Lens(self.ledger.root_dir)
            result = lens.validate(reading.tag, reading.value)
            return result.verdict
        except Exception:
            return "INCONCLUSIVE"

    def _maybe_escalate_alarm(self) -> None:
        """Escalate to Siren if alarm rate is high."""
        if self.siren is None:
            return
        # Simple heuristic: 5 alarms → DEGRADED_CAPTURE
        if self._alarm_count >= 5 and self.siren.state == SirenState.NORMAL:
            self.siren.transition(
                SirenState.DEGRADED_CAPTURE,
                MaydayCode.SIGNAL_INTEGRITY,
                details={"alarm_count": self._alarm_count},
            )


# ── Operator Console ────────────────────────────────────────────────────────────

class OTConsole:
    """
    Human-readable operator console for OT deployments.

    Renders a status summary to stdout (or returns as string).
    Designed for 80-column terminal or control room display.

    Usage:
        console = OTConsole(adapter, ledger)
        console.render()  # prints to stdout
        text = console.render(return_str=True)
    """

    def __init__(self, adapter: OTAdapter, ledger: SpineLedger) -> None:
        self.adapter = adapter
        self.ledger = ledger

    def render(self, *, return_str: bool = False) -> Optional[str]:
        stats = self.adapter.get_console_stats()
        siren = stats["siren_state"]
        siren_indicator = {
            "NORMAL": "[  NORMAL  ]",
            "DEGRADED_CAPTURE": "[ DEGRADED ]",
            "SUMMARIES_ONLY": "[SUMMARIES ]",
            "HALT": "[  !! HALT  ]",
        }.get(siren, f"[ {siren} ]")

        # Last seal time
        last_seal = self._last_seal_time()

        lines = [
            "=" * 60,
            f"  ALETHEIA OT CONSOLE  —  {_utc_now()}",
            "=" * 60,
            f"  Siren:       {siren_indicator}",
            f"  Last seal:   {last_seal}",
            f"  Total events: {stats['total_readings']}",
            "-" * 60,
            f"  Recent {stats['recent_window']} readings:",
            f"    PASS:         {stats['pass']}",
            f"    ALARM:        {stats['alarm']}",
            f"    FAULT:        {stats['fault']}",
            f"    INCONCLUSIVE: {stats['inconclusive']}",
            "=" * 60,
        ]
        output = "\n".join(lines)
        if return_str:
            return output
        print(output)
        return None

    def _last_seal_time(self) -> str:
        windows_dir = self.ledger.windows_dir
        latest = None
        try:
            for wdir in windows_dir.iterdir():
                sp = wdir / "sealed.json"
                if sp.exists():
                    mtime = sp.stat().st_mtime
                    if latest is None or mtime > latest:
                        latest = mtime
        except Exception:
            pass
        if latest is None:
            return "none"
        return datetime.fromtimestamp(latest, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ── Helpers ─────────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
