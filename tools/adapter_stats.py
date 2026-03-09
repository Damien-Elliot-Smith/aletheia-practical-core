"""
tools/adapter_stats.py — Adapter Observability and Drift Detection (Phase 10)

Usage:
  python tools/adapter_stats.py --help

Reads adapter_selfcheck.jsonl (produced by repeated runner calls) and emits:
  - accepted / rejected / loss counts per adapter
  - rejection type distribution
  - loss type distribution
  - adapter version distribution (drift detection)
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path


def main(argv=None):
    parser = argparse.ArgumentParser(description="Adapter observability stats (Phase 10)")
    parser.add_argument("report_file", help="Path to adapter_stats.jsonl produced by AdapterMonitor")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args(argv)

    p = Path(args.report_file)
    if not p.exists():
        print(f"ERROR: {p} does not exist", file=sys.stderr)
        sys.exit(1)

    records = []
    with p.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if not records:
        print("No records found.")
        sys.exit(0)

    stats = _compute_stats(records)

    if args.json:
        print(json.dumps(stats, indent=2))
    else:
        _print_stats(stats)


def _compute_stats(records):
    total = len(records)
    by_adapter = defaultdict(lambda: {
        "runs": 0, "accepted": 0, "accepted_with_loss": 0,
        "rejected": 0, "unsupported": 0,
        "events_produced": 0, "events_gate_accepted": 0, "events_gate_rejected": 0,
        "losses": defaultdict(int),
        "rejections": defaultdict(int),
        "versions": defaultdict(int),
    })

    for rec in records:
        name = rec.get("adapter_name", "unknown")
        a = by_adapter[name]
        a["runs"] += 1
        a["versions"][rec.get("adapter_version", "unknown")] += 1

        status = rec.get("adapter_status", "UNKNOWN")
        for k in ("accepted", "accepted_with_loss", "rejected", "unsupported"):
            if status.upper() == k.upper():
                a[k] += 1

        a["events_produced"]     += rec.get("events_produced", 0)
        a["events_gate_accepted"] += rec.get("events_accepted", 0)
        a["events_gate_rejected"] += rec.get("events_rejected_by_gate", 0)

        for l in rec.get("loss_distribution", {}).items():
            a["losses"][l[0]] += l[1]
        for r in rec.get("rejection_distribution", {}).items():
            a["rejections"][r[0]] += r[1]

    # Version drift: any adapter with >1 distinct version is a drift candidate
    drift_candidates = []
    for name, a in by_adapter.items():
        if len(a["versions"]) > 1:
            drift_candidates.append({"adapter": name, "versions": dict(a["versions"])})

    return {
        "total_runs": total,
        "adapters": {
            name: {
                k: dict(v) if isinstance(v, defaultdict) else v
                for k, v in a.items()
            }
            for name, a in by_adapter.items()
        },
        "version_drift_detected": drift_candidates,
    }


def _print_stats(stats):
    print(f"\n=== Adapter Stats ({stats['total_runs']} total runs) ===\n")
    for name, a in stats["adapters"].items():
        print(f"  {name}")
        print(f"    Runs:              {a['runs']}")
        print(f"    ACCEPTED:          {a['accepted']}")
        print(f"    ACCEPTED_WITH_LOSS:{a['accepted_with_loss']}")
        print(f"    REJECTED:          {a['rejected']}")
        print(f"    Events produced:   {a['events_produced']}")
        print(f"    Gate accepted:     {a['events_gate_accepted']}")
        print(f"    Gate rejected:     {a['events_gate_rejected']}")
        if a["losses"]:
            print(f"    Loss distribution: {dict(a['losses'])}")
        if a["rejections"]:
            print(f"    Reject distribution: {dict(a['rejections'])}")
        if len(a["versions"]) > 1:
            print(f"    *** VERSION DRIFT: {dict(a['versions'])}")
        print()
    if stats["version_drift_detected"]:
        print("  *** VERSION DRIFT DETECTED:")
        for d in stats["version_drift_detected"]:
            print(f"    {d['adapter']}: {d['versions']}")


class AdapterMonitor:
    """
    Phase 10: Records runner reports to a JSONL file for later analysis.

    Usage:
        monitor = AdapterMonitor("adapter_stats.jsonl")
        report = runner.run("json_adapter", raw)
        monitor.record(report)
    """

    def __init__(self, out_path: str | Path) -> None:
        self.out_path = Path(out_path)
        self.out_path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, report) -> None:
        """Append a RunnerReport to the JSONL stats file."""
        from collections import Counter

        loss_dist = Counter()
        for l in report.adapter_result.losses:
            loss_dist[l.loss_type] += 1

        rej_dist = Counter()
        for r in report.adapter_result.rejections:
            rej_dist[r.rejection_type] += 1

        row = {
            "adapter_name":     report.adapter_result.adapter_name,
            "adapter_version":  report.adapter_result.adapter_version,
            "adapter_status":   report.adapter_result.status,
            "events_produced":  len(report.adapter_result.canonical_events),
            "events_accepted":  report.events_accepted,
            "events_rejected_by_gate": report.events_rejected_by_gate,
            "losses":           len(report.adapter_result.losses),
            "rejections":       len(report.adapter_result.rejections),
            "loss_distribution":    dict(loss_dist),
            "rejection_distribution": dict(rej_dist),
        }
        with self.out_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
