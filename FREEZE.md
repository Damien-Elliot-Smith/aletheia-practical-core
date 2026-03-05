# FREEZE SNAPSHOT

- Project: Provenance_Core
- Version: 1.0.0
- Frozen (UTC): 2026-03-02T13:33:13Z

## What this is
A frozen, stable snapshot intended to remain unchanged.

## Integrity
See `SHA256SUMS.txt` for file hashes.

## Run quick checks

```bash
python -m pytest -q
python ag.py demo-ot --root ./demo_root --out ./demo_case.zip
python tools/verify_case.py ./demo_case.zip
```
