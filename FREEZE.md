# FREEZE SNAPSHOT

- Project: Provenance_Core
- Version: 1.0.0
- Frozen (UTC): 2026-03-02T13:33:13Z

## What this is
A frozen, stable snapshot intended to remain unchanged.

## Integrity
See `SHA256SUMS.txt` for hashes of every tracked file (`sha256sum -c SHA256SUMS.txt`).
It is regenerated from the current tree with `python tools/gen_sha256sums.py`, and a test fails if it is stale.

## Run quick checks

```bash
python -m pytest -q
python ag.py demo-ot --root ./demo_root --out ./demo_case.zip
python tools/verify_case.py ./demo_case.zip
```
