# Hardness Pack v1 (Phase 5)

This pack proves the system **fails honestly** under cheating and integrity stress.

## Run

```bash
python -m pytest -q
```

## What it covers

### Claims/Veritas integrity
- Silent upgrade blocked (WITNESSED/DERIVED require pins).
- Missing pin targets => INCONCLUSIVE from case.zip only.
- Pins into unsealed windows => INCONCLUSIVE.
- Invalid transition injection => detected as INVALID_TRANSITIONS.
- Unsealed claims window => INCONCLUSIVE.

### Determinism
- Replaying the same sequence produces stable claim state when sealed.

(Other operational packs like ingest reject-flood and disk-full belong to the ingest/siren hardness suite.)
