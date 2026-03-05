# Operator Runbook (Deployable v1)

This runbook uses only the shipped CLI and scripts.

## 0) Create a root

```bash
python ag.py init --root ./root
```

## 1) Ingest evidence (example)

```bash
python ag.py ingest --root ./root --window main --event-type WITNESS --payload '{"tag":"pump","temp_c":83.2,"vibration":0.31}'
python ag.py ingest --root ./root --window main --event-type WITNESS --payload '{"tag":"pump","temp_c":92.7,"vibration":0.49}'
```

## 2) Seal evidence window

```bash
python ag.py seal --root ./root --window main
```

## 3) Make a claim (Veritas)

```bash
python veritas.py --root ./root
```

Inside Veritas:

```text
propose c1 EMPIRICAL "Pump overheating event"
# link pins after you know them (typically from witness bundles / exports)
seal
exit
```

## 4) Export a case

```bash
python ag.py export --root ./root --out ./case.zip
```

This writes:
- `case_manifest.json`
- `evidence/verify_report.json`
- sealed windows + referenced bundles

## 5) External verification (zero-install)

```bash
python tools/verify_case.py ./case.zip
```

Expect:
- `verdict: PASS` if the case is intact
- `FAIL` if tampered

## 6) ClaimCheck (case.zip only)

```bash
python ag.py claimcheck --case ./case.zip --all
```

## 7) Detective claim review (case.zip only)

```bash
python ag.py detective-claims --case ./case.zip --all
```

## Decision rules

- If **verify_case FAIL**: do not use the case.
- If **claimcheck INCONCLUSIVE**: do not conclude; seal missing windows or re-export with required evidence.
- If **detective-claims INCONCLUSIVE**: treat as “evidence needed”, not “model uncertainty”.
