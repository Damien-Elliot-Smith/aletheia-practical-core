# Demo (Deployable v1)

## One command

```bash
python ag.py demo-ot --root ./demo_root --out ./demo_case.zip
```

## What it does
- Creates a small OT-ish evidence stream (syslog-like witness events)
- Seals the evidence window
- Creates a claim and pins it
- Seals claims
- Exports `case.zip`
- Prints follow-up commands to verify and review
