# Threat Model (Deployable v1)

## Scope
This stack is a **single-node, filesystem-backed, tamper-evident evidence ledger + claim layer**.
It is designed to make:
- **tampering**, **omission**, and **post-hoc rewriting** visible, and
- “unknown / unsafe to conclude” explicit via **INCONCLUSIVE**.

It is **not** a secure remote collection system, and it is **not** an intrusion-prevention system.

## Assets (what we protect)
- Integrity of sealed evidence windows (event chain + seal root hash)
- Integrity of claim lifecycle events (append-only; transitions constrained)
- Auditability of exports (`case.zip`) by third parties

## Trust boundaries
- **Adapters / ingest sources are untrusted.** They can be wrong, malicious, noisy, or buggy.
- **Spine is the single authoritative truth trail.** No other module writes evidence.
- **Exported `case.zip` is the audit artifact.** Verification must succeed using only the zip.

## Attacker capabilities assumed
- Can feed malformed or adversarial inputs (reject flood)
- Can attempt to claim “witnessed” status without evidence
- Can copy/modify/delete files in the exported `case.zip`
- Can try to rely on unsealed/open data to smuggle claims
- Can crash/power-cut the host mid-run (dirty shutdown)

## Security properties (what should hold)
- **Sealed-window integrity:** event hashes must verify and match the seal’s root hash.
- **No silent upgrades:** WITNESSED/DERIVED claims require pins.
- **Detectable tampering:** modifying `case.zip` must be detected by external verification.
- **Honest failure:** missing evidence, open windows, dirty shutdowns => **INCONCLUSIVE**, not “best guess”.

## Out of scope / not defended
- A compromised OS/kernel/hardware can always lie at the source.
- Confidentiality: this system is about integrity and auditability, not encryption-at-rest (yet).
- Identity/authentication of remote senders (unless you add it later in adapters).
- Real-time blocking of attacks on OT networks.

## When the system MUST return INCONCLUSIVE
- Claims window is not sealed.
- A claim’s pins cannot be found in the case evidence.
- Pins refer to evidence in unsealed windows.
- Dirty shutdown scars exist and requested reasoning crosses scar boundaries.

## What “PASS” means here
PASS means: **the artifact is self-consistent and verifiable**, not that the underlying world-state is true.
"Truth" about the world still depends on the quality of witness sources.
