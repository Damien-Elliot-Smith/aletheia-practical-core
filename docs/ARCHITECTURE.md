# Architecture Overview (Practical Core)

[Adapter] → [Strict Validator] → [Spine]
                                   ↘ [Siren]

Detective (Read-only EQI to Spine)

Single node.
Local storage.
Deterministic replay.


## Strict Ingest Gate v1
- Validate-or-reject adapter records
- Bounded reject ring log
- Reject surge detection + optional Siren MAYDAY escalation
- Token-bucket accept rate limiting
