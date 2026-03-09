# PROFILE_SPEC.md — Mapping Profile Specification

**Version:** 1.0  
**Phase:** 7

---

## Purpose

Mapping profiles allow adapters to support new external systems via configuration, without rewriting adapter code. A profile is a JSON file that defines how to map fields from an external system's data format to canonical Aletheia event fields.

**Critical constraint:** Profiles may map fields. They cannot invent certainty that the source did not provide.

---

## Profile Location

Profiles live in the `profiles/` directory. The filename convention is: `{profile_id}.json`.

---

## Profile Schema

See `schemas/adapter_profile.schema.json` for the JSON Schema.

Required top-level fields:

| Field | Type | Description |
|---|---|---|
| `profile_id` | string | Stable unique identifier. Never changes. |
| `profile_version` | string | Version of this profile definition. |
| `adapter_name` | string | Which adapter processes this profile. |
| `source_name` | string | Human name of the external system. |
| `trust_level` | string | Default trust level for events from this profile. |
| `event_mappings` | array | One or more event mapping definitions. |
| `retention_mode` | string | How raw input is retained. Default: HASHED. |

---

## Event Mapping

Each entry in `event_mappings` defines how to produce one canonical event type from the source object.

```json
{
  "event_type": "SENSOR_READING",
  "match_field": "type",
  "match_value": "reading",
  "field_mappings": [...],
  "preserve_unknown": false
}
```

- `match_field` + `match_value`: only apply this mapping if the named source field equals this value. If `match_field` is null, the mapping always applies.
- `preserve_unknown`: if true, source fields not covered by field_mappings are preserved under `_unknown`. Unknown fields are always noted as LOSS_OF_STRUCTURE.

---

## Field Mapping

Each entry in `field_mappings`:

```json
{
  "source_field": "sensor.value",
  "target_field": "value",
  "required": true,
  "transform": "float",
  "fallback": null
}
```

| Field | Description |
|---|---|
| `source_field` | Dot-path into the source object. Supports nested access and list indices. |
| `target_field` | Key in the canonical payload. |
| `required` | If true and field is absent with no fallback → REJECTED/INCOMPLETE. |
| `fallback` | Value to use when field is absent. Records LOSS_OF_COMPLETENESS. |
| `transform` | Type coercion: str, int, float, bool, iso_utc. Failure → REJECTED/MALFORMED. |

---

## Profile Rules

1. A profile may not declare a fallback for a required field. Required means the field must be present in the source — fallback would defeat the purpose.
2. A `transform` that fails is always REJECTED/MALFORMED, even if the field is optional.
3. Unknown fields preserved under `_unknown` always generate LOSS_OF_STRUCTURE.
4. Profiles are cached in memory after first load. They are read-only — modifying a loaded profile object has no effect on the cache.
5. Profiles are validated on load — missing required top-level keys raise ValueError immediately.
