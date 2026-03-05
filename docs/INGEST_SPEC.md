# Strict Ingest Gate v1 (Implemented)

## Key properties
- **Validate-or-reject**: no coercion, no guessing
- **Adapter isolation**: only sanitized fields go to Spine
- **Bounded reject log**: overwrite-on-wrap ring (prevents unbounded disk growth)
- **Reject surge detection**: flags storms; can optionally raise Siren MAYDAY
- **Accept rate limit**: token bucket to prevent overload

## Incoming record schema (strict)
{
  "source": "string (1..64)",
  "event_type": "string (1..64)",
  "payload": { ... dict ... },
  "time_wall": "optional string",
  "meta": { ... optional dict ... }
}

## Stored in Spine on ACCEPT
event_type = incoming.event_type
payload = {
  "source": source,
  "payload": payload,
  "meta": meta?,
  "time_wall": time_wall?
}

## Reject log
Stored under: spine/rejects/
- meta.json (write_index, total_rejects)
- ring.jsonl (fixed line count = max_records)
