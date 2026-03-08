Aletheia Practical Core

Aletheia is a deterministic evidence ledger and verification system designed to record events, seal them cryptographically, and produce verifiable case bundles.

It provides a structured way to capture events, validate claims against evidence, and export tamper-evident records that can be independently verified.

The system is designed to run in constrained environments, including mobile environments such as Termux.


---

Current Status

Phase 2 build.

This repository currently contains a tested Phase-2 implementation.

Verified characteristics:

Runs on Python 3.12

Runs on Termux / Android

Portable filesystem layout

Deterministic JSON canonicalization

Cryptographically chained event ledger

Window sealing with root hashes

Case export and verification tooling

HMAC signing support

Adversarial and hostile input testing


Test results:

409 / 409 tests passing
Full regression pack executed on-device.


---

Core Concepts

Spine

The Spine is the core event ledger.

Properties:

append-only event stream

cryptographic hash chain

deterministic JSON encoding

tamper detection

window-based sealing


Each window produces a root hash representing the entire event sequence.


---

Windows

Events are grouped into windows.

A window:

1. opens


2. accepts events


3. seals


4. produces a root hash



Once sealed, a window cannot be modified.


---

Case Export

A sealed ledger can be exported as a case bundle.

Case bundles contain:

event files

window metadata

sealed root hashes

manifest with file hashes

verification report


These bundles can be independently verified.


---

Claim System

Aletheia allows claims to be made about evidence.

Claims:

are stored as events

reference evidence via cryptographic pins

transition through lifecycle states


Typical claim flow:

proposed → witnessed → verified

Claim verification ensures:

referenced evidence exists

transitions are valid

evidence windows are sealed



---

Detective

The Detective module evaluates hypotheses against evidence.

Capabilities include:

structured hypothesis evaluation

coverage gates

deterministic reasoning traces

reproducible outputs


Detective produces structured results containing:

verdict

pins

reasoning metadata



---

Ingest Gate

The ingest gate validates incoming records.

Validation includes:

schema checks

payload depth limits

payload size limits

event type constraints

source constraints

reject logging


Invalid records are rejected and logged.


---

Siren

The Siren state machine monitors system health.

States include:

NORMAL

DEGRADED

SUMMARIES_ONLY

HALT


Triggers include:

disk pressure

verification failures

integrity compromise

reject surges


State transitions emit Mayday events into the ledger.


---

Sentinel

Sentinel evaluates policy rules against proposed actions.

It returns a verdict:

PASS
FAIL
INCONCLUSIVE
UNAVAILABLE

Policies may include:

actor restrictions

target restrictions

risk levels

witness requirements



---

Federation

Federation allows multiple independent nodes to verify the same case.

A federation result aggregates node results into a combined outcome.

Each federation bundle includes:

node case archives

federation manifest

federation hash

federation result



---

OT Adapter

The OT adapter allows operational data streams (for example sensors) to be recorded into the spine.

Capabilities include:

sensor reading ingestion

quality tagging

fault detection

window sealing



---

AI Audit Recorder

The AI audit module records AI interaction events.

Recorded data may include:

request events

response events

latency

model version

constraint decisions

human overrides


This creates a verifiable audit trail of AI behaviour.


---

Security Model

Aletheia is designed around tamper evidence.

Security properties include:

SHA-256 hash chaining

deterministic canonical JSON

sealed windows

independent verification

optional HMAC signing

hostile input protection

ZIP extraction guards


Verification tools detect:

missing events

altered payloads

chain corruption

manifest mismatches

signature failures



---

Example Workflow

Basic flow:

start window
append events
seal window
export case
verify case

Example command usage:

python aletheia_demo.py

Verify a case:

python tools/verify_case.py path/to/case.zip


---

Running Tests

Full regression pack:

export PYTHONPATH=.
python -m unittest discover -s tests409 -p "test_*.py"

Expected result:

409 tests
OK


---

Directory Overview

aletheia/
 spine/
 claims/
 detective/
 ingest/
 siren/
 sentinel/
 federation/
 streaming/
 ai_audit/
 ot/

tools/
 verify_case.py
 release_pack.py

tests/
tests409/


---

Design Goals

Aletheia aims to provide:

deterministic behaviour

verifiable outputs

tamper-evident event recording

portable execution

independent verification

hostile-input resilience



---

Limitations

Current limitations include:

RFC3161 timestamp signing not implemented

distributed federation still experimental

performance tuning ongoing



---

Author

Damien Elliot Smith
