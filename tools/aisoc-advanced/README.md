# AiSOC Advanced Correlation Workbench

A local SOC investigation workbench for normalized security events. It reads
JSON Lines, builds an event timeline, correlates shared actors and source IPs,
and runs a bounded rule set with evidence references. Current rules cover:

- Repeated login failures followed by a successful login.
- Password spraying across distinct actors from one source IP.
- Implausible travel speed between two successful logins with coordinates.
- MFA disabled before a successful login.
- Privilege change followed by sensitive data access.
- Outbound byte volume above a configurable threshold.
- A small set of suspicious command-line patterns.

Findings include rule IDs, rule-defined severity, candidate ATT&CK references,
the exact source event lines, and the measured values behind each finding.
Candidate technique mapping is an analyst lead, not proof of technique use.
Login sequences require a recognized authentication
action (`login`, `logon`, `authentication`, `authenticate`, or the corresponding
`auth.*`, `user.*`, or `user.session.start` form) so unrelated event outcomes
are not described as authentication attempts.

It requires Python 3.11 or newer and runs with the standard library only. It makes no network requests,
does not use an LLM, does not rank risk, and cannot execute response actions.
Every link includes source line numbers and event IDs so an analyst can inspect
the original records.

## Input format

Each line must be a JSON object with a timezone-qualified ISO-8601 timestamp.
The other fields are optional; detections only run when their required evidence
is present. Coordinates must be a latitude/longitude pair, and `bytes_out` must
be a non-negative integer:

```json
{"id":"evt-1","timestamp":"2026-11-14T10:00:00Z","actor":"analyst@example.org","src_ip":"198.51.100.12","action":"login","outcome":"failure"}
{"id":"evt-2","timestamp":"2026-11-14T10:03:00Z","actor":"analyst@example.org","src_ip":"203.0.113.8","action":"login","outcome":"success"}
```

## Run

Start with the [installation guide](../../INSTALLATION.md) or run the explicitly
synthetic [POC](poc/README.md): `python3 tools/aisoc-advanced/poc/run_demo.py`.

```bash
python3 tools/aisoc-advanced/aisoc_advanced.py ./events.jsonl
python3 tools/aisoc-advanced/aisoc_advanced.py ./events.jsonl --format text
python3 tools/aisoc-advanced/aisoc_advanced.py ./events.jsonl --window-minutes 30 --output ./review.json
python3 tools/aisoc-advanced/aisoc_advanced.py --verify-report ./review.json
```

`--output` requires a new filename and never overwrites an existing file,
including the input or aliases to it. MFA and privilege-change sequences require
recognized successful outcomes on the change events; sensitive access also
requires a successful outcome and an exact normalized action match. Missing or
failed outcomes do not establish a completed change or access.

Correlations use the flat `actor` identifier. Normalize it consistently across
sources and use one tenant per input file; the workbench does not provide tenant
isolation or distinguish a change initiator from its target account. VPNs, NAT,
shared accounts, legitimate downloads and administration can trigger review
leads. Validate rules against your own labeled telemetry before operational use.

The JSON report includes the input file's SHA-256 digest, event timeline,
findings, correlation links, a severity summary, and a SHA-256 chain bound to
both the input and report content. `--verify-report` checks the chain and
detects edits to the report. The chain is not a digital signature: it does not
establish who created the report. Shared identifiers and rule matches are
review leads, not proof of malicious activity. The workbench does not emit a
model confidence score or disposition.
For bounded local resource use, input is limited to 64 MiB and 50,000 events;
correlation output is capped at 100,000 event links, window comparisons at one
million, and findings at 10,000. Authentication sequences use the most recent
prior failure, and IP-change patterns report consecutive address transitions
as evidence pairs. The brute-force and password-spray thresholds default to 5;
the outbound transfer threshold defaults to 100 MiB. Tune `--min-failures` and
`--exfil-bytes` to match the
telemetry source and the environment; defaults are simple heuristics, not
calibrated production thresholds.

Run the CLI-path checks with:

```bash
python3 -m unittest discover -s tools/aisoc-advanced/tests -v
```
