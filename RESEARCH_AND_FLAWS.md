# AiSOC repository review

Reviewed 2026-11-14 against the checked-out `main` snapshot. The upstream
project is MIT licensed; its license and copyright notice remain in this clone.
This is a repository-level product review, not a penetration test or a claim
that the listed limitations are exploitable security vulnerabilities.

## Findings

### 1. Most imported detections are not executable in the shipped engine

The repository reports 7,408 indexed detections and 2,966 rules loaded by the
engine. That leaves 4,442 indexed rules outside the executable engine corpus.
The repository is candid that these include rule languages without an
evaluator, but users can still mistake a large imported corpus for active
coverage. Keep these counts beside every corpus-size claim and make the
executable subset easy to filter in the UI. I also found and corrected a stale
7,407 figure in `AGENTS.md`; the checked-in source of truth is
`apps/web/src/data/corpus-stats.json`, and
`python3 scripts/generate_corpus_stats.py --check` reports 7,408 on disk.

### 2. The published local-model result is narrow

The README reports usable triage output on 44 of 50 alerts before constraining
the reply to JSON and 50 of 50 afterward. That is a small, repository-defined
cohort and a format reliability measurement; it does not establish detection
accuracy, analyst acceptance, or performance on a customer's alerts. Keep the
cohort and metric adjacent to the claim, and expand evaluation with labeled,
representative telemetry before using it to justify automated decisions.

### 3. Hosted model behavior is unmeasured

The current README says no hosted provider has been exercised because there is
no funded key. Local model behavior therefore cannot establish how a hosted
provider will behave, what it will cost, or how its data handling will fit an
operator's requirements. Present per-provider results only after a reproducible
measurement, and keep unmeasured providers labeled as such.

### 4. Full deployment has a substantial resource floor

The quick-start requirements call for about 8 GB RAM and 20 GB disk for CORE;
the full profile is described at about 12 GB RAM. This makes realistic
deployment difficult on small endpoints or developer laptops. The existing
offline sandbox helps with exploration, and the new workbench adds multi-event
correlation without Docker, but neither substitutes for exercising the real
pipeline on a supported host.

### 5. The repository reality audit is behind the current release

`docs/audit/REPOSITORY_REALITY.md` identifies itself as an audit from
2026-09-23 against v8.1.0, while this checkout's README identifies the project
as v23.4.0. Its dated scope is clear, but readers can easily treat it as a
current inventory. Refresh it for the current release or move it under an
archive heading and link a current audit from the README.

## Added improvement

`tools/aisoc-advanced/aisoc_advanced.py` and `detections.py` provide local,
multi-event correlation over normalized JSONL input. Built-in analytics cover
password spraying, repeated login failures followed by success, impossible
travel when coordinates are present, MFA disabling before login, privilege
change before sensitive access, large outbound transfers, and command-line
patterns. Reports include an event timeline, source line references, candidate
ATT&CK mappings, and a hash chain bound to the source digest and report body.
The chain is not signed; the tool makes no network calls and has no
response-action path.

## Limits of this review

The project was cloned from its public `main` branch at review time. This review
did not perform a full source audit of every service, deploy the multi-service
stack, exercise vendor integrations, or validate the new workbench against a
customer dataset. It should not be read as a security certification.
