# Verification record — 2026-11-14

Scope: the complete AiSOC source snapshot at
`06bc35b6b1939fd3ab976e97f8a60e98c1c0900e`, plus the offline correlation workbench,
POC, tests, and documentation in this repository. This is a code and local CLI
verification record; it is not a certification of the full deployed platform.

## Results

| Check | Result |
| --- | --- |
| Workbench suite on Python 3.11 | 32 tests passed |
| Workbench suite on Python 3.12 | 32 tests passed |
| Workbench suite on Python 3.13 | 32 tests passed |
| POC through the real CLI | Six synthetic events; one expected high severity finding; report verifies; edited report rejected |
| Regression negative control | Saved pre-fix implementation fails 17 assertions/subtests in the 20 initial release tests; corrected implementation passes |
| Ruff 0.16.10, repository lint and formatting | Passed |
| mypy 2.4.1, Python 3.11, isolated baseline environment | Passed baseline comparison: 987 existing findings, no new findings |
| Gitleaks 8.21.2 working-tree scan | No unallowlisted findings |
| Gitleaks detection control | A temporary synthetic token-shaped probe inside the checkout was detected; probe removed afterward |
| Executable detection corpus count | 2,966 executable; 7,408 indexed; generated data agrees |
| Detection-field reachability gate | Passed; two rules still require unavailable derived/stateful context |
| Connector count | 95 registered; generated data agrees |
| Deployment profile counts | CORE 16; full 22; production full 21; definitions agree |
| Claim matrix | 402 entries: 393 gated, 9 partial; gate passed |
| Published-secret safeguards | Gate passed for 15 guarded variables and 35 services |
| Attribution and naming gates | Passed |
| Full container deployment and golden pipeline | Not verified: Docker daemon unreachable and Compose plugin link broken on this host |
| Full backend service test suites and frontend build/UI tests | Not run; this review did not establish the required per-service environments or deployment |
| Live vendor integrations and real-world detection accuracy | Not measured |

The existing type-check baseline is technical debt, not a clean type-check
result. The secret scan uses the repository's existing reviewed ignore list;
no ceiling or ignore entry was raised for this work. The scanner control proves
that a detectable synthetic probe in this checkout is actually inspected.

## Defects reproduced and corrected

- Report output could overwrite the input file, including through a hardlink
  or symlink. Output now uses exclusive file creation and refuses existing files.
- Failed, pending, or missing-outcome MFA and privilege changes could be
  described as completed changes. These sequences now require recognized
  successful outcomes; sensitive access also requires success.
- Substring action matching treated actions such as `secret.read.policy.check`
  as a sensitive read. Matching is now exact after normalization.
- `blocked` and `allowed` authentication outcomes were interpreted differently
  by patterns and detections. Both paths now use the same outcome sets.
- Invalid UTF-8 reports, deeply nested JSON, and lone Unicode surrogates could
  cause tracebacks. They now return controlled input errors.
- Minimum-date timestamps caused rolling-window subtraction to overflow.
  Windows now compare elapsed durations directly.
- Five type errors and POC lint issues were fixed without relaxing checkers.

## What the tests exercise

The CLI is invoked in separate processes using temporary files. Checks include
positive and negative detection scenarios, threshold boundaries, malformed
field types, timestamp validation, out-of-order source lines, a seeded random
correlation corpus compared against an independent pairwise oracle, report
tampering, output aliases, and failed runs leaving no report.

Resource-boundary cases include accepting 50,000 sparse events, rejecting
50,001 events, rejecting input beyond 64 MiB, refusing dense correlation output
beyond 100,000 links, and enforcing the 10,000-finding limit. These are behavior
checks, not production throughput or latency benchmarks.

## Reproduce the checks

```bash
python3 -m unittest discover -s tools/aisoc-advanced/tests -v
python3 tools/aisoc-advanced/poc/run_demo.py
python3 scripts/generate_corpus_stats.py --check
python3 scripts/generate_connector_count.py --check
python3 scripts/check_profile_service_counts.py
python3 scripts/check_claim_gate_matrix.py
python3 scripts/check_published_secrets.py --check
python3 scripts/check_attribution.py --all
python3 scripts/check_competitor_names.py
```

Use Ruff `>=0.16.8,<0.17` for `ruff check services/ scripts/ tests/ tools/`
and `ruff format --check .`. Run `scripts/check_mypy_baseline.py` in an isolated
Python 3.11 environment with only mypy 2.4.1 and its dependencies installed.
Gitleaks is pinned to 8.21.2 by the repository security workflow.

## Remaining review limits

The rules are transparent heuristics, with false-positive and false-negative
rates not measured against representative customer telemetry. The workbench
expects one tenant per input file and consistently normalized actor identifiers.
It cannot establish that a privilege-change actor is also the target account.
Its hash chain is unsigned; someone who can edit a report can recompute its
hashes. Keep source telemetry and trusted hashes independently if authenticity
matters. The workbench does not execute commands found in telemetry.

The original Jigsaw files are retained byte-for-byte under
[`docs/archive/jigsaw-original`](docs/archive/jigsaw-original/README.md).
The old character-shift example is historical material, not secure encryption
or a component of the SOC tool.
