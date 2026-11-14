# SOC correlation proof of concept

This proof of concept demonstrates a local investigation flow over synthetic
JSONL events. It creates the demo input in a temporary directory, runs the
workbench, and removes the input when it exits. No real telemetry is included.

From the repository root, run:

```bash
python3 tools/aisoc-advanced/poc/run_demo.py
```

Expected result: one high severity finding for repeated authentication failures
followed by a success, with references to all six synthetic input lines. The
demo then generates and verifies a JSON report, changes its finding count,
and checks that verification rejects the changed report. The final two lines
are `Evidence ledger: VALID` and a successful negative-control message. This
demonstrates the rule path and report rendering; it does not measure detection
accuracy or prove activity in a real environment.

The [terminal output](terminal-output.txt) was captured from this executable
demo. It is a text transcript. A native terminal screenshot could not be
captured by the available desktop interface.
