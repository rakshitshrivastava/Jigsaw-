# Installation

This repository includes the full upstream AiSOC platform and the local
correlation workbench. The workbench can run independently of the platform.

## Get the source

```bash
git clone https://github.com/rakshitshrivastava/Jigsaw-
cd Jigsaw-
```

## Local correlation workbench

Requires Python 3.11 or newer. The tool uses the Python standard library;
no packages, credentials, database, Docker, or model download are required.

On macOS or Linux:

```bash
python3 --version
python3 tools/aisoc-advanced/poc/run_demo.py
python3 -m unittest discover -s tools/aisoc-advanced/tests -v
```

On Windows PowerShell, use `py -3` in place of `python3`.

The demo explicitly generates synthetic data in a temporary directory and
deletes the input afterward. Its expected result is one high severity finding
for five failed logins followed by a success. The captured
[terminal transcript](tools/aisoc-advanced/poc/terminal-output.txt) is a real
CLI run over this synthetic scenario, not a production incident or a screenshot.

For your own normalized events:

```bash
python3 tools/aisoc-advanced/aisoc_advanced.py events.jsonl --format text
python3 tools/aisoc-advanced/aisoc_advanced.py events.jsonl --output review.json
python3 tools/aisoc-advanced/aisoc_advanced.py --verify-report review.json
```

Use a new output filename for each report: existing files are refused to protect
input evidence. See the [input schema, thresholds and limits](tools/aisoc-advanced/README.md).
Verification checks internal report consistency; the hash chain is unsigned.

## Full AiSOC platform

Requires a running Docker engine, Docker Compose v2, Bash, Make and Python.
The upstream CORE profile calls for approximately 8 GB RAM and 20 GB free disk
inside the Docker VM. The full profile calls for approximately 12 GB RAM.
Check capacity for image builds and model downloads as well.

From the repository root:

```bash
docker info
docker compose version
make up UP_FLAGS=--build
make doctor
make smoke
```

`UP_FLAGS=--build` makes the CORE startup build the local source. Startup creates
`.env` with generated secrets and prints the administrator password once; store
it privately. Use the console address printed by startup because occupied ports
can change that address. Do not commit `.env`, tokens, credentials, or private logs.

For the optional full profile, follow the upstream deployment guide in
[`docs/architecture`](docs/architecture/README.md) and the repository Makefile.
Stop services with `make down`. Check the Makefile before running clean/reset
targets, which may remove persistent data.

The full platform has not passed runtime verification on the review host:
the Docker daemon is unreachable and the Compose plugin is unavailable.
The offline POC passing is not evidence that vendor integrations or the
container pipeline work. See [the recorded verification scope](VERIFICATION.md).
