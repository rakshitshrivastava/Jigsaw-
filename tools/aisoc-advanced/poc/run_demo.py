#!/usr/bin/env python3
"""Run a clearly labeled synthetic end-to-end SOC correlation demonstration."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    base = datetime(2026, 11, 14, 10, 0, tzinfo=UTC)
    events = [
        {
            "id": f"demo-fail-{index}",
            "timestamp": (base + timedelta(minutes=index)).isoformat().replace("+00:00", "Z"),
            "actor": "alex@example.test",
            "src_ip": "198.51.100.23",
            "action": "login",
            "outcome": "failure",
        }
        for index in range(5)
    ]
    events.append(
        {
            "id": "demo-success",
            "timestamp": (base + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            "actor": "alex@example.test",
            "src_ip": "198.51.100.23",
            "action": "login",
            "outcome": "success",
        }
    )

    with tempfile.TemporaryDirectory(prefix="aisoc-poc-") as directory:
        input_path = Path(directory) / "synthetic-events.jsonl"
        input_path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")
        print("SYNTHETIC DEMO DATA — not production telemetry", flush=True)
        print("Scenario: five failed logins followed by a successful login for one account.\n", flush=True)
        result = subprocess.run(
            [sys.executable, str(ROOT / "aisoc_advanced.py"), str(input_path), "--format", "text"],
            check=False,
        )
        if result.returncode:
            return result.returncode
        report_path = Path(directory) / "report.json"
        generated = subprocess.run(
            [sys.executable, str(ROOT / "aisoc_advanced.py"), str(input_path), "--output", str(report_path)],
            check=False,
        )
        if generated.returncode:
            return generated.returncode
        verified = subprocess.run(
            [sys.executable, str(ROOT / "aisoc_advanced.py"), "--verify-report", str(report_path)],
            check=False,
        )
        if verified.returncode:
            return verified.returncode
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["summary"]["finding_count"] = 999
        report_path.write_text(json.dumps(report), encoding="utf-8")
        tampered = subprocess.run(
            [sys.executable, str(ROOT / "aisoc_advanced.py"), "--verify-report", str(report_path)],
            check=False,
            capture_output=True,
            text=True,
        )
        if tampered.returncode != 1:
            print("FAIL: changed report was not rejected as expected", file=sys.stderr)
            return 1
        print("Negative control: changed report rejected (exit code 1).")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
