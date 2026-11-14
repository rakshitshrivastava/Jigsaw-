from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "aisoc_advanced.py"
sys.path.insert(0, str(ROOT))

from aisoc_advanced import correlate, load_events  # noqa: E402

from detections import detect, seal_findings, verify_ledger  # noqa: E402


class CorrelationTests(unittest.TestCase):
    def test_failure_success_and_ip_change_are_evidence_linked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "events.jsonl"
            source.write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "id": "e1",
                                "timestamp": "2026-11-14T10:00:00Z",
                                "actor": "alice",
                                "src_ip": "198.51.100.1",
                                "action": "login",
                                "outcome": "failure",
                            }
                        ),
                        json.dumps(
                            {
                                "id": "e2",
                                "timestamp": "2026-11-14T10:03:00Z",
                                "actor": "alice",
                                "src_ip": "203.0.113.2",
                                "action": "login",
                                "outcome": "success",
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            expected_digest = hashlib.sha256(source.read_bytes()).hexdigest()
            events, digest = load_events(source)
            report = correlate(events, timedelta(minutes=15))

        self.assertEqual(digest, expected_digest)
        self.assertEqual(report["events_read"], 2)
        self.assertEqual(report["links"][0]["source_lines"], [1, 2])
        types = {pattern["type"] for pattern in report["patterns"]}
        self.assertEqual(types, {"failure_then_success", "actor_multiple_source_ips"})
        self.assertTrue(all(pattern["source_lines"] == [1, 2] for pattern in report["patterns"]))

    def test_events_outside_window_are_not_correlated(self) -> None:
        events = [
            {
                "id": "a",
                "line": 1,
                "timestamp": _dt("2026-11-14T10:00:00Z"),
                "actor": "alice",
                "src_ip": "198.51.100.1",
                "action": "login",
                "is_authentication": True,
                "outcome": "failure",
            },
            {
                "id": "b",
                "line": 2,
                "timestamp": _dt("2026-11-14T10:30:00Z"),
                "actor": "alice",
                "src_ip": "203.0.113.2",
                "action": "login",
                "is_authentication": True,
                "outcome": "success",
            },
        ]
        report = correlate(events, timedelta(minutes=5))
        self.assertEqual(report["links"], [])
        self.assertEqual(report["patterns"], [])

    def test_naive_timestamp_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "events.jsonl"
            source.write_text('{"timestamp":"2026-11-14T10:00:00","actor":"alice"}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "must include a timezone"):
                load_events(source)

    def test_non_authentication_outcomes_are_not_called_auth_failures(self) -> None:
        events = [
            {
                "id": "a",
                "line": 1,
                "timestamp": _dt("2026-11-14T10:00:00Z"),
                "actor": "alice",
                "src_ip": None,
                "outcome": "failure",
                "is_authentication": False,
            },
            {
                "id": "b",
                "line": 2,
                "timestamp": _dt("2026-11-14T10:01:00Z"),
                "actor": "alice",
                "src_ip": None,
                "outcome": "success",
                "is_authentication": False,
            },
        ]
        report = correlate(events, timedelta(minutes=5))
        self.assertEqual(report["patterns"], [])

    def test_cli_emits_json_and_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "events.jsonl"
            source.write_text('{"id":"one","timestamp":"2026-11-14T10:00:00Z","actor":"alice"}\n', encoding="utf-8")
            expected_digest = hashlib.sha256(source.read_bytes()).hexdigest()
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(source)],
                check=False,
                capture_output=True,
                text=True,
            )
            text_result = subprocess.run(
                [sys.executable, str(SCRIPT), str(source), "--format", "text"],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["events_read"], 1)
        self.assertEqual(payload["source"]["sha256"], expected_digest)
        self.assertIn("not a verdict", payload["disclaimer"])
        self.assertEqual(payload["summary"]["finding_count"], 0)
        self.assertTrue(verify_ledger(payload["evidence_ledger"]))
        self.assertEqual(text_result.returncode, 0, text_result.stderr)
        self.assertIn("Offline Investigation", text_result.stdout)

    def test_detection_rules_and_evidence_chain(self) -> None:
        records = []
        base = "2026-11-14T10:{minute:02d}:00Z"
        records.append(
            {
                "id": "travel-start",
                "timestamp": "2026-11-14T09:55:00Z",
                "actor": "alice",
                "src_ip": "198.51.100.44",
                "action": "login",
                "outcome": "success",
                "latitude": 40.7128,
                "longitude": -74.006,
            }
        )
        for minute in range(5):
            records.append(
                {
                    "id": f"fail-{minute}",
                    "timestamp": base.format(minute=minute),
                    "actor": "alice",
                    "src_ip": "198.51.100.44",
                    "action": "login",
                    "outcome": "failure",
                }
            )
        records.append(
            {
                "id": "login-ok",
                "timestamp": base.format(minute=5),
                "actor": "alice",
                "src_ip": "203.0.113.9",
                "action": "login",
                "outcome": "success",
                "latitude": 51.5074,
                "longitude": -0.1278,
            }
        )
        records.extend(
            [
                {
                    "id": "mfa-off",
                    "timestamp": "2026-11-14T11:00:00Z",
                    "actor": "bob",
                    "action": "mfa.disable",
                    "outcome": "success",
                },
                {
                    "id": "bob-login",
                    "timestamp": "2026-11-14T11:01:00Z",
                    "actor": "bob",
                    "action": "login",
                    "outcome": "success",
                },
                {
                    "id": "transfer",
                    "timestamp": "2026-11-14T12:00:00Z",
                    "actor": "carol",
                    "bytes_out": 200_000_000,
                    "command": "powershell -enc ZABvAC0AbgBvAHQA",
                },
                {
                    "id": "role-change",
                    "timestamp": "2026-11-14T13:00:00Z",
                    "actor": "dave",
                    "action": "role.assign",
                    "outcome": "success",
                },
                {
                    "id": "secret-read",
                    "timestamp": "2026-11-14T13:01:00Z",
                    "actor": "dave",
                    "action": "secret.read",
                    "outcome": "success",
                },
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "events.jsonl"
            source.write_text("\n".join(json.dumps(record) for record in records), encoding="utf-8")
            events, _ = load_events(source)
        findings = detect(events, window=timedelta(minutes=15), min_failures=5)
        rule_ids = {finding["rule_id"] for finding in findings}
        self.assertTrue(
            {
                "AUTH_BRUTE_FORCE_SUCCESS",
                "AUTH_IMPOSSIBLE_TRAVEL",
                "MFA_DISABLED_THEN_LOGIN",
                "LARGE_OUTBOUND_TRANSFER",
                "SUSPICIOUS_COMMAND_POWERSHELL_ENCODED",
                "PRIVILEGE_CHANGE_THEN_SENSITIVE_ACCESS",
            }.issubset(rule_ids)
        )
        self.assertTrue(all(finding["source_lines"] for finding in findings))
        ledger = seal_findings(findings, "a" * 64, "b" * 64)
        self.assertTrue(verify_ledger(ledger))
        ledger["entries"][0]["finding"]["title"] = "tampered"
        self.assertFalse(verify_ledger(ledger))

    def test_password_spray_detects_distinct_accounts(self) -> None:
        records = [
            {
                "id": f"spray-{index}",
                "timestamp": f"2026-11-14T10:0{index}:00Z",
                "actor": f"user-{index}",
                "src_ip": "198.51.100.77",
                "action": "login",
                "outcome": "failure",
            }
            for index in range(5)
        ]
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "events.jsonl"
            source.write_text("\n".join(json.dumps(record) for record in records), encoding="utf-8")
            events, _ = load_events(source)
        findings = detect(events, window=timedelta(minutes=15), min_failures=5)
        spray = [finding for finding in findings if finding["rule_id"] == "AUTH_PASSWORD_SPRAY"]
        self.assertEqual(len(spray), 1)
        self.assertEqual(spray[0]["evidence"]["distinct_actors"], 5)

    def test_equal_timestamps_do_not_create_infinite_travel_speed(self) -> None:
        records = [
            {
                "id": "ny",
                "timestamp": "2026-11-14T10:00:00Z",
                "actor": "alice",
                "action": "login",
                "outcome": "success",
                "latitude": 40.7128,
                "longitude": -74.006,
            },
            {
                "id": "london",
                "timestamp": "2026-11-14T10:00:00Z",
                "actor": "alice",
                "action": "login",
                "outcome": "success",
                "latitude": 51.5074,
                "longitude": -0.1278,
            },
        ]
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "events.jsonl"
            source.write_text("\n".join(json.dumps(record) for record in records), encoding="utf-8")
            events, _ = load_events(source)
        findings = detect(events, window=timedelta(minutes=15))
        self.assertNotIn("AUTH_IMPOSSIBLE_TRAVEL", {finding["rule_id"] for finding in findings})

    def test_verify_report_cli_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "events.jsonl"
            report_path = Path(tmp) / "report.json"
            source.write_text(
                '{"id":"e1","timestamp":"2026-11-14T10:00:00Z","actor":"alice"}\n',
                encoding="utf-8",
            )
            generated = subprocess.run(
                [sys.executable, str(SCRIPT), str(source), "--output", str(report_path)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(generated.returncode, 0, generated.stderr)
            verified = subprocess.run(
                [sys.executable, str(SCRIPT), "--verify-report", str(report_path)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(verified.returncode, 0)
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["findings"].append({"rule_id": "tampered"})
            report_path.write_text(json.dumps(report), encoding="utf-8")
            tampered = subprocess.run(
                [sys.executable, str(SCRIPT), "--verify-report", str(report_path)],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(tampered.returncode, 1)
        self.assertIn("INVALID", tampered.stderr)


def _dt(value: str):
    from datetime import datetime

    return datetime.fromisoformat(value.replace("Z", "+00:00"))


if __name__ == "__main__":
    unittest.main()
