#!/usr/bin/env python3
"""Offline, evidence-first correlation for normalized SOC event JSONL.

This companion utility reads local files only. It links events that share an
actor or source IP within a time window, annotates authentication and IP-change
patterns, and applies the evidence-backed rules in detections.py.
It does not assign risk scores, call an LLM, access a network, or execute
response actions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from detections import AUTH_ACTIONS, FAILURES, SUCCESSES, detect, seal_findings, verify_ledger

MAX_EVENTS = 50_000
MAX_LINKS = 100_000
MAX_INPUT_BYTES = 64 * 1024 * 1024


def _timestamp(value: Any, line: int) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"line {line}: timestamp must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"line {line}: invalid ISO-8601 timestamp {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"line {line}: timestamp must include a timezone")
    return parsed


def load_events(path: Path) -> tuple[list[dict[str, Any]], str]:
    """Load JSONL events and return them with the source file SHA-256."""
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError(f"input exceeds the {MAX_INPUT_BYTES // (1024 * 1024)} MiB safety limit")
    with path.open("rb") as stream:
        raw = stream.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("input grew beyond the input byte limit while reading")
    events: list[dict[str, Any]] = []
    for line_no, raw_line in enumerate(raw.splitlines(), 1):
        if not raw_line.strip():
            continue
        try:
            event = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {line_no}: invalid JSON: {exc.msg}") from exc
        if not isinstance(event, dict):
            raise ValueError(f"line {line_no}: each JSONL record must be an object")
        for field in ("id", "actor", "src_ip", "action", "outcome", "command"):
            value = event.get(field)
            if isinstance(value, str):
                try:
                    value.encode("utf-8")
                except UnicodeError as exc:
                    raise ValueError(f"line {line_no}: {field} contains invalid Unicode") from exc
        event_id = event.get("id", f"line-{line_no}")
        if not isinstance(event_id, (str, int)):
            raise ValueError(f"line {line_no}: id must be a string or integer")
        actor = event.get("actor")
        src_ip = event.get("src_ip")
        if actor is not None and not isinstance(actor, str):
            raise ValueError(f"line {line_no}: actor must be a string when provided")
        if src_ip is not None and not isinstance(src_ip, str):
            raise ValueError(f"line {line_no}: src_ip must be a string when provided")
        outcome = event.get("outcome")
        if outcome is not None and not isinstance(outcome, str):
            raise ValueError(f"line {line_no}: outcome must be a string when provided")
        action = event.get("action")
        if action is not None and not isinstance(action, str):
            raise ValueError(f"line {line_no}: action must be a string when provided")
        command = event.get("command")
        if command is not None and not isinstance(command, str):
            raise ValueError(f"line {line_no}: command must be a string when provided")
        bytes_out = event.get("bytes_out")
        if bytes_out is not None and (isinstance(bytes_out, bool) or not isinstance(bytes_out, int) or bytes_out < 0):
            raise ValueError(f"line {line_no}: bytes_out must be a non-negative integer")
        latitude, longitude = event.get("latitude"), event.get("longitude")
        if (latitude is None) != (longitude is None):
            raise ValueError(f"line {line_no}: latitude and longitude must be provided together")
        if latitude is not None:
            if longitude is None:
                raise ValueError(f"line {line_no}: longitude must accompany latitude")
            if any(
                isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value)
                for value in (latitude, longitude)
            ):
                raise ValueError(f"line {line_no}: coordinates must be finite numbers")
            if not -90 <= latitude <= 90 or not -180 <= longitude <= 180:
                raise ValueError(f"line {line_no}: coordinates are outside latitude/longitude bounds")
        events.append(
            {
                "id": str(event_id),
                "line": line_no,
                "timestamp": _timestamp(event.get("timestamp"), line_no),
                "actor": actor.strip() if actor and actor.strip() else None,
                "src_ip": src_ip.strip() if src_ip and src_ip.strip() else None,
                "action": action,
                "action_normalized": action.strip().casefold().replace("_", ".") if action else "",
                "is_authentication": isinstance(action, str) and action.strip().casefold().replace("_", ".") in AUTH_ACTIONS,
                "outcome": outcome.lower().strip() if outcome else None,
                "bytes_out": bytes_out,
                "latitude": float(latitude) if latitude is not None else None,
                "longitude": float(longitude) if longitude is not None else None,
                "command": command,
            }
        )
        if len(events) > MAX_EVENTS:
            raise ValueError(f"input exceeds the {MAX_EVENTS:,}-event safety limit")
    return events, hashlib.sha256(raw).hexdigest()


def correlate(events: list[dict[str, Any]], window: timedelta) -> dict[str, Any]:
    """Return pair links and observable patterns, without inferring intent."""
    ordered = sorted(events, key=lambda event: (event["timestamp"], event["line"]))
    by_key: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in ordered:
        for kind in ("actor", "src_ip"):
            value = event[kind]
            if value:
                by_key[(kind, value.casefold())].append(event)

    links: dict[tuple[int, int], dict[str, Any]] = {}
    for (kind, _), bucket in by_key.items():
        for idx, left in enumerate(bucket):
            for right_index in range(idx + 1, len(bucket)):
                right = bucket[right_index]
                delta = right["timestamp"] - left["timestamp"]
                if delta > window:
                    break
                pair = (left["line"], right["line"])
                link = links.setdefault(
                    pair,
                    {
                        "event_ids": [left["id"], right["id"]],
                        "source_lines": list(pair),
                        "delta_seconds": int(delta.total_seconds()),
                        "shared": [],
                    },
                )
                link["shared"].append({"field": kind, "value": left[kind]})
                if len(links) > MAX_LINKS:
                    raise ValueError(f"correlation exceeds the {MAX_LINKS:,}-link output limit; narrow the time window")

    patterns: list[dict[str, Any]] = []
    actors: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in ordered:
        if event["actor"]:
            actors[event["actor"].casefold()].append(event)

    for actor_events in actors.values():
        failures: deque[dict[str, Any]] = deque()
        ip_history: deque[dict[str, Any]] = deque()
        for current in actor_events:
            while failures and current["timestamp"] - failures[0]["timestamp"] > window:
                failures.popleft()
            while ip_history and current["timestamp"] - ip_history[0]["timestamp"] > window:
                ip_history.popleft()

            if current["is_authentication"] and current["outcome"] in SUCCESSES and failures:
                failure = failures[-1]
                patterns.append(
                    {
                        "type": "failure_then_success",
                        "event_ids": [failure["id"], current["id"]],
                        "source_lines": [failure["line"], current["line"]],
                        "actor": current["actor"],
                        "delta_seconds": int((current["timestamp"] - failure["timestamp"]).total_seconds()),
                        "evidence": "An authentication failure preceded a success for the same actor within the configured window.",
                    }
                )

            current_ip = current["src_ip"]
            if current_ip:
                if ip_history and ip_history[-1]["src_ip"] != current_ip:
                    prior = ip_history[-1]
                    patterns.append(
                        {
                            "type": "actor_multiple_source_ips",
                            "event_ids": [prior["id"], current["id"]],
                            "source_lines": [prior["line"], current["line"]],
                            "actor": current["actor"],
                            "source_ips": [prior["src_ip"], current_ip],
                            "evidence": "The same actor appears with these two source IPs within the configured window.",
                        }
                    )
                    ip_history.append(current)
                elif ip_history:
                    # Compress consecutive observations of the same address
                    # while keeping the latest timestamp inside the window.
                    ip_history[-1] = current
                else:
                    ip_history.append(current)
            if current["is_authentication"] and current["outcome"] in FAILURES:
                failures.append(current)

    return {
        "events_read": len(events),
        "links": sorted(links.values(), key=lambda item: item["source_lines"]),
        "patterns": patterns,
        "disclaimer": (
            "Offline correlation only. Shared identifiers and event sequences are evidence for review, "
            "not a verdict or proof of malicious activity."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Correlate normalized SOC event JSONL locally; no network or response actions.")
    parser.add_argument("input", nargs="?", type=Path, help="JSONL file with normalized security events")
    parser.add_argument("--verify-report", type=Path, help="Verify the evidence hash chain in a previously generated report")
    parser.add_argument("--window-minutes", type=float, default=15.0, help="Maximum time between linked events (default: 15)")
    parser.add_argument("--min-failures", type=int, default=5, help="Failed events required for authentication rules (default: 5)")
    parser.add_argument("--exfil-bytes", type=int, default=100 * 1024 * 1024, help="Outbound byte threshold (default: 104857600)")
    parser.add_argument("--format", choices=("json", "text"), default="json", help="Report format (default: json)")
    parser.add_argument("--output", type=Path, help="Write report to a new file; existing files are never overwritten")
    args = parser.parse_args(argv)
    if args.verify_report:
        try:
            report = json.loads(args.verify_report.read_text(encoding="utf-8"))
            if not isinstance(report, dict):
                valid = False
            else:
                ledger = report.get("evidence_ledger", {})
                entries = ledger.get("entries") if isinstance(ledger, dict) else None
                ledger_findings = (
                    [entry.get("finding") for entry in entries]
                    if isinstance(entries, list) and all(isinstance(entry, dict) for entry in entries)
                    else None
                )
                unsigned_report = {key: value for key, value in report.items() if key != "evidence_ledger"}
                canonical_report = json.dumps(unsigned_report, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                report_digest = hashlib.sha256(canonical_report.encode("utf-8")).hexdigest()
                valid = (
                    isinstance(report.get("source"), dict)
                    and isinstance(ledger, dict)
                    and ledger.get("source_sha256") == report["source"].get("sha256")
                    and ledger.get("report_sha256") == report_digest
                    and report.get("findings") == ledger_findings
                    and verify_ledger(ledger)
                )
        except (OSError, ValueError, RecursionError):
            print("aisoc-advanced: report is unreadable or invalid JSON", file=sys.stderr)
            return 2
        print("Evidence ledger: VALID" if valid else "Evidence ledger: INVALID", file=sys.stdout if valid else sys.stderr)
        return 0 if valid else 1
    if args.input is None:
        parser.error("input is required unless --verify-report is used")
    if not args.input.is_file():
        parser.error(f"input file does not exist: {args.input}")
    if args.format == "text" and args.output and args.output.suffix.lower() == ".json":
        parser.error("--format text cannot write to a .json output path")
    if not 0 < args.window_minutes <= 1440:
        parser.error("--window-minutes must be greater than 0 and at most 1440")
    if not 2 <= args.min_failures <= MAX_EVENTS:
        parser.error("--min-failures must be between 2 and 50000")
    if args.exfil_bytes < 1:
        parser.error("--exfil-bytes must be greater than 0")
    try:
        events, digest = load_events(args.input)
        result = correlate(events, timedelta(minutes=args.window_minutes))
        findings = detect(
            events,
            window=timedelta(minutes=args.window_minutes),
            min_failures=args.min_failures,
            exfil_bytes=args.exfil_bytes,
        )
    except (OSError, ValueError, RecursionError, OverflowError) as exc:
        print(f"aisoc-advanced: {exc}", file=sys.stderr)
        return 2
    result["source"] = {"file": args.input.name, "sha256": digest}
    result["window_minutes"] = args.window_minutes
    result["ruleset"] = "aisoc-advanced-1"
    result["findings"] = findings
    result["timeline"] = [
        {
            "event_id": event["id"],
            "source_line": event["line"],
            "timestamp": event["timestamp"].isoformat(),
            "actor": event["actor"],
            "src_ip": event["src_ip"],
            "action": event["action"],
            "outcome": event["outcome"],
        }
        for event in sorted(events, key=lambda item: (item["timestamp"], item["line"]))
    ]
    result["summary"] = {
        "finding_count": len(findings),
        "by_severity": {
            severity: sum(f["severity"] == severity for f in findings) for severity in ("critical", "high", "medium", "low", "info")
        },
        "mitre_techniques": sorted({tech for finding in findings for tech in finding["mitre_techniques"]}),
    }
    canonical_report = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    report_digest = hashlib.sha256(canonical_report.encode("utf-8")).hexdigest()
    result["evidence_ledger"] = seal_findings(findings, digest, report_digest)
    payload = json.dumps(result, indent=2, ensure_ascii=False) if args.format == "json" else _render_text(result)
    try:
        if args.output:
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(payload + "\n")
        else:
            print(payload)
    except OSError as exc:
        print(f"aisoc-advanced: cannot write report: {exc}", file=sys.stderr)
        return 2
    return 0


def _render_text(report: dict[str, Any]) -> str:
    source = report["source"]
    summary = report["summary"]
    ledger = report["evidence_ledger"]
    lines = [
        "AiSOC Advanced · Offline Investigation",
        f"Events: {report['events_read']} · Findings: {summary['finding_count']} · Window: {report['window_minutes']} min",
        f"Input SHA-256: {source['sha256']}",
        f"Evidence chain: {ledger['entry_count']} entries · {ledger['final_hash']} · signed: no",
        "",
    ]
    for finding in report["findings"]:
        techniques = ", ".join(finding["mitre_techniques"]) or "none"
        lines.extend(
            [
                f"[{finding['severity'].upper()}] {finding['rule_id']} — {finding['title']}",
                f"  Evidence lines: {', '.join(map(str, finding['source_lines']))} | ATT&CK: {techniques}",
                f"  Details: {json.dumps(finding['evidence'], ensure_ascii=False, sort_keys=True)}",
            ]
        )
    if not report["findings"]:
        lines.append("No built-in rule matched. This is not proof that the input is benign.")
    lines.extend(["", report["disclaimer"]])
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
