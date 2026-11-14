"""Deterministic, evidence-backed detections for normalized event records."""

from __future__ import annotations

import hashlib
import json
import math
from collections import defaultdict, deque
from collections.abc import Iterator
from datetime import timedelta
from typing import Any

AUTH_ACTIONS = {
    "auth.login",
    "auth.logon",
    "authenticate",
    "authentication",
    "login",
    "logon",
    "user.authentication",
    "user.login",
    "user.session.start",
}
FAILURES = {"failure", "failed", "denied", "blocked"}
SUCCESSES = {"success", "succeeded", "successful", "allowed"}
SENSITIVE_ACTIONS = ("secret.read", "key.export", "data.download", "s3.getobject", "database.export", "sensitive.access")
PRIVILEGE_ACTIONS = {"privilege.change", "role.assign", "admin.grant", "user.privilege.update", "user.role.assign"}
SUSPICIOUS_COMMANDS = (
    ("powershell_encoded", ("-enc ", "-encodedcommand ", "frombase64string"), "T1059.001"),
    ("download_tool", ("curl ", "wget ", "invoke-webrequest"), "T1105"),
    ("shell_pipe", ("| sh", "| bash", "| /bin/sh", "| /bin/bash"), "T1059.004"),
)
MAX_WINDOW_COMPARISONS = 1_000_000


def _is_auth(event: dict[str, Any]) -> bool:
    return bool(event.get("is_authentication"))


def _finding(
    rule_id: str,
    title: str,
    severity: str,
    techniques: list[str],
    events: list[dict[str, Any]],
    evidence: dict[str, Any],
) -> dict[str, Any]:
    ordered = sorted(events, key=lambda event: (event["timestamp"], event["line"]))
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "mitre_techniques": techniques,
        "event_ids": [event["id"] for event in ordered],
        "source_lines": [event["line"] for event in ordered],
        "first_seen": ordered[0]["timestamp"].isoformat(),
        "last_seen": ordered[-1]["timestamp"].isoformat(),
        "evidence": evidence,
    }


def _within(events: list[dict[str, Any]], window: timedelta) -> Iterator[tuple[dict[str, Any], dict[str, Any]]]:
    """Event pairs in time order that are inside a rolling window."""
    comparisons = 0
    for index, left in enumerate(events):
        for right_index in range(index + 1, len(events)):
            right = events[right_index]
            if right["timestamp"] - left["timestamp"] > window:
                break
            comparisons += 1
            if comparisons > MAX_WINDOW_COMPARISONS:
                raise ValueError("windowed detection exceeds the comparison limit; narrow the time window")
            yield left, right


def _haversine_km(a: dict[str, Any], b: dict[str, Any]) -> float:
    earth_km = 6371.0088
    lat1, lat2 = math.radians(a["latitude"]), math.radians(b["latitude"])
    dlat = lat2 - lat1
    dlon = math.radians(b["longitude"] - a["longitude"])
    value = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    value = min(1.0, max(0.0, value))
    return earth_km * 2 * math.atan2(math.sqrt(value), math.sqrt(1 - value))


def detect(
    events: list[dict[str, Any]],
    *,
    window: timedelta,
    min_failures: int = 5,
    exfil_bytes: int = 100 * 1024 * 1024,
    max_findings: int = 10_000,
) -> list[dict[str, Any]]:
    """Apply bounded rules and return findings with the event evidence used."""
    findings: list[dict[str, Any]] = []
    by_actor: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    ordered = sorted(events, key=lambda event: (event["timestamp"], event["line"]))
    for event in ordered:
        if event["actor"]:
            by_actor[event["actor"].casefold()].append(event)
        if event["src_ip"]:
            by_ip[event["src_ip"].casefold()].append(event)

    def add(*args: Any, **kwargs: Any) -> None:
        if len(findings) >= max_findings:
            raise ValueError(f"detection output exceeds the {max_findings:,}-finding safety limit")
        findings.append(_finding(*args, **kwargs))

    # Brute force followed by a successful authentication, grouped per actor.
    for actor_events in by_actor.values():
        failures: deque[dict[str, Any]] = deque()
        for current in actor_events:
            while failures and current["timestamp"] - failures[0]["timestamp"] > window:
                failures.popleft()
            if _is_auth(current) and current["outcome"] in SUCCESSES and len(failures) >= min_failures:
                sample = list(failures)[-min_failures:] + [current]
                add(
                    "AUTH_BRUTE_FORCE_SUCCESS",
                    "Repeated authentication failures followed by success",
                    "high",
                    ["T1110", "T1078"],
                    sample,
                    {"failure_count": len(failures), "actor": current["actor"], "window_seconds": int(window.total_seconds())},
                )
            if _is_auth(current) and current["outcome"] in FAILURES:
                failures.append(current)

    # Password spraying: one source IP fails against several distinct actors.
    for ip, ip_events in by_ip.items():
        failures = deque()
        actors: dict[str, dict[str, Any]] = {}
        actor_counts: dict[str, int] = defaultdict(int)
        last_reported: frozenset[str] = frozenset()
        for current in ip_events:
            while failures and current["timestamp"] - failures[0]["timestamp"] > window:
                expired = failures.popleft()
                if expired["actor"]:
                    key = expired["actor"].casefold()
                    actor_counts[key] -= 1
                    if actor_counts[key] <= 0:
                        actors.pop(key, None)
                        actor_counts.pop(key, None)
            if _is_auth(current) and current["outcome"] in FAILURES and current["actor"]:
                failures.append(current)
                actors[current["actor"].casefold()] = current
                actor_counts[current["actor"].casefold()] += 1
                distinct = frozenset(actors)
                if len(distinct) >= min_failures and distinct != last_reported:
                    sample = sorted(actors.values(), key=lambda event: (event["timestamp"], event["line"]))
                    add(
                        "AUTH_PASSWORD_SPRAY",
                        "Authentication failures span multiple accounts from one source IP",
                        "high",
                        ["T1110.003"],
                        sample,
                        {"distinct_actors": len(distinct), "source_ip": ip, "window_seconds": int(window.total_seconds())},
                    )
                    last_reported = distinct
                elif len(distinct) < min_failures:
                    last_reported = frozenset()

    # Impossible travel requires measured coordinates on two successful logins.
    for actor_events in by_actor.values():
        logins = [
            event
            for event in actor_events
            if _is_auth(event) and event["outcome"] in SUCCESSES and event["latitude"] is not None and event["longitude"] is not None
        ]
        for left, right in _within(logins, window):
            elapsed_hours = (right["timestamp"] - left["timestamp"]).total_seconds() / 3600
            if elapsed_hours <= 0:
                continue
            distance = _haversine_km(left, right)
            speed = distance / elapsed_hours
            if distance >= 100 and speed > 1000:
                add(
                    "AUTH_IMPOSSIBLE_TRAVEL",
                    "Successful logins imply implausible travel speed",
                    "high",
                    ["T1078"],
                    [left, right],
                    {"distance_km": round(distance, 1), "elapsed_seconds": int(elapsed_hours * 3600), "implied_kmh": round(speed, 1)},
                )

    # MFA control changes followed by successful auth; only explicit state/actions qualify.
    mfa_actions = {"mfa.disable", "mfa.disabled", "authentication.mfa.disable"}
    for actor_events in by_actor.values():
        recent_changes: deque[dict[str, Any]] = deque()
        for event in actor_events:
            while recent_changes and event["timestamp"] - recent_changes[0]["timestamp"] > window:
                recent_changes.popleft()
            if _is_auth(event) and event["outcome"] in SUCCESSES and recent_changes:
                change = recent_changes[-1]
                add(
                    "MFA_DISABLED_THEN_LOGIN",
                    "MFA was disabled before a successful login",
                    "high",
                    ["T1556.006", "T1078"],
                    [change, event],
                    {"actor": event["actor"], "mfa_change_action": change["action"]},
                )
            if event["action_normalized"] in mfa_actions and event["outcome"] in SUCCESSES:
                recent_changes.append(event)

    # A privilege or role change followed by a sensitive read/export.
    for actor_events in by_actor.values():
        privilege_changes: deque[dict[str, Any]] = deque()
        for event in actor_events:
            while privilege_changes and event["timestamp"] - privilege_changes[0]["timestamp"] > window:
                privilege_changes.popleft()
            action = event["action_normalized"]
            if action in SENSITIVE_ACTIONS and event["outcome"] in SUCCESSES and privilege_changes:
                change = privilege_changes[-1]
                add(
                    "PRIVILEGE_CHANGE_THEN_SENSITIVE_ACCESS",
                    "Privilege change preceded sensitive data access",
                    "high",
                    ["T1098", "T1078"],
                    [change, event],
                    {"actor": event["actor"], "privilege_action": change["action"], "sensitive_action": event["action"]},
                )
            if action in PRIVILEGE_ACTIONS and event["outcome"] in SUCCESSES:
                privilege_changes.append(event)

    # Single-event detections use explicit telemetry fields and transparent thresholds.
    for event in ordered:
        if event["bytes_out"] is not None and event["bytes_out"] >= exfil_bytes:
            add(
                "LARGE_OUTBOUND_TRANSFER",
                "Outbound transfer exceeded the configured byte threshold",
                "medium",
                [],
                [event],
                {"bytes_out": event["bytes_out"], "threshold_bytes": exfil_bytes},
            )
        command = event["command"].casefold() if event["command"] else ""
        for rule, markers, technique in SUSPICIOUS_COMMANDS:
            matched = next((marker for marker in markers if marker in command), None)
            if matched:
                add(
                    f"SUSPICIOUS_COMMAND_{rule.upper()}",
                    "Command line contains a suspicious execution pattern",
                    "high",
                    [technique],
                    [event],
                    {"matched_marker": matched, "command_field": "command"},
                )

    return sorted(findings, key=lambda finding: (finding["first_seen"], finding["rule_id"], finding["source_lines"]))


def seal_findings(findings: list[dict[str, Any]], source_sha256: str, report_sha256: str) -> dict[str, Any]:
    """Create a reproducible SHA-256 chain over findings and report content (not a signature)."""
    root = f"aisoc-advanced-ledger-v1:{source_sha256}:{report_sha256}"
    previous = hashlib.sha256(root.encode("ascii")).hexdigest()
    entries = []
    for sequence, finding in enumerate(findings, 1):
        canonical = json.dumps(finding, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        digest = hashlib.sha256(f"{previous}:{canonical}".encode()).hexdigest()
        entries.append({"sequence": sequence, "previous_hash": previous, "entry_hash": digest, "finding": finding})
        previous = digest
    return {
        "entries": entries,
        "entry_count": len(entries),
        "final_hash": previous,
        "source_sha256": source_sha256,
        "report_sha256": report_sha256,
        "signed": False,
    }


def verify_ledger(ledger: dict[str, Any]) -> bool:
    """Check the finding chain for edits, reordering, missing or extra entries."""
    entries = ledger.get("entries")
    if not isinstance(entries, list) or ledger.get("entry_count") != len(entries):
        return False
    source_sha256 = ledger.get("source_sha256")
    report_sha256 = ledger.get("report_sha256")
    if not isinstance(source_sha256, str) or not isinstance(report_sha256, str):
        return False
    if any(len(value) != 64 or any(char not in "0123456789abcdef" for char in value) for value in (source_sha256, report_sha256)):
        return False
    try:
        int(source_sha256, 16)
        int(report_sha256, 16)
    except ValueError:
        return False
    root = f"aisoc-advanced-ledger-v1:{source_sha256}:{report_sha256}"
    previous = hashlib.sha256(root.encode("ascii")).hexdigest()
    for sequence, entry in enumerate(entries, 1):
        if not isinstance(entry, dict) or entry.get("sequence") != sequence or entry.get("previous_hash") != previous:
            return False
        finding = entry.get("finding")
        if not isinstance(finding, dict):
            return False
        canonical = json.dumps(finding, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        expected = hashlib.sha256(f"{previous}:{canonical}".encode()).hexdigest()
        if entry.get("entry_hash") != expected:
            return False
        previous = expected
    return ledger.get("final_hash") == previous
