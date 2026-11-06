"""
Security Log Analyzer — CodeNova Cybersecurity Internship, Task 4.
Analyzes synthetic auth logs and writes a Markdown incident report.
"""

import re
import sys
from collections import defaultdict
from datetime import datetime


AUTH_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}).*?"
    r"(?P<status>Failed|Accepted) password for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>[\d.]+)"
)
THRESHOLD = 5
RAPID_WINDOW = 60


def parse(path):
    """Parse SSH authentication events from a syslog-style file."""
    events = []
    year = datetime.now().year
    with open(path, encoding="utf-8", errors="replace") as log_file:
        for line in log_file:
            match = AUTH_RE.search(line)
            if not match:
                continue
            timestamp = datetime.strptime(
                f"{year} {match['mon']} {match['day']} {match['time']}",
                "%Y %b %d %H:%M:%S",
            )
            events.append(
                {
                    "ts": timestamp,
                    "status": match["status"],
                    "user": match["user"],
                    "ip": match["ip"],
                }
            )
    return events


def analyze(events):
    """Return one incident per IP meeting the failed-login threshold."""
    failures = defaultdict(list)
    for event in events:
        if event["status"] == "Failed":
            failures[event["ip"]].append(event["ts"])

    incidents = []
    for ip, timestamps in failures.items():
        timestamps.sort()
        rapid = any(
            (timestamps[index + 1] - timestamps[index]).total_seconds()
            <= RAPID_WINDOW
            for index in range(len(timestamps) - 1)
        )
        off_hours = any(timestamp.hour < 6 or timestamp.hour >= 22 for timestamp in timestamps)
        if len(timestamps) >= THRESHOLD:
            severity = (
                "HIGH"
                if len(timestamps) >= THRESHOLD * 3 or rapid
                else "MEDIUM"
            )
            incidents.append(
                {
                    "ip": ip,
                    "count": len(timestamps),
                    "rapid": rapid,
                    "off_hours": off_hours,
                    "severity": severity,
                }
            )

    incidents.sort(key=lambda incident: (-incident["count"], incident["ip"]))
    return incidents


def write_report(incidents, out="Security_Incident_Report.md"):
    """Write incidents to a Markdown report."""
    lines = [
        "# Security Incident Report",
        "",
        f"Generated: {datetime.now().isoformat(timespec='seconds')}",
        "",
        f"Threshold: {THRESHOLD} failed logins per IP",
        "",
        "| Source IP | Failed Attempts | Rapid Sequence | Off-Hours | Severity |",
        "|---|---:|---|---|---|",
    ]
    for incident in incidents:
        lines.append(
            f"| {incident['ip']} | {incident['count']} "
            f"| {'Yes' if incident['rapid'] else 'No'} "
            f"| {'Yes' if incident['off_hours'] else 'No'} "
            f"| {incident['severity']} |"
        )
    if not incidents:
        lines.append("| — | — | — | — | No threshold violations |")
    lines += [
        "",
        "> Routine login errors below threshold are not listed as incidents.",
    ]
    with open(out, "w", encoding="utf-8") as report_file:
        report_file.write("\n".join(lines) + "\n")
    print(f"Report written: {out} ({len(incidents)} incidents)")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(f"Usage: python {sys.argv[0]} <auth-log-path>")
    write_report(analyze(parse(sys.argv[1])))
