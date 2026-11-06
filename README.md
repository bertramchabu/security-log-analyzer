# Security Log Analyzer

A dependency-free Python script that parses synthetic, syslog-style SSH
authentication events and writes a Markdown incident report.

## Run

```powershell
python log_analyzer.py samples/auth.log
```

The report is written to `Security_Incident_Report.md` in the current
directory. Pass exactly one log-file path.

## Parsing and detection

- The parser recognizes `Failed password` and `Accepted password` SSH log
  messages, including the optional `invalid user` phrase.
- Timestamps use the month, day, and time in the log; because syslog records do
  not include a year, the current year is used.
- Only failed logins are counted, grouped by source IP. Successful logins are
  parsed but do not contribute to incident counts.
- `THRESHOLD` is **5 failed attempts per IP**. IPs below this threshold are not
  included in the report.
- `RAPID_WINDOW` is **60 seconds**. A sequence is rapid if any two consecutive
  failures for that IP are no more than 60 seconds apart.
- Attempts at or after 22:00, or before 06:00, are marked off-hours.
- An incident is **HIGH** if it has at least 15 failures or a rapid sequence;
  otherwise, an incident meeting the threshold is **MEDIUM**.
- Incidents are sorted by descending failure count, then by source IP.

## Sample report excerpt

| Source IP | Failed Attempts | Rapid Sequence | Off-Hours | Severity |
|---|---:|---|---|---|
| 203.0.113.9 | 6 | Yes | Yes | HIGH |

The single failure from `198.51.100.7` is below threshold and is not reported.

## Data safety

The included `samples/auth.log` contains synthetic documentation-only data.
Use synthetic data only; this project does not collect or access live logs.
