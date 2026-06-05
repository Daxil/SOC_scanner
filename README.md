# SOC_util

A lightweight SOC utility that scans Linux `auth.log` files for brute-force
attacks, credential compromise, and reconnaissance activity. It parses raw
syslog records into normalized events, runs time-window detection heuristics,
and produces either a human-readable report or JSON for downstream tooling.

![python](https://img.shields.io/badge/python-3.10%2B-blue)
![dependencies](https://img.shields.io/badge/dependencies-stdlib%20only-green)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

## Features

- **Brute-force detection** — flags source IPs that exceed a configurable
  failure threshold inside a sliding time window, with severity scaled to volume.
- **Compromise detection** — raises a critical alert when a successful login
  follows a burst of failures from the same IP (likely credential stuffing).
- **DDoS / flood detection** — flags a surge of connection attempts inside the
  window and reports whether it is concentrated or distributed across many IPs
  (botnet-style attacks).
- **Statistics** — top 10 source IPs by connection requests, top IPs by failed
  attempts, most-targeted accounts, and per-type counts.
- **Broad parsing** — failed/accepted passwords, invalid users, sudo commands,
  pre-auth disconnects, and "too many authentication failures" events.
- **Flexible input** — multiple files, gzip-compressed logs, or stdin.
- **Two output modes** — aligned console report or machine-readable JSON.
- **No dependencies** — pure Python standard library, Python 3.10+.

## How it works

```
log files / stdin  ->  parser  ->  AuthEvent stream  ->  detectors  ->  reporter
   (.log, .gz)         regex        (normalized)       brute force /     console
                                                        compromise /      or JSON
                                                        statistics
```

## Installation

```bash
git clone https://github.com/<your-username>/SOC_util.git
cd SOC_util
```

No installation step is required. Python 3.10 or newer is the only prerequisite.

## Usage

```bash
python soc_scan.py sample_logs/auth.log
python soc_scan.py /var/log/auth.log /var/log/auth.log.1.gz
python soc_scan.py sample_logs/auth.log --json
python soc_scan.py sample_logs/ddos.log
cat /var/log/auth.log | python soc_scan.py -
```

Options:

| Flag | Default | Description |
| --- | --- | --- |
| `--threshold N` | 5 | Failed attempts from one IP to flag as brute force |
| `--window SECONDS` | 60 | Detection time window |
| `--ddos-rate N` | 40 | Connection events in the window to flag a flood |
| `--ddos-ips N` | 15 | Distinct source IPs in the window to flag it as distributed |
| `--json` | off | Emit JSON instead of the console report |
| `--year YEAR` | current | Year assumed for syslog timestamps (which omit it) |

The process exits with code `1` when any HIGH or CRITICAL alert is raised, so it
can gate a pipeline or cron job; otherwise it exits `0`.

### Example output

```
SOC AUTH LOG SCAN REPORT

Summary
  Events parsed: 20
  Time range:    2026-01-15T09:58:12 -> 2026-01-15T11:18:44
  ...

Alerts (2)
  [CRITICAL] compromise - 203.0.113.50
      Successful login for 'root' after 10 recent failures
      window: 2026-01-15 10:22:41 -> 2026-01-15 10:23:01
      accounts: root
  [HIGH] brute_force - 203.0.113.50
      10 failed authentication attempts within 60s
      window: 2026-01-15 10:22:41 -> 2026-01-15 10:22:58
      accounts: admin, oracle, postgres, root
```

## Detection logic

- **Brute force**: events are grouped per source IP and sorted by time. A
  two-pointer sweep finds the densest `--window`-second interval; if it contains
  at least `--threshold` failures the IP is flagged. Severity is MEDIUM at the
  threshold, HIGH at 2x, and CRITICAL at 4x.
- **Compromise**: for every accepted login, the scanner counts failures from the
  same IP within the preceding window. Meeting the threshold marks the session as
  a likely successful brute force and emits a CRITICAL alert.
- **DDoS / flood**: a sliding window tracks total connection events and the number
  of distinct source IPs at once. When the busiest window exceeds `--ddos-rate`
  events or `--ddos-ips` distinct addresses, an alert is raised; severity scales
  with how far the peak exceeds the thresholds, and the description states whether
  the traffic is concentrated or distributed.

## Project structure

```
SOC_util/
├── soc_scan.py          CLI entry point
├── socscan/
│   ├── models.py        AuthEvent, Alert, EventType, Severity
│   ├── parser.py        line parsing and file/stdin/gzip reading
│   ├── detectors.py     brute-force, compromise, DDoS, statistics
│   └── reporter.py      console and JSON rendering
└── sample_logs/
    ├── auth.log         demo data with a brute-force-then-compromise scenario
    └── ddos.log         demo data with a distributed connection flood
```

## Roadmap

- Optional GeoIP/ASN enrichment for source IPs.
- Support for additional log formats (journald JSON, web server logs).
- Allowlist for known automation hosts to reduce noise.

## License

Released under the MIT License.
