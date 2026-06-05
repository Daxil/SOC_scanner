from __future__ import annotations

import re
from collections import Counter, defaultdict

from .detectors import _peak_window
from .models import Alert, Severity, WebEvent

INJECTION_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    ("sqli", re.compile(r"union\s+select", re.IGNORECASE)),
    ("sqli", re.compile(r"\bor\s+1\s*=\s*1", re.IGNORECASE)),
    ("sqli", re.compile(r"information_schema", re.IGNORECASE)),
    ("sqli", re.compile(r"\b(sleep|benchmark|concat|extractvalue|updatexml)\s*\(", re.IGNORECASE)),
    ("sqli", re.compile(r"(--|#|/\*)\s*$|;\s*--", re.IGNORECASE)),
    ("xss", re.compile(r"<\s*script", re.IGNORECASE)),
    ("xss", re.compile(r"on(error|load|mouseover)\s*=", re.IGNORECASE)),
    ("xss", re.compile(r"javascript:", re.IGNORECASE)),
    ("xss", re.compile(r"<\s*img[^>]*src", re.IGNORECASE)),
    ("xss", re.compile(r"\balert\s*\(", re.IGNORECASE)),
    ("cmdi", re.compile(r";\s*(cat|ls|wget|curl|nc|bash|sh|id|whoami)\b", re.IGNORECASE)),
    ("cmdi", re.compile(r"\$\(|`", re.IGNORECASE)),
    ("cmdi", re.compile(r"\|\s*(sh|bash|nc|python)\b", re.IGNORECASE)),
]

TRAVERSAL_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    ("traversal", re.compile(r"\.\./|\.\.\\")),
    ("traversal", re.compile(r"/etc/passwd|/etc/shadow", re.IGNORECASE)),
    ("traversal", re.compile(r"/proc/self", re.IGNORECASE)),
    ("traversal", re.compile(r"\b(php|file|data|expect)://", re.IGNORECASE)),
    ("sensitive", re.compile(r"/\.(env|git|aws|ssh|htpasswd)\b", re.IGNORECASE)),
    ("sensitive", re.compile(r"/(wp-login|wp-admin|xmlrpc\.php)", re.IGNORECASE)),
    ("sensitive", re.compile(r"/(admin|phpmyadmin|administrator|manager)\b", re.IGNORECASE)),
    ("sensitive", re.compile(r"\.(sql|bak|old|backup|swp|tar\.gz|zip)\b", re.IGNORECASE)),
    ("sensitive", re.compile(r"/(config|backup|dump)\b", re.IGNORECASE)),
]

SCANNER_AGENTS: list[re.Pattern[str]] = [
    re.compile(r"sqlmap", re.IGNORECASE),
    re.compile(r"nikto", re.IGNORECASE),
    re.compile(r"nmap", re.IGNORECASE),
    re.compile(r"dirb|dirbuster", re.IGNORECASE),
    re.compile(r"gobuster|feroxbuster|ffuf", re.IGNORECASE),
    re.compile(r"wpscan", re.IGNORECASE),
    re.compile(r"masscan|zgrab", re.IGNORECASE),
    re.compile(r"acunetix|nessus|nuclei|wfuzz", re.IGNORECASE),
    re.compile(r"python-requests|go-http-client|libwww-perl|curl/", re.IGNORECASE),
]


def _scale(count: int, base: Severity) -> Severity:
    if count >= 20:
        return Severity.CRITICAL
    if count >= 8:
        return Severity.HIGH if base < Severity.HIGH else Severity.CRITICAL
    return base


def _signature_alert(
    events: list[WebEvent],
    signatures: list[tuple[str, re.Pattern[str]]],
    category: str,
    base: Severity,
) -> list[Alert]:
    by_ip: dict[str, list[tuple[WebEvent, str]]] = defaultdict(list)
    for event in events:
        for kind, pattern in signatures:
            if pattern.search(event.target):
                by_ip[event.source_ip].append((event, kind))
                break

    alerts: list[Alert] = []
    for ip, hits in by_ip.items():
        kinds = sorted({kind for _, kind in hits})
        ordered = sorted(hits, key=lambda item: item[0].timestamp)
        evidence = [f"{e.method} {e.target} -> {e.status}" for e, _ in ordered[:5]]
        alerts.append(
            Alert(
                severity=_scale(len(hits), base),
                category=category,
                source_ip=ip,
                description=(
                    f"{len(hits)} suspicious requests ({', '.join(kinds)})"
                ),
                count=len(hits),
                first_seen=ordered[0][0].timestamp,
                last_seen=ordered[-1][0].timestamp,
                evidence=evidence,
            )
        )
    alerts.sort(key=lambda alert: (alert.severity, alert.count), reverse=True)
    return alerts


def detect_injections(events: list[WebEvent]) -> list[Alert]:
    return _signature_alert(events, INJECTION_SIGNATURES, "web_injection", Severity.HIGH)


def detect_traversal_and_sensitive(events: list[WebEvent]) -> list[Alert]:
    return _signature_alert(
        events, TRAVERSAL_SIGNATURES, "web_path_abuse", Severity.MEDIUM
    )


def detect_scanners(events: list[WebEvent]) -> list[Alert]:
    by_ip: dict[str, list[WebEvent]] = defaultdict(list)
    for event in events:
        ua = event.user_agent.strip()
        flagged = not ua or ua == "-" or any(p.search(ua) for p in SCANNER_AGENTS)
        if flagged:
            by_ip[event.source_ip].append(event)

    alerts: list[Alert] = []
    for ip, hits in by_ip.items():
        hits.sort(key=lambda event: event.timestamp)
        agents = sorted({h.user_agent.strip() or "<empty>" for h in hits})
        evidence = agents[:5]
        alerts.append(
            Alert(
                severity=_scale(len(hits), Severity.MEDIUM),
                category="web_scanner",
                source_ip=ip,
                description=(
                    f"{len(hits)} requests from scanner/suspicious user-agent"
                ),
                count=len(hits),
                first_seen=hits[0].timestamp,
                last_seen=hits[-1].timestamp,
                evidence=evidence,
            )
        )
    alerts.sort(key=lambda alert: (alert.severity, alert.count), reverse=True)
    return alerts


def detect_traffic_anomalies(
    events: list[WebEvent],
    window_seconds: int,
    error_threshold: int,
    flood_threshold: int,
) -> list[Alert]:
    by_ip: dict[str, list[WebEvent]] = defaultdict(list)
    for event in events:
        by_ip[event.source_ip].append(event)

    alerts: list[Alert] = []
    for ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda event: event.timestamp)
        timestamps = [event.timestamp for event in ip_events]

        not_found = [e for e in ip_events if e.status == 404]
        distinct_404 = {e.path for e in not_found}
        if len(distinct_404) >= error_threshold:
            sample = sorted(distinct_404)[:5]
            alerts.append(
                Alert(
                    severity=_scale(len(distinct_404), Severity.MEDIUM),
                    category="web_enumeration",
                    source_ip=ip,
                    description=(
                        f"{len(distinct_404)} distinct 404 paths probed "
                        f"(directory/file enumeration)"
                    ),
                    count=len(distinct_404),
                    first_seen=not_found[0].timestamp,
                    last_seen=not_found[-1].timestamp,
                    evidence=sample,
                )
            )

        server_errors = [e for e in ip_events if 500 <= e.status < 600]
        if len(server_errors) >= error_threshold:
            sample = [f"{e.method} {e.target} -> {e.status}" for e in server_errors[:5]]
            alerts.append(
                Alert(
                    severity=_scale(len(server_errors), Severity.MEDIUM),
                    category="web_server_errors",
                    source_ip=ip,
                    description=f"{len(server_errors)} server errors (5xx) triggered",
                    count=len(server_errors),
                    first_seen=server_errors[0].timestamp,
                    last_seen=server_errors[-1].timestamp,
                    evidence=sample,
                )
            )

        peak, start, end = _peak_window(timestamps, window_seconds)
        if peak >= flood_threshold:
            window_events = ip_events[start : end + 1]
            alerts.append(
                Alert(
                    severity=_scale(peak, Severity.MEDIUM),
                    category="web_flood",
                    source_ip=ip,
                    description=(
                        f"{peak} requests within {window_seconds}s (request flood)"
                    ),
                    count=peak,
                    first_seen=window_events[0].timestamp,
                    last_seen=window_events[-1].timestamp,
                )
            )

    alerts.sort(key=lambda alert: (alert.severity, alert.count), reverse=True)
    return alerts


def aggregate_web_stats(events: list[WebEvent]) -> dict:
    request_ips: Counter[str] = Counter()
    paths: Counter[str] = Counter()
    not_found_paths: Counter[str] = Counter()
    agents: Counter[str] = Counter()
    methods: Counter[str] = Counter()
    status_classes: Counter[str] = Counter()

    for event in events:
        request_ips[event.source_ip] += 1
        paths[event.path] += 1
        methods[event.method] += 1
        status_classes[f"{event.status // 100}xx"] += 1
        agents[event.user_agent.strip() or "<empty>"] += 1
        if event.status == 404:
            not_found_paths[event.path] += 1

    timestamps = [event.timestamp for event in events]
    return {
        "total_events": len(events),
        "by_status_class": dict(sorted(status_classes.items())),
        "by_method": dict(sorted(methods.items())),
        "top_request_ips": request_ips.most_common(10),
        "top_paths": paths.most_common(10),
        "top_404_paths": not_found_paths.most_common(10),
        "top_user_agents": agents.most_common(10),
        "first_event": min(timestamps).isoformat() if timestamps else None,
        "last_event": max(timestamps).isoformat() if timestamps else None,
    }
