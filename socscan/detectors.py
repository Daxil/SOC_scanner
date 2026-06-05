from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime

from .models import FAILURE_EVENTS, FLOOD_EVENTS, Alert, AuthEvent, EventType, Severity


def _bruteforce_severity(count: int, threshold: int) -> Severity:
    if count >= threshold * 4:
        return Severity.CRITICAL
    if count >= threshold * 2:
        return Severity.HIGH
    return Severity.MEDIUM


def _peak_window(
    timestamps: list[datetime], window_seconds: int
) -> tuple[int, int, int]:
    start = 0
    best = 0
    best_start = 0
    best_end = 0
    for end in range(len(timestamps)):
        while (timestamps[end] - timestamps[start]).total_seconds() > window_seconds:
            start += 1
        span = end - start + 1
        if span > best:
            best = span
            best_start = start
            best_end = end
    return best, best_start, best_end


def detect_bruteforce(
    events: list[AuthEvent], threshold: int, window_seconds: int
) -> list[Alert]:
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.event_type in FAILURE_EVENTS and event.source_ip:
            by_ip[event.source_ip].append(event)

    alerts: list[Alert] = []
    for ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda event: event.timestamp)
        timestamps = [event.timestamp for event in ip_events]
        peak, start, end = _peak_window(timestamps, window_seconds)
        if peak < threshold:
            continue
        window_events = ip_events[start : end + 1]
        usernames = sorted({e.username for e in window_events if e.username})
        alerts.append(
            Alert(
                severity=_bruteforce_severity(peak, threshold),
                category="brute_force",
                source_ip=ip,
                description=(
                    f"{peak} failed authentication attempts within "
                    f"{window_seconds}s"
                ),
                count=peak,
                first_seen=window_events[0].timestamp,
                last_seen=window_events[-1].timestamp,
                usernames=usernames,
            )
        )
    alerts.sort(key=lambda alert: (alert.severity, alert.count), reverse=True)
    return alerts


def detect_compromise(
    events: list[AuthEvent], fail_threshold: int, window_seconds: int
) -> list[Alert]:
    ordered = sorted(events, key=lambda event: event.timestamp)
    failures_by_ip: dict[str, list[datetime]] = defaultdict(list)
    alerts: list[Alert] = []

    for event in ordered:
        if not event.source_ip:
            continue
        if event.event_type in FAILURE_EVENTS:
            failures_by_ip[event.source_ip].append(event.timestamp)
        elif event.event_type == EventType.ACCEPTED_PASSWORD:
            recent = [
                ts
                for ts in failures_by_ip.get(event.source_ip, [])
                if 0 <= (event.timestamp - ts).total_seconds() <= window_seconds
            ]
            if len(recent) >= fail_threshold:
                alerts.append(
                    Alert(
                        severity=Severity.CRITICAL,
                        category="compromise",
                        source_ip=event.source_ip,
                        description=(
                            f"Successful login for '{event.username}' after "
                            f"{len(recent)} recent failures"
                        ),
                        count=len(recent),
                        first_seen=recent[0],
                        last_seen=event.timestamp,
                        usernames=[event.username] if event.username else [],
                    )
                )
    return alerts


def _ddos_severity(
    events_count: int, unique_ips: int, rate_threshold: int, min_unique_ips: int
) -> Severity:
    ratio = max(events_count / rate_threshold, unique_ips / max(min_unique_ips, 1))
    if ratio >= 3:
        return Severity.CRITICAL
    if ratio >= 2:
        return Severity.HIGH
    return Severity.MEDIUM


def detect_ddos(
    events: list[AuthEvent],
    window_seconds: int,
    rate_threshold: int,
    min_unique_ips: int,
) -> list[Alert]:
    flood = sorted(
        (event for event in events if event.event_type in FLOOD_EVENTS and event.source_ip),
        key=lambda event: event.timestamp,
    )
    if not flood:
        return []

    timestamps = [event.timestamp for event in flood]
    ips_in_window: Counter[str] = Counter()
    start = 0
    best: tuple[int, int, int, int] | None = None

    for end in range(len(flood)):
        ips_in_window[flood[end].source_ip] += 1
        while (timestamps[end] - timestamps[start]).total_seconds() > window_seconds:
            leaving = flood[start].source_ip
            ips_in_window[leaving] -= 1
            if ips_in_window[leaving] == 0:
                del ips_in_window[leaving]
            start += 1
        count = end - start + 1
        if best is None or count > best[0]:
            best = (count, len(ips_in_window), start, end)

    count, unique, start, end = best
    if count < rate_threshold and unique < min_unique_ips:
        return []

    window_events = flood[start : end + 1]
    if unique >= min_unique_ips:
        shape = f"distributed from {unique} source IPs"
    else:
        shape = f"concentrated from {unique} source IPs"
    return [
        Alert(
            severity=_ddos_severity(count, unique, rate_threshold, min_unique_ips),
            category="ddos",
            source_ip=None,
            description=(
                f"Connection flood: {count} events {shape} within {window_seconds}s"
            ),
            count=count,
            first_seen=window_events[0].timestamp,
            last_seen=window_events[-1].timestamp,
            usernames=[],
        )
    ]


def aggregate_stats(events: list[AuthEvent]) -> dict:
    connection_ips: Counter[str] = Counter()
    failed_ips: Counter[str] = Counter()
    targeted_users: Counter[str] = Counter()
    type_counts: Counter[str] = Counter()

    for event in events:
        type_counts[event.event_type.value] += 1
        if event.source_ip:
            connection_ips[event.source_ip] += 1
        if event.event_type in FAILURE_EVENTS:
            if event.source_ip:
                failed_ips[event.source_ip] += 1
            if event.username:
                targeted_users[event.username] += 1

    timestamps = [event.timestamp for event in events]
    return {
        "total_events": len(events),
        "by_type": dict(type_counts),
        "top_connection_ips": connection_ips.most_common(10),
        "top_source_ips": failed_ips.most_common(10),
        "top_targeted_users": targeted_users.most_common(10),
        "first_event": min(timestamps).isoformat() if timestamps else None,
        "last_event": max(timestamps).isoformat() if timestamps else None,
    }
