from __future__ import annotations

import json

from .models import Alert


def _format_pairs(pairs: list[tuple[str, int]], empty: str) -> list[str]:
    if not pairs:
        return [f"  {empty}"]
    width = max(len(name) for name, _ in pairs)
    return [f"  {name.ljust(width)}  {count}" for name, count in pairs]


def _alert_lines(alert: Alert) -> list[str]:
    origin = alert.source_ip or "multiple sources"
    lines = [
        f"  [{alert.severity.name}] {alert.category} - {origin}",
        f"      {alert.description}",
        f"      window: {alert.first_seen} -> {alert.last_seen}",
    ]
    if alert.usernames:
        lines.append(f"      accounts: {', '.join(alert.usernames)}")
    for sample in alert.evidence:
        lines.append(f"      evidence: {sample}")
    return lines


def render_console(stats: dict, alerts: list[Alert]) -> str:
    lines: list[str] = []
    lines.append("SOC AUTH LOG SCAN REPORT")
    lines.append("")
    lines.append("Summary")
    lines.append(f"  Events parsed: {stats['total_events']}")
    lines.append(f"  Time range:    {stats['first_event']} -> {stats['last_event']}")
    for name, count in sorted(stats["by_type"].items()):
        lines.append(f"  {name}: {count}")

    lines.append("")
    lines.append("Top source IPs (connection requests)")
    lines.extend(_format_pairs(stats["top_connection_ips"], "none"))

    lines.append("")
    lines.append("Top source IPs (failed attempts)")
    lines.extend(_format_pairs(stats["top_source_ips"], "none"))

    lines.append("")
    lines.append("Top targeted accounts")
    lines.extend(_format_pairs(stats["top_targeted_users"], "none"))

    lines.append("")
    lines.append(f"Alerts ({len(alerts)})")
    if not alerts:
        lines.append("  No alerts raised")
    for alert in alerts:
        lines.extend(_alert_lines(alert))

    lines.append("")
    return "\n".join(lines)


def render_web_console(stats: dict, alerts: list[Alert]) -> str:
    lines: list[str] = []
    lines.append("SOC WEB LOG SCAN REPORT")
    lines.append("")
    lines.append("Summary")
    lines.append(f"  Requests parsed: {stats['total_events']}")
    lines.append(f"  Time range:      {stats['first_event']} -> {stats['last_event']}")
    for name, count in stats["by_status_class"].items():
        lines.append(f"  {name}: {count}")
    for name, count in stats["by_method"].items():
        lines.append(f"  {name}: {count}")

    lines.append("")
    lines.append("Top source IPs (requests)")
    lines.extend(_format_pairs(stats["top_request_ips"], "none"))

    lines.append("")
    lines.append("Top requested paths")
    lines.extend(_format_pairs(stats["top_paths"], "none"))

    lines.append("")
    lines.append("Top 404 paths")
    lines.extend(_format_pairs(stats["top_404_paths"], "none"))

    lines.append("")
    lines.append("Top user agents")
    lines.extend(_format_pairs(stats["top_user_agents"], "none"))

    lines.append("")
    lines.append(f"Alerts ({len(alerts)})")
    if not alerts:
        lines.append("  No alerts raised")
    for alert in alerts:
        lines.extend(_alert_lines(alert))

    lines.append("")
    return "\n".join(lines)


def render_json(stats: dict, alerts: list[Alert]) -> str:
    payload = {
        "summary": stats,
        "alerts": [alert.to_dict() for alert in alerts],
    }
    return json.dumps(payload, indent=2)


def render_web_json(stats: dict, alerts: list[Alert]) -> str:
    return render_json(stats, alerts)
