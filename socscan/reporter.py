from __future__ import annotations

import json

from .models import Alert


def _format_pairs(pairs: list[tuple[str, int]], empty: str) -> list[str]:
    if not pairs:
        return [f"  {empty}"]
    width = max(len(name) for name, _ in pairs)
    return [f"  {name.ljust(width)}  {count}" for name, count in pairs]


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
        origin = alert.source_ip or "multiple sources"
        lines.append(f"  [{alert.severity.name}] {alert.category} - {origin}")
        lines.append(f"      {alert.description}")
        lines.append(f"      window: {alert.first_seen} -> {alert.last_seen}")
        if alert.usernames:
            lines.append(f"      accounts: {', '.join(alert.usernames)}")

    lines.append("")
    return "\n".join(lines)


def render_json(stats: dict, alerts: list[Alert]) -> str:
    payload = {
        "summary": stats,
        "alerts": [alert.to_dict() for alert in alerts],
    }
    return json.dumps(payload, indent=2)
