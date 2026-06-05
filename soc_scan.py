from __future__ import annotations

import argparse
from itertools import chain

from socscan.detectors import (
    aggregate_stats,
    detect_bruteforce,
    detect_compromise,
    detect_ddos,
)
from socscan.models import Severity
from socscan.parser import iter_events, read_lines
from socscan.reporter import (
    render_console,
    render_json,
    render_web_console,
    render_web_json,
)
from socscan.webdetectors import (
    aggregate_web_stats,
    detect_injections,
    detect_scanners,
    detect_traffic_anomalies,
    detect_traversal_and_sensitive,
)
from socscan.webparser import iter_web_events, sniff_format


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc_scan",
        description=(
            "Scan auth.log or web (nginx/apache) access logs for suspicious "
            "activity. The log format is auto-detected."
        ),
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Log files to scan (.gz supported). Use '-' or omit for stdin.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of a console report.",
    )
    parser.add_argument(
        "--format",
        choices=("auto", "auth", "web"),
        default="auto",
        help="Log format. 'auto' detects auth vs web (default: auto).",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Failed attempts from one IP to flag as brute force (default: 5).",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=60,
        help="Detection window in seconds (default: 60).",
    )
    parser.add_argument(
        "--ddos-rate",
        type=int,
        default=40,
        help="Connection events within the window to flag a flood (default: 40).",
    )
    parser.add_argument(
        "--ddos-ips",
        type=int,
        default=15,
        help="Distinct source IPs within the window to flag as distributed (default: 15).",
    )
    parser.add_argument(
        "--web-errors",
        type=int,
        default=15,
        help="Distinct 404 paths or 5xx errors from one IP to flag (default: 15).",
    )
    parser.add_argument(
        "--web-flood",
        type=int,
        default=100,
        help="Requests from one IP within the window to flag a flood (default: 100).",
    )
    parser.add_argument(
        "--year",
        type=int,
        default=None,
        help="Year to assume for auth.log timestamps without one (default: current year).",
    )
    return parser


def scan_auth(lines, args) -> tuple[dict, list]:
    events = list(iter_events(lines, args.year))
    stats = aggregate_stats(events)
    alerts = detect_compromise(events, args.threshold, args.window)
    alerts += detect_ddos(events, args.window, args.ddos_rate, args.ddos_ips)
    alerts += detect_bruteforce(events, args.threshold, args.window)
    return stats, alerts


def scan_web(lines, args) -> tuple[dict, list]:
    events = list(iter_web_events(lines))
    stats = aggregate_web_stats(events)
    alerts = detect_injections(events)
    alerts += detect_traversal_and_sensitive(events)
    alerts += detect_scanners(events)
    alerts += detect_traffic_anomalies(
        events, args.window, args.web_errors, args.web_flood
    )
    return stats, alerts


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    fmt = args.format
    stream = read_lines(args.paths)
    if fmt == "auto":
        fmt, buffered = sniff_format(stream)
        stream = chain(buffered, stream)

    if fmt == "web":
        stats, alerts = scan_web(stream, args)
        report = render_web_json(stats, alerts) if args.json else render_web_console(
            stats, alerts
        )
    else:
        stats, alerts = scan_auth(stream, args)
        report = render_json(stats, alerts) if args.json else render_console(
            stats, alerts
        )

    print(report)

    if any(alert.severity >= Severity.HIGH for alert in alerts):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
