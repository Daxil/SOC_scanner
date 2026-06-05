from __future__ import annotations

import argparse

from socscan.detectors import (
    aggregate_stats,
    detect_bruteforce,
    detect_compromise,
    detect_ddos,
)
from socscan.models import Severity
from socscan.parser import iter_events, read_lines
from socscan.reporter import render_console, render_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc_scan",
        description="Scan auth.log files for brute-force, compromise, and DDoS activity.",
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
        "--year",
        type=int,
        default=None,
        help="Year to assume for timestamps without one (default: current year).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    events = list(iter_events(read_lines(args.paths), args.year))
    stats = aggregate_stats(events)
    alerts = detect_compromise(events, args.threshold, args.window)
    alerts += detect_ddos(events, args.window, args.ddos_rate, args.ddos_ips)
    alerts += detect_bruteforce(events, args.threshold, args.window)

    if args.json:
        print(render_json(stats, alerts))
    else:
        print(render_console(stats, alerts))

    if any(alert.severity >= Severity.HIGH for alert in alerts):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
