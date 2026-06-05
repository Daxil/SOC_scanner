from .models import Alert, AuthEvent, EventType, Severity
from .parser import iter_events, parse_line, read_lines
from .detectors import (
    aggregate_stats,
    detect_bruteforce,
    detect_compromise,
    detect_ddos,
)
from .reporter import render_console, render_json

__version__ = "1.0.0"

__all__ = [
    "Alert",
    "AuthEvent",
    "EventType",
    "Severity",
    "iter_events",
    "parse_line",
    "read_lines",
    "aggregate_stats",
    "detect_bruteforce",
    "detect_compromise",
    "detect_ddos",
    "render_console",
    "render_json",
]
