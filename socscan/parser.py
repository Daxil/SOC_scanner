from __future__ import annotations

import gzip
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator

from .models import AuthEvent, EventType

_TS = r"(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})"
_HOST = r"\S+"
_PROC = r"(?P<service>\w+)\[\d+\]"
_IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"

PATTERNS: list[tuple[re.Pattern[str], EventType]] = [
    (
        re.compile(
            rf"{_TS}\s+{_HOST}\s+{_PROC}:\s+Failed password for invalid user "
            rf"(?P<user>\S+) from {_IP}"
        ),
        EventType.INVALID_USER,
    ),
    (
        re.compile(
            rf"{_TS}\s+{_HOST}\s+{_PROC}:\s+Failed password for "
            rf"(?P<user>\S+) from {_IP}"
        ),
        EventType.FAILED_PASSWORD,
    ),
    (
        re.compile(
            rf"{_TS}\s+{_HOST}\s+{_PROC}:\s+Accepted password for "
            rf"(?P<user>\S+) from {_IP}"
        ),
        EventType.ACCEPTED_PASSWORD,
    ),
    (
        re.compile(
            rf"{_TS}\s+{_HOST}\s+{_PROC}:\s+Invalid user (?P<user>\S+) from {_IP}"
        ),
        EventType.INVALID_USER,
    ),
    (
        re.compile(
            rf"{_TS}\s+{_HOST}\s+{_PROC}:\s+Disconnecting.*?\[preauth\]"
        ),
        EventType.MAX_AUTH_ATTEMPTS,
    ),
    (
        re.compile(
            rf"{_TS}\s+{_HOST}\s+{_PROC}:\s+Connection closed by (?:authenticating |invalid )?"
            rf"(?:user \S+ )?{_IP}.*?\[preauth\]"
        ),
        EventType.CONNECTION_CLOSED,
    ),
    (
        re.compile(
            rf"{_TS}\s+{_HOST}\s+sudo:\s+(?P<user>\S+)\s+:.*?COMMAND="
        ),
        EventType.SUDO,
    ),
]

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_timestamp(raw: str, default_year: int) -> datetime:
    month_name, day, clock = raw.split()
    hour, minute, second = (int(part) for part in clock.split(":"))
    return datetime(
        year=default_year,
        month=_MONTHS[month_name],
        day=int(day),
        hour=hour,
        minute=minute,
        second=second,
    )


def parse_line(line: str, default_year: int | None = None) -> AuthEvent | None:
    if default_year is None:
        default_year = datetime.now().year

    for pattern, event_type in PATTERNS:
        match = pattern.search(line)
        if not match:
            continue
        groups = match.groupdict()
        timestamp = _parse_timestamp(groups["ts"], default_year)
        return AuthEvent(
            timestamp=timestamp,
            event_type=event_type,
            username=groups.get("user"),
            source_ip=groups.get("ip"),
            service=groups.get("service") or "sudo",
            raw=line.rstrip("\n"),
        )
    return None


def iter_events(
    lines: Iterable[str], default_year: int | None = None
) -> Iterator[AuthEvent]:
    if default_year is None:
        default_year = datetime.now().year

    previous: datetime | None = None
    year = default_year
    for line in lines:
        event = parse_line(line, year)
        if event is None:
            continue
        if previous is not None and event.timestamp < previous and (
            previous - event.timestamp
        ).days > 300:
            year += 1
            event = parse_line(line, year)
            if event is None:
                continue
        previous = event.timestamp
        yield event


def _open(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", errors="replace")
    return path.open("r", errors="replace")


def read_lines(paths: list[str]) -> Iterator[str]:
    if not paths or paths == ["-"]:
        yield from sys.stdin
        return

    for raw_path in paths:
        if raw_path == "-":
            yield from sys.stdin
            continue
        path = Path(raw_path)
        with _open(path) as handle:
            yield from handle
