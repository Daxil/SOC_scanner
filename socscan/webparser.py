from __future__ import annotations

import re
from datetime import datetime
from typing import Iterable, Iterator
from urllib.parse import unquote, unquote_plus

from .models import WebEvent

_IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
_USER = r"\S+"
_TS = r"\[(?P<ts>[^\]]+)\]"
_REQUEST = r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)\s+(?P<proto>HTTP/\d\.\d)"'
_STATUS = r"(?P<status>\d{3})"
_BYTES = r"(?P<bytes>\d+|-)"
_COMBINED_TAIL = r'\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"'

WEB_PATTERN = re.compile(
    rf'{_IP}\s+{_USER}\s+{_USER}\s+{_TS}\s+{_REQUEST}\s+{_STATUS}\s+{_BYTES}'
    rf'(?:{_COMBINED_TAIL})?'
)

_TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def parse_web_line(line: str) -> WebEvent | None:
    match = WEB_PATTERN.search(line)
    if not match:
        return None

    groups = match.groupdict()
    try:
        timestamp = datetime.strptime(groups["ts"], _TS_FORMAT)
    except ValueError:
        return None

    url = groups["url"]
    if "?" in url:
        raw_path, raw_query = url.split("?", 1)
    else:
        raw_path, raw_query = url, ""

    raw_bytes = groups["bytes"]
    size = 0 if raw_bytes == "-" else int(raw_bytes)

    return WebEvent(
        timestamp=timestamp,
        source_ip=groups["ip"],
        method=groups["method"],
        path=unquote(raw_path),
        query=unquote_plus(raw_query),
        status=int(groups["status"]),
        bytes=size,
        user_agent=groups.get("ua") or "",
        referer=groups.get("referer") or "",
        protocol=groups["proto"],
        raw=line.rstrip("\n"),
    )


def iter_web_events(lines: Iterable[str]) -> Iterator[WebEvent]:
    for line in lines:
        event = parse_web_line(line)
        if event is not None:
            yield event


def sniff_format(lines: Iterable[str]) -> tuple[str, list[str]]:
    buffered: list[str] = []
    inspected = 0
    web_hits = 0

    for line in lines:
        buffered.append(line)
        if not line.strip():
            continue
        inspected += 1
        if WEB_PATTERN.search(line):
            web_hits += 1
        if inspected >= 50:
            break

    fmt = "web" if inspected and web_hits >= max(1, inspected // 2) else "auth"
    return fmt, buffered
