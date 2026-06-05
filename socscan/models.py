
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, IntEnum


class EventType(Enum):


    FAILED_PASSWORD = "failed_password"
    ACCEPTED_PASSWORD = "accepted_password"
    INVALID_USER = "invalid_user"
    SUDO = "sudo"
    CONNECTION_CLOSED = "connection_closed"
    MAX_AUTH_ATTEMPTS = "max_auth_attempts"


FAILURE_EVENTS = frozenset(
    {
        EventType.FAILED_PASSWORD,
        EventType.INVALID_USER,
        EventType.MAX_AUTH_ATTEMPTS,
    }
)

FLOOD_EVENTS = frozenset(
    {
        EventType.FAILED_PASSWORD,
        EventType.INVALID_USER,
        EventType.MAX_AUTH_ATTEMPTS,
        EventType.CONNECTION_CLOSED,
    }
)


class Severity(IntEnum):


    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class AuthEvent:

    timestamp: datetime
    event_type: EventType
    username: str | None
    source_ip: str | None
    service: str
    raw: str


@dataclass
class Alert:

    severity: Severity
    category: str
    source_ip: str | None
    description: str
    count: int
    first_seen: datetime
    last_seen: datetime
    usernames: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "severity": self.severity.name,
            "category": self.category,
            "source_ip": self.source_ip,
            "description": self.description,
            "count": self.count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "usernames": self.usernames,
        }
