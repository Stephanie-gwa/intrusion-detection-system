"""Plain data structures for the two kinds of input event this prototype
understands, plus the Alert shape every detector produces.

Keeping these as simple, explicit dataclasses (rather than passing raw
dicts or DB rows around) is what makes the detectors readable and lets
every alert's "evidence" be literally the input events that triggered
it, serialized straight to JSON.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional


@dataclass
class ConnectionEvent:
    """One observed (or synthetically generated) network connection attempt."""

    timestamp: datetime
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str  # "tcp" or "udp"
    bytes_sent: int = 0
    flag: str = ""  # e.g. "S" (SYN), "SA" (SYN-ACK), "R" (reset) — advisory only

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "bytes_sent": self.bytes_sent,
            "flag": self.flag,
        }


@dataclass
class AuthEvent:
    """One observed (or synthetically generated) authentication attempt,
    modeled loosely on an sshd-style auth log line."""

    timestamp: datetime
    src_ip: str
    username: str
    success: bool
    service: str = "ssh"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip,
            "username": self.username,
            "success": self.success,
            "service": self.service,
        }


@dataclass
class Alert:
    """One fired detection, with everything needed to explain it."""

    rule_id: str
    severity: str  # "low" | "medium" | "high"
    timestamp: datetime
    title: str
    description: str
    threshold: str
    source_ip: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat(),
            "title": self.title,
            "description": self.description,
            "threshold": self.threshold,
            "source_ip": self.source_ip,
            "evidence": self.evidence,
        }
