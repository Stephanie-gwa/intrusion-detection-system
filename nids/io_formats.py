"""Reading and writing the two on-disk formats this prototype understands.

connection events  -> a simple CSV (timestamp,src_ip,dst_ip,dst_port,protocol,bytes_sent,flag)
auth events        -> plain text log lines styled after OpenSSH's sshd,
                       e.g.:
                         2026-01-15T09:20:03 sshd: Failed password for root from 198.51.100.23 port 51422 ssh2
                         2026-01-15T09:20:05 sshd: Accepted password for root from 198.51.100.23 port 51430 ssh2

Using a line format close to a real log (rather than CSV) for auth
events is deliberate: it demonstrates basic log parsing, and makes it
obvious how you'd point this at a real (sanitized) auth.log.
"""

import csv
import re
from datetime import datetime
from pathlib import Path
from typing import List, Union

from .events import AuthEvent, ConnectionEvent

CONNECTION_CSV_HEADER = ["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "bytes_sent", "flag"]

_AUTH_LINE_RE = re.compile(
    r"^(?P<ts>\S+)\s+sshd:\s+(?P<result>Failed|Accepted)\s+password\s+for\s+"
    r"(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+\d+\s+ssh2\s*$"
)


def write_connection_csv(events: List[ConnectionEvent], path: Union[str, Path]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(CONNECTION_CSV_HEADER)
        for e in events:
            writer.writerow([
                e.timestamp.isoformat(), e.src_ip, e.dst_ip, e.dst_port,
                e.protocol, e.bytes_sent, e.flag,
            ])


def read_connection_csv(path: Union[str, Path]) -> List[ConnectionEvent]:
    events: List[ConnectionEvent] = []
    with open(path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            events.append(ConnectionEvent(
                timestamp=datetime.fromisoformat(row["timestamp"]),
                src_ip=row["src_ip"],
                dst_ip=row["dst_ip"],
                dst_port=int(row["dst_port"]),
                protocol=row["protocol"],
                bytes_sent=int(row["bytes_sent"]),
                flag=row.get("flag", "") or "",
            ))
    return events


def write_auth_log(events: List[AuthEvent], path: Union[str, Path]) -> None:
    lines = []
    for e in events:
        result = "Accepted" if e.success else "Failed"
        port = 40000 + (hash((e.src_ip, e.timestamp.isoformat())) % 10000)
        lines.append(
            f"{e.timestamp.isoformat()} sshd: {result} password for "
            f"{e.username} from {e.src_ip} port {port} ssh2"
        )
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def read_auth_log(path: Union[str, Path]) -> List[AuthEvent]:
    events: List[AuthEvent] = []
    text = Path(path).read_text(encoding="utf-8")
    for line_no, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        match = _AUTH_LINE_RE.match(line)
        if not match:
            # Skip unparseable lines rather than crashing the whole ingest —
            # a real auth.log has plenty of lines this simple parser doesn't
            # model (session opened/closed, PAM messages, etc).
            continue
        events.append(AuthEvent(
            timestamp=datetime.fromisoformat(match["ts"]),
            src_ip=match["ip"],
            username=match["user"],
            success=(match["result"] == "Accepted"),
        ))
    return events
