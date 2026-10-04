"""SQLite storage for ingested events and fired alerts.

Deliberately plain stdlib `sqlite3` — no ORM. The schema is small
enough that raw SQL stays readable, and it keeps the project's only
hard dependency (Flask, for the dashboard) honest.
"""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Union

from .events import Alert, AuthEvent, ConnectionEvent

SCHEMA = """
CREATE TABLE IF NOT EXISTS connection_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    dst_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    bytes_sent INTEGER NOT NULL DEFAULT 0,
    flag TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS auth_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    username TEXT NOT NULL,
    success INTEGER NOT NULL,
    service TEXT NOT NULL DEFAULT 'ssh'
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    threshold TEXT NOT NULL,
    source_ip TEXT,
    evidence TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_connection_events_src_ts
    ON connection_events (src_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_auth_events_src_ts
    ON auth_events (src_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
    ON alerts (timestamp);
"""


class Database:
    """Thin wrapper around a single SQLite file (or an in-memory DB for tests)."""

    def __init__(self, path: Union[str, Path] = ":memory:"):
        self.path = str(path)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def _cursor(self) -> Iterator[sqlite3.Cursor]:
        cur = self._conn.cursor()
        try:
            yield cur
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        finally:
            cur.close()

    # ---- ingestion ----------------------------------------------------

    def clear_all(self) -> None:
        with self._cursor() as cur:
            cur.execute("DELETE FROM connection_events")
            cur.execute("DELETE FROM auth_events")
            cur.execute("DELETE FROM alerts")

    def clear_alerts(self) -> None:
        with self._cursor() as cur:
            cur.execute("DELETE FROM alerts")

    def insert_connection_events(self, events: List[ConnectionEvent]) -> int:
        with self._cursor() as cur:
            cur.executemany(
                "INSERT INTO connection_events "
                "(timestamp, src_ip, dst_ip, dst_port, protocol, bytes_sent, flag) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (e.timestamp.isoformat(), e.src_ip, e.dst_ip, e.dst_port,
                     e.protocol, e.bytes_sent, e.flag)
                    for e in events
                ],
            )
        return len(events)

    def insert_auth_events(self, events: List[AuthEvent]) -> int:
        with self._cursor() as cur:
            cur.executemany(
                "INSERT INTO auth_events (timestamp, src_ip, username, success, service) "
                "VALUES (?, ?, ?, ?, ?)",
                [
                    (e.timestamp.isoformat(), e.src_ip, e.username, int(e.success), e.service)
                    for e in events
                ],
            )
        return len(events)

    # ---- reading events back out ---------------------------------------

    def get_connection_events(self) -> List[ConnectionEvent]:
        with self._cursor() as cur:
            cur.execute(
                "SELECT timestamp, src_ip, dst_ip, dst_port, protocol, bytes_sent, flag "
                "FROM connection_events ORDER BY timestamp"
            )
            rows = cur.fetchall()
        return [
            ConnectionEvent(
                timestamp=datetime.fromisoformat(r["timestamp"]),
                src_ip=r["src_ip"],
                dst_ip=r["dst_ip"],
                dst_port=r["dst_port"],
                protocol=r["protocol"],
                bytes_sent=r["bytes_sent"],
                flag=r["flag"],
            )
            for r in rows
        ]

    def get_auth_events(self) -> List[AuthEvent]:
        with self._cursor() as cur:
            cur.execute(
                "SELECT timestamp, src_ip, username, success, service "
                "FROM auth_events ORDER BY timestamp"
            )
            rows = cur.fetchall()
        return [
            AuthEvent(
                timestamp=datetime.fromisoformat(r["timestamp"]),
                src_ip=r["src_ip"],
                username=r["username"],
                success=bool(r["success"]),
                service=r["service"],
            )
            for r in rows
        ]

    # ---- alerts ---------------------------------------------------------

    def insert_alerts(self, alerts: List[Alert]) -> int:
        with self._cursor() as cur:
            cur.executemany(
                "INSERT INTO alerts "
                "(rule_id, severity, timestamp, title, description, threshold, "
                " source_ip, evidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (a.rule_id, a.severity, a.timestamp.isoformat(), a.title,
                     a.description, a.threshold, a.source_ip, json.dumps(a.evidence))
                    for a in alerts
                ],
            )
        return len(alerts)

    def get_alerts(
        self, rule_id: Optional[str] = None, severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM alerts"
        clauses = []
        params: List[Any] = []
        if rule_id:
            clauses.append("rule_id = ?")
            params.append(rule_id)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY timestamp DESC, id DESC"

        with self._cursor() as cur:
            cur.execute(query, params)
            rows = cur.fetchall()
        return [_alert_row_to_dict(r) for r in rows]

    def get_alert(self, alert_id: int) -> Optional[Dict[str, Any]]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
            row = cur.fetchone()
        return _alert_row_to_dict(row) if row else None

    def summary(self) -> Dict[str, Any]:
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM connection_events")
            n_conn = cur.fetchone()["n"]
            cur.execute("SELECT COUNT(*) AS n FROM auth_events")
            n_auth = cur.fetchone()["n"]
            cur.execute("SELECT COUNT(*) AS n FROM alerts")
            n_alerts = cur.fetchone()["n"]
            cur.execute(
                "SELECT rule_id, COUNT(*) AS n FROM alerts GROUP BY rule_id"
            )
            by_rule = {r["rule_id"]: r["n"] for r in cur.fetchall()}
            cur.execute(
                "SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity"
            )
            by_severity = {r["severity"]: r["n"] for r in cur.fetchall()}
        return {
            "connection_events": n_conn,
            "auth_events": n_auth,
            "alerts": n_alerts,
            "alerts_by_rule": by_rule,
            "alerts_by_severity": by_severity,
        }


def _alert_row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    d["evidence"] = json.loads(d["evidence"])
    return d
