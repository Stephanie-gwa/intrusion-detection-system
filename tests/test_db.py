from datetime import datetime

from nids.db import Database
from nids.events import Alert, AuthEvent, ConnectionEvent


def _conn(ts="2026-01-01T00:00:00", src="10.0.0.1", dst="10.0.0.2", port=80):
    return ConnectionEvent(timestamp=datetime.fromisoformat(ts), src_ip=src, dst_ip=dst,
                            dst_port=port, protocol="tcp", bytes_sent=100, flag="S")


def _auth(ts="2026-01-01T00:00:00", src="10.0.0.1", user="alice", success=True):
    return AuthEvent(timestamp=datetime.fromisoformat(ts), src_ip=src, username=user, success=success)


def test_insert_and_get_connection_events():
    db = Database(":memory:")
    db.insert_connection_events([_conn(), _conn(port=443)])
    events = db.get_connection_events()
    assert len(events) == 2
    assert {e.dst_port for e in events} == {80, 443}


def test_insert_and_get_auth_events():
    db = Database(":memory:")
    db.insert_auth_events([_auth(), _auth(success=False)])
    events = db.get_auth_events()
    assert len(events) == 2
    assert any(e.success is False for e in events)


def test_clear_all():
    db = Database(":memory:")
    db.insert_connection_events([_conn()])
    db.insert_auth_events([_auth()])
    db.clear_all()
    assert db.get_connection_events() == []
    assert db.get_auth_events() == []


def test_insert_and_get_alerts_roundtrip_evidence():
    db = Database(":memory:")
    alert = Alert(
        rule_id="port_scan", severity="high", timestamp=datetime(2026, 1, 1),
        title="t", description="d", threshold="th", source_ip="1.2.3.4",
        evidence={"foo": "bar", "n": 3},
    )
    db.insert_alerts([alert])
    rows = db.get_alerts()
    assert len(rows) == 1
    assert rows[0]["evidence"] == {"foo": "bar", "n": 3}
    assert rows[0]["source_ip"] == "1.2.3.4"


def test_get_alerts_filters_by_rule_and_severity():
    db = Database(":memory:")
    db.insert_alerts([
        Alert(rule_id="a", severity="high", timestamp=datetime(2026, 1, 1), title="x",
              description="d", threshold="t", evidence={}),
        Alert(rule_id="b", severity="low", timestamp=datetime(2026, 1, 2), title="y",
              description="d", threshold="t", evidence={}),
    ])
    assert len(db.get_alerts(rule_id="a")) == 1
    assert len(db.get_alerts(severity="low")) == 1
    assert len(db.get_alerts(rule_id="a", severity="low")) == 0


def test_get_alert_by_id_and_missing():
    db = Database(":memory:")
    db.insert_alerts([Alert(rule_id="a", severity="high", timestamp=datetime(2026, 1, 1),
                             title="x", description="d", threshold="t", evidence={})])
    assert db.get_alert(1) is not None
    assert db.get_alert(999) is None


def test_clear_alerts_only():
    db = Database(":memory:")
    db.insert_connection_events([_conn()])
    db.insert_alerts([Alert(rule_id="a", severity="high", timestamp=datetime(2026, 1, 1),
                             title="x", description="d", threshold="t", evidence={})])
    db.clear_alerts()
    assert db.get_alerts() == []
    assert len(db.get_connection_events()) == 1


def test_summary_counts():
    db = Database(":memory:")
    db.insert_connection_events([_conn(), _conn(port=443)])
    db.insert_auth_events([_auth()])
    db.insert_alerts([
        Alert(rule_id="port_scan", severity="high", timestamp=datetime(2026, 1, 1),
              title="x", description="d", threshold="t", evidence={}),
        Alert(rule_id="port_scan", severity="medium", timestamp=datetime(2026, 1, 1),
              title="y", description="d", threshold="t", evidence={}),
    ])
    summary = db.summary()
    assert summary["connection_events"] == 2
    assert summary["auth_events"] == 1
    assert summary["alerts"] == 2
    assert summary["alerts_by_rule"] == {"port_scan": 2}
    assert summary["alerts_by_severity"] == {"high": 1, "medium": 1}
