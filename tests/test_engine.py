from nids.db import Database
from nids.engine import DetectionEngine
from nids.sample_data import generate_all


def test_engine_runs_all_detectors_against_sample_data_and_stores_alerts():
    conns, auths = generate_all()
    db = Database(":memory:")
    db.insert_connection_events(conns)
    db.insert_auth_events(auths)

    alerts = DetectionEngine().run(db)

    rule_ids = {a.rule_id for a in alerts}
    assert "port_scan" in rule_ids
    assert "failed_auth_burst" in rule_ids
    assert "traffic_spike" in rule_ids

    stored = db.get_alerts()
    assert len(stored) == len(alerts)


def test_engine_store_false_does_not_write_to_db():
    conns, auths = generate_all()
    db = Database(":memory:")
    db.insert_connection_events(conns)
    db.insert_auth_events(auths)

    alerts = DetectionEngine().run(db, store=False)
    assert len(alerts) > 0
    assert db.get_alerts() == []


def test_engine_with_no_events_fires_no_alerts():
    db = Database(":memory:")
    alerts = DetectionEngine().run(db)
    assert alerts == []


def test_alerts_are_sorted_by_timestamp():
    conns, auths = generate_all()
    db = Database(":memory:")
    db.insert_connection_events(conns)
    db.insert_auth_events(auths)
    alerts = DetectionEngine().run(db)
    timestamps = [a.timestamp for a in alerts]
    assert timestamps == sorted(timestamps)
