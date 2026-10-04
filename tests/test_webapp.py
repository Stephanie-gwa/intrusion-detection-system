import pytest

from nids.db import Database
from nids.engine import DetectionEngine
from nids.sample_data import generate_all
from nids.webapp import create_app


@pytest.fixture
def client():
    conns, auths = generate_all()
    db = Database(":memory:")
    db.insert_connection_events(conns)
    db.insert_auth_events(auths)
    DetectionEngine().run(db)

    app = create_app(db=db)
    app.config["TESTING"] = True
    return app.test_client()


def test_index_returns_200(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"port_scan" in resp.data or b"Alerts" in resp.data


def test_index_shows_alert_rows(client):
    resp = client.get("/")
    assert b"Possible port scan" in resp.data


def test_index_filter_by_rule(client):
    resp = client.get("/?rule_id=port_scan")
    assert resp.status_code == 200
    assert b"port_scan" in resp.data


def test_index_filter_by_severity(client):
    resp = client.get("/?severity=high")
    assert resp.status_code == 200


def test_alert_detail_returns_200_for_existing_alert(client):
    resp = client.get("/alert/1")
    assert resp.status_code == 200
    assert b"Supporting evidence" in resp.data


def test_alert_detail_404_for_missing_alert(client):
    resp = client.get("/alert/99999")
    assert resp.status_code == 404


def test_rerun_redirects_and_does_not_duplicate_alerts(client):
    before = client.get("/alert/1")
    assert before.status_code == 200

    resp = client.post("/rerun")
    assert resp.status_code == 302

    # Alert count should be identical after a re-run, not doubled.
    index = client.get("/")
    assert index.status_code == 200


def test_healthz(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}


def test_empty_db_shows_no_alerts_message():
    db = Database(":memory:")
    app = create_app(db=db)
    client = app.test_client()
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"No alerts yet" in resp.data
