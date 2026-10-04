from datetime import datetime, timedelta

from nids.detectors.failed_auth import FailedAuthDetector
from nids.events import AuthEvent


def _failures(n=10, src="198.51.100.23", start=None, gap_s=2):
    start = start or datetime(2026, 1, 1, 9, 0, 0)
    events = []
    t = start
    for i in range(n):
        events.append(AuthEvent(timestamp=t, src_ip=src, username="root", success=False))
        t += timedelta(seconds=gap_s)
    return events, t


def test_detects_brute_force_above_threshold():
    detector = FailedAuthDetector(window_seconds=60, failure_threshold=8)
    events, _ = _failures(n=10)
    alerts = detector.run(events)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "failed_auth_burst"
    assert alerts[0].source_ip == "198.51.100.23"
    assert alerts[0].evidence["failed_attempts"] == 10


def test_no_alert_below_threshold():
    detector = FailedAuthDetector(window_seconds=60, failure_threshold=8)
    events, _ = _failures(n=5)
    assert detector.run(events) == []


def test_successful_logins_never_counted_as_failures():
    detector = FailedAuthDetector(window_seconds=60, failure_threshold=8)
    start = datetime(2026, 1, 1, 9, 0, 0)
    events = [
        AuthEvent(timestamp=start + timedelta(seconds=2 * i), src_ip="10.0.0.1",
                  username="alice", success=True)
        for i in range(10)
    ]
    assert detector.run(events) == []


def test_burst_followed_by_success_escalates_severity_and_notes_it():
    detector = FailedAuthDetector(window_seconds=60, failure_threshold=8, success_lookahead_seconds=30)
    failures, last_ts = _failures(n=10)
    success = AuthEvent(timestamp=last_ts + timedelta(seconds=2), src_ip="198.51.100.23",
                         username="root", success=True)
    alerts = detector.run(failures + [success])
    assert len(alerts) == 1
    assert alerts[0].severity == "high"
    assert alerts[0].evidence["followed_by_success"] is True
    assert alerts[0].evidence["success_username"] == "root"


def test_burst_without_success_is_medium_severity():
    detector = FailedAuthDetector(window_seconds=60, failure_threshold=8)
    events, _ = _failures(n=10)
    alerts = detector.run(events)
    assert alerts[0].severity == "medium"


def test_failures_spread_too_far_apart_do_not_alert():
    detector = FailedAuthDetector(window_seconds=60, failure_threshold=8)
    events, _ = _failures(n=10, gap_s=20)  # 10 failures over 180s, window is 60s
    assert detector.run(events) == []


def test_multiple_sources_each_detected_independently():
    detector = FailedAuthDetector(window_seconds=60, failure_threshold=8)
    a, _ = _failures(n=10, src="1.1.1.1")
    b, _ = _failures(n=10, src="2.2.2.2")
    alerts = detector.run(a + b)
    assert {al.source_ip for al in alerts} == {"1.1.1.1", "2.2.2.2"}


def test_usernames_tried_captured_in_evidence():
    detector = FailedAuthDetector(window_seconds=60, failure_threshold=4)
    start = datetime(2026, 1, 1, 9, 0, 0)
    events = [
        AuthEvent(timestamp=start + timedelta(seconds=2 * i), src_ip="9.9.9.9",
                  username=name, success=False)
        for i, name in enumerate(["root", "admin", "root", "test", "guest"])
    ]
    alerts = detector.run(events)
    assert set(alerts[0].evidence["usernames_tried"]) == {"root", "admin", "test", "guest"}
