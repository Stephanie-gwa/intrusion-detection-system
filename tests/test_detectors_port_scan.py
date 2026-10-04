from datetime import datetime, timedelta

from nids.detectors.port_scan import PortScanDetector
from nids.events import ConnectionEvent


def _scan_events(n_ports=20, src="203.0.113.50", dst="10.0.0.5", start=None, gap_ms=100):
    start = start or datetime(2026, 1, 1, 9, 0, 0)
    events = []
    t = start
    for port in range(1, n_ports + 1):
        events.append(ConnectionEvent(timestamp=t, src_ip=src, dst_ip=dst, dst_port=port,
                                       protocol="tcp", bytes_sent=60, flag="S"))
        t += timedelta(milliseconds=gap_ms)
    return events


def test_detects_port_scan_above_threshold():
    detector = PortScanDetector(window_seconds=10, port_threshold=15)
    events = _scan_events(n_ports=20)  # 20 ports within ~2 seconds
    alerts = detector.run(events)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "port_scan"
    assert alerts[0].source_ip == "203.0.113.50"
    assert alerts[0].evidence["distinct_ports"] == 20


def test_no_alert_below_threshold():
    detector = PortScanDetector(window_seconds=10, port_threshold=15)
    events = _scan_events(n_ports=5)
    assert detector.run(events) == []


def test_no_alert_for_ports_spread_out_over_time():
    """Same number of distinct ports, but spread so far apart that no single
    10-second window ever contains enough of them."""
    detector = PortScanDetector(window_seconds=10, port_threshold=15)
    events = _scan_events(n_ports=20, gap_ms=2000)  # 2s apart => 20 ports over 40s
    assert detector.run(events) == []


def test_repeated_same_port_does_not_count_as_many_distinct_ports():
    detector = PortScanDetector(window_seconds=10, port_threshold=15)
    start = datetime(2026, 1, 1, 9, 0, 0)
    events = [
        ConnectionEvent(timestamp=start + timedelta(milliseconds=100 * i), src_ip="1.2.3.4",
                         dst_ip="10.0.0.5", dst_port=80, protocol="tcp", bytes_sent=60, flag="S")
        for i in range(30)
    ]
    assert detector.run(events) == []


def test_normal_background_traffic_fires_nothing():
    detector = PortScanDetector()
    start = datetime(2026, 1, 1, 9, 0, 0)
    events = [
        ConnectionEvent(timestamp=start + timedelta(seconds=30 * i), src_ip="10.0.0.1",
                         dst_ip="10.0.0.2", dst_port=[22, 80, 443][i % 3], protocol="tcp",
                         bytes_sent=500, flag="S")
        for i in range(10)
    ]
    assert detector.run(events) == []


def test_multiple_sources_scanning_both_detected():
    detector = PortScanDetector(window_seconds=10, port_threshold=15)
    events = _scan_events(n_ports=20, src="1.1.1.1") + _scan_events(n_ports=20, src="2.2.2.2")
    alerts = detector.run(events)
    assert {a.source_ip for a in alerts} == {"1.1.1.1", "2.2.2.2"}


def test_high_severity_for_very_large_scan():
    detector = PortScanDetector(window_seconds=10, port_threshold=15)
    events = _scan_events(n_ports=40, gap_ms=50)  # >= 2x threshold
    alerts = detector.run(events)
    assert alerts[0].severity == "high"


def test_evidence_includes_sample_events_and_window_bounds():
    detector = PortScanDetector(window_seconds=10, port_threshold=15)
    events = _scan_events(n_ports=20)
    alerts = detector.run(events)
    ev = alerts[0].evidence
    assert "window_start" in ev and "window_end" in ev
    assert len(ev["sample_events"]) <= 20
    assert ev["sample_events"][0]["src_ip"] == "203.0.113.50"
