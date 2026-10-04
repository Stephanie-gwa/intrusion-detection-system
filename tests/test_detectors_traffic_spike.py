from datetime import datetime, timedelta

from nids.detectors.traffic_spike import TrafficSpikeDetector
from nids.events import ConnectionEvent


def _baseline_events(n_buckets=10, bucket_seconds=10, bytes_per_bucket=5000, start=None):
    start = start or datetime(2026, 1, 1, 9, 0, 0)
    events = []
    for b in range(n_buckets):
        t = start + timedelta(seconds=b * bucket_seconds + 1)
        events.append(ConnectionEvent(timestamp=t, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                                       dst_port=443, protocol="tcp", bytes_sent=bytes_per_bucket, flag="S"))
    return events, start


def test_detects_obvious_spike():
    detector = TrafficSpikeDetector(bucket_seconds=10, z_threshold=3.0, min_absolute_bytes=50_000)
    events, start = _baseline_events(n_buckets=10, bytes_per_bucket=5_000)
    spike_time = start + timedelta(seconds=10 * 10 + 1)
    events.append(ConnectionEvent(timestamp=spike_time, src_ip="10.0.0.1", dst_ip="10.0.0.9",
                                   dst_port=443, protocol="tcp", bytes_sent=500_000, flag="S"))

    alerts = detector.run(events)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "traffic_spike"
    assert alerts[0].evidence["bucket_total_bytes"] == 500_000


def test_no_alert_for_uniform_traffic():
    detector = TrafficSpikeDetector(bucket_seconds=10, z_threshold=3.0, min_absolute_bytes=1_000)
    events, _ = _baseline_events(n_buckets=10, bytes_per_bucket=5_000)
    assert detector.run(events) == []


def test_no_alert_when_too_few_buckets():
    detector = TrafficSpikeDetector(bucket_seconds=10)
    events, _ = _baseline_events(n_buckets=2, bytes_per_bucket=500_000)
    assert detector.run(events) == []


def test_absolute_floor_prevents_flagging_tiny_baseline_noise():
    """A near-silent capture with one bucket slightly bigger than the rest
    should not alert just because the z-score is large against a near-zero
    baseline — the min_absolute_bytes floor exists for exactly this."""
    detector = TrafficSpikeDetector(bucket_seconds=10, z_threshold=3.0, min_absolute_bytes=50_000)
    events, start = _baseline_events(n_buckets=10, bytes_per_bucket=10)
    bigger_time = start + timedelta(seconds=10 * 10 + 1)
    events.append(ConnectionEvent(timestamp=bigger_time, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                                   dst_port=443, protocol="tcp", bytes_sent=500, flag="S"))
    assert detector.run(events) == []


def test_empty_events_returns_no_alerts():
    detector = TrafficSpikeDetector()
    assert detector.run([]) == []


def test_high_severity_for_extreme_spike():
    detector = TrafficSpikeDetector(bucket_seconds=10, z_threshold=3.0, min_absolute_bytes=50_000)
    events, start = _baseline_events(n_buckets=10, bytes_per_bucket=5_000)
    spike_time = start + timedelta(seconds=10 * 10 + 1)
    events.append(ConnectionEvent(timestamp=spike_time, src_ip="10.0.0.1", dst_ip="10.0.0.9",
                                   dst_port=443, protocol="tcp", bytes_sent=5_000_000, flag="S"))
    alerts = detector.run(events)
    assert alerts[0].severity == "high"
