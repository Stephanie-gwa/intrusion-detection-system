"""Rule: unusual traffic volume spikes relative to a recent baseline.

How it works
------------
Connection events are bucketed into fixed-size time windows
(`bucket_seconds`). For each bucket we compute total bytes transferred
and total connection count. A bucket is flagged if its byte total
exceeds `mean + z_threshold * stdev` of the *other* buckets' byte
totals (a simple z-score outlier test), AND its byte total is at least
`min_absolute_bytes` — the absolute floor exists so that a perfectly
quiet capture (tiny mean, tiny stdev) doesn't flag an ordinary bucket
just because it's a few standard deviations above an almost-zero
baseline.

This is a simple statistical heuristic, not a trained anomaly-detection
model — see the README for what that means for false positives (e.g. a
legitimate large backup or software update will trip it too).
"""

import statistics
from dataclasses import dataclass
from datetime import timedelta
from typing import Dict, List

from ..events import Alert, ConnectionEvent

DEFAULT_BUCKET_SECONDS = 10
DEFAULT_Z_THRESHOLD = 3.0
DEFAULT_MIN_ABSOLUTE_BYTES = 200_000


@dataclass
class TrafficSpikeDetector:
    bucket_seconds: int = DEFAULT_BUCKET_SECONDS
    z_threshold: float = DEFAULT_Z_THRESHOLD
    min_absolute_bytes: int = DEFAULT_MIN_ABSOLUTE_BYTES
    rule_id: str = "traffic_spike"

    def run(self, events: List[ConnectionEvent]) -> List[Alert]:
        if not events:
            return []

        events = sorted(events, key=lambda e: e.timestamp)
        bucket = timedelta(seconds=self.bucket_seconds)
        start = events[0].timestamp

        buckets: Dict[int, List[ConnectionEvent]] = {}
        for e in events:
            idx = int((e.timestamp - start) / bucket)
            buckets.setdefault(idx, []).append(e)

        bucket_bytes = {idx: sum(e.bytes_sent for e in evs) for idx, evs in buckets.items()}
        if len(bucket_bytes) < 3:
            # Not enough buckets to establish any meaningful baseline.
            return []

        alerts: List[Alert] = []
        all_totals = list(bucket_bytes.values())

        for idx, total in bucket_bytes.items():
            others = [v for i, v in bucket_bytes.items() if i != idx]
            if len(others) < 2:
                continue
            mean_other = statistics.mean(others)
            stdev_other = statistics.pstdev(others) if len(others) > 1 else 0.0

            if stdev_other == 0:
                is_outlier = total > mean_other and total >= self.min_absolute_bytes
                z = float("inf") if is_outlier else 0.0
            else:
                z = (total - mean_other) / stdev_other
                is_outlier = z >= self.z_threshold and total >= self.min_absolute_bytes

            if is_outlier:
                bucket_events = buckets[idx]
                window_start = start + idx * bucket
                window_end = window_start + bucket
                src_ips = sorted({e.src_ip for e in bucket_events})
                dst_ips = sorted({e.dst_ip for e in bucket_events})

                alerts.append(Alert(
                    rule_id=self.rule_id,
                    severity="high" if total >= self.min_absolute_bytes * 3 else "medium",
                    timestamp=window_start,
                    title="Unusual traffic volume spike",
                    description=(
                        f"{total:,} bytes transferred in a {self.bucket_seconds}-second "
                        f"window ({len(bucket_events)} connections), "
                        f"compared to a baseline average of {mean_other:,.0f} bytes "
                        f"across the other {len(others)} windows observed."
                    ),
                    threshold=(
                        f">= {self.z_threshold} std. deviations above baseline AND "
                        f">= {self.min_absolute_bytes:,} bytes"
                    ),
                    source_ip=src_ips[0] if len(src_ips) == 1 else None,
                    evidence={
                        "bucket_total_bytes": total,
                        "bucket_connection_count": len(bucket_events),
                        "baseline_mean_bytes": mean_other,
                        "baseline_stdev_bytes": stdev_other,
                        "z_score": z if z != float("inf") else None,
                        "window_start": window_start.isoformat(),
                        "window_end": window_end.isoformat(),
                        "source_ips": src_ips,
                        "destination_ips": dst_ips,
                        "sample_events": [e.to_dict() for e in bucket_events[:20]],
                    },
                ))

        return alerts
