"""Rule: repeated connection attempts across many distinct ports from one
source within a short time window — a basic port-scan pattern.

How it works
------------
Events are grouped by source IP. Within each group, we slide a
fixed-size time window (`window_seconds`) across the (already
time-sorted) events and count the number of *distinct destination
ports* touched inside each window. If that count reaches
`port_threshold`, we fire one alert for that source IP covering the
window where the threshold was first reached, and then skip ahead past
the whole burst so one scan doesn't produce dozens of near-duplicate
alerts.

This is intentionally one of the simplest possible port-scan heuristics
— see the README's "False positives" section for what legitimately
triggers this (load balancer health checks, a vulnerability scanner
*you* run, NAT'd offices).
"""

from dataclasses import dataclass
from datetime import timedelta
from typing import Dict, List

from ..events import Alert, ConnectionEvent

DEFAULT_WINDOW_SECONDS = 10
DEFAULT_PORT_THRESHOLD = 15


@dataclass
class PortScanDetector:
    window_seconds: int = DEFAULT_WINDOW_SECONDS
    port_threshold: int = DEFAULT_PORT_THRESHOLD
    rule_id: str = "port_scan"

    def run(self, events: List[ConnectionEvent]) -> List[Alert]:
        by_src: Dict[str, List[ConnectionEvent]] = {}
        for e in events:
            by_src.setdefault(e.src_ip, []).append(e)

        alerts: List[Alert] = []
        window = timedelta(seconds=self.window_seconds)

        for src_ip, src_events in by_src.items():
            src_events = sorted(src_events, key=lambda e: e.timestamp)
            n = len(src_events)
            i = 0
            while i < n:
                window_end = src_events[i].timestamp + window
                j = i
                ports_seen: Dict[int, ConnectionEvent] = {}
                while j < n and src_events[j].timestamp <= window_end:
                    ports_seen[src_events[j].dst_port] = src_events[j]
                    j += 1

                if len(ports_seen) >= self.port_threshold:
                    window_events = src_events[i:j]
                    dst_ips = sorted({e.dst_ip for e in window_events})
                    alerts.append(Alert(
                        rule_id=self.rule_id,
                        severity="high" if len(ports_seen) >= self.port_threshold * 2 else "medium",
                        timestamp=window_events[0].timestamp,
                        title=f"Possible port scan from {src_ip}",
                        description=(
                            f"{src_ip} touched {len(ports_seen)} distinct destination "
                            f"ports within a {self.window_seconds}-second window "
                            f"(threshold: {self.port_threshold})."
                        ),
                        threshold=f">= {self.port_threshold} distinct ports / {self.window_seconds}s",
                        source_ip=src_ip,
                        evidence={
                            "distinct_ports": len(ports_seen),
                            "destination_ips": dst_ips,
                            "window_start": window_events[0].timestamp.isoformat(),
                            "window_end": window_events[-1].timestamp.isoformat(),
                            "sample_events": [e.to_dict() for e in window_events[:20]],
                            "total_events_in_window": len(window_events),
                        },
                    ))
                    # Skip past this whole burst so a single scan doesn't
                    # generate one alert per sliding step.
                    i = j
                else:
                    i += 1

        return alerts
