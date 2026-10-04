"""Orchestrates: read events out of the database, run every detector,
write resulting alerts back.
"""

from dataclasses import dataclass, field
from typing import List

from .db import Database
from .detectors import FailedAuthDetector, PortScanDetector, TrafficSpikeDetector
from .events import Alert


@dataclass
class DetectionEngine:
    port_scan: PortScanDetector = field(default_factory=PortScanDetector)
    failed_auth: FailedAuthDetector = field(default_factory=FailedAuthDetector)
    traffic_spike: TrafficSpikeDetector = field(default_factory=TrafficSpikeDetector)

    def run(self, db: Database, store: bool = True) -> List[Alert]:
        connection_events = db.get_connection_events()
        auth_events = db.get_auth_events()

        alerts: List[Alert] = []
        alerts.extend(self.port_scan.run(connection_events))
        alerts.extend(self.failed_auth.run(auth_events))
        alerts.extend(self.traffic_spike.run(connection_events))

        alerts.sort(key=lambda a: a.timestamp)

        if store and alerts:
            db.insert_alerts(alerts)

        return alerts
