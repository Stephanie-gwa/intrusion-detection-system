"""Rule: repeated failed authentication attempts from one source within a
short time window — a basic brute-force pattern.

Same sliding-window approach as the port-scan detector, but counting
consecutive-ish *failed* logins per source IP rather than distinct
ports. If a success appears from the same source shortly after a burst
of failures, it's called out specifically in the evidence — "lots of
failures followed by a success" is a materially more concerning pattern
than failures alone, since it can mean the credential-guessing worked.
"""

from dataclasses import dataclass
from datetime import timedelta
from typing import Dict, List

from ..events import Alert, AuthEvent

DEFAULT_WINDOW_SECONDS = 60
DEFAULT_FAILURE_THRESHOLD = 8
DEFAULT_SUCCESS_LOOKAHEAD_SECONDS = 30


@dataclass
class FailedAuthDetector:
    window_seconds: int = DEFAULT_WINDOW_SECONDS
    failure_threshold: int = DEFAULT_FAILURE_THRESHOLD
    success_lookahead_seconds: int = DEFAULT_SUCCESS_LOOKAHEAD_SECONDS
    rule_id: str = "failed_auth_burst"

    def run(self, events: List[AuthEvent]) -> List[Alert]:
        by_src: Dict[str, List[AuthEvent]] = {}
        for e in events:
            by_src.setdefault(e.src_ip, []).append(e)

        alerts: List[Alert] = []
        window = timedelta(seconds=self.window_seconds)
        lookahead = timedelta(seconds=self.success_lookahead_seconds)

        for src_ip, src_events in by_src.items():
            src_events = sorted(src_events, key=lambda e: e.timestamp)
            failures = [e for e in src_events if not e.success]
            n = len(failures)
            i = 0
            while i < n:
                window_end = failures[i].timestamp + window
                j = i
                while j < n and failures[j].timestamp <= window_end:
                    j += 1

                burst = failures[i:j]
                if len(burst) >= self.failure_threshold:
                    followed_by_success = [
                        e for e in src_events
                        if e.success and burst[-1].timestamp < e.timestamp <= burst[-1].timestamp + lookahead
                    ]
                    usernames = sorted({e.username for e in burst})
                    severity = "high" if followed_by_success else "medium"

                    description = (
                        f"{src_ip} generated {len(burst)} failed login attempts within a "
                        f"{self.window_seconds}-second window (threshold: {self.failure_threshold})."
                    )
                    if followed_by_success:
                        description += (
                            f" A successful login as "
                            f"'{followed_by_success[0].username}' from the same source followed "
                            f"within {self.success_lookahead_seconds}s of the burst."
                        )

                    alerts.append(Alert(
                        rule_id=self.rule_id,
                        severity=severity,
                        timestamp=burst[0].timestamp,
                        title=f"Possible brute-force login attempt from {src_ip}",
                        description=description,
                        threshold=f">= {self.failure_threshold} failed logins / {self.window_seconds}s",
                        source_ip=src_ip,
                        evidence={
                            "failed_attempts": len(burst),
                            "usernames_tried": usernames,
                            "window_start": burst[0].timestamp.isoformat(),
                            "window_end": burst[-1].timestamp.isoformat(),
                            "followed_by_success": bool(followed_by_success),
                            "success_username": (
                                followed_by_success[0].username if followed_by_success else None
                            ),
                            "sample_events": [e.to_dict() for e in burst[:20]],
                        },
                    ))
                    i = j
                else:
                    i += 1

        return alerts
