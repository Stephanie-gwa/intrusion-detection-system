"""Reproducible sample data generation.

Rather than depending on a real packet capture (which would need a
parsing library and would not be reproducible across runs), this module
generates deterministic, seeded synthetic data representing exactly the
patterns this prototype is built to detect, plus a baseline of ordinary
"nothing interesting happening" traffic around them. Every run with the
same seed produces byte-identical output, which is what makes the
bundled sample_data/ files and the test suite reliable.

Three scenarios are generated:
    - normal background traffic: a handful of internal hosts making a
      few ordinary connections to common ports, and a few successful
      logins.
    - a port scan: one source IP probing many distinct ports on one
      destination in a short window.
    - an authentication brute-force: one source IP sending many failed
      logins against one destination in a short window, then (optionally)
      one success.
    - a traffic spike: a short burst of unusually large/numerous
      connections from otherwise-normal hosts.
"""

import random
from datetime import datetime, timedelta
from typing import List, Tuple

from .events import AuthEvent, ConnectionEvent

DEFAULT_SEED = 1337
BASE_TIME = datetime(2026, 1, 15, 9, 0, 0)

COMMON_PORTS = (22, 25, 53, 80, 443, 3306, 8080)
INTERNAL_HOSTS = ("10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8")
USERNAMES = ("alice", "bob", "svc-backup", "root")


def generate_connection_events(seed: int = DEFAULT_SEED) -> List[ConnectionEvent]:
    """A reproducible stream of connection events: background traffic plus
    one embedded port-scan burst and one embedded traffic-spike burst."""
    rng = random.Random(seed)
    events: List[ConnectionEvent] = []

    # --- background traffic: ordinary, low-volume, spread out ---
    t = BASE_TIME
    for _ in range(40):
        t += timedelta(seconds=rng.randint(5, 40))
        src = rng.choice(INTERNAL_HOSTS)
        dst = rng.choice(INTERNAL_HOSTS)
        if dst == src:
            continue
        events.append(ConnectionEvent(
            timestamp=t,
            src_ip=src,
            dst_ip=dst,
            dst_port=rng.choice(COMMON_PORTS),
            protocol="tcp",
            bytes_sent=rng.randint(200, 4000),
            flag="S",
        ))

    # --- embedded port scan: one external IP hits many ports on one host fast ---
    scan_start = BASE_TIME + timedelta(minutes=12)
    scanner_ip = "203.0.113.50"  # RFC 5737 documentation range — not a real host
    target_ip = "10.0.0.5"
    scan_ports = list(range(1, 1025, 7))  # 147 distinct ports
    t = scan_start
    for port in scan_ports:
        t += timedelta(milliseconds=rng.randint(50, 300))
        events.append(ConnectionEvent(
            timestamp=t,
            src_ip=scanner_ip,
            dst_ip=target_ip,
            dst_port=port,
            protocol="tcp",
            bytes_sent=rng.randint(40, 80),
            flag="S",
        ))

    # --- more background traffic after the scan ---
    t = scan_start + timedelta(minutes=5)
    for _ in range(20):
        t += timedelta(seconds=rng.randint(5, 40))
        src = rng.choice(INTERNAL_HOSTS)
        dst = rng.choice(INTERNAL_HOSTS)
        if dst == src:
            continue
        events.append(ConnectionEvent(
            timestamp=t,
            src_ip=src,
            dst_ip=dst,
            dst_port=rng.choice(COMMON_PORTS),
            protocol="tcp",
            bytes_sent=rng.randint(200, 4000),
            flag="S",
        ))

    # --- embedded traffic spike: a short, dense burst of large transfers ---
    spike_start = BASE_TIME + timedelta(minutes=30)
    t = spike_start
    for _ in range(80):
        t += timedelta(milliseconds=rng.randint(20, 150))
        events.append(ConnectionEvent(
            timestamp=t,
            src_ip=rng.choice(INTERNAL_HOSTS),
            dst_ip="10.0.0.9",
            dst_port=443,
            protocol="tcp",
            bytes_sent=rng.randint(50_000, 120_000),
            flag="S",
        ))

    events.sort(key=lambda e: e.timestamp)
    return events


def generate_auth_events(seed: int = DEFAULT_SEED) -> List[AuthEvent]:
    """A reproducible stream of auth events: background logins plus one
    embedded brute-force burst."""
    rng = random.Random(seed + 1)
    events: List[AuthEvent] = []

    # --- background: a few ordinary successful logins ---
    t = BASE_TIME
    for _ in range(10):
        t += timedelta(minutes=rng.randint(2, 15))
        events.append(AuthEvent(
            timestamp=t,
            src_ip=rng.choice(INTERNAL_HOSTS),
            username=rng.choice(USERNAMES),
            success=True,
        ))

    # --- embedded brute-force: one external IP, many failed attempts fast ---
    brute_start = BASE_TIME + timedelta(minutes=20)
    attacker_ip = "198.51.100.23"  # RFC 5737 documentation range
    t = brute_start
    for i in range(25):
        t += timedelta(seconds=rng.randint(1, 4))
        events.append(AuthEvent(
            timestamp=t,
            src_ip=attacker_ip,
            username=rng.choice(("root", "admin", "test", "user")),
            success=False,
        ))
    # one eventual success — the scenario a brute-force detector most needs to catch
    t += timedelta(seconds=2)
    events.append(AuthEvent(timestamp=t, src_ip=attacker_ip, username="root", success=True))

    # --- more background logins afterward ---
    t = brute_start + timedelta(minutes=10)
    for _ in range(5):
        t += timedelta(minutes=rng.randint(2, 10))
        events.append(AuthEvent(
            timestamp=t,
            src_ip=rng.choice(INTERNAL_HOSTS),
            username=rng.choice(USERNAMES),
            success=True,
        ))

    events.sort(key=lambda e: e.timestamp)
    return events


def generate_all(seed: int = DEFAULT_SEED) -> Tuple[List[ConnectionEvent], List[AuthEvent]]:
    return generate_connection_events(seed), generate_auth_events(seed)
