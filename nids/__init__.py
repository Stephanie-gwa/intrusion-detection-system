"""
nids — a small, explainable network intrusion detection PROTOTYPE.

WHAT THIS IS
    A learning/portfolio project that ingests connection-log and
    authentication-log style events (from reproducible sample data, a
    simple CSV/log format, or — opt-in only — a live capture on an
    interface you control) and runs a small set of clearly-defined,
    rule-based detectors over them:

      - repeated connection attempts across many ports from one source
        (a basic port-scan pattern)
      - repeated failed authentication attempts from one source
        (a basic brute-force pattern)
      - unusual spikes in traffic volume relative to a recent baseline

    Every alert records which rule fired, the threshold it crossed, a
    timestamp, and the exact supporting evidence (the specific events
    that triggered it), and is stored in SQLite and shown in a small
    Flask dashboard.

WHAT THIS IS NOT
    This is not a production IDS/IPS. It has no relationship to
    Suricata, Zeek, Snort, or any commercial product, implements no
    protocol parsing beyond simple field extraction from pre-structured
    sample records, does no deep packet inspection, and detects only
    the handful of patterns listed above. See the README's
    "What this cannot detect" section before drawing any conclusions
    from its output.

SAFETY
    Live monitoring is entirely optional, off by default, and only
    ever sniffs a network interface the caller explicitly names on the
    command line after confirming they are authorized to monitor it.
    Nothing in this project scans, probes, or sends traffic to any
    other host.
"""

__version__ = "1.0.0"
