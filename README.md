# nids — a small, explainable network intrusion detection prototype

A rule-based intrusion-detection **prototype**: it ingests connection-log
and authentication-log style events, runs three clearly-defined
detectors over them, and shows every resulting alert — with its
timestamp, the rule and threshold that fired, the source IP, and the
exact supporting evidence — in a small Flask dashboard backed by
SQLite.

> **This is a learning/portfolio project, not a production IDS.** It
> has no relationship to Suricata, Zeek, or Snort, does no deep packet
> inspection, and detects exactly the three patterns listed below.
> See [What this cannot detect](#what-this-cannot-detect).

## What it detects

| Rule | Pattern | Default threshold |
|---|---|---|
| `port_scan` | One source IP touching many distinct destination ports in a short window | ≥ 15 distinct ports / 10 seconds |
| `failed_auth_burst` | One source IP generating many failed logins in a short window | ≥ 8 failed attempts / 60 seconds |
| `traffic_spike` | A time bucket's total traffic volume is a statistical outlier vs. the surrounding baseline | ≥ 3 standard deviations above baseline **and** ≥ 200,000 bytes |

Every alert records which of these fired, the exact threshold crossed,
a timestamp, and the specific input events that triggered it (up to 20
sample events plus summary counts) — nothing here is a black box.

## Quick start

```bash
# From the project root:
python3 -m venv .venv && source .venv/bin/activate   # optional but recommended
pip install -e .

# 1. Generate reproducible sample data (also already checked into sample_data/):
python3 -m nids generate-sample-data --out-dir sample_data

# 2. Load it into the database:
python3 -m nids ingest --sample --clear
#    (equivalent to: --connections sample_data/connections.csv --auth-log sample_data/auth.log)

# 3. Run the detectors:
python3 -m nids detect

# 4. Launch the dashboard:
python3 -m nids serve
# then open http://127.0.0.1:5000/
```

That's the whole demo loop. `nids.db` (a plain SQLite file in the
project root) holds everything; delete it any time to start fresh.

## CLI reference

```
nids [--db PATH] generate-sample-data [--out-dir DIR] [--seed N]
nids [--db PATH] ingest (--sample | --connections CSV --auth-log LOG) [--clear]
nids [--db PATH] detect [--clear-alerts]
nids [--db PATH] list-alerts
nids [--db PATH] serve [--host HOST] [--port PORT] [--debug]
nids [--db PATH] live --iface IFACE [--duration SECONDS] [--yes-i-own-this-network]
```

`--db` defaults to `nids.db` in the current directory and can point at
any path (or `:memory:` when used as a library) so you can keep
multiple scenarios in separate files.

## Optional live monitoring

`nids live` can capture real traffic and feed it straight into the same
detectors — but only ever on a network interface **you name explicitly
and confirm you're authorized to monitor**:

```bash
pip install -r requirements-live.txt   # installs scapy, not a default dependency
sudo python3 -m nids live --iface eth0 --duration 30
python3 -m nids detect
```

Safety properties of this path (see [`nids/live_capture.py`](nids/live_capture.py)):
- Disabled unless you pass `--iface` **and** either answer `y` to the
  interactive confirmation prompt or pass `--yes-i-own-this-network`
  explicitly (for scripted use).
- Only ever listens — it never transmits a single packet.
- Only sniffs the one interface you name, never "all interfaces".
- Always has a hard time limit (`--duration`, default 30s); it cannot
  be left running indefinitely by accident.
- Requires the optional `scapy` dependency (not installed by default)
  and typically root/administrator privileges; if either is missing it
  fails with a clear message rather than crashing.

**Only run this against an interface you own or are explicitly
authorized to monitor.** Capturing traffic on a network you don't
control or don't have permission to monitor can be unauthorized access
and quite possibly illegal where you live — this flag exists to make
that an explicit, deliberate choice, not a default.

## Project layout

```
nids/
  events.py          ConnectionEvent, AuthEvent, Alert dataclasses
  db.py              SQLite storage (stdlib sqlite3, no ORM)
  io_formats.py       CSV / sshd-log-style file reading & writing
  sample_data.py      reproducible synthetic traffic + auth-log generator
  engine.py           runs every detector, stores resulting alerts
  live_capture.py      optional, opt-in scapy-based live sniffing
  detectors/
    port_scan.py
    failed_auth.py
    traffic_spike.py
  webapp/              the Flask dashboard (templates/, static/)
  cli.py
tests/                 67 tests covering every module above
sample_data/           checked-in reproducible sample connections.csv + auth.log
examples/              saved CLI output and a JSON alert dump from the sample data
```

## How detection works

```
connections.csv ──┐                       ┌──► port_scan.py ─────┐
                   ├──► SQLite (db.py) ────┤                      ├──► alerts table ──► dashboard
auth.log ──────────┘                       ├──► failed_auth.py ───┤
                                            └──► traffic_spike.py ─┘
```

`ingest` parses files (or the built-in generator) into `ConnectionEvent`
/ `AuthEvent` records and stores them. `detect` reads those back out,
runs each detector (each one groups events — by source IP, or into
fixed time buckets — and looks for a clearly defined pattern crossing a
fixed threshold), and stores every resulting `Alert`. The dashboard is
a thin, mostly read-only view over the `alerts` table, with a "re-run
detectors" button that clears and redoes the last detection pass.

## Thresholds, and why they're set where they are

The defaults were chosen to clearly separate the embedded attack
scenarios in `sample_data/` from the embedded background traffic around
them — they are **illustrative starting points, not values validated
against real production traffic**. Expect to tune them for your own
environment:

- `port_scan`: 15 distinct ports in 10 seconds. A normal client talking
  to a handful of services rarely crosses this; a scanner sweeping
  hundreds of ports does so almost immediately.
- `failed_auth_burst`: 8 failed logins in 60 seconds. Real users
  mistyping a password a couple of times stays well under this; an
  automated credential-guessing tool blows past it in seconds.
- `traffic_spike`: ≥3 standard deviations above the other observed
  buckets, **and** at least 200,000 bytes absolute. The absolute floor
  matters — without it, a nearly-silent baseline makes even an ordinary
  bucket look like a huge statistical outlier.

All three are constructor arguments on their respective detector
classes (see `nids/detectors/*.py`), so they're easy to override from
code; a `--threshold`-style CLI flag would be a natural next step.

## False positives — what legitimately trips these rules

- **Port scan:** your own vulnerability scanner, a load balancer or
  monitoring system's health checks hitting many backend ports quickly,
  or a NAT'd office where many users' traffic appears to come from one
  public IP.
- **Failed-auth burst:** a misconfigured service retrying a stale
  credential in a loop, a shared jump host where several people mistype
  passwords around the same time, or a password-rotation rollout that
  briefly breaks automated logins everywhere at once.
- **Traffic spike:** a legitimate large backup, software update, or
  bulk data export; any workload with a naturally bursty baseline (the
  z-score test assumes buckets are roughly comparable, which isn't true
  for every environment).
- **General:** a single sustained port scan or auth-burst that happens
  to straddle more than one detection window can produce more than one
  alert for the same underlying event, rather than being merged into a
  single one (visible in the bundled sample output).

## What this cannot detect

Be specific about this before drawing any conclusion from its output:

- **No deep packet inspection.** It never looks at payload content —
  no malware signatures, no protocol anomaly detection, no TLS
  fingerprinting.
- **No low-and-slow attacks.** A scan or brute-force spread out slower
  than the detection windows (e.g. one port every few minutes) will not
  cross any threshold.
- **No distributed attacks.** Each detector groups by a single source
  IP; a scan or credential-stuffing attempt spread across many source
  IPs (a botnet) looks like ordinary, separate low-volume traffic to
  every rule here.
- **No encrypted-content analysis, no DNS tunneling detection, no
  lateral-movement/beaconing detection, no anomaly detection via machine
  learning.** None of that is implemented.
- **Only as good as its input.** Live mode's packet-to-event mapping is
  intentionally minimal (TCP/UDP, destination port, byte count); the
  file-based auth-log parser only understands one sshd-style log line
  format.
- **Thresholds are fixed and global**, not learned per-host or
  per-network, so what counts as "unusual" doesn't adapt to a specific
  environment's real baseline the way a production system would.

## Running the tests

```bash
pip install -e ".[dev]"
python3 -m pytest -v
```

67 tests cover every module: storage, file I/O round-tripping, each
detector (including true-negative and edge cases — ports spread too far
apart, failures too far apart, an absolute-floor check against a
near-silent baseline), the orchestration engine, the reproducible sample
generator (determinism is itself tested), the CLI, and the Flask
dashboard's routes. All run against in-memory SQLite and local Flask
test clients — none make a network connection or need the optional
`scapy`/live-capture path.

## Technologies used

- Python 3 standard library for all core logic: `sqlite3`, `argparse`,
  `dataclasses`, `csv`, `re`, `statistics`.
- **Flask** for the dashboard — the project's only required dependency.
- **pytest**, with 67 tests and no mocked internals — every test
  exercises real detector logic, a real (in-memory) SQLite database, or
  a real Flask test client.
- Optional: **scapy**, used only by the opt-in live-capture path.

## Portfolio notes

This project demonstrates rule-based detection logic with fully
explainable output (every alert traceable to a concrete rule, threshold,
and evidence set), a small full-stack app (Flask + SQLite + a
hand-rolled dashboard), and — importantly — a security tool that is
honest about its own limits rather than overstating what "intrusion
detection" means at this scale.

**Dashboard demo suggestions:**
- Run through the Quick Start above, then open the dashboard and click
  into the `port_scan` alert from `203.0.113.50` — point out the
  evidence block listing the 58+ distinct ports actually touched.
- Filter the alert list by severity to show the medium-vs-high framing
  (e.g. a port scan 2x past threshold is automatically escalated).
- Open the `failed_auth_burst` alert and highlight the
  `followed_by_success` evidence field — the detector specifically
  calls out when a brute-force burst appears to have succeeded.
- Click "Re-run detectors" live to show the pipeline isn't just
  pre-baked output.
- Show `nids live --iface <iface>` refusing to run without
  confirmation, then running it (on your own machine/VM) to capture a
  few seconds of real local traffic.
