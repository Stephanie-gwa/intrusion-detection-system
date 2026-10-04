"""Command-line interface for nids."""

import argparse
import sys
from pathlib import Path

from .db import Database
from .engine import DetectionEngine
from .io_formats import read_auth_log, read_connection_csv, write_auth_log, write_connection_csv
from .live_capture import ConfirmationRequiredError, LiveCaptureConfig, LiveCaptureUnavailable, capture_live
from .sample_data import generate_all

DEFAULT_DB_PATH = "nids.db"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nids",
        description="A small, explainable, rule-based network intrusion detection "
                     "prototype. Not a production IDS — see README.",
    )
    parser.add_argument("--db", default=DEFAULT_DB_PATH, help=f"SQLite DB path (default: {DEFAULT_DB_PATH})")
    sub = parser.add_subparsers(dest="command")

    p_gen = sub.add_parser("generate-sample-data", help="Write reproducible sample data files to disk")
    p_gen.add_argument("--out-dir", default="sample_data", help="Output directory")
    p_gen.add_argument("--seed", type=int, default=None, help="Override the random seed")

    p_ingest = sub.add_parser("ingest", help="Load connection/auth events from files into the DB")
    p_ingest.add_argument("--connections", help="Path to a connection-events CSV")
    p_ingest.add_argument("--auth-log", help="Path to an sshd-style auth log")
    p_ingest.add_argument("--sample", action="store_true", help="Ingest the built-in reproducible sample data instead of files")
    p_ingest.add_argument("--clear", action="store_true", help="Clear existing events/alerts first")

    p_detect = sub.add_parser("detect", help="Run all detectors against events already in the DB")
    p_detect.add_argument("--clear-alerts", action="store_true", help="Clear previously stored alerts first")

    p_serve = sub.add_parser("serve", help="Run the Flask dashboard")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=5000)
    p_serve.add_argument("--debug", action="store_true")

    p_live = sub.add_parser(
        "live",
        help="(Optional, opt-in) Capture live traffic on an interface you control and run detectors on it",
    )
    p_live.add_argument("--iface", required=True, help="Network interface to sniff (must be one you control)")
    p_live.add_argument("--duration", type=int, default=30, help="Seconds to capture (default: 30)")
    p_live.add_argument(
        "--yes-i-own-this-network",
        action="store_true",
        dest="confirmed",
        help="Skip the interactive confirmation prompt (for scripted/non-interactive use)",
    )

    sub.add_parser("list-alerts", help="Print stored alerts as text")

    return parser


def cmd_generate_sample_data(args) -> int:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    kwargs = {} if args.seed is None else {"seed": args.seed}
    conns, auths = generate_all(**kwargs)

    conn_path = out_dir / "connections.csv"
    auth_path = out_dir / "auth.log"
    write_connection_csv(conns, conn_path)
    write_auth_log(auths, auth_path)

    print(f"Wrote {len(conns)} connection events to {conn_path}")
    print(f"Wrote {len(auths)} auth events to {auth_path}")
    return 0


def cmd_ingest(args) -> int:
    db = Database(args.db)
    if args.clear:
        db.clear_all()

    if args.sample:
        conns, auths = generate_all()
    else:
        conns = read_connection_csv(args.connections) if args.connections else []
        auths = read_auth_log(args.auth_log) if args.auth_log else []
        if not args.connections and not args.auth_log:
            print("Nothing to ingest: pass --sample, or --connections/--auth-log.", file=sys.stderr)
            return 1

    n_conn = db.insert_connection_events(conns) if conns else 0
    n_auth = db.insert_auth_events(auths) if auths else 0
    print(f"Ingested {n_conn} connection events and {n_auth} auth events into {args.db}")
    return 0


def cmd_detect(args) -> int:
    db = Database(args.db)
    if args.clear_alerts:
        db.clear_alerts()
    alerts = DetectionEngine().run(db)
    print(f"Ran detectors: {len(alerts)} alert(s) fired and stored in {args.db}")
    for a in alerts:
        print(f"  [{a.severity:>6}] {a.rule_id:<20} {a.timestamp}  {a.title}")
    return 0


def cmd_list_alerts(args) -> int:
    db = Database(args.db)
    alerts = db.get_alerts()
    if not alerts:
        print("No alerts stored. Run `nids ingest` and `nids detect` first.")
        return 0
    for a in alerts:
        print(f"#{a['id']:<4} [{a['severity']:>6}] {a['rule_id']:<20} {a['timestamp']}  "
              f"src={a['source_ip'] or '-':<16} {a['title']}")
    return 0


def cmd_serve(args) -> int:
    from .webapp import create_app
    app = create_app(db_path=args.db)
    app.run(host=args.host, port=args.port, debug=args.debug)
    return 0


def cmd_live(args) -> int:
    confirmed = args.confirmed
    if not confirmed:
        print(
            f"You are about to capture live traffic on interface '{args.iface}' "
            f"for {args.duration} seconds.\n"
            f"Only do this on an interface YOU control and are authorized to monitor."
        )
        try:
            answer = input("Type 'y' to continue: ").strip().lower()
        except EOFError:
            answer = ""
        confirmed = answer == "y"

    config = LiveCaptureConfig(interface=args.iface, duration_seconds=args.duration)
    try:
        events = capture_live(config, confirm=confirmed)
    except ConfirmationRequiredError as exc:
        print(f"Capture cancelled: {exc}", file=sys.stderr)
        return 1
    except LiveCaptureUnavailable as exc:
        print(f"Live capture unavailable: {exc}", file=sys.stderr)
        return 1

    db = Database(args.db)
    n = db.insert_connection_events(events)
    print(f"Captured {n} connection-shaped packets from '{args.iface}'. Run `nids detect` to analyze them.")
    return 0


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    dispatch = {
        "generate-sample-data": cmd_generate_sample_data,
        "ingest": cmd_ingest,
        "detect": cmd_detect,
        "list-alerts": cmd_list_alerts,
        "serve": cmd_serve,
        "live": cmd_live,
    }
    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        return 1
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
