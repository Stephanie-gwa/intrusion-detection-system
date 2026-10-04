"""The Flask dashboard: a small read-only UI over the alerts/events
already stored in SQLite by `nids ingest` + `nids detect`.

Nothing in this app writes to the database except the one-click
"re-run detectors" action on the index page, which just calls the same
DetectionEngine used by the CLI.
"""

from pathlib import Path
from typing import Optional, Union

from flask import Flask, abort, redirect, render_template, request, url_for

from ..db import Database
from ..engine import DetectionEngine

TEMPLATE_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"


def create_app(db_path: Union[str, Path] = "nids.db", db: Optional[Database] = None) -> Flask:
    app = Flask(
        __name__,
        template_folder=str(TEMPLATE_DIR),
        static_folder=str(STATIC_DIR),
    )

    # A Database can be injected directly (tests, in-memory DBs); otherwise
    # open the given path. Kept on app.config rather than a module global so
    # multiple app instances (e.g. in tests) don't share state.
    app.config["NIDS_DB"] = db if db is not None else Database(db_path)

    def get_db() -> Database:
        return app.config["NIDS_DB"]

    @app.route("/")
    def index():
        rule_id = request.args.get("rule_id") or None
        severity = request.args.get("severity") or None
        alerts = get_db().get_alerts(rule_id=rule_id, severity=severity)
        summary = get_db().summary()
        return render_template(
            "index.html",
            alerts=alerts,
            summary=summary,
            active_rule=rule_id,
            active_severity=severity,
        )

    @app.route("/alert/<int:alert_id>")
    def alert_detail(alert_id: int):
        alert = get_db().get_alert(alert_id)
        if alert is None:
            abort(404)
        return render_template("alert_detail.html", alert=alert)

    @app.route("/rerun", methods=["POST"])
    def rerun():
        # Re-running detectors against the same stored events would
        # otherwise duplicate every alert; clear old alerts first so the
        # dashboard always reflects exactly one detection pass.
        database = get_db()
        database.clear_alerts()
        DetectionEngine().run(database, store=True)
        return redirect(url_for("index"))

    @app.route("/healthz")
    def healthz():
        return {"status": "ok"}

    return app
