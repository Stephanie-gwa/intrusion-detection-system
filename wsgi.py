"""
wsgi.py — production entry point for gunicorn.

    gunicorn wsgi:app

Render (and any host with an ephemeral filesystem) resets the database on
every restart/deploy. Since this is a read-only demo dashboard, we seed it
with the project's own reproducible synthetic sample data and run the
detectors once at startup, so the dashboard always has alerts to show.
"""
from nids.db import Database
from nids.engine import DetectionEngine
from nids.sample_data import generate_all
from nids.webapp.app import create_app

db = Database(":memory:")
connection_events, auth_events = generate_all()
db.insert_connection_events(connection_events)
db.insert_auth_events(auth_events)
DetectionEngine().run(db)

app = create_app(db=db)
