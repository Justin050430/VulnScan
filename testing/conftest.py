"""
Shared pytest fixtures for VulnScan.

Each test runs against a fresh in-memory SQLite database (models are
DB-agnostic) seeded with the reference data, so tests are deterministic and
require no external SQL Server instance.
"""
import importlib.util
import os
import sys
import threading
from pathlib import Path

import pytest
from werkzeug.serving import make_server

BACKEND = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND))

# Controlled local targets used by the scanner tests (never public hosts).
TARGET_URL = "http://127.0.0.1:5199/"
EXTERNAL_URL = "http://127.0.0.1:5198/"
VULN_APP_PATH = Path(__file__).resolve().parent / "vuln_test_app" / "app.py"

from app import create_app  # noqa: E402
from app.extensions import db as _db  # noqa: E402
from app.seeds import run_seed  # noqa: E402


@pytest.fixture()
def app():
    app = create_app("testing")
    with app.app_context():
        _db.create_all()
        run_seed()
        # Remove request delays so the suite runs quickly (test-only tweak).
        from app.models import ScanProfile

        for profile in ScanProfile.query.all():
            profile.RequestDelayMs = 0
        _db.session.commit()
    yield app
    with app.app_context():
        _db.session.remove()
        _db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def login(client, email, password):
    resp = client.post("/api/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()["access_token"]


@pytest.fixture()
def admin_token(client):
    return login(client, "admin@vulnscan.local", "Admin@VulnScan2025")


@pytest.fixture()
def dev_token(client):
    return login(client, "developer@vulnscan.local", "Developer@VulnScan2025")


def auth(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Local HTTP servers used by the scanner tests
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def external_server():
    """A separate 'out-of-scope' host that counts any request it receives."""
    from flask import Flask, jsonify

    ext = Flask("external_target")
    hits = {"count": 0}

    @ext.route("/")
    def index():
        hits["count"] += 1
        return "<html><body><h1>external</h1></body></html>"

    @ext.route("/count")
    def count():
        return jsonify(hits)

    server = make_server("127.0.0.1", 5198, ext)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield hits
    server.shutdown()


@pytest.fixture(scope="session")
def target(external_server):
    """The controlled intentionally-vulnerable target (localhost only)."""
    os.environ["VULN_TEST_EXTERNAL_URL"] = EXTERNAL_URL
    spec = importlib.util.spec_from_file_location("test_vuln_target", str(VULN_APP_PATH))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    server = make_server("127.0.0.1", 5199, mod.app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield TARGET_URL
    server.shutdown()
