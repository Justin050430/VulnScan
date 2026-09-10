"""
Scan lifecycle tests: reachability handling, status transitions and
concurrent scan isolation.

Concurrency requires a file-backed database (background worker threads use
separate DB connections), so those tests build a dedicated app whose config
points at a temporary SQLite file.
"""
import time
from datetime import timedelta

import pytest

import config as config_module
from conftest import auth, TARGET_URL
from app import create_app
from app.extensions import db as _db
from app.seeds import run_seed

UNREACHABLE = "http://127.0.0.1:5197/"   # nothing listens here


def _basic_profile_id(client, token):
    profiles = client.get("/api/scan-profiles", headers=auth(token)).get_json()["ScanProfiles"]
    return next(p for p in profiles if p["Name"] == "Basic Security Headers")["ScanProfileID"]


def test_unreachable_target_marks_scan_failed(client, dev_token):
    pid = _basic_profile_id(client, dev_token)
    resp = client.post("/api/scans", headers=auth(dev_token), json={
        "target_url": UNREACHABLE, "scan_profile_id": pid, "scan_name": "Unreachable"})
    assert resp.status_code == 202
    scan_id = resp.get_json()["Scan"]["ScanID"]
    detail = client.get(f"/api/scans/{scan_id}", headers=auth(dev_token)).get_json()["Scan"]
    assert detail["Status"] == "Failed"
    assert detail["FinishedAt"] is not None


def test_status_is_running_during_crawl(app, client, dev_token, target, monkeypatch):
    """The scan must be persisted as Running while the crawler executes."""
    from app.scanner import engine as engine_module

    observed = {}
    real_crawl = engine_module.Crawler.crawl

    def spy(self, start_url):
        from app.models import Scan

        row = _db.session.query(Scan).filter_by(Status="Running").first()
        observed["status"] = row.Status if row else None
        return real_crawl(self, start_url)

    monkeypatch.setattr(engine_module.Crawler, "crawl", spy)
    pid = _basic_profile_id(client, dev_token)
    resp = client.post("/api/scans", headers=auth(dev_token), json={
        "target_url": target, "scan_profile_id": pid, "scan_name": "Running check"})
    assert resp.status_code == 202
    assert observed.get("status") == "Running"


# ---------------------------------------------------------------------------
# Concurrency (file-backed DB + background workers)
# ---------------------------------------------------------------------------
@pytest.fixture()
def async_app(tmp_path):
    db_file = (tmp_path / "vulnscan_concurrent.db").as_posix()

    class _FileTestingConfig(config_module.TestingConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{db_file}"
        SQLALCHEMY_ENGINE_OPTIONS = {
            "connect_args": {"timeout": 30, "check_same_thread": False},
            "pool_pre_ping": True,
        }
        SCAN_ASYNC = True
        JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)

    config_module.config_by_name["filetesting"] = _FileTestingConfig
    app = create_app("filetesting")
    with app.app_context():
        from sqlalchemy import event

        @event.listens_for(_db.engine, "connect")
        def _sqlite_pragmas(dbapi_conn, _record):
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA busy_timeout=30000")
            cur.close()

        _db.create_all()
        run_seed()
        # Zero request delays so concurrent scans finish promptly in tests.
        from app.models import ScanProfile

        for profile in ScanProfile.query.all():
            profile.RequestDelayMs = 0
        _db.session.commit()
    yield app
    with app.app_context():
        _db.session.remove()
        _db.drop_all()


def _poll_scan(client, token, scan_id, timeout=90):
    deadline = time.time() + timeout
    detail = None
    while time.time() < deadline:
        detail = client.get(f"/api/scans/{scan_id}", headers=auth(token)).get_json()["Scan"]
        if detail["Status"] in ("Completed", "Failed"):
            return detail
        time.sleep(0.4)
    raise AssertionError(f"scan {scan_id} did not finish: {detail and detail['Status']}")


def test_concurrent_scans_complete_and_are_isolated(async_app, target):
    client = async_app.test_client()
    token = client.post("/api/auth/login", json={
        "email": "developer@vulnscan.local",
        "password": "Developer@VulnScan2025"}).get_json()["access_token"]

    profiles = client.get("/api/scan-profiles", headers=auth(token)).get_json()["ScanProfiles"]
    pid = next(p for p in profiles if p["Name"] == "OWASP Top 10 Full Scan")["ScanProfileID"]

    scan_ids = []
    for i in (1, 2):
        resp = client.post("/api/scans", headers=auth(token), json={
            "target_url": target, "scan_profile_id": pid, "scan_name": f"Concurrent {i}"})
        assert resp.status_code == 202
        scan_ids.append(resp.get_json()["Scan"]["ScanID"])

    details = [_poll_scan(client, token, sid) for sid in scan_ids]

    for detail in details:
        assert detail["Status"] == "Completed"
        assert detail["FindingCount"] >= 1
        assert detail["PageCount"] >= 5

    # Each scan's persisted findings must match its own detail view (isolation).
    with async_app.app_context():
        from sqlalchemy import func

        from app.models import DiscoveredPage, Finding

        for detail in details:
            db_count = (
                _db.session.query(func.count(Finding.FindingID))
                .join(DiscoveredPage, Finding.PageID == DiscoveredPage.PageID)
                .filter(DiscoveredPage.ScanID == detail["ScanID"])
                .scalar()
            )
            assert db_count == detail["FindingCount"]

    # Scan list shows both, exactly once each.
    listed = client.get("/api/scans", headers=auth(token)).get_json()["Scans"]
    listed_ids = [s["ScanID"] for s in listed]
    for sid in scan_ids:
        assert listed_ids.count(sid) == 1
