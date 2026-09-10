"""
Integration tests against a REAL Microsoft SQL Server instance.

These tests verify SQL-Server-specific behaviour (transactions, foreign keys,
unique constraints, concurrent writes and concurrent scans) rather than
assuming SQLite behaves identically.  They are skipped automatically when no
SQL Server/LocalDB instance is reachable (e.g. in a plain Linux CI runner).

Environment overrides:
    MSSQL_TEST_SERVER    (default: (localdb)\\MSSQLLocalDB)
    MSSQL_TEST_DATABASE  (default: VulnScanTest)
"""
import os
import time

import pytest

from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

import config as config_module
from conftest import auth, TARGET_URL
from app import create_app
from app.extensions import db as _db
from app.seeds import run_seed

pytestmark = pytest.mark.mssql


def _urls():
    server = os.getenv("MSSQL_TEST_SERVER", r"(localdb)\MSSQLLocalDB")
    database = os.getenv("MSSQL_TEST_DATABASE", "VulnScanTest")
    driver = os.getenv("MSSQL_DRIVER", "ODBC Driver 17 for SQL Server").replace(" ", "+")
    opts = f"driver={driver}&trusted_connection=yes&Encrypt=no&TrustServerCertificate=yes"
    return (f"mssql+pyodbc://@{server}/master?{opts}",
            f"mssql+pyodbc://@{server}/{database}?{opts}",
            database)


@pytest.fixture(scope="module")
def mssql_app():
    master_url, target_url, database = _urls()
    try:
        # CREATE DATABASE cannot run inside a transaction -> AUTOCOMMIT.
        engine = create_engine(master_url, isolation_level="AUTOCOMMIT")
        with engine.connect() as conn:
            conn.exec_driver_sql(
                f"IF DB_ID('{database}') IS NULL CREATE DATABASE [{database}]")
        engine.dispose()
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"SQL Server not available: {exc.__class__.__name__}: {exc}")

    class _MssqlTestConfig(config_module.TestingConfig):
        SQLALCHEMY_DATABASE_URI = target_url
        SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True, "pool_recycle": 1800}
        SCAN_ASYNC = True

    config_module.config_by_name["mssqltest"] = _MssqlTestConfig
    app = create_app("mssqltest")
    with app.app_context():
        _db.drop_all()
        _db.create_all()
        run_seed()
        from app.models import ScanProfile

        for profile in ScanProfile.query.all():
            profile.RequestDelayMs = 0
        _db.session.commit()
    yield app
    with app.app_context():
        _db.session.remove()
        _db.drop_all()


@pytest.fixture()
def mssql_client(mssql_app):
    return mssql_app.test_client()


def _login(client, email, password):
    resp = client.post("/api/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()["access_token"]


def test_dialect_is_sql_server(mssql_app):
    with mssql_app.app_context():
        assert _db.engine.dialect.name == "mssql"


def test_unique_constraints_enforced(mssql_client):
    token = _login(mssql_client, "admin@vulnscan.local", "Admin@VulnScan2025")
    first = mssql_client.post("/api/users", headers=auth(token), json={
        "username": "uniqueuser", "email": "unique@vulnscan.local",
        "password": "Unique@12345", "role": "Developer"})
    assert first.status_code == 201
    duplicate = mssql_client.post("/api/users", headers=auth(token), json={
        "username": "uniqueuser2", "email": "unique@vulnscan.local",
        "password": "Unique@12345", "role": "Developer"})
    assert duplicate.status_code == 400


def test_foreign_key_enforced(mssql_app):
    with mssql_app.app_context():
        from app.models import Finding, Vulnerability

        vuln = Vulnerability.query.first()
        orphan = Finding(Severity="Low", PageID=99999999,
                         VulnerabilityID=vuln.VulnerabilityID)
        _db.session.add(orphan)
        with pytest.raises(IntegrityError):
            _db.session.commit()
        _db.session.rollback()


def test_transaction_rollback(mssql_app):
    with mssql_app.app_context():
        from app.models import User

        before = User.query.count()
        user = User(Username="rollbackuser", Email="rollback@vulnscan.local",
                    Role="Developer")
        user.set_password("Rollback@123")
        _db.session.add(user)
        _db.session.rollback()
        assert User.query.count() == before


def test_profile_delete_blocked_when_referenced(mssql_app, mssql_client, target):
    admin = _login(mssql_client, "admin@vulnscan.local", "Admin@VulnScan2025")
    dev = _login(mssql_client, "developer@vulnscan.local", "Developer@VulnScan2025")
    profiles = mssql_client.get("/api/scan-profiles", headers=auth(dev)).get_json()["ScanProfiles"]
    profile = next(p for p in profiles if p["Name"] == "Basic Security Headers")
    # create a scan referencing this profile (synchronous in tests)
    resp = mssql_client.post("/api/scans", headers=auth(dev), json={
        "target_url": target, "scan_profile_id": profile["ScanProfileID"],
        "scan_name": "FK profile test"})
    assert resp.status_code == 202
    # now deleting the profile must be refused
    resp = mssql_client.delete(f"/api/scan-profiles/{profile['ScanProfileID']}",
                               headers=auth(admin))
    assert resp.status_code == 400


def test_concurrent_scans_on_sql_server(mssql_app, mssql_client, target):
    dev = _login(mssql_client, "developer@vulnscan.local", "Developer@VulnScan2025")
    profiles = mssql_client.get("/api/scan-profiles", headers=auth(dev)).get_json()["ScanProfiles"]
    pid = next(p for p in profiles if p["Name"] == "OWASP Top 10 Full Scan")["ScanProfileID"]

    scan_ids = []
    for i in (1, 2, 3):
        resp = mssql_client.post("/api/scans", headers=auth(dev), json={
            "target_url": target, "scan_profile_id": pid,
            "scan_name": f"SQL Server concurrent {i}"})
        assert resp.status_code == 202
        scan_ids.append(resp.get_json()["Scan"]["ScanID"])

    deadline = time.time() + 120
    details = {}
    while time.time() < deadline and len(details) < len(scan_ids):
        for sid in scan_ids:
            if sid in details:
                continue
            detail = mssql_client.get(f"/api/scans/{sid}", headers=auth(dev)).get_json()["Scan"]
            if detail["Status"] in ("Completed", "Failed"):
                details[sid] = detail
        time.sleep(0.4)

    assert len(details) == len(scan_ids)
    for detail in details.values():
        assert detail["Status"] == "Completed"
        assert detail["FindingCount"] >= 1
