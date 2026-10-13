"""Authentication, JWT and RBAC tests."""
from conftest import auth


def test_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_health_reports_database_readiness(client):
    """The probe distinguishes liveness from database readiness."""
    body = client.get("/api/health").get_json()
    assert body["status"] == "ok"
    assert body["database"] == "ok"


def test_health_reports_degraded_when_database_unavailable(app, client, monkeypatch):
    """
    Regression: /api/health must act as a readiness probe.  It used to answer
    `200 ok` even when the database was unreachable.
    """
    from sqlalchemy.exc import OperationalError

    from app.extensions import db as real_db

    class _FailingSession:
        """Proxy whose execute() always fails; everything else delegates."""

        def execute(self, *args, **kwargs):
            raise OperationalError("SELECT 1", {}, Exception("down"))

        def __getattr__(self, name):
            return getattr(real_db.session, name)

    class _DbProxy:
        session = _FailingSession()

        def __getattr__(self, name):
            return getattr(real_db, name)

    import app.extensions as extensions

    monkeypatch.setattr(extensions, "db", _DbProxy())
    resp = client.get("/api/health")
    assert resp.status_code == 503
    body = resp.get_json()
    assert body["status"] == "degraded"
    assert body["database"] == "unavailable"


def test_login_success(client):
    resp = client.post("/api/auth/login", json={
        "email": "developer@vulnscan.local",
        "password": "Developer@VulnScan2025",
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["access_token"]
    assert data["user"]["Role"] == "Developer"


def test_login_wrong_password(client):
    resp = client.post("/api/auth/login", json={
        "email": "developer@vulnscan.local",
        "password": "wrong-password",
    })
    assert resp.status_code == 401


def test_login_unknown_email(client):
    resp = client.post("/api/auth/login", json={
        "email": "nobody@vulnscan.local",
        "password": "whatever123",
    })
    assert resp.status_code == 401


def test_login_requires_fields(client):
    assert client.post("/api/auth/login", json={"email": ""}).status_code == 401


def test_protected_endpoint_requires_token(client):
    resp = client.get("/api/users")
    assert resp.status_code == 401


def test_rbac_developer_cannot_list_users(client, dev_token):
    resp = client.get("/api/users", headers=auth(dev_token))
    assert resp.status_code == 403


def test_rbac_admin_can_list_users(client, admin_token):
    resp = client.get("/api/users", headers=auth(admin_token))
    assert resp.status_code == 200


def test_developer_cannot_create_profiles(client, dev_token):
    resp = client.post("/api/scan-profiles", headers=auth(dev_token), json={"name": "X"})
    assert resp.status_code == 403


def test_developer_cannot_post_vulnerabilities(client, dev_token):
    resp = client.post("/api/vulnerabilities", headers=auth(dev_token), json={"Name": "X"})
    assert resp.status_code == 403


def test_developer_cannot_read_audit_logs(client, dev_token):
    resp = client.get("/api/audit-logs", headers=auth(dev_token))
    assert resp.status_code == 403


def test_logout_revokes_token(client, admin_token):
    resp = client.post("/api/auth/logout", headers=auth(admin_token))
    assert resp.status_code == 200
    # Reusing the same token must now fail.
    resp = client.get("/api/audit-logs", headers=auth(admin_token))
    assert resp.status_code == 401


def test_google_not_configured(client):
    # No Google credentials in the test environment -> clear error, no crash.
    resp = client.get("/api/auth/google/url")
    assert resp.status_code == 200
    assert resp.get_json()["configured"] is False

    resp = client.post("/api/auth/google", json={"code": "abc"})
    assert resp.status_code == 503


def test_login_audit_recorded(client):
    client.post("/api/auth/login", json={
        "email": "developer@vulnscan.local", "password": "Developer@VulnScan2025"})
    # failed attempt too
    client.post("/api/auth/login", json={
        "email": "developer@vulnscan.local", "password": "bad"})
    # admin views logs
    token = _login_admin(client)
    logs = client.get("/api/audit-logs", headers=auth(token)).get_json()["AuditLogs"]
    actions = [l["Action"] for l in logs]
    assert "LOGIN_SUCCESS" in actions
    assert "LOGIN_FAILED" in actions


def _login_admin(client):
    resp = client.post("/api/auth/login", json={
        "email": "admin@vulnscan.local", "password": "Admin@VulnScan2025"})
    return resp.get_json()["access_token"]
