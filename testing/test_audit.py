"""Security audit log endpoint tests."""
from conftest import auth


def test_audit_logs_admin_only(client, dev_token):
    assert client.get("/api/audit-logs", headers=auth(dev_token)).status_code == 403


def test_audit_logs_list_and_filters(client, admin_token):
    # perform some actions to generate logs
    client.post("/api/auth/login", json={
        "email": "admin@vulnscan.local", "password": "Admin@VulnScan2025"})
    data = client.get("/api/audit-logs", headers=auth(admin_token)).get_json()
    assert data["Total"] >= 1
    assert "Authentication" in data["Categories"]

    filtered = client.get("/api/audit-logs",
                          headers=auth(admin_token),
                          query_string={"category": "Authentication"}).get_json()
    assert all(l["Category"] == "Authentication" for l in filtered["AuditLogs"])

    searched = client.get("/api/audit-logs",
                          headers=auth(admin_token),
                          query_string={"search": "signed in"}).get_json()
    assert searched["Total"] >= 1


def test_audit_log_structure(client, admin_token):
    logs = client.get("/api/audit-logs", headers=auth(admin_token)).get_json()["AuditLogs"]
    assert logs
    log = logs[0]
    for field in ("AuditID", "EventTime", "Category", "Action", "Status", "IPAddress"):
        assert field in log
