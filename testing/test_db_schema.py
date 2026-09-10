"""
Database schema integrity tests.

Verifies that the eight documented ERD entities exist with the documented
columns and relationships (including the final `SecurityAuditLog.EventTime`
terminology), and that API writes genuinely persist to the database rather
than living in memory.
"""
from sqlalchemy import inspect

from conftest import auth

EXPECTED_TABLES = {
    "User": {
        "UserID", "Username", "Email", "PasswordHash", "Role",
        "IsActive", "CreatedAt", "LastLogin",
    },
    "Scan": {
        "ScanID", "ScanName", "TargetURL", "Status", "StartedAt",
        "FinishedAt", "UserID", "ScanProfileID",
    },
    "ScanProfile": {
        "ScanProfileID", "Name", "MaxDepth", "FollowExternalLinks",
        "RequestDelayMs", "MaxPages",
    },
    "ProfileModule": {"ProfileModuleID", "ScanProfileID", "VulnerabilityID"},
    "Vulnerability": {
        "VulnerabilityID", "Name", "OWASPCategory", "Description", "Impact",
        "Recommendation", "SecurityCodingPractice", "OWASPReference",
        "ReferenceURL", "IsEnabled",
    },
    "DiscoveredPage": {
        "PageID", "URL", "PageTitle", "HTTPStatus", "CrawlDepth",
        "DiscoveryOrder", "ScanID",
    },
    "Finding": {
        "FindingID", "Severity", "RiskScore", "Confidence", "RequestMethod",
        "Parameter", "Payload", "Evidence", "Status", "DetectedAt",
        "PageID", "VulnerabilityID",
    },
    "SecurityAuditLog": {
        "AuditID", "EventTime", "Category", "Action", "EntityType",
        "EntityID", "Description", "IPAddress", "Status", "UserID",
    },
}

EXPECTED_FOREIGN_KEYS = {
    "Scan": {("UserID", "User"), ("ScanProfileID", "ScanProfile")},
    "ProfileModule": {("ScanProfileID", "ScanProfile"), ("VulnerabilityID", "Vulnerability")},
    "DiscoveredPage": {("ScanID", "Scan")},
    "Finding": {("PageID", "DiscoveredPage"), ("VulnerabilityID", "Vulnerability")},
    "SecurityAuditLog": {("UserID", "User")},
}


def test_all_eight_erd_entities_exist(app):
    with app.app_context():
        from app.extensions import db

        inspector = inspect(db.engine)
        tables = set(inspector.get_table_names())
    assert set(EXPECTED_TABLES).issubset(tables)
    assert len(EXPECTED_TABLES) == 8


def test_entity_columns_match_erd(app):
    with app.app_context():
        from app.extensions import db

        inspector = inspect(db.engine)
        for table, expected_cols in EXPECTED_TABLES.items():
            actual = {c["name"] for c in inspector.get_columns(table)}
            assert expected_cols == actual, f"{table} columns differ: {actual ^ expected_cols}"


def test_security_audit_log_uses_event_time_not_legacy_event_type(app):
    with app.app_context():
        from app.extensions import db

        inspector = inspect(db.engine)
        cols = {c["name"] for c in inspector.get_columns("SecurityAuditLog")}
    assert "EventTime" in cols
    assert "EventType" not in cols  # legacy terminology must not reappear


def test_foreign_keys_match_erd(app):
    with app.app_context():
        from app.extensions import db

        inspector = inspect(db.engine)
        for table, expected in EXPECTED_FOREIGN_KEYS.items():
            actual = set()
            for fk in inspector.get_foreign_keys(table):
                for col in fk["constrained_columns"]:
                    actual.add((col, fk["referred_table"]))
            assert expected.issubset(actual), f"{table} FKs missing: {expected - actual}"


def test_unique_constraints_present(app):
    with app.app_context():
        from app.extensions import db

        inspector = inspect(db.engine)
        for table, cols in (("User", "Email"), ("User", "Username"),
                            ("Vulnerability", "Name"), ("ScanProfile", "Name")):
            uniques = inspector.get_unique_constraints(table)
            indexes = inspector.get_indexes(table)
            found = any(cols in u["column_names"] for u in uniques) or \
                any(i.get("unique") and cols in i["column_names"] for i in indexes)
            assert found, f"expected unique constraint on {table}.{cols}"

        pm_uniques = inspector.get_unique_constraints("ProfileModule")
        assert any(set(u["column_names"]) == {"ScanProfileID", "VulnerabilityID"}
                   for u in pm_uniques)


def test_api_writes_persist_to_database(app, client, admin_token):
    """A vulnerability created through the API must be readable from the DB."""
    resp = client.post("/api/vulnerabilities", headers=auth(admin_token), json={
        "Name": "Persistence Check", "OWASPCategory": "Test",
        "Description": "stored", "IsEnabled": True})
    assert resp.status_code == 201
    vid = resp.get_json()["Vulnerability"]["VulnerabilityID"]

    with app.app_context():
        from app.extensions import db
        from app.models import Vulnerability

        row = db.session.get(Vulnerability, vid)
        assert row is not None
        assert row.Name == "Persistence Check"
        assert row.Description == "stored"
