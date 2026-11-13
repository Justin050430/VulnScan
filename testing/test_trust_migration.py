"""Schema tests: the frozen core ERD is untouched and additive tables exist."""
import pytest
from sqlalchemy import inspect

from app.extensions import db
from app.models import CORE_ENTITIES, TRUST_ENTITIES

#: Exact column sets of the frozen eight core entities (ERD contract).
CORE_COLUMNS = {
    "User": {
        "UserID", "Username", "Email", "PasswordHash", "Role", "IsActive",
        "CreatedAt", "LastLogin",
    },
    "Scan": {
        "ScanID", "ScanName", "TargetURL", "Status", "StartedAt", "FinishedAt",
        "UserID", "ScanProfileID",
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
        "Parameter", "Payload", "Evidence", "Status", "DetectedAt", "PageID",
        "VulnerabilityID",
    },
    "SecurityAuditLog": {
        "AuditID", "EventTime", "Category", "Action", "EntityType", "EntityID",
        "Description", "IPAddress", "Status", "UserID",
    },
}


def test_core_erd_tables_and_columns_unchanged(app):
    with app.app_context():
        inspector = inspect(db.engine)
        tables = set(inspector.get_table_names())
        for entity in CORE_ENTITIES:
            assert entity in tables, f"missing core table {entity}"
            columns = {c["name"] for c in inspector.get_columns(entity)}
            assert columns == CORE_COLUMNS[entity], entity


def test_trust_boundary_tables_present(app):
    with app.app_context():
        tables = set(inspect(db.engine).get_table_names())
        for entity in TRUST_ENTITIES:
            assert entity in tables, f"missing trust table {entity}"


def test_trust_scan_context_is_additive(app):
    with app.app_context():
        inspector = inspect(db.engine)
        columns = {c["name"] for c in inspector.get_columns("TrustScanContext")}
        assert columns == {
            "ScanID", "OrganisationID", "ProjectID", "AssetID", "AttestationID",
            "CreditID", "StartedByUserID", "CreatedAt",
        }
        # The bridge table points at the core Scan table without changing it.
        fks = inspector.get_foreign_keys("TrustScanContext")
        assert any(fk["referred_table"] == "Scan" for fk in fks)


def test_one_active_attestation_per_asset_index(app):
    with app.app_context():
        inspector = inspect(db.engine)
        indexes = {i["name"] for i in inspector.get_indexes("TrustAuthorizationAttestation")}
        assert "ux_trust_attestation_active_asset" in indexes


def test_one_active_redemption_per_credit_index(app):
    with app.app_context():
        inspector = inspect(db.engine)
        indexes = {i["name"] for i in inspector.get_indexes("TrustCreditRedemption")}
        assert "ux_trust_redemption_active_credit" in indexes


def test_missing_trust_schema_fails_closed(app, client, admin_token):
    """An un-migrated database must answer 503, never a generic 500."""
    from testing.trust_helpers import bearer

    with app.app_context():
        db.drop_all()

    response = client.get("/api/v1/organisations", headers=bearer(admin_token))
    assert response.status_code == 503
    body = response.get_json()
    assert body["code"] == "TRUST_BOUNDARY_UNAVAILABLE"
    assert "flask --app run.py db upgrade" in body["message"]
    assert body["details"]["missing_migration"] == "c4d8f1a2b6e9_temporary_scan_credentials"


def test_trust_schema_available_after_migration(app):
    from app.trust.schema import available

    with app.app_context():
        assert available() is True


def test_missing_column_is_reported_with_the_exact_migration():
    """
    A database that has every Trust table but an older column set must be
    reported as a missing column, not as a generic server error.
    """
    from app.trust.schema import REQUIRED_COLUMNS, check_schema, missing_schema_response

    class _Inspector:
        """Inspector stub: all tables exist, InviteEmail does not."""

        def get_table_names(self):
            from app.models import TRUST_ENTITIES

            return list(TRUST_ENTITIES)

        def get_columns(self, table):
            columns = {"OrganisationMembershipID", "ProjectMembershipID"}
            columns |= {
                name
                for name in REQUIRED_COLUMNS.get(table, {})
                if name != "InviteEmail"
            }
            return [{"name": name} for name in columns]

    missing_tables, missing_columns = check_schema(_Inspector())
    assert missing_tables == []
    assert {item["column"] for item in missing_columns} == {"InviteEmail"}

    payload, status = missing_schema_response(
        {"missing_tables": missing_tables, "missing_columns": missing_columns}
    )
    assert status == 503
    assert payload["code"] == "TRUST_BOUNDARY_UNAVAILABLE"
    assert "InviteEmail" in payload["message"]
    assert payload["details"]["missing_migration"] == "d9f2a4c8b1e7_invitation_email"


def test_complete_schema_reports_no_problem(app):
    from app.trust.schema import problem

    with app.app_context():
        assert problem() is None
