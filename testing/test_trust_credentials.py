"""Temporary authenticated-scan credential tests.

Covers maker-checker approval, encryption at rest, single-use binding,
form login (including CSRF), credit release on failed authentication,
authenticated crawling/detection, retests and secret redaction.
"""
import pytest

from app.extensions import db
from app.models import (
    TrustAuditEvent,
    TrustScanCredential,
    TrustScanCredentialBinding,
)
from testing.trust_helpers import (
    bearer,
    buy_credit,
    create_user,
    full_scenario,
    profile_id,
)

try:  # PyMuPDF provides both module names depending on version
    import pymupdf as _pdf
except ImportError:  # pragma: no cover
    import fitz as _pdf


def _pdf_text(response):
    doc = _pdf.open(stream=response.data, filetype="pdf")
    try:
        return "\n".join(page.get_text() for page in doc)
    finally:
        doc.close()


@pytest.fixture()
def trust_app(app):
    app.config.update(
        TRUST_BOUNDARY_MODE="enforce",
        SCAN_ASYNC=False,
        TRUST_CREDENTIAL_ALLOW_SELF_APPROVAL=False,
        TRUST_CREDENTIAL_TEST_COOLDOWN_SECONDS=0,
        TRUST_CREDENTIAL_DEFAULT_HOURS=4,
        TRUST_CREDENTIAL_MAX_HOURS=24,
    )
    return app


@pytest.fixture()
def auth_scenario(trust_app, client, admin_token, dev_token, target):
    """Project with a second PROJECT_OWNER available to approve credentials."""
    email, approver_token = create_user(client, admin_token)
    scenario = full_scenario(
        trust_app,
        client,
        admin_token,
        dev_token,
        target_url="http://localhost:5199/dashboard",
        extra_member_role="PROJECT_OWNER",
        extra_member_token=approver_token,
        extra_member_email=email,
    )
    scenario["approver_token"] = approver_token
    scenario["approver_email"] = email
    return scenario


def _credential_payload(scenario, **overrides):
    payload = {
        "name": "Pentest test account",
        "auth_type": "FORM",
        "login_url": "http://localhost:5199/login",
        "username": "pentester@example.test",
        "password": "Temporary!Pass123",
        "success_url_contains": "/dashboard",
        "expires_in_minutes": 60,
    }
    payload.update(overrides)
    return payload


def _create(client, token, scenario, **overrides):
    response = client.post(
        f"/api/v1/projects/{scenario['project']['ProjectID']}"
        f"/assets/{scenario['asset']['AssetID']}/credentials",
        json=_credential_payload(scenario, **overrides),
        headers=bearer(token),
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()["Credential"]


def _approve(client, token, scenario, credential_id):
    return client.post(
        f"/api/v1/projects/{scenario['project']['ProjectID']}"
        f"/credentials/{credential_id}/approve",
        json={"acknowledge": True},
        headers=bearer(token),
    )


def _start(client, token, scenario, credential_id=None, credit=None,
           target_url=None):
    payload = {
        "asset_id": scenario["asset"]["AssetID"],
        "scan_profile_id": profile_id(client, token),
        "credit_id": (credit or scenario["credit"])["CreditUUID"],
        "target_url": target_url or scenario["target_url"],
    }
    if credential_id is not None:
        payload["credential_id"] = credential_id
    return client.post(
        f"/api/v1/projects/{scenario['project']['ProjectID']}/scans",
        json=payload,
        headers=bearer(token),
    )


def _credential_row(app, credential_id):
    with app.app_context():
        return db.session.get(TrustScanCredential, int(credential_id))


# ------------------------------------------------------------------ lifecycle
def test_create_encrypts_secret_and_never_returns_it(trust_app, client,
                                                     auth_scenario, dev_token):
    credential = _create(client, dev_token, auth_scenario)
    assert credential["Status"] == "PendingApproval"
    assert credential["HasSecret"] is True
    assert "password" not in {k.lower() for k in credential}
    assert "secret" not in {k.lower() for k in credential}
    assert credential["Username"] == "pentester@example.test"

    row = _credential_row(trust_app, credential["CredentialID"])
    assert row.SecretEncrypted
    assert "Temporary!Pass123" not in row.SecretEncrypted
    from app.trust import credential_crypto

    with trust_app.app_context():
        assert credential_crypto.decrypt_secret(row.SecretEncrypted) == (
            "Temporary!Pass123"
        )

    events = client.get(
        f"/api/v1/projects/{auth_scenario['project']['ProjectID']}/audit-events",
        headers=bearer(dev_token),
    ).get_json()["Events"]
    encoded = " ".join(str(e.get("MetadataJson") or "") for e in events)
    assert "Temporary!Pass123" not in encoded


def test_missing_production_key_fails_closed(trust_app, client, auth_scenario,
                                             dev_token):
    trust_app.config.update(
        TRUST_CREDENTIAL_KEY="", TRUST_CREDENTIAL_KEY_OLD="",
        REQUIRE_SECRET=True,
    )
    response = client.post(
        f"/api/v1/projects/{auth_scenario['project']['ProjectID']}"
        f"/assets/{auth_scenario['asset']['AssetID']}/credentials",
        json=_credential_payload(auth_scenario),
        headers=bearer(dev_token),
    )
    assert response.status_code == 503
    assert response.get_json()["code"] == "CREDENTIAL_STORAGE_UNAVAILABLE"


def test_key_rotation_keeps_old_ciphertext_readable(trust_app):
    from cryptography.fernet import Fernet

    from app.trust import credential_crypto

    old_key = Fernet.generate_key().decode()
    new_key = Fernet.generate_key().decode()
    trust_app.config.update(
        TRUST_CREDENTIAL_KEY=old_key, TRUST_CREDENTIAL_KEY_OLD="",
        REQUIRE_SECRET=True,
    )
    with trust_app.app_context():
        token = credential_crypto.encrypt_secret("rotation-secret")
    trust_app.config.update(
        TRUST_CREDENTIAL_KEY=new_key, TRUST_CREDENTIAL_KEY_OLD=old_key,
    )
    with trust_app.app_context():
        assert credential_crypto.decrypt_secret(token) == "rotation-secret"
        assert credential_crypto.encrypt_secret("new").startswith("v1:")


def test_creator_cannot_approve_own_credential(trust_app, client,
                                               auth_scenario, dev_token):
    credential = _create(client, dev_token, auth_scenario)
    response = _approve(client, dev_token, auth_scenario,
                        credential["CredentialID"])
    assert response.status_code == 403
    assert response.get_json()["code"] == "CREDENTIAL_SELF_APPROVAL_DENIED"


def test_other_owner_approves_credential(trust_app, client, auth_scenario,
                                         dev_token):
    credential = _create(client, dev_token, auth_scenario)
    response = _approve(
        client, auth_scenario["approver_token"], auth_scenario,
        credential["CredentialID"],
    )
    assert response.status_code == 200, response.get_json()
    approved = response.get_json()["Credential"]
    assert approved["Status"] == "Approved"
    assert approved["ApprovedByUserID"] is not None
    assert approved["ApprovedAt"]


def test_approval_requires_active_attestation(client, trust_app, admin_token,
                                              dev_token):
    email, approver_token = create_user(client, admin_token)
    scenario = full_scenario(
        trust_app, client, admin_token, dev_token,
        target_url="http://localhost:5199/dashboard",
        extra_member_role="PROJECT_OWNER",
        extra_member_token=approver_token,
        extra_member_email=email,
        attest=False,
    )
    scenario["approver_token"] = approver_token
    credential = _create(client, dev_token, scenario)
    response = _approve(client, approver_token, scenario,
                        credential["CredentialID"])
    assert response.status_code == 409
    assert response.get_json()["code"] == "ATTESTATION_REQUIRED"


def test_login_url_must_match_the_asset(client, auth_scenario, dev_token):
    response = client.post(
        f"/api/v1/projects/{auth_scenario['project']['ProjectID']}"
        f"/assets/{auth_scenario['asset']['AssetID']}/credentials",
        json=_credential_payload(
            auth_scenario, login_url="http://evil.example.test/login"
        ),
        headers=bearer(dev_token),
    )
    assert response.status_code == 400
    assert response.get_json()["code"] == "VALIDATION_ERROR"


def test_pending_credential_cannot_start_a_scan(trust_app, client,
                                                auth_scenario, dev_token):
    credential = _create(client, dev_token, auth_scenario)
    response = _start(client, dev_token, auth_scenario,
                      credential_id=credential["CredentialID"])
    assert response.status_code == 409
    assert response.get_json()["code"] == "CREDENTIAL_NOT_APPROVED"


def test_revoke_purges_secret(trust_app, client, auth_scenario, dev_token):
    credential = _create(client, dev_token, auth_scenario)
    _approve(client, auth_scenario["approver_token"], auth_scenario,
             credential["CredentialID"])

    response = client.post(
        f"/api/v1/projects/{auth_scenario['project']['ProjectID']}"
        f"/credentials/{credential['CredentialID']}/revoke",
        json={"reason": "rotation"},
        headers=bearer(auth_scenario["approver_token"]),
    )
    assert response.status_code == 200
    assert response.get_json()["Credential"]["Status"] == "Revoked"
    row = _credential_row(trust_app, credential["CredentialID"])
    assert row.SecretEncrypted is None


def test_expired_credential_is_rejected_and_purged(trust_app, client,
                                                   auth_scenario, dev_token):
    from datetime import datetime, timedelta

    credential = _create(client, dev_token, auth_scenario)
    _approve(client, auth_scenario["approver_token"], auth_scenario,
             credential["CredentialID"])
    with trust_app.app_context():
        row = db.session.get(TrustScanCredential, credential["CredentialID"])
        row.ExpiresAt = datetime.utcnow() - timedelta(minutes=1)
        db.session.commit()

    response = _start(client, dev_token, auth_scenario,
                      credential_id=credential["CredentialID"])
    assert response.status_code == 409
    assert response.get_json()["code"] == "CREDENTIAL_EXPIRED"
    row = _credential_row(trust_app, credential["CredentialID"])
    assert row.Status == "Expired"
    assert row.SecretEncrypted is None


# ------------------------------------------------------------------ login test
def test_test_login_succeeds_without_consuming_credential(trust_app, client,
                                                          auth_scenario,
                                                          dev_token):
    credential = _create(client, dev_token, auth_scenario)
    response = client.post(
        f"/api/v1/projects/{auth_scenario['project']['ProjectID']}"
        f"/credentials/{credential['CredentialID']}/test-login",
        json={},
        headers=bearer(dev_token),
    )
    assert response.status_code == 200, response.get_json()
    login = response.get_json()["Login"]
    assert "/dashboard" in login["FinalURL"]
    assert login["StatusCode"] == 200
    row = _credential_row(trust_app, credential["CredentialID"])
    assert row.Status == "PendingApproval"
    assert row.SecretEncrypted


def test_wrong_password_fails_without_leaking_it(trust_app, client,
                                                 auth_scenario, dev_token):
    credential = _create(
        client, dev_token, auth_scenario, password="Wrong!Pass999"
    )
    response = client.post(
        f"/api/v1/projects/{auth_scenario['project']['ProjectID']}"
        f"/credentials/{credential['CredentialID']}/test-login",
        json={},
        headers=bearer(dev_token),
    )
    assert response.status_code == 409
    body = response.get_json()
    assert body["code"] == "CREDENTIAL_LOGIN_FAILED"
    assert "Wrong!Pass999" not in body["message"]
    row = _credential_row(trust_app, credential["CredentialID"])
    assert row.FailureReason
    assert "Wrong!Pass999" not in (row.FailureReason or "")


# --------------------------------------------------------------- real scanning
def test_authenticated_scan_reaches_protected_pages(trust_app, client,
                                                    auth_scenario, dev_token):
    credential = _create(client, dev_token, auth_scenario)
    _approve(client, auth_scenario["approver_token"], auth_scenario,
             credential["CredentialID"])

    response = _start(client, dev_token, auth_scenario,
                      credential_id=credential["CredentialID"])
    assert response.status_code == 202, response.get_json()
    scan_id = response.get_json()["Scan"]["ScanID"]

    detail = client.get(f"/api/scans/{scan_id}",
                        headers=bearer(dev_token)).get_json()["Scan"]
    assert detail["Status"] == "Completed"
    urls = [page["URL"] for page in detail["Pages"]]
    assert any("/dashboard" in url for url in urls)
    assert any("/dashboard/search" in url for url in urls)
    assert not any("/logout" in url for url in urls)

    xss = [
        f for f in detail["Findings"]
        if "Cross-Site Scripting" in f["VulnerabilityName"]
        and "/dashboard/search" in f["URL"]
    ]
    assert xss, detail["Findings"]

    with trust_app.app_context():
        row = db.session.get(TrustScanCredential, credential["CredentialID"])
        assert row.Status == "Used"
        assert row.UsedAt is not None
        assert row.SecretEncrypted
        binding = db.session.get(TrustScanCredentialBinding, scan_id)
        assert binding is not None
        assert binding.CredentialID == credential["CredentialID"]

    report = client.get(
        f"/api/scans/{scan_id}/report?format=csv", headers=bearer(dev_token)
    )
    assert report.status_code == 200
    text = report.get_data(as_text=True)
    assert "Temporary credential" in text
    assert "Temporary!Pass123" not in text

    # The report must describe the authenticated coverage it actually achieved.
    assert detail["Coverage"]["Authentication"]["Mode"] == "Authenticated"
    pdf = client.get(
        f"/api/scans/{scan_id}/report?format=pdf", headers=bearer(dev_token)
    )
    assert pdf.status_code == 200
    pdf_text = _pdf_text(pdf)
    assert "Authentication:" in pdf_text
    assert "reachable by the approved temporary test account were included" \
        in pdf_text
    assert "Login-protected coverage is limited to pages" in pdf_text
    assert "Temporary!Pass123" not in pdf_text


def test_failed_authentication_note_does_not_duplicate_or_contradict(
        trust_app, client, auth_scenario, dev_token):
    """
    A failed-login scan has zero analysed pages; the coverage note must be
    grammatical and must not claim forms were submitted.
    """
    credential = _create(
        client, dev_token, auth_scenario, password="Wrong!Pass999"
    )
    _approve(client, auth_scenario["approver_token"], auth_scenario,
             credential["CredentialID"])
    response = _start(client, dev_token, auth_scenario,
                      credential_id=credential["CredentialID"])
    scan_id = response.get_json()["Scan"]["ScanID"]
    detail = client.get(f"/api/scans/{scan_id}",
                        headers=bearer(dev_token)).get_json()["Scan"]

    note = detail["CoverageNote"]
    assert detail["Coverage"]["Authentication"]["Mode"] == "AuthenticationFailed"
    assert "Authentication was attempted" in note
    assert "because no page could be analysed, so no detection module ran" \
        not in note
    assert "No detection module ran because no page could be analysed." in note
    # With nothing analysed the note must not claim any parameter was tested.
    assert "HTML form fields (GET and POST) are tested" not in note
    assert "No HTML form or parameter was tested" in note

    pdf_text = _pdf_text(client.get(
        f"/api/scans/{scan_id}/report?format=pdf", headers=bearer(dev_token)))
    assert "No HTML form was submitted" in pdf_text
    assert "GET and POST HTML forms are submitted" not in pdf_text
    assert "because the authentication attempt failed" in pdf_text


def test_failed_login_report_does_not_claim_protected_coverage(
        trust_app, client, auth_scenario, dev_token):
    """A failed authentication attempt must never be reported as coverage."""
    credential = _create(
        client, dev_token, auth_scenario, password="Wrong!Pass999"
    )
    _approve(client, auth_scenario["approver_token"], auth_scenario,
             credential["CredentialID"])
    response = _start(client, dev_token, auth_scenario,
                      credential_id=credential["CredentialID"])
    assert response.status_code == 202, response.get_json()
    scan_id = response.get_json()["Scan"]["ScanID"]

    detail = client.get(f"/api/scans/{scan_id}",
                        headers=bearer(dev_token)).get_json()["Scan"]
    assert detail["Status"] == "Failed"
    assert detail["Coverage"]["Authentication"]["Mode"] == "AuthenticationFailed"
    assert detail["Coverage"]["Authentication"]["Reason"]

    pdf = client.get(
        f"/api/scans/{scan_id}/report?format=pdf", headers=bearer(dev_token)
    )
    assert pdf.status_code == 200
    pdf_text = _pdf_text(pdf)
    assert "authentication attempt failed" in pdf_text
    # It must not claim the protected pages were covered.
    assert "reachable by the approved temporary test account were included" \
        not in pdf_text


def test_credential_is_single_use(trust_app, client, auth_scenario, dev_token):
    credential = _create(client, dev_token, auth_scenario)
    _approve(client, auth_scenario["approver_token"], auth_scenario,
             credential["CredentialID"])
    first = _start(client, dev_token, auth_scenario,
                   credential_id=credential["CredentialID"])
    assert first.status_code == 202
    second_credit = buy_credit(
        client, dev_token, auth_scenario["project"]["ProjectID"]
    )
    second = _start(client, dev_token, auth_scenario,
                    credential_id=credential["CredentialID"],
                    credit=second_credit)
    assert second.status_code == 409
    assert second.get_json()["code"] == "CREDENTIAL_ALREADY_USED"


def test_failed_login_fails_scan_and_releases_credit(trust_app, client,
                                                     auth_scenario, dev_token):
    credential = _create(
        client, dev_token, auth_scenario, password="Wrong!Pass999"
    )
    _approve(client, auth_scenario["approver_token"], auth_scenario,
             credential["CredentialID"])
    response = _start(client, dev_token, auth_scenario,
                      credential_id=credential["CredentialID"])
    assert response.status_code == 202
    scan_id = response.get_json()["Scan"]["ScanID"]
    detail = client.get(f"/api/scans/{scan_id}",
                        headers=bearer(dev_token)).get_json()["Scan"]
    assert detail["Status"] == "Failed"

    credits = client.get(
        f"/api/v1/projects/{auth_scenario['project']['ProjectID']}"
        f"/credits?status=Available",
        headers=bearer(dev_token),
    ).get_json()["Credits"]
    assert credits

    row = _credential_row(trust_app, credential["CredentialID"])
    assert row.FailureReason
    assert row.SecretEncrypted is None


def test_lost_session_is_reauthenticated_once(trust_app, client, auth_scenario,
                                             dev_token, vuln_target_module):
    """The HttpClient re-login path restores a session dropped mid-scan."""
    vuln_target_module.EXPIRE_ONCE["armed"] = True
    credential = _create(client, dev_token, auth_scenario)
    _approve(client, auth_scenario["approver_token"], auth_scenario,
             credential["CredentialID"])
    response = _start(
        client, dev_token, auth_scenario,
        credential_id=credential["CredentialID"],
        target_url="http://localhost:5199/dashboard/expire",
    )
    assert response.status_code == 202, response.get_json()
    scan_id = response.get_json()["Scan"]["ScanID"]
    detail = client.get(f"/api/scans/{scan_id}",
                        headers=bearer(dev_token)).get_json()["Scan"]
    assert detail["Status"] == "Completed", detail.get("CoverageNote")
    expired_page = [
        p for p in detail["Pages"] if p["URL"].endswith("/dashboard/expire")
    ]
    assert expired_page and expired_page[0]["HTTPStatus"] == 200


def test_retest_reuses_bound_credential(trust_app, client, auth_scenario,
                                        dev_token):
    credential = _create(client, dev_token, auth_scenario)
    _approve(client, auth_scenario["approver_token"], auth_scenario,
             credential["CredentialID"])
    response = _start(client, dev_token, auth_scenario,
                      credential_id=credential["CredentialID"])
    scan_id = response.get_json()["Scan"]["ScanID"]
    detail = client.get(f"/api/scans/{scan_id}",
                        headers=bearer(dev_token)).get_json()["Scan"]
    finding = [
        f for f in detail["Findings"]
        if "Cross-Site Scripting" in f["VulnerabilityName"]
        and "/dashboard/search" in f["URL"]
    ][0]
    retest = client.post(
        f"/api/scans/{scan_id}/findings/{finding['FindingID']}/retest",
        headers=bearer(dev_token),
    )
    assert retest.status_code == 200, retest.get_json()
    result = retest.get_json()["Retest"]
    assert result["Verdict"] in ("Still Detected", "Resolved")
    assert "RETEST" in retest.get_json()["Finding"]["Evidence"]


def test_audit_lifecycle_contains_no_secret(trust_app, client, auth_scenario,
                                            dev_token):
    credential = _create(client, dev_token, auth_scenario)
    _approve(client, auth_scenario["approver_token"], auth_scenario,
             credential["CredentialID"])
    with trust_app.app_context():
        rows = TrustAuditEvent.query.filter(
            TrustAuditEvent.EventType.like("CREDENTIAL_%")
        ).all()
        assert {row.EventType for row in rows} >= {
            "CREDENTIAL_CREATED", "CREDENTIAL_APPROVED"
        }
        joined = " ".join((row.MetadataJson or "") for row in rows)
        assert "Temporary!Pass123" not in joined
        assert "password" not in joined.lower()
