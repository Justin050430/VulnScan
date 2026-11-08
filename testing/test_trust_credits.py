"""Scan-credit lifecycle, atomic reservation and double-spend protection."""
import threading
from datetime import datetime, timedelta
import pytest

from app.extensions import db
from app.models import TrustCreditRedemption, TrustScanCredit, User
from app.services import credit_service
from app.trust.permissions import TrustError
from testing.trust_helpers import (
    bearer,
    buy_credit,
    create_attestation,
    create_org,
    create_project,
    full_scenario,
    profile_id,
    register_asset,
    verify_asset_directly,
)


@pytest.fixture()
def trust_app(app):
    app.config["TRUST_BOUNDARY_MODE"] = "enforce"
    return app


@pytest.fixture()
def project(trust_app, client, dev_token):
    organisation = create_org(client, dev_token)
    return create_project(client, dev_token, organisation["OrganisationID"])


def _developer_id(trust_app):
    with trust_app.app_context():
        return User.query.filter_by(Email="developer@vulnscan.local").first().UserID


def test_reserve_moves_available_to_reserved(trust_app, client, dev_token, project):
    credit = buy_credit(client, dev_token, project["ProjectID"])
    with trust_app.app_context():
        credit_id = TrustScanCredit.query.filter_by(
            CreditUUID=credit["CreditUUID"]
        ).first().CreditID
        user = db.session.get(User, _developer_id(trust_app))
        row, reserved_until = credit_service.reserve_credit(credit_id, user)
        assert row.Status == "Reserved"
        assert row.ReservedUntil > datetime.utcnow()
        db.session.commit()


def test_reserve_twice_is_rejected(trust_app, client, dev_token, project):
    credit = buy_credit(client, dev_token, project["ProjectID"])
    with trust_app.app_context():
        credit_id = TrustScanCredit.query.filter_by(
            CreditUUID=credit["CreditUUID"]
        ).first().CreditID
        user = db.session.get(User, _developer_id(trust_app))
        credit_service.reserve_credit(credit_id, user)
        db.session.commit()
        with pytest.raises(TrustError) as exc:
            credit_service.reserve_credit(credit_id, user)
        assert exc.value.code == "CREDIT_NOT_AVAILABLE"


def test_credit_cannot_be_reserved_twice_across_sessions(trust_app, client,
                                                        dev_token, project):
    """The conditional UPDATE must affect exactly one row.

    A true two-thread race is exercised against SQL Server in
    ``test_sqlserver_integration.py``; SQLite's shared in-memory connection
    cannot model two independent writers faithfully.
    """
    credit = buy_credit(client, dev_token, project["ProjectID"])
    with trust_app.app_context():
        credit_id = TrustScanCredit.query.filter_by(
            CreditUUID=credit["CreditUUID"]
        ).first().CreditID
        user = db.session.get(User, _developer_id(trust_app))
        credit_service.reserve_credit(credit_id, user)
        db.session.commit()

    with trust_app.app_context():
        user = db.session.get(User, _developer_id(trust_app))
        with pytest.raises(TrustError) as exc:
            credit_service.reserve_credit(credit_id, user)
        assert exc.value.code == "CREDIT_NOT_AVAILABLE"
        db.session.rollback()

    with trust_app.app_context():
        row = db.session.get(TrustScanCredit, credit_id)
        assert row.Status == "Reserved"


def test_expired_credit_is_not_available(trust_app, client, dev_token, project):
    credit = buy_credit(client, dev_token, project["ProjectID"])
    with trust_app.app_context():
        row = TrustScanCredit.query.filter_by(
            CreditUUID=credit["CreditUUID"]
        ).first()
        row.ExpiresAt = datetime.utcnow() - timedelta(days=1)
        db.session.commit()

    listing = client.get(
        f"/api/v1/projects/{project['ProjectID']}/credits",
        headers=bearer(dev_token),
    ).get_json()
    assert listing["AvailableCount"] == 0
    assert listing["Credits"][0]["Status"] == "Expired"


def test_release_returns_credit_to_available(trust_app, client, dev_token,
                                             project):
    credit = buy_credit(client, dev_token, project["ProjectID"])
    with trust_app.app_context():
        row = TrustScanCredit.query.filter_by(
            CreditUUID=credit["CreditUUID"]
        ).first()
        user = db.session.get(User, _developer_id(trust_app))
        credit_service.reserve_credit(row.CreditID, user)
        redemption = credit_service.create_redemption(
            row, user_id=user.UserID, idempotency_key="release-test"
        )
        db.session.commit()
        credit_service.release_redemption(redemption, reason="test release")
        db.session.refresh(row)
        assert row.Status == "Available"
        assert row.ReservedAt is None


def test_expired_reservation_is_released(trust_app, client, dev_token, project):
    credit = buy_credit(client, dev_token, project["ProjectID"])
    with trust_app.app_context():
        row = TrustScanCredit.query.filter_by(
            CreditUUID=credit["CreditUUID"]
        ).first()
        user = db.session.get(User, _developer_id(trust_app))
        credit_service.reserve_credit(row.CreditID, user)
        redemption = credit_service.create_redemption(
            row, user_id=user.UserID, idempotency_key="timeout-test"
        )
        row.ReservedUntil = datetime.utcnow() - timedelta(minutes=1)
        db.session.commit()
        released = credit_service.release_expired_reservations()
        assert redemption.RedemptionID in released
        db.session.refresh(row)
        assert row.Status == "Available"
        assert redemption.Status == "Released"


def test_second_scan_with_consumed_credit_is_rejected(trust_app, client,
                                                      dev_token, target):
    email = None
    scenario = full_scenario(trust_app, client, None, dev_token, target_url=target)
    body = {
        "asset_id": scenario["asset"]["AssetID"],
        "scan_profile_id": profile_id(client, dev_token),
        "credit_id": scenario["credit"]["CreditUUID"],
        "target_url": scenario["target_url"],
    }
    first = client.post(
        f"/api/v1/projects/{scenario['project']['ProjectID']}/scans",
        json=body, headers=bearer(dev_token),
    )
    assert first.status_code == 202, first.get_json()
    second = client.post(
        f"/api/v1/projects/{scenario['project']['ProjectID']}/scans",
        json=body, headers=bearer(dev_token),
    )
    assert second.status_code == 409
    assert second.get_json()["code"] in {"CREDIT_NOT_AVAILABLE", "ACTIVE_SCAN_EXISTS"}


def test_redemption_records_are_immutable_history(trust_app, client, dev_token,
                                                  target):
    scenario = full_scenario(trust_app, client, None, dev_token, target_url=target)
    client.post(
        f"/api/v1/projects/{scenario['project']['ProjectID']}/scans",
        json={
            "asset_id": scenario["asset"]["AssetID"],
            "scan_profile_id": profile_id(client, dev_token),
            "credit_id": scenario["credit"]["CreditUUID"],
            "target_url": scenario["target_url"],
        },
        headers=bearer(dev_token),
    )
    rows = client.get(
        f"/api/v1/projects/{scenario['project']['ProjectID']}/credit-redemptions",
        headers=bearer(dev_token),
    ).get_json()["Redemptions"]
    assert len(rows) == 1
    assert rows[0]["Status"] == "Consumed"
    assert rows[0]["ScanID"] is not None
