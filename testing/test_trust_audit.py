"""Append-only Trust audit-event tests."""
import json

import pytest

from app.extensions import db
from app.models import TrustAuditEvent
from testing.trust_helpers import (
    bearer,
    buy_credit,
    create_attestation,
    create_org,
    create_project,
    full_scenario,
    invite_and_accept,
    profile_id,
    create_user,
)


@pytest.fixture()
def trust_app(app):
    app.config["TRUST_BOUNDARY_MODE"] = "enforce"
    return app


def _events(client, token, project_id):
    return client.get(
        f"/api/v1/projects/{project_id}/audit-events?per_page=200",
        headers=bearer(token),
    ).get_json()["Events"]


def test_every_sensitive_action_is_audited(trust_app, client, admin_token,
                                           dev_token, target):
    email, member_token = create_user(client, admin_token)
    organisation = create_org(client, dev_token)
    project = create_project(client, dev_token, organisation["OrganisationID"])
    invite_and_accept(
        client, dev_token, project["ProjectID"], member_token, email, "ANALYST"
    )
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

    membership_events = {e["EventType"] for e in _events(
        client, dev_token, project["ProjectID"])}
    assert {
        "PROJECT_CREATED", "PROJECT_MEMBER_INVITED", "PROJECT_MEMBER_ACCEPTED",
    }.issubset(membership_events), membership_events

    scan_events = {e["EventType"] for e in _events(
        client, dev_token, scenario["project"]["ProjectID"])}
    assert {
        "ASSET_REGISTERED", "ATTESTATION_CREATED",
        "PAYMENT_CHECKOUT_CREATED", "PAYMENT_VERIFIED", "CREDIT_ISSUED",
        "CREDIT_RESERVED", "CREDIT_CONSUMED", "SCAN_STARTED",
    }.issubset(scan_events), scan_events


def test_denied_scan_is_audited_with_reason(trust_app, client, dev_token, target):
    email = None
    scenario = full_scenario(trust_app, client, None, dev_token,
                             target_url=target, credit=False)
    response = client.post(
        f"/api/v1/projects/{scenario['project']['ProjectID']}/scans",
        json={
            "asset_id": scenario["asset"]["AssetID"],
            "scan_profile_id": profile_id(client, dev_token),
            "target_url": scenario["target_url"],
        },
        headers=bearer(dev_token),
    )
    assert response.status_code == 402

    denied = [
        e for e in _events(client, dev_token, scenario["project"]["ProjectID"])
        if e["EventType"] == "SCAN_DENIED"
    ]
    assert denied
    assert denied[0]["Outcome"] == "Denied"
    assert denied[0]["ReasonCode"] == "CREDIT_REQUIRED"


def test_audit_metadata_never_contains_raw_tokens_or_secrets(
        trust_app, client, admin_token, dev_token):
    email, member_token = create_user(client, admin_token)
    organisation = create_org(client, dev_token)
    project = create_project(client, dev_token, organisation["OrganisationID"])
    invite = client.post(
        f"/api/v1/projects/{project['ProjectID']}/members",
        json={"email": email, "role": "VIEWER"}, headers=bearer(dev_token),
    ).get_json()
    invite_token = invite["InviteToken"]

    with trust_app.app_context():
        dumped = " ".join(
            (e.MetadataJson or "") for e in TrustAuditEvent.query.all()
        )
    assert invite_token not in dumped
    assert "vulnscan-verify=" not in dumped
    for marker in ("secret", "password", "signature"):
        # Only the redaction marker may appear, never an actual value.
        assert f'"{marker}"' not in dumped


def test_audit_events_are_append_only(trust_app, client, dev_token):
    organisation = create_org(client, dev_token)
    project = create_project(client, dev_token, organisation["OrganisationID"])
    events = _events(client, dev_token, project["ProjectID"])
    assert events
    event_id = events[0]["EventID"]

    with trust_app.app_context():
        db.session.expire_all()
        row = db.session.get(TrustAuditEvent, event_id)
        original_outcome = row.Outcome

    put = client.put(
        f"/api/v1/projects/{project['ProjectID']}/audit-events/{event_id}",
        json={"Outcome": "Denied"}, headers=bearer(dev_token),
    )
    delete = client.delete(
        f"/api/v1/projects/{project['ProjectID']}/audit-events/{event_id}",
        headers=bearer(dev_token),
    )
    # No mutation route exists at all: the request cannot match an endpoint.
    assert put.status_code in (404, 405)
    assert delete.status_code in (404, 405)

    with trust_app.app_context():
        row = db.session.get(TrustAuditEvent, event_id)
        assert row is not None
        assert row.Outcome == original_outcome


def test_audit_events_form_a_hash_chain(trust_app, client, dev_token):
    organisation = create_org(client, dev_token)
    project = create_project(client, dev_token, organisation["OrganisationID"])
    with trust_app.app_context():
        rows = TrustAuditEvent.query.order_by(TrustAuditEvent.EventID.asc()).all()
        assert len(rows) >= 2
        for previous, current in zip(rows, rows[1:]):
            if current.PrevEventHash is not None:
                assert current.PrevEventHash == previous.EventHash
        assert all(row.EventHash for row in rows)


def test_audit_events_are_project_scoped(trust_app, client, dev_token):
    first_org = create_org(client, dev_token, name="Audit One")
    first = create_project(client, dev_token, first_org["OrganisationID"])
    second_org = create_org(client, dev_token, name="Audit Two")
    second = create_project(client, dev_token, second_org["OrganisationID"])
    create_org(client, dev_token, name="Unrelated Org")

    first_events = _events(client, dev_token, first["ProjectID"])
    second_events = _events(client, dev_token, second["ProjectID"])
    assert first_events and second_events
    assert all(e["ProjectID"] == first["ProjectID"] for e in first_events)
    assert all(e["ProjectID"] == second["ProjectID"] for e in second_events)
