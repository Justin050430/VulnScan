"""Mock payment, callback idempotency and credit issuance tests."""
import pytest

from app.extensions import db
from app.models import TrustPaymentTransaction, TrustScanCredit
from testing.trust_helpers import (
    bearer,
    create_org,
    create_project,
)


@pytest.fixture()
def trust_app(app):
    app.config["TRUST_BOUNDARY_MODE"] = "enforce"
    return app


@pytest.fixture()
def project(trust_app, client, dev_token):
    organisation = create_org(client, dev_token)
    return create_project(client, dev_token, organisation["OrganisationID"])


def _checkout(client, token, project_id, product="SCAN_CREDIT_1", quantity=1,
              key=None):
    body = {"product_code": product, "quantity": quantity}
    if key:
        body["idempotency_key"] = key
    return client.post(
        f"/api/v1/projects/{project_id}/payments/checkout",
        json=body, headers=bearer(token),
    )


def _complete(client, token, project_id, payment_uuid, outcome="success"):
    return client.post(
        f"/api/v1/projects/{project_id}/payments/{payment_uuid}/mock-complete",
        json={"outcome": outcome}, headers=bearer(token),
    )


def _credits(app, project_id):
    with app.app_context():
        return TrustScanCredit.query.filter_by(ProjectID=int(project_id)).all()


def test_products_are_labelled_mock(trust_app, client, dev_token):
    body = client.get("/api/v1/products", headers=bearer(dev_token)).get_json()
    assert body["Mock"] is True
    assert "no real money" in body["Notice"].lower()
    assert {p["ProductCode"] for p in body["Products"]} == {
        "SCAN_CREDIT_1", "SCAN_CREDIT_5"
    }


def test_checkout_uses_server_side_price(trust_app, client, dev_token, project):
    response = _checkout(client, dev_token, project["ProjectID"],
                         product="SCAN_CREDIT_5", quantity=2)
    assert response.status_code == 201
    payment = response.get_json()["Payment"]
    # 4500 minor units * 2, never a client-supplied amount.
    assert payment["AmountMinor"] == 9000
    assert payment["Currency"] == "MYR"
    assert payment["Status"] == "PendingPayment"
    assert response.get_json()["Mock"] is True


def test_browser_return_alone_does_not_issue_credit(trust_app, client, dev_token,
                                                    project):
    payment = _checkout(client, dev_token, project["ProjectID"]).get_json()["Payment"]
    # Simulate the browser simply returning and polling the status endpoint.
    status = client.get(
        f"/api/v1/projects/{project['ProjectID']}/payments/{payment['PaymentUUID']}",
        headers=bearer(dev_token),
    )
    assert status.status_code == 200
    assert status.get_json()["Payment"]["Status"] == "PendingPayment"
    assert _credits(trust_app, project["ProjectID"]) == []


def test_mock_completion_issues_one_credit(trust_app, client, dev_token, project):
    payment = _checkout(client, dev_token, project["ProjectID"]).get_json()["Payment"]
    completed = _complete(client, dev_token, project["ProjectID"],
                          payment["PaymentUUID"])
    assert completed.status_code == 200
    assert completed.get_json()["CreditsIssued"] == 1

    credits = _credits(trust_app, project["ProjectID"])
    assert len(credits) == 1
    assert credits[0].Status == "Available"
    assert credits[0].PurchasePriceMinor == 1000


def test_five_credit_product_issues_five_credits(trust_app, client, dev_token,
                                                 project):
    payment = _checkout(
        client, dev_token, project["ProjectID"], product="SCAN_CREDIT_5"
    ).get_json()["Payment"]
    completed = _complete(client, dev_token, project["ProjectID"],
                          payment["PaymentUUID"])
    assert completed.status_code == 200
    assert completed.get_json()["CreditsIssued"] == 5

    credits = _credits(trust_app, project["ProjectID"])
    assert len(credits) == 5
    assert {c.Status for c in credits} == {"Available"}
    assert {c.ProductCode for c in credits} == {"SCAN_CREDIT_5"}
    assert sorted(c.CreditSequence for c in credits) == [1, 2, 3, 4, 5]
    # The bundle price is split evenly across the credits it grants.
    assert {c.PurchasePriceMinor for c in credits} == {900}
    assert len({c.CreditUUID for c in credits}) == 5


def test_bundle_quantity_multiplies_credits(trust_app, client, dev_token,
                                            project):
    payment = _checkout(
        client, dev_token, project["ProjectID"], product="SCAN_CREDIT_5",
        quantity=2,
    ).get_json()["Payment"]
    assert payment["AmountMinor"] == 9000
    completed = _complete(client, dev_token, project["ProjectID"],
                          payment["PaymentUUID"])
    assert completed.get_json()["CreditsIssued"] == 10

    credits = _credits(trust_app, project["ProjectID"])
    assert len(credits) == 10
    assert sorted(c.CreditSequence for c in credits) == list(range(1, 11))


def test_duplicate_completion_is_idempotent(trust_app, client, dev_token, project):
    payment = _checkout(client, dev_token, project["ProjectID"]).get_json()["Payment"]
    first = _complete(client, dev_token, project["ProjectID"], payment["PaymentUUID"])
    second = _complete(client, dev_token, project["ProjectID"], payment["PaymentUUID"])
    assert first.status_code == 200
    assert second.status_code == 200
    assert second.get_json()["Duplicate"] is True
    assert second.get_json()["CreditsIssued"] == 0
    assert len(_credits(trust_app, project["ProjectID"])) == 1


def test_duplicate_webhook_is_idempotent(trust_app, client, dev_token, project):
    from app.payments.registry import get_provider

    payment = _checkout(client, dev_token, project["ProjectID"]).get_json()["Payment"]
    with trust_app.app_context():
        provider = get_provider()
        txn = "mock-txn-duplicate-1"
        signature = provider.sign(
            payment["PaymentUUID"], txn, payment["AmountMinor"], payment["Currency"],
            payment["ProductCode"], payment["Quantity"], "success",
        )
        payload = {
            "payment_uuid": payment["PaymentUUID"],
            "provider_transaction_id": txn,
            "amount_minor": payment["AmountMinor"],
            "currency": payment["Currency"],
            "product_code": payment["ProductCode"],
            "quantity": payment["Quantity"],
            "status": "success",
        }
    headers = {**bearer(dev_token), "X-VulnScan-Signature": signature}
    first = client.post("/api/v1/payments/webhooks/MOCK", json=payload, headers=headers)
    second = client.post("/api/v1/payments/webhooks/MOCK", json=payload, headers=headers)
    assert first.status_code == 200
    assert first.get_json()["CreditsIssued"] == 1
    assert second.status_code == 200
    assert second.get_json()["Duplicate"] is True
    assert len(_credits(trust_app, project["ProjectID"])) == 1


def test_webhook_rejects_invalid_signature(trust_app, client, dev_token, project):
    payment = _checkout(client, dev_token, project["ProjectID"]).get_json()["Payment"]
    payload = {
        "payment_uuid": payment["PaymentUUID"],
        "provider_transaction_id": "tampered",
        "amount_minor": payment["AmountMinor"],
        "currency": payment["Currency"],
        "product_code": payment["ProductCode"],
        "quantity": payment["Quantity"],
        "status": "success",
    }
    response = client.post(
        "/api/v1/payments/webhooks/MOCK", json=payload,
        headers={**bearer(dev_token), "X-VulnScan-Signature": "0" * 64},
    )
    assert response.status_code == 400
    assert response.get_json()["code"] == "PAYMENT_NOT_VERIFIED"
    assert _credits(trust_app, project["ProjectID"]) == []


def test_webhook_rejects_amount_mismatch(trust_app, client, dev_token, project):
    from app.payments.registry import get_provider

    payment = _checkout(client, dev_token, project["ProjectID"]).get_json()["Payment"]
    with trust_app.app_context():
        provider = get_provider()
        signature = provider.sign(
            payment["PaymentUUID"], "txn-underpay", 1, payment["Currency"],
            payment["ProductCode"], payment["Quantity"], "success",
        )
    payload = {
        "payment_uuid": payment["PaymentUUID"],
        "provider_transaction_id": "txn-underpay",
        "amount_minor": 1,
        "currency": payment["Currency"],
        "product_code": payment["ProductCode"],
        "quantity": payment["Quantity"],
        "status": "success",
    }
    response = client.post(
        "/api/v1/payments/webhooks/MOCK", json=payload,
        headers={**bearer(dev_token), "X-VulnScan-Signature": signature},
    )
    assert response.status_code == 409
    assert response.get_json()["code"] == "PAYMENT_AMOUNT_MISMATCH"
    with trust_app.app_context():
        row = TrustPaymentTransaction.query.filter_by(
            PaymentUUID=payment["PaymentUUID"]
        ).first()
        assert row.Status == "Failed"
    assert _credits(trust_app, project["ProjectID"]) == []


def test_checkout_idempotency_replay(trust_app, client, dev_token, project):
    key = "checkout-key-123"
    first = _checkout(client, dev_token, project["ProjectID"], key=key)
    second = _checkout(client, dev_token, project["ProjectID"], key=key)
    assert first.status_code == 201
    assert second.status_code == 201
    assert second.get_json()["IdempotentReplay"] is True
    assert first.get_json()["Payment"]["PaymentUUID"] == \
        second.get_json()["Payment"]["PaymentUUID"]


def test_checkout_idempotency_conflict(trust_app, client, dev_token, project):
    key = "checkout-key-conflict"
    _checkout(client, dev_token, project["ProjectID"], product="SCAN_CREDIT_1", key=key)
    conflict = _checkout(client, dev_token, project["ProjectID"],
                         product="SCAN_CREDIT_5", key=key)
    assert conflict.status_code == 409
    assert conflict.get_json()["code"] == "IDEMPOTENCY_CONFLICT"


def test_failed_payment_issues_no_credit(trust_app, client, dev_token, project):
    payment = _checkout(client, dev_token, project["ProjectID"]).get_json()["Payment"]
    failed = _complete(client, dev_token, project["ProjectID"],
                       payment["PaymentUUID"], outcome="failed")
    assert failed.status_code == 200
    assert failed.get_json()["CreditsIssued"] == 0
    assert _credits(trust_app, project["ProjectID"]) == []


def test_credits_are_project_scoped(trust_app, client, dev_token, project):
    other_org = create_org(client, dev_token, name="Other Credit Org")
    other = create_project(client, dev_token, other_org["OrganisationID"])
    payment = _checkout(client, dev_token, project["ProjectID"]).get_json()["Payment"]
    _complete(client, dev_token, project["ProjectID"], payment["PaymentUUID"])

    visible = client.get(
        f"/api/v1/projects/{other['ProjectID']}/credits", headers=bearer(dev_token)
    ).get_json()
    assert visible["Credits"] == []
    assert visible["AvailableCount"] == 0
