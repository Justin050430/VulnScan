"""Mock checkout, callback verification and single-use credit issuance."""
import uuid
from datetime import datetime, timedelta

from flask import current_app
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import TrustPaymentTransaction, TrustScanCredit
from app.payments.base import PaymentProviderError
from app.payments.mock_provider import STATUS_FAILED, STATUS_SUCCESS
from app.payments.registry import get_provider
from app.services import trust_audit_service as audit
from app.trust.constants import (
    CREDIT_AVAILABLE,
    ERR_IDEMPOTENCY_CONFLICT,
    ERR_NOT_FOUND,
    ERR_PAYMENT_AMOUNT_MISMATCH,
    ERR_PAYMENT_NOT_VERIFIED,
    ERR_VALIDATION,
    EVENT_CREDIT_ISSUED,
    EVENT_PAYMENT_CHECKOUT_CREATED,
    EVENT_PAYMENT_DUPLICATE_IGNORED,
    EVENT_PAYMENT_FAILED,
    EVENT_PAYMENT_VERIFIED,
    OUTCOME_FAILURE,
    PAYMENT_FAILED,
    PAYMENT_PENDING,
    PAYMENT_VERIFIED,
    PROVIDER_MOCK,
)
from app.trust.permissions import TrustError

#: Server-side catalogue.  Prices are never accepted from the client.
PRODUCTS = {
    "SCAN_CREDIT_1": {
        "ProductCode": "SCAN_CREDIT_1",
        "Name": "Single scan credit",
        "Credits": 1,
        "AmountMinor": 1000,
        "Currency": "MYR",
    },
    "SCAN_CREDIT_5": {
        "ProductCode": "SCAN_CREDIT_5",
        "Name": "Five scan credits",
        "Credits": 5,
        "AmountMinor": 4500,
        "Currency": "MYR",
    },
}

MAX_QUANTITY = 10


def list_products():
    return list(PRODUCTS.values())


def _credit_validity_days():
    return int(current_app.config.get("TRUST_CREDIT_VALIDITY_DAYS", 180))


def create_checkout(actor, access, product_code, quantity=1, idempotency_key=None,
                    ip_address=None):
    product = PRODUCTS.get(product_code)
    if product is None:
        raise TrustError("Unknown product.", ERR_VALIDATION, 400)
    try:
        quantity = int(quantity)
    except (TypeError, ValueError):
        raise TrustError("quantity must be an integer.", ERR_VALIDATION, 400) from None
    if quantity < 1 or quantity > MAX_QUANTITY:
        raise TrustError(
            f"quantity must be between 1 and {MAX_QUANTITY}.", ERR_VALIDATION, 400
        )
    if not idempotency_key:
        idempotency_key = str(uuid.uuid4())
    idempotency_key = str(idempotency_key)[:64]

    existing = TrustPaymentTransaction.query.filter_by(
        IdempotencyKey=idempotency_key
    ).first()
    if existing is not None:
        if (
            existing.ProjectID != access.project_id
            or existing.ProductCode != product["ProductCode"]
            or existing.Quantity != quantity
        ):
            raise TrustError(
                "This idempotency key was used with different payment details.",
                ERR_IDEMPOTENCY_CONFLICT,
                409,
            )
        return existing, True

    provider = get_provider()
    amount_minor = product["AmountMinor"] * quantity
    payment = TrustPaymentTransaction(
        PaymentUUID=str(uuid.uuid4()),
        OrganisationID=access.organisation_id,
        ProjectID=access.project_id,
        PurchasedByUserID=actor.UserID,
        Provider=provider.code,
        IdempotencyKey=idempotency_key,
        ProductCode=product["ProductCode"],
        Quantity=quantity,
        AmountMinor=amount_minor,
        Currency=product["Currency"],
        Status=PAYMENT_PENDING,
    )
    db.session.add(payment)
    db.session.flush()
    checkout_url = provider.create_checkout(payment)
    payment.ProviderCheckoutID = payment.PaymentUUID
    audit.record(
        EVENT_PAYMENT_CHECKOUT_CREATED,
        organisation_id=access.organisation_id,
        project_id=access.project_id,
        actor=actor,
        entity_type="TrustPaymentTransaction",
        entity_id=payment.PaymentTransactionID,
        metadata={
            "product_code": payment.ProductCode,
            "quantity": quantity,
            "amount_minor": amount_minor,
            "currency": payment.Currency,
            "provider": provider.code,
        },
        ip_address=ip_address,
        commit=False,
    )
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        raise TrustError(
            "This idempotency key is already in use.",
            ERR_IDEMPOTENCY_CONFLICT,
            409,
        )
    return payment, False


def complete_mock_checkout(payment, outcome="success", ip_address=None,
                           actor=None):
    """Simulate the provider callback (development/test only).

    The browser returning from checkout can never reach this path: it requires
    an authenticated caller and a signed callback produced server-side.
    """
    provider = get_provider()
    if provider.code != PROVIDER_MOCK:
        raise TrustError(
            "Mock checkout is only available with the mock provider.",
            ERR_VALIDATION,
            400,
        )
    status = STATUS_SUCCESS if str(outcome).lower() == "success" else STATUS_FAILED
    transaction_id = f"mock-{payment.PaymentUUID[:8]}-{int(datetime.utcnow().timestamp())}"
    signature = provider.sign(
        payment.PaymentUUID, transaction_id, payment.AmountMinor,
        payment.Currency, payment.ProductCode, payment.Quantity, status,
    )
    payload = {
        "payment_uuid": payment.PaymentUUID,
        "provider_transaction_id": transaction_id,
        "amount_minor": payment.AmountMinor,
        "currency": payment.Currency,
        "product_code": payment.ProductCode,
        "quantity": payment.Quantity,
        "status": status,
    }
    return process_callback(payload, signature, ip_address=ip_address, actor=actor)


def process_callback(payload, signature, ip_address=None, actor=None):
    """Verify a provider callback and issue credits exactly once."""
    provider = get_provider()
    try:
        event = provider.verify_webhook(payload, signature)
    except PaymentProviderError as exc:
        raise TrustError(str(exc), ERR_PAYMENT_NOT_VERIFIED, 400) from exc

    payment = TrustPaymentTransaction.query.filter_by(
        PaymentUUID=event.payment_uuid
    ).first()
    if payment is None:
        raise TrustError("Payment not found.", ERR_NOT_FOUND, 404)

    # Server-side expectation checks - never trust the callback amounts.
    if (
        event.amount_minor != payment.AmountMinor
        or event.currency != payment.Currency
        or event.product_code != payment.ProductCode
        or event.quantity != payment.Quantity
    ):
        payment.Status = PAYMENT_FAILED
        payment.FailureReason = "Provider amount/currency/product mismatch"
        audit.record(
            EVENT_PAYMENT_FAILED,
            outcome=OUTCOME_FAILURE,
            organisation_id=payment.OrganisationID,
            project_id=payment.ProjectID,
            actor=actor,
            entity_type="TrustPaymentTransaction",
            entity_id=payment.PaymentTransactionID,
            reason_code=ERR_PAYMENT_AMOUNT_MISMATCH,
            ip_address=ip_address,
            commit=False,
        )
        db.session.commit()
        raise TrustError(
            "The payment does not match the expected amount, currency or product.",
            ERR_PAYMENT_AMOUNT_MISMATCH,
            409,
        )

    if payment.Status == PAYMENT_VERIFIED:
        audit.record(
            EVENT_PAYMENT_DUPLICATE_IGNORED,
            organisation_id=payment.OrganisationID,
            project_id=payment.ProjectID,
            actor=actor,
            entity_type="TrustPaymentTransaction",
            entity_id=payment.PaymentTransactionID,
            metadata={"provider_transaction_id": event.provider_transaction_id},
            ip_address=ip_address,
        )
        return {
            "Payment": payment,
            "CreditsIssued": 0,
            "Duplicate": True,
        }

    if event.status == STATUS_FAILED:
        payment.Status = PAYMENT_FAILED
        payment.FailureReason = "Provider reported failure"
        audit.record(
            EVENT_PAYMENT_FAILED,
            outcome=OUTCOME_FAILURE,
            organisation_id=payment.OrganisationID,
            project_id=payment.ProjectID,
            actor=actor,
            entity_type="TrustPaymentTransaction",
            entity_id=payment.PaymentTransactionID,
            ip_address=ip_address,
            commit=False,
        )
        db.session.commit()
        return {"Payment": payment, "CreditsIssued": 0, "Duplicate": False}

    if payment.Status != PAYMENT_PENDING:
        raise TrustError(
            "This payment can no longer be completed.",
            ERR_PAYMENT_NOT_VERIFIED,
            409,
        )

    now = datetime.utcnow()
    payment.Status = PAYMENT_VERIFIED
    payment.ProviderTransactionID = event.provider_transaction_id
    payment.VerifiedAt = now
    payment.CallbackHash = signature[:64] if signature else None
    payment.Version += 1

    credits = []
    for sequence in range(1, payment.Quantity + 1):
        credit = TrustScanCredit(
            CreditUUID=str(uuid.uuid4()),
            OrganisationID=payment.OrganisationID,
            ProjectID=payment.ProjectID,
            PaymentTransactionID=payment.PaymentTransactionID,
            CreditSequence=sequence,
            ProductCode=payment.ProductCode,
            Status=CREDIT_AVAILABLE,
            IssuedAt=now,
            ExpiresAt=now + timedelta(days=_credit_validity_days()),
            PurchasePriceMinor=payment.AmountMinor // max(payment.Quantity, 1),
            Currency=payment.Currency,
        )
        db.session.add(credit)
        credits.append(credit)

    audit.record(
        EVENT_PAYMENT_VERIFIED,
        organisation_id=payment.OrganisationID,
        project_id=payment.ProjectID,
        actor=actor,
        entity_type="TrustPaymentTransaction",
        entity_id=payment.PaymentTransactionID,
        metadata={
            "provider_transaction_id": event.provider_transaction_id,
            "amount_minor": payment.AmountMinor,
            "quantity": payment.Quantity,
        },
        ip_address=ip_address,
        commit=False,
    )
    audit.record(
        EVENT_CREDIT_ISSUED,
        organisation_id=payment.OrganisationID,
        project_id=payment.ProjectID,
        actor=actor,
        entity_type="TrustScanCredit",
        entity_id=0,
        metadata={"issued": len(credits), "payment_id": payment.PaymentTransactionID},
        ip_address=ip_address,
        commit=False,
    )
    try:
        db.session.commit()
    except IntegrityError:
        # A concurrent duplicate callback already issued the credits.
        db.session.rollback()
        payment = TrustPaymentTransaction.query.filter_by(
            PaymentUUID=event.payment_uuid
        ).first()
        audit.record(
            EVENT_PAYMENT_DUPLICATE_IGNORED,
            organisation_id=payment.OrganisationID if payment else None,
            project_id=payment.ProjectID if payment else None,
            actor=actor,
            entity_type="TrustPaymentTransaction",
            entity_id=payment.PaymentTransactionID if payment else None,
            ip_address=ip_address,
        )
        return {"Payment": payment, "CreditsIssued": 0, "Duplicate": True}

    return {"Payment": payment, "CreditsIssued": len(credits), "Duplicate": False}


def get_payment(project_id, payment_uuid):
    payment = TrustPaymentTransaction.query.filter_by(
        ProjectID=int(project_id), PaymentUUID=str(payment_uuid)
    ).first()
    if payment is None:
        raise TrustError("Payment not found.", ERR_NOT_FOUND, 404)
    return payment
