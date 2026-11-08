"""Mock payment provider - no real money, no external network calls."""
import hashlib
import hmac

from flask import current_app

from app.payments.base import PaymentProvider, PaymentProviderError, WebhookEvent

STATUS_SUCCESS = "success"
STATUS_FAILED = "failed"


def _canonical(payment_uuid, provider_transaction_id, amount_minor, currency,
               product_code, quantity, status):
    return "|".join([
        str(payment_uuid),
        str(provider_transaction_id),
        str(amount_minor),
        str(currency),
        str(product_code),
        str(quantity),
        str(status),
    ])


class MockProvider(PaymentProvider):
    """Deterministic, HMAC-signed mock provider used for demonstrations."""

    code = "MOCK"
    label = "Mock provider (no real money)"

    def _secret(self):
        return current_app.config.get(
            "TRUST_MOCK_PAYMENT_SECRET", "mock-provider-not-a-real-secret"
        )

    def sign(self, payment_uuid, provider_transaction_id, amount_minor,
             currency, product_code, quantity, status):
        message = _canonical(
            payment_uuid, provider_transaction_id, amount_minor, currency,
            product_code, quantity, status,
        )
        return hmac.new(
            self._secret().encode("utf-8"),
            message.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def create_checkout(self, payment):
        return f"/api/v1/mock-checkout/{payment.PaymentUUID}"

    def verify_webhook(self, payload, signature):
        if not signature:
            raise PaymentProviderError("Missing callback signature.")
        try:
            payment_uuid = payload["payment_uuid"]
            provider_transaction_id = payload["provider_transaction_id"]
            amount_minor = int(payload["amount_minor"])
            currency = payload["currency"]
            product_code = payload["product_code"]
            quantity = int(payload["quantity"])
            status = payload["status"]
        except (KeyError, TypeError, ValueError) as exc:
            raise PaymentProviderError("Malformed callback payload.") from exc

        if status not in (STATUS_SUCCESS, STATUS_FAILED):
            raise PaymentProviderError("Unsupported callback status.")

        expected = self.sign(
            payment_uuid, provider_transaction_id, amount_minor, currency,
            product_code, quantity, status,
        )
        if not hmac.compare_digest(expected, str(signature)):
            raise PaymentProviderError("Invalid callback signature.")

        return WebhookEvent(
            payment_uuid=payment_uuid,
            provider_transaction_id=provider_transaction_id,
            status=status,
            amount_minor=amount_minor,
            currency=currency,
            product_code=product_code,
            quantity=quantity,
            raw_status=status,
        )

    def fetch_status(self, provider_transaction_id):
        # The mock provider has no external state; the signed callback is the
        # authoritative event for this demonstration.
        return "success"
