"""Payment provider abstraction.

Only the mock provider is implemented in this FYP slice.  A real gateway
(Billplz / ToyyibPay / senangPay) would implement the same interface in a
future release; no card data is ever handled here.
"""
from dataclasses import dataclass, field


@dataclass
class WebhookEvent:
    payment_uuid: str
    provider_transaction_id: str
    status: str              # "success" | "failed"
    amount_minor: int
    currency: str
    product_code: str
    quantity: int
    raw_status: str = ""
    extra: dict = field(default_factory=dict)


class PaymentProviderError(Exception):
    """Raised when provider interaction or verification fails."""


class PaymentProvider:
    """Interface implemented by every payment provider adapter."""

    code = "BASE"
    label = "Base provider"

    def create_checkout(self, payment):
        """Return a checkout URL/path for a PendingPayment transaction."""
        raise NotImplementedError

    def verify_webhook(self, payload, signature):
        """Validate the callback and return a WebhookEvent."""
        raise NotImplementedError

    def fetch_status(self, provider_transaction_id):
        """Reconcile the payment status with the provider."""
        raise NotImplementedError
