"""Provider registry - resolves the configured payment provider."""
from app.payments.base import PaymentProviderError
from app.payments.mock_provider import MockProvider

_PROVIDERS = {
    MockProvider.code: MockProvider,
}


def get_provider(code=None):
    from flask import current_app

    if code is None:
        code = current_app.config.get("TRUST_PAYMENT_PROVIDER", "MOCK")
    provider_class = _PROVIDERS.get(str(code).upper())
    if provider_class is None:
        raise PaymentProviderError(
            f"Payment provider '{code}' is not implemented in this release."
        )
    return provider_class()
