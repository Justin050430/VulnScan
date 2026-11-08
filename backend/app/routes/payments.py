"""Product catalogue, mock checkout, credits and provider callbacks."""
from flask import Blueprint, jsonify, request

from app.models import TrustPaymentTransaction
from app.services import credit_service, payment_service
from app.trust.constants import (
    PERM_CREDIT_PURCHASE,
    PERM_CREDIT_READ,
    PROVIDER_MOCK,
)
from app.trust.permissions import (
    client_ip,
    mock_provider_enabled,
    not_found,
    require_permission,
)
from app.utils.security import any_authenticated, get_current_user

payments_bp = Blueprint("trust_payments", __name__, url_prefix="")
payments_scoped_bp = Blueprint("trust_project_payments", __name__, url_prefix="/projects")

SIGNATURE_HEADER = "X-VulnScan-Signature"


@payments_bp.get("/products")
@any_authenticated
def list_products():
    return jsonify({
        "Products": payment_service.list_products(),
        "Provider": PROVIDER_MOCK,
        "Mock": True,
        "Notice": "Mock provider - no real money is processed.",
    }), 200


@payments_scoped_bp.post("/<int:project_id>/payments/checkout")
@require_permission(PERM_CREDIT_PURCHASE)
def create_checkout(project_id, _access=None):
    data = request.get_json(silent=True) or {}
    payment, replay = payment_service.create_checkout(
        get_current_user(),
        _access,
        data.get("product_code"),
        quantity=data.get("quantity", 1),
        idempotency_key=data.get("idempotency_key"),
        ip_address=client_ip(),
    )
    return jsonify({
        "Payment": payment.to_dict(),
        "CheckoutURL": f"/api/v1/mock-checkout/{payment.PaymentUUID}",
        "Mock": True,
        "Notice": "Mock provider - no real money is processed.",
        "IdempotentReplay": replay,
    }), 201


@payments_scoped_bp.get("/<int:project_id>/payments/<payment_uuid>")
@require_permission(PERM_CREDIT_READ)
def get_payment(project_id, payment_uuid, _access=None):
    payment = payment_service.get_payment(project_id, payment_uuid)
    return jsonify({"Payment": payment.to_dict(), "Mock": True}), 200


@payments_scoped_bp.post(
    "/<int:project_id>/payments/<payment_uuid>/mock-complete"
)
@require_permission(PERM_CREDIT_PURCHASE)
def complete_mock_payment(project_id, payment_uuid, _access=None):
    """Server-side mock completion.  A browser redirect alone never grants a
    credit; this endpoint stands in for a signed provider callback."""
    if not mock_provider_enabled():
        from app.trust.permissions import TrustError
        from app.trust.constants import ERR_VALIDATION

        raise TrustError(
            "Mock checkout is only available with the mock provider.",
            ERR_VALIDATION,
            400,
        )
    payment = payment_service.get_payment(project_id, payment_uuid)
    if payment.Status == "PaymentVerified":
        return jsonify({
            "Payment": payment.to_dict(),
            "CreditsIssued": 0,
            "Duplicate": True,
        }), 200
    data = request.get_json(silent=True) or {}
    result = payment_service.complete_mock_checkout(
        payment,
        outcome=data.get("outcome", "success"),
        ip_address=client_ip(),
        actor=get_current_user(),
    )
    return jsonify({
        "Payment": result["Payment"].to_dict() if result["Payment"] else None,
        "CreditsIssued": result["CreditsIssued"],
        "Duplicate": result["Duplicate"],
    }), 200


@payments_bp.post("/payments/webhooks/<provider>")
def provider_webhook(provider):
    """Provider callback.  Authenticated by signature, never by the browser."""
    signature = (
        request.headers.get(SIGNATURE_HEADER)
        or (request.get_json(silent=True) or {}).get("signature")
    )
    payload = request.get_json(silent=True) or {}
    if provider.upper() != "MOCK":
        from app.trust.constants import ERR_PAYMENT_NOT_VERIFIED
        from app.trust.permissions import TrustError

        raise TrustError(
            "This payment provider is not implemented.",
            ERR_PAYMENT_NOT_VERIFIED,
            400,
        )
    result = payment_service.process_callback(
        payload, signature, ip_address=client_ip()
    )
    return jsonify({
        "received": True,
        "CreditsIssued": result["CreditsIssued"],
        "Duplicate": result["Duplicate"],
    }), 200


@payments_scoped_bp.get("/<int:project_id>/credits")
@require_permission(PERM_CREDIT_READ)
def list_credits(project_id, _access=None):
    credit_service.expire_stale(project_id)
    status = request.args.get("status")
    credits = credit_service.list_credits(project_id, status=status)
    return jsonify({
        "Credits": [c.to_dict() for c in credits],
        "AvailableCount": len(credit_service.available_credits(project_id)),
        "Total": len(credits),
    }), 200


@payments_scoped_bp.get("/<int:project_id>/credit-redemptions")
@require_permission(PERM_CREDIT_READ)
def list_redemptions(project_id, _access=None):
    from app.models import TrustCreditRedemption

    rows = (
        TrustCreditRedemption.query.filter_by(ProjectID=int(project_id))
        .order_by(TrustCreditRedemption.RedemptionID.desc())
        .all()
    )
    return jsonify({
        "Redemptions": [r.to_dict() for r in rows],
        "Total": len(rows),
    }), 200


@payments_bp.get("/mock-checkout/<payment_uuid>")
def mock_checkout_page(payment_uuid):
    """Minimal clearly-labelled mock checkout page (no secrets, no card data)."""
    payment = TrustPaymentTransaction.query.filter_by(
        PaymentUUID=str(payment_uuid)
    ).first()
    if payment is None:
        raise not_found("Payment")
    html = f"""<!doctype html><html><head><meta charset="utf-8">
<title>Mock checkout - VulnScan</title>
<style>body{{font-family:system-ui,sans-serif;max-width:520px;margin:60px auto;
padding:24px;border:1px solid #ddd;border-radius:12px}}
.banner{{background:#fff4e5;border:1px solid #f0b429;padding:12px;
border-radius:8px;font-weight:600;margin-bottom:18px}}
button{{padding:10px 18px;border-radius:8px;border:0;background:#1d4ed8;
color:#fff;font-weight:600;cursor:pointer}}</style></head><body>
<div class="banner">No real money — this is a mock payment page.</div>
<h2>Mock payment</h2>
<p>Product: <b>{payment.ProductCode}</b><br/>
Quantity: <b>{payment.Quantity}</b><br/>
Amount: <b>{payment.AmountMinor / 100:.2f} {payment.Currency}</b></p>
<p>Reference: <code>{payment.PaymentUUID}</code></p>
<button onclick="completePayment()">Pay (mock)</button>
<script>
async function completePayment() {{
  const token = localStorage.getItem('vulnscan_token');
  const resp = await fetch('/api/v1/projects/{payment.ProjectID}/payments/{payment.PaymentUUID}/mock-complete', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + token}},
    body: JSON.stringify({{outcome: 'success'}})
  }});
  const body = await resp.json();
  document.body.insertAdjacentHTML('beforeend',
    '<p><b>' + (resp.ok ? 'Mock payment verified. Credits issued: ' + body.CreditsIssued : 'Failed: ' + body.message) + '</b></p>');
}}
</script></body></html>"""
    from flask import Response

    return Response(html, mimetype="text/html")
