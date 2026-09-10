"""Authentication endpoints: login, Google sign-in, logout."""
import logging

from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt

from app.models import User
from app.services import auth_service, google_service
from app.utils.security import get_current_user, roles_required

logger = logging.getLogger("vulnscan.auth_routes")

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr

    user = auth_service.authenticate_user(email, password)
    if user is None:
        # Do not reveal whether the account exists or is merely disabled.
        auth_service.record_login_failure(email, ip_address=ip)
        return (
            jsonify({
                "message": "Invalid email address or password.",
                "code": "invalid_credentials",
            }),
            401,
        )

    token = auth_service.issue_token_for_user(user)
    auth_service.record_login_success(user, ip_address=ip)
    return jsonify({
        "access_token": token,
        "token_type": "Bearer",
        "user": user.to_dict(),
    }), 200


@auth_bp.get("/google/url")
def google_authorize_url():
    """Return the Google authorization URL for the 'Sign in with Google' button."""
    if not google_service.is_configured():
        return jsonify({
            "configured": False,
            "message": "Google Sign-In is not configured.",
        }), 200
    url = google_service.build_authorize_url()
    return jsonify({"configured": True, "authorize_url": url}), 200


@auth_bp.get("/google/callback")
def google_callback():
    """Handles the Google redirect containing the authorization code.

    Returns a tiny page that forwards the code to the JSON API endpoint
    POST /api/auth/google and stores the resulting JWT on the client.
    """
    code = request.args.get("code")
    error = request.args.get("error")
    state = request.args.get("state")
    if error:
        html = _redirect_script("/#/login?error=" + error)
        return _html_response(html)
    if not code:
        return _html_response(_redirect_script("/#/login?error=missing_code"))
    html = f"""<!doctype html><html><head><meta charset="utf-8">
<title>Signing in...</title></head><body>
<script>
const code = {json_safe(code)};
fetch('/api/auth/google', {{
  method: 'POST',
  headers: {{'Content-Type': 'application/json'}},
  body: JSON.stringify({{ code: code }})
}})
.then(r => r.json().then(b => ({{ ok: r.ok, body: b }})))
.then(({{ ok, body }}) => {{
  if (ok && body.access_token) {{
    localStorage.setItem('vulnscan_token', body.access_token);
    localStorage.setItem('vulnscan_user', JSON.stringify(body.user));
    window.location.href = '/#/dashboard';
  }} else {{
    window.location.href = '/#/login?error=' + encodeURIComponent(body.message || 'google_failed');
  }}
}})
.catch(() => window.location.href = '/#/login?error=google_network_error');
</script></body></html>"""
    return _html_response(html)


@auth_bp.post("/google")
def google_sign_in():
    """Complete Google OAuth 2.0 sign-in and return a JWT.

    Body: { code: <authorization code>, redirect_uri?: <optional> }
    """
    if not google_service.is_configured():
        return jsonify({
            "message": "Google Sign-In is not configured on the server.",
            "code": "google_not_configured",
        }), 503

    data = request.get_json(silent=True) or {}
    code = data.get("code")
    redirect_uri = data.get("redirect_uri")
    ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr

    if not code:
        return jsonify({"message": "Authorization code is required.", "code": "bad_request"}), 400

    try:
        profile = google_service.get_google_user_profile(code, redirect_uri=redirect_uri)
    except google_service.GoogleNotConfiguredError as exc:
        return jsonify({"message": str(exc), "code": "google_not_configured"}), 503
    except google_service.GoogleOAuthError as exc:
        auth_service.record_login_failure("unknown@google", ip_address=ip,
                                          reason="google oauth error")
        return jsonify({"message": str(exc), "code": "google_auth_failed"}), 400

    email = profile["email"]
    user = User.query.filter_by(Email=email).first()
    if user is None:
        auth_service.record_login_failure(email, ip_address=ip, reason="no account")
        return jsonify({
            "message": "No VulnScan account is associated with this Google account. "
                       "Please contact your administrator.",
            "code": "account_not_found",
        }), 403
    if not user.IsActive:
        auth_service.record_login_failure(email, ip_address=ip, reason="account disabled")
        return jsonify({"message": "This account has been disabled.", "code": "account_disabled"}), 403

    token = auth_service.issue_token_for_user(user)
    auth_service.record_login_success(user, ip_address=ip)
    return jsonify({
        "access_token": token,
        "token_type": "Bearer",
        "user": user.to_dict(),
    }), 200


@auth_bp.post("/logout")
@roles_required("Administrator", "Developer")
def logout():
    jwt_payload = get_jwt()
    auth_service.revoke_jti(jwt_payload.get("jti"), jwt_payload.get("exp"))
    user = get_current_user()
    ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr
    auth_service.record_logout(user, ip_address=ip)
    return jsonify({"message": "Signed out successfully."}), 200


def json_safe(value):
    import json

    return json.dumps(value)


def _html_response(html):
    from flask import Response

    return Response(html, mimetype="text/html")


def _redirect_script(url):
    return (
        f"<!doctype html><html><head><meta charset='utf-8'><title>Redirecting...</title>"
        f"</head><body><script>window.location.href = {json_safe(url)};</script></body></html>"
    )
