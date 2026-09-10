"""
Google Sign-In (OAuth 2.0) service.

Implements the documented flow:
  user clicks "Sign in with Google" -> Google returns an authorization code ->
  the web UI posts the code to /api/auth/google -> this service exchanges the
  code for tokens, verifies the ID token (using the official google-auth
  library), and returns the verified profile (incl. verified email).

Configuration is read exclusively from environment variables; no credentials
are hard-coded.
"""
import logging
import secrets
import urllib.parse

import requests
from flask import current_app
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token

logger = logging.getLogger("vulnscan.google")


class GoogleOAuthError(Exception):
    """Raised when Google sign-in cannot be completed."""


class GoogleNotConfiguredError(GoogleOAuthError):
    pass


def is_configured():
    cfg = current_app.config
    return bool(cfg.get("GOOGLE_CLIENT_ID") and cfg.get("GOOGLE_CLIENT_SECRET"))


def _require_config():
    cfg = current_app.config
    client_id = cfg.get("GOOGLE_CLIENT_ID")
    client_secret = cfg.get("GOOGLE_CLIENT_SECRET")
    if not client_id or not client_secret:
        raise GoogleNotConfiguredError(
            "Google Sign-In is not configured on the server. Contact your administrator."
        )
    return client_id, client_secret


def build_authorize_url(state=None, redirect_uri=None):
    """Construct the Google OAuth 2.0 authorization URL (server-side flow)."""
    client_id, _ = _require_config()
    cfg = current_app.config
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri or cfg.get("GOOGLE_REDIRECT_URI"),
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "online",
        "prompt": "select_account",
        "state": state or secrets.token_urlsafe(16),
    }
    return cfg.get("GOOGLE_AUTH_URI") + "?" + urllib.parse.urlencode(params)


def exchange_authorization_code(code, redirect_uri=None):
    """
    Exchange an authorization code for a verified Google profile.

    Returns a dict with 'sub', 'email', 'email_verified', 'name' and other
    standard OpenID Connect claims.
    """
    client_id, client_secret = _require_config()
    cfg = current_app.config
    token_resp = requests.post(
        cfg.get("GOOGLE_TOKEN_URI"),
        data={
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri or cfg.get("GOOGLE_REDIRECT_URI"),
            "grant_type": "authorization_code",
        },
        timeout=15,
    )
    if token_resp.status_code != 200:
        logger.warning("Google token exchange failed: %s", token_resp.text[:300])
        raise GoogleOAuthError("Google could not complete the sign-in.")

    tokens = token_resp.json()
    id_token_str = tokens.get("id_token")
    if not id_token_str:
        raise GoogleOAuthError("Google did not return an identity token.")

    try:
        claims = id_token.verify_oauth2_token(
            id_token_str,
            google_requests.Request(),
            audience=client_id,
        )
    except ValueError as exc:
        raise GoogleOAuthError("Could not verify the Google identity token.") from exc

    if not claims.get("email_verified", False):
        raise GoogleOAuthError("The Google account email is not verified.")
    return claims


def get_google_user_profile(code, redirect_uri=None):
    """High-level helper returning (email, name, google_sub)."""
    claims = exchange_authorization_code(code, redirect_uri=redirect_uri)
    email = (claims.get("email") or "").lower()
    if not email:
        raise GoogleOAuthError("Google did not return an email address.")
    return {
        "email": email,
        "name": claims.get("name"),
        "google_sub": claims.get("sub"),
    }
