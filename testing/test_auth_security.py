"""
Authentication security tests: JWT tampering/expiry/revocation and a genuine
(end-to-end) Google OAuth 2.0 code-exchange flow with the external identity
provider mocked at the HTTP/library boundary only.
"""
from datetime import timedelta

import pytest
from flask_jwt_extended import create_access_token

from conftest import auth


# --------------------------------------------------------------------------
# JWT security
# --------------------------------------------------------------------------
def test_jwt_with_wrong_signature_rejected(client):
    """A token signed with the wrong key must be rejected."""
    import time

    import jwt as pyjwt

    forged = pyjwt.encode(
        {"sub": "1", "role": "Administrator", "jti": "forged",
         "iat": int(time.time()), "exp": int(time.time()) + 3600},
        "an-attacker-secret",
        algorithm="HS256",
    )
    resp = client.get("/api/users", headers=auth(forged))
    assert resp.status_code == 401


def test_expired_jwt_rejected(app, client):
    with app.app_context():
        token = create_access_token(identity="1", expires_delta=timedelta(seconds=-10))
    resp = client.get("/api/vulnerabilities", headers=auth(token))
    assert resp.status_code == 401


def test_disabled_user_token_rejected(client, admin_token, dev_token):
    """A token issued before the account is disabled must stop working."""
    # find the developer's id and disable the account
    users = client.get("/api/users", headers=auth(admin_token)).get_json()["Users"]
    dev = next(u for u in users if u["Email"] == "developer@vulnscan.local")
    assert client.delete(f"/api/users/{dev['UserID']}", headers=auth(admin_token)).status_code == 200
    resp = client.get("/api/vulnerabilities", headers=auth(dev_token))
    assert resp.status_code == 401


def test_token_cannot_be_reused_after_logout(client, admin_token):
    assert client.post("/api/auth/logout", headers=auth(admin_token)).status_code == 200
    assert client.get("/api/users", headers=auth(admin_token)).status_code == 401


# --------------------------------------------------------------------------
# Google OAuth 2.0 (real flow, external IdP mocked at the boundary)
# --------------------------------------------------------------------------
@pytest.fixture()
def google_app(app):
    app.config["GOOGLE_CLIENT_ID"] = "test-client-id.apps.googleusercontent.com"
    app.config["GOOGLE_CLIENT_SECRET"] = "test-client-secret"
    app.config["GOOGLE_REDIRECT_URI"] = "http://localhost:5000/api/auth/google/callback"
    return app


def test_google_authorize_url_is_built_correctly(google_app, client):
    resp = client.get("/api/auth/google/url")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["configured"] is True
    url = body["authorize_url"]
    assert url.startswith("https://accounts.google.com/o/oauth2/v2/auth?")
    assert "client_id=test-client-id.apps.googleusercontent.com" in url
    assert "response_type=code" in url
    assert "scope=openid" in url and "email" in url
    assert "redirect_uri=" in url


def test_google_sign_in_issues_jwt_for_known_user(google_app, client, monkeypatch):
    import app.services.google_service as gs

    def fake_exchange(code, redirect_uri=None):
        assert code == "auth-code-123"
        return {
            "sub": "google-sub-1",
            "email": "developer@vulnscan.local",
            "email_verified": True,
            "name": "Developer",
        }

    monkeypatch.setattr(gs, "exchange_authorization_code", fake_exchange)
    resp = client.post("/api/auth/google", json={"code": "auth-code-123"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["access_token"]
    assert body["user"]["Email"] == "developer@vulnscan.local"
    # the issued JWT is a real working token
    assert client.get("/api/vulnerabilities",
                      headers=auth(body["access_token"])).status_code == 200


def test_google_sign_in_rejects_unknown_email(google_app, client, monkeypatch):
    import app.services.google_service as gs

    monkeypatch.setattr(gs, "exchange_authorization_code", lambda code, redirect_uri=None: {
        "sub": "google-sub-2",
        "email": "stranger@gmail.com",
        "email_verified": True,
        "name": "Stranger",
    })
    resp = client.post("/api/auth/google", json={"code": "x"})
    assert resp.status_code == 403
    assert resp.get_json()["code"] == "account_not_found"


def test_google_sign_in_rejects_unverified_email(google_app, client, monkeypatch):
    """An unverified Google email must not authenticate."""
    import requests as requests_lib

    import app.services.google_service as gs

    class _Resp:
        status_code = 200

        def json(self):
            return {"id_token": "fake-id-token"}

    monkeypatch.setattr(requests_lib, "post", lambda *a, **k: _Resp())
    monkeypatch.setattr(
        gs.id_token, "verify_oauth2_token",
        lambda *a, **k: {"sub": "s", "email": "u@example.com", "email_verified": False},
    )
    resp = client.post("/api/auth/google", json={"code": "x"})
    assert resp.status_code == 400
    assert "not verified" in resp.get_json()["message"].lower()


def test_google_code_exchange_uses_token_endpoint(google_app, client, monkeypatch):
    """The real exchange path must POST the code to Google's token endpoint."""
    import requests as requests_lib

    import app.services.google_service as gs

    captured = {}

    class _Resp:
        status_code = 200

        def json(self):
            return {"id_token": "fake-id-token"}

    def fake_post(url, data=None, timeout=None):
        captured["url"] = url
        captured["data"] = data
        return _Resp()

    monkeypatch.setattr(requests_lib, "post", fake_post)
    monkeypatch.setattr(
        gs.id_token, "verify_oauth2_token",
        lambda *a, **k: {"sub": "s", "email": "developer@vulnscan.local",
                         "email_verified": True},
    )
    resp = client.post("/api/auth/google", json={"code": "the-code"})
    assert resp.status_code == 200
    assert captured["url"] == "https://oauth2.googleapis.com/token"
    assert captured["data"]["grant_type"] == "authorization_code"
    assert captured["data"]["code"] == "the-code"
    assert captured["data"]["client_secret"] == "test-client-secret"


def test_google_missing_code_rejected(google_app, client):
    resp = client.post("/api/auth/google", json={})
    assert resp.status_code == 400
