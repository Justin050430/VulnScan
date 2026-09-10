"""User management API tests (Administrator)."""
from conftest import auth


def test_admin_creates_user(client, admin_token):
    resp = client.post("/api/users", headers=auth(admin_token), json={
        "username": "alice",
        "email": "alice@vulnscan.local",
        "password": "Alice@12345",
        "role": "Developer",
    })
    assert resp.status_code == 201
    body = resp.get_json()
    assert body["User"]["Email"] == "alice@vulnscan.local"
    assert body["User"]["Role"] == "Developer"
    assert "PasswordHash" not in body["User"]  # never exposed


def test_create_user_duplicate_email(client, admin_token):
    resp = client.post("/api/users", headers=auth(admin_token), json={
        "username": "someone",
        "email": "developer@vulnscan.local",
        "password": "Some@12345",
    })
    assert resp.status_code == 400


def test_create_user_invalid_email(client, admin_token):
    resp = client.post("/api/users", headers=auth(admin_token), json={
        "username": "bob",
        "email": "not-an-email",
        "password": "Some@12345",
    })
    assert resp.status_code == 400


def test_create_user_short_password(client, admin_token):
    resp = client.post("/api/users", headers=auth(admin_token), json={
        "username": "bob",
        "email": "bob@vulnscan.local",
        "password": "short",
    })
    assert resp.status_code == 400


def test_create_user_invalid_role(client, admin_token):
    resp = client.post("/api/users", headers=auth(admin_token), json={
        "username": "bob",
        "email": "bob@vulnscan.local",
        "password": "Some@12345",
        "role": "Superuser",
    })
    assert resp.status_code == 400


def test_admin_updates_user_role_and_status(client, admin_token):
    # create
    r = client.post("/api/users", headers=auth(admin_token), json={
        "username": "carol", "email": "carol@vulnscan.local",
        "password": "Carol@12345", "role": "Developer"})
    uid = r.get_json()["User"]["UserID"]
    # update role to admin
    resp = client.put(f"/api/users/{uid}", headers=auth(admin_token),
                      json={"role": "Administrator"})
    assert resp.status_code == 200
    assert resp.get_json()["User"]["Role"] == "Administrator"
    # disable
    resp = client.put(f"/api/users/{uid}", headers=auth(admin_token),
                      json={"is_active": False})
    assert resp.get_json()["User"]["IsActive"] is False


def test_disable_user_prevents_login(client, admin_token):
    r = client.post("/api/users", headers=auth(admin_token), json={
        "username": "dave", "email": "dave@vulnscan.local",
        "password": "Dave@12345", "role": "Developer"})
    uid = r.get_json()["User"]["UserID"]
    client.delete(f"/api/users/{uid}", headers=auth(admin_token))
    resp = client.post("/api/auth/login", json={
        "email": "dave@vulnscan.local", "password": "Dave@12345"})
    assert resp.status_code == 401


def test_cannot_disable_last_admin(client, admin_token):
    users = client.get("/api/users", headers=auth(admin_token)).get_json()["Users"]
    admin = next(u for u in users if u["Role"] == "Administrator")
    resp = client.delete(f"/api/users/{admin['UserID']}", headers=auth(admin_token))
    assert resp.status_code == 400  # protected
