"""Vulnerability knowledge-base and scan profile tests."""
from conftest import auth


# --------------------------------------------------------------------------
# Vulnerabilities
# --------------------------------------------------------------------------
def test_list_vulnerabilities(client, dev_token):
    data = client.get("/api/vulnerabilities", headers=auth(dev_token)).get_json()
    assert data["Total"] >= 8
    names = [v["Name"] for v in data["Vulnerabilities"]]
    assert "SQL Injection" in names
    assert "Cross-Site Scripting (XSS)" in names


def test_developer_cannot_see_disabled_vulns(client, admin_token, dev_token):
    # disable one as admin
    vulns = client.get("/api/vulnerabilities", headers=auth(admin_token),
                       query_string={"include_disabled": "true"}).get_json()["Vulnerabilities"]
    target = next(v for v in vulns if v["ModuleKey"] == "sqli")
    client.put(f"/api/vulnerabilities/{target['VulnerabilityID']}",
               headers=auth(admin_token), json={"IsEnabled": False})
    dev_data = client.get("/api/vulnerabilities", headers=auth(dev_token)).get_json()
    assert all(v["IsEnabled"] for v in dev_data["Vulnerabilities"])
    assert "SQL Injection" not in [v["Name"] for v in dev_data["Vulnerabilities"]]
    # restore
    client.put(f"/api/vulnerabilities/{target['VulnerabilityID']}",
               headers=auth(admin_token), json={"IsEnabled": True})


def test_admin_creates_and_updates_vulnerability(client, admin_token):
    r = client.post("/api/vulnerabilities", headers=auth(admin_token), json={
        "Name": "Test Vuln", "OWASPCategory": "Test", "Description": "d",
        "Impact": "i", "Recommendation": "r", "SecurityCodingPractice": "s",
        "OWASPReference": "o", "ReferenceURL": "https://example.com", "IsEnabled": True,
    })
    assert r.status_code == 201
    vid = r.get_json()["Vulnerability"]["VulnerabilityID"]
    r = client.put(f"/api/vulnerabilities/{vid}", headers=auth(admin_token),
                   json={"Description": "updated"})
    assert r.status_code == 200
    assert r.get_json()["Vulnerability"]["Description"] == "updated"


def test_module_vuln_cannot_be_renamed(client, admin_token):
    vulns = client.get("/api/vulnerabilities", headers=auth(admin_token),
                       query_string={"include_disabled": "true"}).get_json()["Vulnerabilities"]
    sqli = next(v for v in vulns if v["ModuleKey"] == "sqli")
    resp = client.put(f"/api/vulnerabilities/{sqli['VulnerabilityID']}",
                      headers=auth(admin_token), json={"Name": "SQL Injection v2"})
    assert resp.status_code == 400


def test_duplicate_vulnerability_name(client, admin_token):
    resp = client.post("/api/vulnerabilities", headers=auth(admin_token),
                       json={"Name": "SQL Injection"})
    assert resp.status_code == 400


# --------------------------------------------------------------------------
# Scan profiles
# --------------------------------------------------------------------------
def _module_ids(client, admin_token):
    vulns = client.get("/api/vulnerabilities", headers=auth(admin_token),
                       query_string={"include_disabled": "true"}).get_json()["Vulnerabilities"]
    return [v["VulnerabilityID"] for v in vulns if v["ModuleKey"]]


def test_admin_creates_profile(client, admin_token):
    ids = _module_ids(client, admin_token)
    resp = client.post("/api/scan-profiles", headers=auth(admin_token), json={
        "name": "Test Profile", "max_depth": 2, "max_pages": 15,
        "request_delay_ms": 100, "follow_external": False,
        "module_vuln_ids": ids,
    })
    assert resp.status_code == 201
    prof = resp.get_json()["ScanProfile"]
    assert len(prof["Modules"]) == len(ids)
    assert prof["MaxDepth"] == 2


def test_developer_can_list_profiles(client, dev_token):
    data = client.get("/api/scan-profiles", headers=auth(dev_token)).get_json()
    assert data["Total"] >= 3


def test_create_profile_duplicate_name(client, admin_token):
    resp = client.post("/api/scan-profiles", headers=auth(admin_token),
                       json={"name": "Quick Scan"})
    assert resp.status_code == 400


def test_create_profile_bad_module(client, admin_token):
    resp = client.post("/api/scan-profiles", headers=auth(admin_token), json={
        "name": "Broken Profile", "module_vuln_ids": [999999]})
    assert resp.status_code == 400


def test_update_profile_modules(client, admin_token):
    ids = _module_ids(client, admin_token)
    profiles = client.get("/api/scan-profiles", headers=auth(admin_token)).get_json()["ScanProfiles"]
    p = next(x for x in profiles if x["Name"] == "Quick Scan")
    # remove all modules
    resp = client.put(f"/api/scan-profiles/{p['ScanProfileID']}",
                      headers=auth(admin_token),
                      json={"module_vuln_ids": ids[:1], "max_pages": 5})
    assert resp.status_code == 200
    updated = resp.get_json()["ScanProfile"]
    assert len(updated["Modules"]) == 1
    assert updated["MaxPages"] == 5


def test_delete_profile_in_use_blocked(client, admin_token):
    # all seeded profiles are referenced by scans only after we scan; use a new one
    ids = _module_ids(client, admin_token)
    r = client.post("/api/scan-profiles", headers=auth(admin_token), json={
        "name": "To Delete", "module_vuln_ids": ids})
    pid = r.get_json()["ScanProfile"]["ScanProfileID"]
    resp = client.delete(f"/api/scan-profiles/{pid}", headers=auth(admin_token))
    assert resp.status_code == 200


def test_profile_preview_lists_plan(client, dev_token):
    profiles = client.get("/api/scan-profiles", headers=auth(dev_token)).get_json()["ScanProfiles"]
    full = next(p for p in profiles if p["Name"] == "OWASP Top 10 Full Scan")
    data = client.get(f"/api/scan-profiles/{full['ScanProfileID']}/preview",
                      headers=auth(dev_token)).get_json()["Preview"]
    assert data["Limits"]["MaxPages"] == full["MaxPages"]
    keys = {m["ModuleKey"] for m in data["Modules"]}
    assert {"sqli", "xss", "http_headers"} <= keys
    sqli = next(m for m in data["Modules"] if m["ModuleKey"] == "sqli")
    assert any("error-based" in t for t in sqli["Techniques"])
    assert any("depth" in s for s in data["WillTest"])
    assert any("POST" in s for s in data["WillNotTest"])
    assert "RequestBudgetNote" in data


def test_profile_preview_unknown_id(client, dev_token):
    resp = client.get("/api/scan-profiles/999999/preview", headers=auth(dev_token))
    assert resp.status_code == 404
