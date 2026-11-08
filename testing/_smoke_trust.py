"""Temporary end-to-end smoke script for the Trust Boundary slice."""
import sys
from datetime import datetime, timedelta

sys.path.insert(0, "backend")

from app import create_app
from app.extensions import db as _db
from app.seeds import run_seed


def main():
    app = create_app("testing")
    app.config["TRUST_BOUNDARY_MODE"] = "enforce"
    with app.app_context():
        _db.create_all()
        run_seed()
        for p in app.url_map.iter_rules():
            pass
    client = app.test_client()

    def login(email, password):
        r = client.post("/api/auth/login", json={"email": email, "password": password})
        assert r.status_code == 200, r.get_json()
        return r.get_json()["access_token"]

    token = login("developer@vulnscan.local", "Developer@VulnScan2025")
    h = {"Authorization": f"Bearer {token}"}

    r = client.post("/api/v1/organisations", json={"name": "Smoke Org"}, headers=h)
    print("org", r.status_code, r.get_json())
    org = r.get_json()["Organisation"]

    r = client.post("/api/v1/projects", json={"organisation_id": org["OrganisationID"],
                                              "name": "Smoke Project"}, headers=h)
    print("project", r.status_code, r.get_json())
    project = r.get_json()["Project"]

    r = client.post(f"/api/v1/projects/{project['ProjectID']}/assets",
                    json={"hostname": "localhost", "scheme": "http"}, headers=h)
    print("asset", r.status_code, r.get_json())
    asset = r.get_json()["Asset"]

    with app.app_context():
        from app.models import TrustAsset
        a = _db.session.get(TrustAsset, asset["AssetID"])
        a.VerificationStatus = "Verified"
        a.VerifiedAt = datetime.utcnow()
        a.VerificationExpiresAt = datetime.utcnow() + timedelta(days=90)
        _db.session.commit()

    r = client.post(f"/api/v1/projects/{project['ProjectID']}/assets/{asset['AssetID']}/attestations",
                    json={"expires_in_days": 30}, headers=h)
    print("attestation", r.status_code, r.get_json())

    r = client.post(f"/api/v1/projects/{project['ProjectID']}/payments/checkout",
                    json={"product_code": "SCAN_CREDIT_1", "quantity": 1}, headers=h)
    print("checkout", r.status_code, r.get_json())
    pay = r.get_json()["Payment"]

    r = client.post(f"/api/v1/projects/{project['ProjectID']}/payments/{pay['PaymentUUID']}/mock-complete",
                    json={"outcome": "success"}, headers=h)
    print("complete", r.status_code, r.get_json())

    r = client.get(f"/api/v1/projects/{project['ProjectID']}/credits", headers=h)
    print("credits", r.status_code, r.get_json())
    credit = r.get_json()["Credits"][0]

    r = client.get(f"/api/v1/projects/{project['ProjectID']}/scan-readiness?asset_id={asset['AssetID']}",
                   headers=h)
    print("readiness", r.status_code, r.get_json())

    profiles = client.get("/api/scan-profiles", headers=h).get_json()["ScanProfiles"]
    profile = [p for p in profiles if p["Name"] == "OWASP Top 10 Full Scan"][0]

    r = client.post(f"/api/v1/projects/{project['ProjectID']}/scans",
                    json={"asset_id": asset["AssetID"], "scan_profile_id": profile["ScanProfileID"],
                          "credit_id": credit["CreditUUID"], "target_url": "http://localhost:5199/"},
                    headers=h)
    print("scan", r.status_code, r.get_json())

    r = client.get(f"/api/v1/projects/{project['ProjectID']}/audit-events", headers=h)
    print("audit", r.status_code, len(r.get_json().get("Events", [])))

    r = client.post("/api/scans", json={"target_url": "http://localhost:5199/",
                                        "scan_profile_id": profile["ScanProfileID"]}, headers=h)
    print("legacy", r.status_code, r.get_json())

    with app.app_context():
        from app.models import TrustScanCredit, TrustCreditRedemption
        print("credit status", [c.Status for c in TrustScanCredit.query.all()])
        print("redemptions", [r.Status for r in TrustCreditRedemption.query.all()])


if __name__ == "__main__":
    main()
