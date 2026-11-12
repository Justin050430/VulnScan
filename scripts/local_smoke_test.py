"""
End-to-end local smoke test for VulnScan (Trust Boundary flow).

Requires the local environment to be running:

    .\\scripts\\start-local.ps1

The script then drives the real product flow over HTTP - sign in, organisation,
project, verified asset, attestation, mock credit, gated scan - against the
intentionally vulnerable target that ships with the repository, and prints a
detection-quality summary of the findings.

Nothing outside loopback is contacted and no real money is involved.
"""
import argparse
import sys
import time
from collections import Counter, defaultdict

import requests

ORG_NAME = "VulnScan Local Demo"
ORG_SLUG = "vulnscan-local-demo"
PROJECT_NAME = "Demo Shop"
PROJECT_SLUG = "demo-shop"
ASSET_HOST = "localhost"
DEFAULT_PROFILE = "OWASP Top 10 Full Scan"

TERMINAL_SCAN_STATES = {"Completed", "Failed", "Cancelled"}


class ApiError(RuntimeError):
    pass


class Api:
    def __init__(self, base_url, token=None):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.token = token

    def set_token(self, token):
        self.token = token
        self.session.headers["Authorization"] = f"Bearer {token}"

    def request(self, method, path, expected=(200, 201, 202), **kwargs):
        response = self.session.request(
            method, self.base_url + path, timeout=60, **kwargs
        )
        if response.status_code not in expected:
            raise ApiError(
                f"{method} {path} -> {response.status_code}: {response.text[:400]}"
            )
        return response.json() if response.content else {}

    def get(self, path, **kwargs):
        return self.request("GET", path, **kwargs)

    def post(self, path, **kwargs):
        return self.request("POST", path, **kwargs)


def step(message):
    print(f"\n== {message}")


def login(api, email, password):
    data = api.post("/api/auth/login", json={"email": email, "password": password})
    api.set_token(data["access_token"])
    print(f"   signed in as {email} ({data.get('user', {}).get('Role', '?')})")


def ensure_organisation(api):
    for org in api.get("/api/v1/organisations")["Organisations"]:
        if org["Slug"] == ORG_SLUG:
            print(f"   using organisation {org['Name']} (ID {org['OrganisationID']})")
            return org
    data = api.post(
        "/api/v1/organisations", json={"name": ORG_NAME, "slug": ORG_SLUG}
    )
    org = data["Organisation"]
    print(f"   created organisation {org['Name']} (ID {org['OrganisationID']})")
    return org


def ensure_project(api, organisation_id):
    for row in api.get(
        f"/api/v1/projects?organisation_id={organisation_id}"
    )["Projects"]:
        project = row["Project"]
        if project["Slug"] == PROJECT_SLUG:
            print(f"   using project {project['Name']} (ID {project['ProjectID']})")
            return project
    data = api.post(
        "/api/v1/projects",
        json={
            "organisation_id": organisation_id,
            "name": PROJECT_NAME,
            "slug": PROJECT_SLUG,
        },
    )
    project = data["Project"]
    print(f"   created project {project['Name']} (ID {project['ProjectID']})")
    return project


def publish_challenge(target_url, content):
    response = requests.post(
        f"{target_url.rstrip('/')}/__test__/verification",
        data={"content": content},
        timeout=10,
    )
    response.raise_for_status()
    if content not in response.text:
        raise ApiError("the target did not publish the verification challenge")


def ensure_verified_asset(api, project_id, target_url):
    for asset in api.get(f"/api/v1/projects/{project_id}/assets")["Assets"]:
        if asset["Hostname"] == ASSET_HOST:
            print(
                f"   using asset {asset['Hostname']} "
                f"(ID {asset['AssetID']}, {asset['VerificationStatus']})"
            )
            break
    else:
        asset = api.post(
            f"/api/v1/projects/{project_id}/assets",
            json={"hostname": ASSET_HOST, "scheme": "http"},
        )["Asset"]
        print(f"   registered asset {asset['Hostname']} (ID {asset['AssetID']})")

    if asset["VerificationStatus"] == "Verified":
        return asset

    challenge = api.post(
        f"/api/v1/projects/{project_id}/assets/{asset['AssetID']}/verification",
        json={"method": "WEB_FILE"},
    )["Challenge"]
    print(f"   challenge {challenge['FileContent']}")
    print(f"   publishing it to {challenge['FileURL']}")
    publish_challenge(target_url, challenge["FileContent"])
    result = api.post(
        f"/api/v1/projects/{project_id}/assets/{asset['AssetID']}/verification/check"
    )
    asset = result["Asset"]
    print(
        f"   verification {asset['VerificationStatus']}"
        f" ({result['Verification'].get('Evidence', '')})"
    )
    return asset


def ensure_attestation(api, project_id, asset_id):
    base = f"/api/v1/projects/{project_id}/assets/{asset_id}/attestations"
    for attestation in api.get(base)["Attestations"]:
        if attestation["Status"] == "Active":
            print(
                f"   using attestation {attestation['AttestationID']} "
                f"(expires {attestation['ExpiresAt']})"
            )
            return attestation
    attestation = api.post(
        base,
        json={
            "expires_in_days": 7,
            "reference": "local smoke test",
            "statement_version": "v1",
        },
    )["Attestation"]
    print(f"   created attestation {attestation['AttestationID']} (7 days)")
    return attestation


def ensure_credit(api, project_id):
    credits = api.get(f"/api/v1/projects/{project_id}/credits")
    if credits["AvailableCount"]:
        credit = next(c for c in credits["Credits"] if c["Status"] == "Available")
        print(f"   using available credit {credit['CreditUUID']}")
        return credit

    checkout = api.post(
        f"/api/v1/projects/{project_id}/payments/checkout",
        json={"product_code": "SCAN_CREDIT_1", "quantity": 1},
    )
    payment_uuid = checkout["Payment"]["PaymentUUID"]
    print(
        f"   mock checkout {payment_uuid} "
        f"({checkout['Payment']['AmountMinor'] / 100:.2f} "
        f"{checkout['Payment']['Currency']}, no real money)"
    )
    completed = api.post(
        f"/api/v1/projects/{project_id}/payments/{payment_uuid}/mock-complete",
        json={"outcome": "success"},
    )
    print(f"   payment {completed['Payment']['Status']}, "
          f"{completed['CreditsIssued']} credit(s) issued")

    credits = api.get(f"/api/v1/projects/{project_id}/credits")
    credit = next(c for c in credits["Credits"] if c["Status"] == "Available")
    return credit


def profile_id(api, name):
    for profile in api.get("/api/scan-profiles")["ScanProfiles"]:
        if profile["Name"] == name:
            return profile["ScanProfileID"]
    raise ApiError(f"scan profile '{name}' not found")


def legacy_endpoint_is_closed(app_url, token):
    response = requests.post(
        f"{app_url.rstrip('/')}/api/scans",
        json={"target_url": "http://localhost/", "scan_profile_id": 1},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    return response.status_code, response.json().get("code")


def run_scan(api, project_id, asset_id, credit_uuid, target_url, profile):
    readiness = api.get(
        f"/api/v1/projects/{project_id}/scan-readiness?asset_id={asset_id}"
    )["Readiness"]
    print(f"   readiness: ready={readiness['Ready']} next={readiness['NextAction']}")

    started = api.post(
        f"/api/v1/projects/{project_id}/scans",
        json={
            "asset_id": asset_id,
            "scan_profile_id": profile_id(api, profile),
            "scan_name": "Local smoke test",
            "credit_id": credit_uuid,
            "target_url": target_url,
        },
    )
    scan_id = started["Scan"]["ScanID"]
    print(f"   scan {scan_id} started (credit {started['Credit']['Status']})")

    deadline = time.time() + 600
    detail = {}
    while time.time() < deadline:
        detail = api.get(f"/api/scans/{scan_id}")["Scan"]
        status = detail["Status"]
        progress = api.get(f"/api/scans/{scan_id}/progress")["Progress"]
        print(
            f"\r   {status:<10} pages {progress.get('PagesAnalysed', 0)}/"
            f"{progress.get('PagesFound', 0)}  "
            f"findings {progress.get('FindingCount', 0)}  "
            f"requests {progress.get('RequestsIssued') or 0}",
            end="",
            flush=True,
        )
        if status in TERMINAL_SCAN_STATES:
            print()
            break
        time.sleep(1)
    else:
        raise ApiError("the scan did not finish within 10 minutes")
    return detail


def report(detail):
    findings = detail["Findings"]
    print("\n" + "=" * 78)
    print("SCAN RESULT")
    print("=" * 78)
    print(f"status        : {detail['Status']}")
    print(f"target        : {detail['TargetURL']}")
    print(f"pages analysed: {detail['AnalysedPages']} of {detail['PageCount']}")
    print(f"findings      : {len(findings)}")
    print(f"coverage      : {detail['CoverageNote']}")

    by_vuln = Counter(f["VulnerabilityName"] for f in findings)
    by_severity = Counter(f["Severity"] for f in findings)
    by_method = Counter(f["RequestMethod"] for f in findings)

    print("\nfindings by vulnerability")
    for name, count in by_vuln.most_common():
        print(f"  {count:>3}  {name}")
    print("\nfindings by severity")
    for name, count in by_severity.most_common():
        print(f"  {count:>3}  {name}")
    print("\nfindings by request method")
    for name, count in by_method.most_common():
        print(f"  {count:>3}  {name}")

    print("\ndetected injection points (confirmation evidence)")
    grouped = defaultdict(list)
    for finding in findings:
        grouped[(finding["VulnerabilityName"], finding["Severity"])].append(finding)
    for (vuln, severity), rows in sorted(grouped.items()):
        print(f"  {vuln} [{severity}]")
        for finding in rows:
            where = finding["URL"].split("/", 3)[-1]
            parameter = finding["Parameter"] or "-"
            print(
                f"    - {finding['RequestMethod']:<4} {parameter:<12} {where} "
                f"({finding['Classification']}, CVSS {finding['RiskScore']}, "
                f"confidence {finding['Confidence']})"
            )

    print("\nHow to read this")
    print("  Confirmed findings were reproduced with concrete evidence; the")
    print("  POST rows prove that HTML form fields (not only query strings) are")
    print("  tested. Use the UI to open a finding and read its full evidence.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-url", default="http://127.0.0.1:5000")
    parser.add_argument("--target-url", default="http://localhost:5001")
    parser.add_argument("--email", default="developer@vulnscan.local")
    parser.add_argument("--password", default="Developer@VulnScan2025")
    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    args = parser.parse_args()

    api = Api(args.app_url)
    try:
        step("Health")
        print(f"   {api.get('/api/health')}")

        step("Authentication")
        login(api, args.email, args.password)

        step("Organisation and project")
        organisation = ensure_organisation(api)
        project = ensure_project(api, organisation["OrganisationID"])

        step("Verified asset")
        asset = ensure_verified_asset(
            api, project["ProjectID"], args.target_url
        )

        step("Authorisation attestation")
        ensure_attestation(api, project["ProjectID"], asset["AssetID"])

        step("Scan credit (mock payment)")
        credit = ensure_credit(api, project["ProjectID"])

        step("Trust gate sanity check")
        status, code = legacy_endpoint_is_closed(args.app_url, api.token)
        print(f"   POST /api/scans -> {status} {code}")
        if status != 410:
            raise ApiError(
                "the legacy scan endpoint should be disabled in enforce mode; "
                "check TRUST_BOUNDARY_MODE"
            )

        step("Gated scan")
        detail = run_scan(
            api,
            project["ProjectID"],
            asset["AssetID"],
            credit["CreditUUID"],
            args.target_url.rstrip("/") + "/",
            args.profile,
        )
        report(detail)
        return 0 if detail["Status"] == "Completed" else 1
    except ApiError as exc:
        print(f"\nFAILED: {exc}", file=sys.stderr)
        return 2
    except requests.exceptions.RequestException as exc:
        print(
            f"\nCould not reach VulnScan at {args.app_url}: {exc}\n"
            "Start the environment first: .\\scripts\\start-local.ps1",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
