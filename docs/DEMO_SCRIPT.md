# VulnScan — FYP Demonstration Script

A realistic end-to-end walkthrough using the **controlled vulnerable test
application** (`testing/vuln_test_app`, localhost only). Do **not** scan
public third-party websites.

## 0. Prepare (once)

```powershell
# Terminal 1 — VulnScan
cd c:\FYP\VulnScan\backend
$env:TRUST_WEBFILE_PORT = "5001"    # 5003 when demonstrating the SQLi lab
python run.py                       # http://127.0.0.1:5000

# Terminal 2 — controlled vulnerable target (test shop)
cd c:\FYP\VulnScan\testing\vuln_test_app
python run.py                       # http://localhost:5001

# Optional Terminal 3 — SQLi attack lab (SQLi-focused target)
cd c:\FYP\VulnScan\testing\sqli_lab
python app.py                       # http://localhost:5003
```

| Role | Email | Password |
| --- | --- | --- |
| Administrator | `admin@vulnscan.local` | `Admin@VulnScan2025` |
| Developer | `developer@vulnscan.local` | `Developer@VulnScan2025` |

## 1. Login (authentication + JWT + audit)

1. Open `http://127.0.0.1:5000` → the login page.
2. Sign in as the **Developer**.
   - *Show:* successful redirect to the Developer Dashboard.
   - *Also demonstrate:* an incorrect password shows a generic error
     (“Invalid email address or password”) rather than revealing whether the
     account exists.
3. (Optional) Show the **Sign in with Google** button — it is only enabled
   when OAuth credentials are configured on the server.

## 2. Developer dashboard

*Show:* real statistics from the database (scan counts, open/high-critical
findings) and the Recent Scans table. Nothing on screen is hard-coded — every
value comes from `GET /api/scans`.

## 2b. Trust Boundary setup (required before any scan)

Scanning is **project-scoped and gated**. Point out that this is what prevents
VulnScan from being an unsafe public scanner.

1. **Organisations → + New Organisation** → e.g. `Demo Org`.
2. Inside the organisation: **+ New Project** → `Test Shop`.
3. **+ Register asset** → hostname `localhost`, scheme `http`.
   - *Show:* IP addresses and wildcards are rejected (`HOSTNAME_INVALID`).
4. **Verify** the asset:
   - choose `WEB_FILE`;
   - copy the one-time challenge (expires in 30 minutes);
   - publish it on the target: open `http://localhost:5001/__test__/verification`
     and paste the challenge (no code edit, no restart needed);
   - click **Check now** → status becomes **Verified (90 days)**.
   - *Show:* the plaintext token is shown once and is never stored in evidence.
   - *Note:* run VulnScan with `TRUST_WEBFILE_PORT=5001` (or `5003` for the SQLi
     lab) so the verifier fetches the same port the target listens on.
5. **Attest** the asset:
   - read the authorisation statement;
   - set 30 days and an optional reference such as `CHG-1234`;
   - **Create attestation**.
   - *Show:* revoking it immediately blocks scanning.
6. **Buy credit**:
   - the checkout is labelled **No real money — mock provider**;
   - click **Pay (mock)** to complete the server-side mock callback;
   - one **Available** credit appears.
   - *Show:* simply returning from checkout without the callback issues nothing.
7. Optionally invite a teammate with the **VIEWER** or **ANALYST** role and show
   that the **Start scan** action is absent for them.
8. *(Optional) authenticated scan:* the bundled test target has a dedicated test
   account (`pentester@example.test` / `Temporary!Pass123`). On the verified asset open
   **Credentials → + New credential**, set the login URL to
   `http://localhost:5001/login`, the success URL to `/dashboard`, and save. Invite a
   second user as **PROJECT_OWNER**, sign in as them, and **Approve** the credential
   (the creator cannot approve their own). Use **Test login** first; it does not consume
   a credit. Start the scan with target `http://localhost:5001/dashboard` and select the
   credential. Point out that protected pages such as `/dashboard/search` are now
   discovered and tested, the credential is bound to exactly one scan, and the report
   shows the authentication context without the password.

## 3. Create and configure a scan (gated)

1. Project → **Start scan**.
2. *Show:* the readiness panel lists Permission, Asset, Attestation, Credit and
   Active scan; it is green only when every gate passes.
3. Choose profile **OWASP Top 10 Full Scan**, confirm the target URL host matches
   the verified asset, and click **Start Scan**.
   - *Show:* the scan is created, the credit becomes **Reserved** then
     **Consumed**, and the result page auto-refreshes.
4. *Show the denial path:* clear the target to another host → `TARGET_HOST_MISMATCH`;
   revoke the attestation → `ATTESTATION_REQUIRED`; spend the credit → the next
   start returns `CREDIT_NOT_AVAILABLE`.
5. *Show the audit view:* Project → **Audit** lists the verification, attestation,
   payment, credit and scan events.

> The legacy **New Scan** form now displays a notice and is rejected by the API
> with `LEGACY_SCAN_ENDPOINT_DISABLED` unless the server runs in `legacy` mode
> (local compatibility only).

## 4. Scanner behaviour (what to point out)

- The crawler requests only the target's own pages (same origin).
- SQL Injection is detected with **error-based evidence** on `/product?id=`
  (Confirmed, CVSS 9.8 Critical).
- Reflected XSS is detected on `/search?q=` (Confirmed, CVSS 6.1 Medium) but
  **not** on the escaped control page `/safe_search` or in the non-executable
  contexts (`/comment_reflect`, `/textarea_reflect`).
- Boolean (blind) SQLi on `/blind?id=` is reported as **Suspected** (CVSS 5.9)
  with lower confidence — explicitly distinguished from confirmed findings.
- Missing/insecure HTTP security headers are reported per page (CVSS 5.4
  Medium), while the hardened `/headers_ok` page is clean.

## 5. Scan result page

*Show:*
- Overall risk, total findings, scan status and duration cards.
- Findings table with **Severity, Evidence (Confirmed/Suspected + confidence),
  CVSS score, status and location**.
- Expand a finding (**Detail**) to show the payload, raw evidence and the
  remediation guidance from the knowledge base.
- Change a finding's triage status (Open / Resolved / False Positive).

## 6. Report export (real data)

- **Download PDF Report** and **⬇ CSV**.
- *Show:* the PDF/CSV contain the scan metadata, discovered pages and the
  actual findings with CVSS, confidence, classification, evidence and
  remediation. (Sample files are saved under `screenshots/`.)

## 7. Knowledge base

*Show:* the vulnerability knowledge base (descriptions, impact, remediation,
secure-coding practice, OWASP references), with detection modules marked.

## 8. Administrator workflow

Sign in as the **Administrator** (`admin@vulnscan.local`).

1. **Dashboard** — system-wide metrics, severity chart and recent activity.
2. **Users** — create a user, assign a role, disable an account
   (disable, never a destructive delete, to preserve scan history).
3. **Scan Profiles** — create/edit a profile and choose its modules.
4. **Vulnerabilities** — edit knowledge-base content; built-in module
   definitions cannot be renamed; enable/disable a definition.
5. **Audit Logs** — show that logins, failed logins, scan lifecycle events,
   administrative changes, vulnerability changes and report exports are all
   recorded with user, IP address, action and status.

## 9. Safeguards to highlight (real-world behaviour)

- Only the target's own scope is scanned; external links and out-of-scope
  redirects are **never requested**.
- Private/loopback targets are blocked unless explicitly allowed by
  configuration (`SCANNER_ALLOW_PRIVATE_TARGETS`).
- Request timeouts, page/depth limits and rate limiting are enforced; an
  unreachable target results in a **Failed** scan, not a false success.
- Passwords are hashed; JWT tokens expire and are revoked on logout; RBAC is
  enforced server-side; secrets come from environment variables only.

## 10. Suggested closing point

Summarise: automated assessment, CVSS-based risk, integrated remediation
knowledge base, centralized administration and audit logging — matching the
project objectives in Chapter 1.
