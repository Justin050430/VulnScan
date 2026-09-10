# VulnScan — FYP Demonstration Script

A realistic end-to-end walkthrough using the **controlled vulnerable test
application** (`testing/vuln_test_app`, localhost only). Do **not** scan
public third-party websites.

## 0. Prepare (once)

```powershell
# Terminal 1 — VulnScan
cd c:\FYP\VulnScan\backend
python run.py                       # http://127.0.0.1:5000

# Terminal 2 — controlled vulnerable target
cd c:\FYP\VulnScan\testing\vuln_test_app
python run.py                       # http://127.0.0.1:5001
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

## 3. Create and configure a scan

1. **New Scan** → enter:
   - Target URL: `http://127.0.0.1:5001/`
   - Scan Name: `Test Shop (demo)`
   - Scan Profile: **OWASP Top 10 Full Scan**
2. *Show:* the profile panel lists the modules that will run
   (SQL Injection, XSS, HTTP Security Headers) and the crawl limits.
3. Click **Start Scan**.
   - *Show:* the scan is created and (for a slow target) shows
     **Pending → Running → Completed**; the result page auto-refreshes.

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
