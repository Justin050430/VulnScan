# VulnScan

**VulnScan – Intelligent Web Application Vulnerability Assessment Platform with Risk Assessment and Remediation Knowledge Base**

A web-based vulnerability scanner built for the TAR UMT Final Year Project (OOI JIAN XIN). VulnScan lets **Developers** run automated scans for SQL Injection, Cross-Site Scripting (XSS) and HTTP Security Header weaknesses, and gives **Administrators** centralized control over users, scan profiles, vulnerability definitions, scan reports and security audit logs — all backed by an integrated remediation knowledge base.

The implementation follows the approved **Chapters 1–4** of `Assignment/FYP.docx` (the specification): the documented five-layer architecture, the eight-entity ERD, the Table 4.2 REST API blueprint, and the approved UI design.

## Trust Boundary Extension (FYP vertical slice)

VulnScan is **not** a "scan any website" service. Scan creation is gated by an additive
**Trust Boundary Extension** around the frozen eight-entity core ERD:

- **Organisation → Project → Membership** with server-side roles
  (`ORG_OWNER`, `PROJECT_OWNER`, `SCAN_OPERATOR`, `ANALYST`, `VIEWER`). Invitations are
  shareable one-time links bound to the invitee's email address.
- **Verified assets only**: exact hostnames, proven by a DNS TXT
  (`_vulnscan-challenge.<host>`) or `/.well-known/vulnscan.txt` challenge.
  Wildcards, IP literals and sub-domain scanning are rejected.
- **Authorisation attestation** per asset before any active scan, revocable and expiring.
- **Temporary authenticated-scan credentials**: a project member creates a dedicated
  test-account login for one verified asset, a *different* project owner approves it,
  and the scan uses it for one scan only. Secrets are encrypted at rest, never returned
  by the API or written to reports, and are destroyed on expiry or revocation. FORM
  login (including CSRF tokens) is supported; MFA/SSO are out of scope.
- **Single-use scan credits** issued only by a server-side verified **mock** payment
  (no real money, no card data, no real gateway).
- **Atomic gated scan start**: permission + verified asset + active attestation +
  available credit + exact host match + no conflicting active scan.
- **Append-only trust audit** of membership, verification, attestation, payment,
  credit, scan-denial and scan-start actions.

`TRUST_BOUNDARY_MODE=enforce` (default, and forced in production) disables the legacy
`POST /api/scans` with `LEGACY_SCAN_ENDPOINT_DISABLED`. The legacy endpoint exists only
for local compatibility and the pre-existing regression suite (`legacy` mode).

### Injection coverage

The SQLi and XSS modules test every query-string parameter **and every field of the
HTML forms the crawler discovers** (GET and POST). Forms are screened before use:
password/file-upload forms and forms with destructive actions (delete, payment,
logout, …) are never submitted, and hidden fields keep the values the page served so
CSRF tokens stay valid. `SCANNER_ENABLE_FORM_TESTING=false` restores query-string-only
behaviour.

See [docs/TRUST_BOUNDARY.md](docs/TRUST_BOUNDARY.md), [docs/API_TRUST.md](docs/API_TRUST.md)
and [docs/MIGRATION_TRUST.md](docs/MIGRATION_TRUST.md).

To exercise the whole flow locally against targets that ship with the repository
(no third-party systems, no legal risk) follow
[docs/LOCAL_ENVIRONMENT.md](docs/LOCAL_ENVIRONMENT.md).

## Technology stack

| Layer | Technology |
| --- | --- |
| Frontend (Presentation) | HTML / CSS / vanilla JavaScript SPA (no build step), Chart.js |
| Backend (API + Business Logic) | Python, Flask |
| ORM / Migrations | SQLAlchemy, Flask-SQLAlchemy, Flask-Migrate (Alembic) |
| Authentication | Flask-JWT-Extended (JWT bearer), Google OAuth 2.0 single sign-on |
| Database | Microsoft SQL Server (Azure SQL / SQL Server LocalDB) |
| Scanner | Built-in Web Crawler + modular detection engine (`requests`); tests query-string parameters and HTML form fields (GET/POST) |
| Reports | PDF (ReportLab) and CSV export |

## Repository layout

```
backend/                  Flask application (application factory)
  app/
    models/               Frozen 8 core entities + 11 additive Trust* entities
    trust/                permissions, hostname rules, attestation statements
    payments/             payment provider interface + mock provider
    routes/               REST API blueprints (/api/* and /api/v1/*)
    services/             business logic (auth, users, scans, reports, audit,
                          trust, verification, attestation, payments, credits)
    scanner/              crawler + SQLi / XSS / HTTP-header modules + engine
    static/  templates/   frontend SPA
  migrations/             Alembic migrations (flask db upgrade)
  config.py  run.py  wsgi.py
testing/
  vuln_test_app/          controlled intentionally-vulnerable local target
  test_*.py               pytest suite (290 tests, incl. SQL Server integration)
  trust_helpers.py        shared Trust Boundary test fixtures
.github/workflows/ci.yml  continuous integration (runs the test suite)
scripts/start-local.ps1   starts/stops the complete local environment
scripts/local_smoke_test.py  end-to-end Trust Boundary + detection-quality check
docs/TRUST_BOUNDARY.md    Trust Boundary design, roles and limits
docs/API_TRUST.md         /api/v1 contracts and error codes
docs/MIGRATION_TRUST.md   additive migration / backup / rollback runbook
docs/DEMO_SCRIPT.md       step-by-step FYP demonstration script
docs/LOCAL_ENVIRONMENT.md local full-flow environment (parity with Azure)
screenshots/              verification evidence (UI screenshots + real reports)
```

## Getting started (local development)

Prerequisites: Python 3.13, a SQL Server instance (LocalDB works) with the **Microsoft ODBC Driver 17 for SQL Server**.

```powershell
# 1. create and activate a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2. install dependencies
pip install -r requirements.txt

# 3. configure the backend
Copy-Item backend\.env.example backend\.env
#   - edit backend\.env if your SQL Server is not LocalDB

# 4. create the database and run migrations
sqlcmd -S "(localdb)\MSSQLLocalDB" -E -Q "IF DB_ID('VulnScan') IS NULL CREATE DATABASE VulnScan"
cd backend
python -m flask --app run.py db upgrade

# 5. seed reference data (vulnerability KB, profiles, default users)
python -m flask --app run.py seed

# 6. run the server
python run.py            # http://127.0.0.1:5000
```

Default accounts (override via `backend/.env`):

| Role | Email | Password |
| --- | --- | --- |
| Administrator | `admin@vulnscan.local` | `Admin@VulnScan2025` |
| Developer | `developer@vulnscan.local` | `Developer@VulnScan2025` |

### One-command local environment

```powershell
.\scripts\start-local.ps1              # starts the target (5001) and VulnScan (5000)
.\scripts\start-local.ps1 -Action status
.\scripts\start-local.ps1 -Action stop
```

The script checks the schema, reseeds reference data, waits until both services
answer, and prints every credential you need (including the test-shop account used
for authenticated scans). To drive the whole Trust Boundary flow and print a
detection-quality summary automatically:

```powershell
.\.venv\Scripts\python.exe scripts\local_smoke_test.py
```

### Trying a real scan (Trust Boundary flow)

Two **project-owned** targets ship with the repository. Both are intentionally
vulnerable and loopback-only — never deploy them.

| Target | Start | Port | Typical findings |
| --- | --- | --- | --- |
| **Test shop** (`testing/vuln_test_app`) | `python run.py` | 5001 | SQLi (Critical 9.8), reflected XSS (6.1), header findings, plus *safe* control pages |
| **SQLi attack lab** (`testing/sqli_lab`) | `python app.py` | 5003 | Error-based SQLi on `/search?q=` and `/orders?ref=`, header findings |

Credentials used by the local demo:

| Account | Purpose |
| --- | --- |
| `developer@vulnscan.local` / `Developer@VulnScan2025` | VulnScan Developer (creates the org, project, scans) |
| `admin@vulnscan.local` / `Admin@VulnScan2025` | VulnScan Administrator (users, KB, audit logs) |
| `pentester@example.test` / `Temporary!Pass123` | Test-shop login for **authenticated** scans (single-use credential) |

The test shop also exposes POST forms that are vulnerable to reflected XSS
(`/feedback` → `message`) and SQL injection (`/feedback` → `order`), so you can
see that form fields — not just query strings — are tested. `/feedback_safe` is
the escaped control page, and the same page renders a password form and a
`POST /account/delete` form that the scanner must never submit.

```powershell
# Terminal 1 — VulnScan (asset verification fetches the target's port)
cd backend
$env:TRUST_WEBFILE_PORT = "5001"      # 5003 when demoing the SQLi lab
python -m flask --app run.py run --port 5000

# Terminal 2 — controlled target
cd testing\vuln_test_app ; python run.py       # http://localhost:5001
```

1. Sign in as the Developer and open **Organisations**.
2. Create an organisation, then a project.
3. Register the asset hostname **`localhost`** (scheme `http`) — IP addresses are rejected.
4. Run **Verify** → `WEB_FILE`. VulnScan shows a one-time challenge value and the
   exact file URL (`http://localhost:5001/.well-known/vulnscan.txt`).
5. Publish it without editing code: open
   `http://localhost:5001/__test__/verification`, paste the challenge, submit.
6. Click **Check now** → status becomes **Verified** (90 days).
7. Create an **attestation** for the asset (1–90 days).
8. Buy a credit through the clearly labelled **mock** checkout (no real money), then
   press **Pay (mock)**.
9. Open **Project → Start scan**, confirm the readiness panel is green, and start the
   scan. The target URL host must match the verified asset exactly
   (`http://localhost:5001/`).
10. Review findings and download the PDF/CSV report as before.

A full 9-page / 45-finding scan of the test shop completes in roughly 20 seconds.

The scanner only ever requests pages **within the target's own scope** and never
contacts arbitrary third-party websites. Do not scan public sites you do not own.

> For local development only, `TRUST_BOUNDARY_MODE=legacy` restores the historical
> **New Scan** form. Production always runs in `enforce` mode.

### Troubleshooting the Trust Boundary

| Symptom | Cause | Fix |
| --- | --- | --- |
| Organisations tab shows **"An internal server error occurred"** (older build) or **503 `TRUST_BOUNDARY_UNAVAILABLE`** | Database is behind the additive Trust schema (the `Trust*` tables are missing) | `cd backend` then `python -m flask --app run.py db upgrade`, restart the server |
| Verification returns `VERIFICATION_MISMATCH ... Connection error` | `/.well-known` was fetched on port 80/443 but the target listens on 5001/5003 | Start VulnScan with `TRUST_WEBFILE_PORT=5001` (or `5003`) |
| `HOSTNAME_INVALID` when registering an asset | IP literal, wildcard, scheme/port or path supplied | Register the exact hostname only, e.g. `localhost` |
| `TARGET_HOST_MISMATCH` on scan start | Target URL host differs from the verified asset | Use the same host, e.g. `http://localhost:5001/` |
| `CREDIT_REQUIRED` / `CREDIT_NOT_AVAILABLE` | No available credit, or the credit was already consumed | Buy another credit (one per scan) |
| `ATTESTATION_REQUIRED` / `ATTESTATION_EXPIRED` | No active attestation for the asset | Create a new attestation (1–90 days) |
| `credential.approve` returns `CREDENTIAL_SELF_APPROVAL_DENIED` | Maker-checker is enabled and the creator tried to approve their own credential | Sign in as a different project owner (or set `TRUST_CREDENTIAL_ALLOW_SELF_APPROVAL=true` for local demos only) |
| Credential creation returns `CREDENTIAL_STORAGE_UNAVAILABLE` | `TRUST_CREDENTIAL_KEY` is blank in production, or the key is not valid Fernet base64 | Set a valid key in App Settings and restart |
| Scan fails with `CREDENTIAL_LOGIN_FAILED` | Wrong account/password, wrong field names, missing CSRF handling or the success indicator did not match | Use **Test login** on the credential, fix the login URL/fields/success indicator, then create and re-approve a new credential (single-use) |
| Authenticated scan still only finds public pages | Target URL starts on a page that does not link to the protected area, or the account lacks access | Start the scan at a post-login landing page (e.g. `/dashboard`) and use an account that can see the pages you want tested |

Check the schema state at any time:

```powershell
cd backend
python -m flask --app run.py db current
```

The Trust Boundary head revision is `c4d8f1a2b6e9` (temporary scan credentials);
`aaf9e35de1fe` is the base Trust Boundary migration.

## Google Sign-In

To enable **Sign in with Google**, create an OAuth 2.0 Client ID in Google Cloud
Console and set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` and
`GOOGLE_REDIRECT_URI` in `backend/.env`. Register
`http://localhost:5000/api/auth/google/callback` as an Authorized redirect URI.
Users sign in with Google only when their verified email matches a provisioned
VulnScan account. When these variables are empty the button is disabled with a
clear message (no fake authentication is used).

## Running the tests

```powershell
python -m pytest testing -q          # 290 tests; SQL Server tests skip if unavailable
```

The suite uses an in-memory SQLite database, a local controlled target and a
separate out-of-scope host; no external systems are contacted.  It covers
authentication, JWT tampering/expiry/revocation, RBAC, Google OAuth (identity
provider mocked at the network boundary only), the database schema, the
management APIs, scanner scope/SSRF/limits/redirects, SQLi/XSS/header detection
with false-positive controls, CVSS scoring, report content, audit events, error
handling, timeout handling and concurrent scans.  The `test_sqlserver_integration`
module additionally runs against a **real SQL Server** instance when one is
reachable (it creates a `VulnScanTest` database and is skipped otherwise).

The Trust Boundary suite (`test_trust_*.py`) adds role-matrix denial, cross-tenant
isolation, DNS/file asset verification, attestation expiry/revocation, mock-payment
idempotency and duplicate callbacks, single-use credit reservation (including a real
two-thread double-spend race on SQL Server), gated scan denial reasons, append-only
audit and scanner/export/retest/progress regression.

### Continuous integration

`.github/workflows/ci.yml` runs the suite on every push/PR to `main` and
uploads the JUnit results as a build artifact.

## Documentation of implementation notes

See `docs/DEVELOPMENT_NOTES.md` for decisions taken while implementing the
specification, validation results, and flagged inconsistencies (useful for the
later FYP chapters).
