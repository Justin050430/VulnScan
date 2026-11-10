# VulnScan

**VulnScan – Intelligent Web Application Vulnerability Assessment Platform with Risk Assessment and Remediation Knowledge Base**

A web-based vulnerability scanner built for the TAR UMT Final Year Project (OOI JIAN XIN). VulnScan lets **Developers** run automated scans for SQL Injection, Cross-Site Scripting (XSS) and HTTP Security Header weaknesses, and gives **Administrators** centralized control over users, scan profiles, vulnerability definitions, scan reports and security audit logs — all backed by an integrated remediation knowledge base.

The implementation follows the approved **Chapters 1–4** of `Assignment/FYP.docx` (the specification): the documented five-layer architecture, the eight-entity ERD, the Table 4.2 REST API blueprint, and the approved UI design.

## Trust Boundary Extension (FYP vertical slice)

VulnScan is **not** a "scan any website" service. Scan creation is gated by an additive
**Trust Boundary Extension** around the frozen eight-entity core ERD:

- **Organisation → Project → Membership** with server-side roles
  (`ORG_OWNER`, `PROJECT_OWNER`, `SCAN_OPERATOR`, `ANALYST`, `VIEWER`).
- **Verified assets only**: exact hostnames, proven by a DNS TXT
  (`_vulnscan-challenge.<host>`) or `/.well-known/vulnscan.txt` challenge.
  Wildcards, IP literals and sub-domain scanning are rejected.
- **Authorisation attestation** per asset before any active scan, revocable and expiring.
- **Single-use scan credits** issued only by a server-side verified **mock** payment
  (no real money, no card data, no real gateway).
- **Atomic gated scan start**: permission + verified asset + active attestation +
  available credit + exact host match + no conflicting active scan.
- **Append-only trust audit** of membership, verification, attestation, payment,
  credit, scan-denial and scan-start actions.

`TRUST_BOUNDARY_MODE=enforce` (default, and forced in production) disables the legacy
`POST /api/scans` with `LEGACY_SCAN_ENDPOINT_DISABLED`. The legacy endpoint exists only
for local compatibility and the pre-existing regression suite (`legacy` mode).

See [docs/TRUST_BOUNDARY.md](docs/TRUST_BOUNDARY.md), [docs/API_TRUST.md](docs/API_TRUST.md)
and [docs/MIGRATION_TRUST.md](docs/MIGRATION_TRUST.md).

## Technology stack

| Layer | Technology |
| --- | --- |
| Frontend (Presentation) | HTML / CSS / vanilla JavaScript SPA (no build step), Chart.js |
| Backend (API + Business Logic) | Python, Flask |
| ORM / Migrations | SQLAlchemy, Flask-SQLAlchemy, Flask-Migrate (Alembic) |
| Authentication | Flask-JWT-Extended (JWT bearer), Google OAuth 2.0 single sign-on |
| Database | Microsoft SQL Server (Azure SQL / SQL Server LocalDB) |
| Scanner | Built-in Web Crawler + modular detection engine (`requests`) |
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
  test_*.py               pytest suite (238 tests, incl. SQL Server integration)
  trust_helpers.py        shared Trust Boundary test fixtures
.github/workflows/ci.yml  continuous integration (runs the test suite)
docs/TRUST_BOUNDARY.md    Trust Boundary design, roles and limits
docs/API_TRUST.md         /api/v1 contracts and error codes
docs/MIGRATION_TRUST.md   additive migration / backup / rollback runbook
docs/DEMO_SCRIPT.md       step-by-step FYP demonstration script
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

### Trying a real scan (Trust Boundary flow)

Two **project-owned** targets ship with the repository. Both are intentionally
vulnerable and loopback-only — never deploy them.

| Target | Start | Port | Typical findings |
| --- | --- | --- | --- |
| **Test shop** (`testing/vuln_test_app`) | `python run.py` | 5001 | SQLi (Critical 9.8), reflected XSS (6.1), header findings, plus *safe* control pages |
| **SQLi attack lab** (`testing/sqli_lab`) | `python app.py` | 5003 | Error-based SQLi on `/search?q=` and `/orders?ref=`, header findings |

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
python -m pytest testing -q          # 238 tests; SQL Server tests skip if unavailable
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
