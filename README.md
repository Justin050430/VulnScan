# VulnScan

**VulnScan – Intelligent Web Application Vulnerability Assessment Platform with Risk Assessment and Remediation Knowledge Base**

A web-based vulnerability scanner built for the TAR UMT Final Year Project (OOI JIAN XIN). VulnScan lets **Developers** run automated scans for SQL Injection, Cross-Site Scripting (XSS) and HTTP Security Header weaknesses, and gives **Administrators** centralized control over users, scan profiles, vulnerability definitions, scan reports and security audit logs — all backed by an integrated remediation knowledge base.

The implementation follows the approved **Chapters 1–4** of `Assignment/FYP.docx` (the specification): the documented five-layer architecture, the eight-entity ERD, the Table 4.2 REST API blueprint, and the approved UI design.

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
    models/               8 entities (User, Scan, ScanProfile, ProfileModule,
                          Vulnerability, DiscoveredPage, Finding, SecurityAuditLog)
    routes/               REST API blueprints (/api/*)
    services/             business logic (auth, users, scans, reports, audit...)
    scanner/              crawler + SQLi / XSS / HTTP-header modules + engine
    static/  templates/   frontend SPA
  migrations/             Alembic migrations (flask db upgrade)
  config.py  run.py  wsgi.py
testing/
  vuln_test_app/          controlled intentionally-vulnerable local target
  test_*.py               pytest suite (154 tests, incl. SQL Server integration)
.github/workflows/ci.yml  continuous integration (runs the test suite)
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

### Trying a real scan

1. Start the controlled (intentionally vulnerable) target:
   ```powershell
   cd testing\vuln_test_app
   python run.py            # http://127.0.0.1:5001  (local only)
   ```
2. Sign in to VulnScan as the Developer, choose **New Scan**, set the target URL to
   `http://127.0.0.1:5001/`, pick the **OWASP Top 10 Full Scan** profile and start the scan.
3. Open the scan result to review findings and download the PDF/CSV report.

The scanner only ever requests pages **within the target's own scope** and never
contacts arbitrary third-party websites.

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
python -m pytest testing -q          # run everything (SQL Server tests skip if unavailable)
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

### Continuous integration

`.github/workflows/ci.yml` runs the suite on every push/PR to `main` and
uploads the JUnit results as a build artifact.

## Documentation of implementation notes

See `docs/DEVELOPMENT_NOTES.md` for decisions taken while implementing the
specification, validation results, and flagged inconsistencies (useful for the
later FYP chapters).
