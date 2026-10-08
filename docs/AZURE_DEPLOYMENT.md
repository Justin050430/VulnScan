# VulnScan — Azure Deployment Guide

This document records how VulnScan is deployed to Microsoft Azure (App Service +
Azure SQL Database) and how the continuous deployment pipeline works. It is
intended both as an operations runbook and as evidence for the FYP deployment
chapter.

---

## 1. Target architecture

| Resource | Service | Notes |
| --- | --- | --- |
| Web application | **Azure App Service** (Linux, Python 3.13) | Serves the Flask API and the SPA |
| Database | **Azure SQL Database** | Microsoft SQL Server engine (matches `mssql+pyodbc`) |
| Secrets | App Service **Application settings** | Optionally backed by Azure Key Vault |
| Source / pipeline | GitHub + **GitHub Actions** | CI on PRs, CD on `main` (NFR-09) |

### Concrete values (this deployment)

| Item | Value |
| --- | --- |
| Subscription | `Azure for Students` (`2e4ea030-fd2b-46af-a753-12f96bd10f23`) |
| Resource group | `vulnscan` (Malaysia West) |
| Web App name | `vulnscan` |
| Public URL | `https://vulnscan-erehf4djeqg8dvbe.malaysiawest-01.azurewebsites.net` |
| SQL server | `vulnscan.database.windows.net` |
| SQL database | `vulnscandb` |
| Runtime | App Service Linux, Python 3.13 |

The `malaysiawest` region does **not** support Azure Service Connector
(`Microsoft.ServiceLinker/linkers`). The Web App is therefore created **without**
the portal "database" option and the connection is configured manually via the
`DATABASE_URL` application setting (see §4).

---

## 2. App Service configuration

**Runtime stack:** Linux, Python **3.13**
(Linux is the only OS option for Python on App Service.)

**Startup command** (Configuration → General settings):

```
gunicorn --bind=0.0.0.0:8000 --timeout 600 --chdir backend wsgi:app
```

> Auto-detection does **not** work for this repository: App Service only looks
> for `app.py` / `application.py` in the site root, or a `wsgi.py` one level
> down. Our WSGI module lives at `backend/wsgi.py`, so the custom startup
> command above is required.

---

## 3. Application settings

Create these under **Configuration → Environment variables**. `backend/.env` is
git-ignored and is **not** deployed, so every value must be set here.

| Name | Value |
| --- | --- |
| `FLASK_ENV` | `production` |
| `SECRET_KEY` | long random string |
| `JWT_SECRET_KEY` | different long random string |
| `DATABASE_URL` | see §4 |
| `GOOGLE_CLIENT_ID` | Google OAuth client id |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `GOOGLE_REDIRECT_URI` | `https://vulnscan-erehf4djeqg8dvbe.malaysiawest-01.azurewebsites.net/api/auth/google/callback` |
| `WEBSITE_HTTPLOGGING_RETENTION_DAYS` | `1` |
| `SCANNER_ALLOW_PRIVATE_TARGETS` | `false` (production SSRF protection) |
| `SCM_DO_BUILD_DURING_DEPLOYMENT` | `1` (enables the Oryx `pip install` build) |

`ProductionConfig` sets `REQUIRE_SECRET = True`, so the app **refuses to start**
if `SECRET_KEY` / `JWT_SECRET_KEY` are missing — this is intentional.

---

## 4. Database connection string

Use the SQLAlchemy `odbc_connect` form so the password is percent-encoded and
the TLS settings are explicit. Generate it locally:

```python
from urllib.parse import quote_plus

cs = (
    "DRIVER={ODBC Driver 18 for SQL Server};"
    "SERVER=tcp:<server>.database.windows.net,1433;"
    "DATABASE=VulnScan;"
    "UID=<admin-login>;PWD=<password>;"
    "Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30"
)
print("mssql+pyodbc:///?odbc_connect=" + quote_plus(cs))
```

Copy the printed value into the `DATABASE_URL` application setting.

Notes:
- The App Service Linux Python image **already contains** the ODBC drivers
  (`msodbcsql17` + `msodbcsql18` on Debian; `msodbcsql18` on Ubuntu), so no
  installation step is required.
- The component-based settings (`MSSQL_SERVER`, `MSSQL_USERNAME`, ...) are
  **not** recommended for Azure: the generated URL embeds the password verbatim
  and forces `Encrypt=no`.
- The SQL Server administrator login must not be a reserved name
  (`admin`, `administrator`, `sa`, `root`, `guest`, `public`, `dbo`, `sys`,
  `securityadmin`, `serveradmin`, ...) and must not contain `@`.

---

## 5. Database firewall

On the **SQL server** → Networking:
1. Add the developer's client IP (so migrations can be run locally).
2. Enable **Allow Azure services and resources to access this server** for the
   App Service to connect (or use a private endpoint).

---

## 6. Migrations and seed data

Run once against Azure SQL from a machine with the firewall rule above:

```powershell
cd backend
$env:DATABASE_URL = "mssql+pyodbc:///?odbc_connect=..."
python -m flask --app run.py db upgrade
python -m flask --app run.py seed
```

---

## 7. Google OAuth

In Google Cloud Console → **Credentials → OAuth 2.0 Client → Authorized redirect
URIs**, add:

```
https://vulnscan-erehf4djeqg8dvbe.malaysiawest-01.azurewebsites.net/api/auth/google/callback
```

---

## 8. Continuous deployment (GitHub Actions)

`.github/workflows/deploy.yml` runs the test suite and, on success, deploys
`main` to the Web App. Configure it once:

1. **Publish profile** — App Service → **Overview → Get publish profile**
   (downloads an XML file). In GitHub: **Settings → Secrets and variables →
   Actions → New repository secret**, name `AZURE_WEBAPP_PUBLISH_PROFILE`,
   paste the entire file contents.
2. **App name** — same page, **Variables** tab → `AZURE_WEBAPP_NAME` =
   your Web App name.

After that, every push to `main` (or a manual *Run workflow*) tests and deploys.
Pull requests are validated by `.github/workflows/ci.yml`.

---

## 9. Verification checklist

- [ ] `https://vulnscan-erehf4djeqg8dvbe.malaysiawest-01.azurewebsites.net/`
      loads the login page (not the Azure default site).
- [ ] Login as the seeded Developer works.
- [ ] A scan can be started and reaches *Completed*.
- [ ] The PDF/CSV report downloads.
- [ ] Google sign-in redirects back to the app (not a blank page).
- [ ] Failed/unauthorised logins appear in the audit log.

---

## 10. Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| Azure default page shown | Startup command not set (see §2) |
| App won't start / 500 on boot | `SECRET_KEY` / `JWT_SECRET_KEY` missing (§3) |
| `Can't open lib 'ODBC Driver ...'` | Use `ODBC Driver 18 for SQL Server` in `DATABASE_URL` |
| Database connection timeout | SQL firewall missing client IP / "Allow Azure services" (§5) |
| `Login failed for user ... Azure Active Directory only authentication is enabled` | SQL server created with **Entra-only auth** (SQL auth disabled) | `az sql server ad-only-auth disable -g vulnscan -n vulnscan` then reset the admin password |
| `NoRegisteredProviderFound ... linkers` | Region lacks Service Connector — create the Web App without the DB option |
| `InUseSubnetCannotBeDeleted` | Delete the attached Private Endpoint before the subnet/VNet |
| `InvalidParameterValue ... Login` | SQL admin login uses a reserved/invalid name (§4) |
