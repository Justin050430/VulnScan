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
gunicorn --bind=0.0.0.0:8000 --timeout 600 --workers 2 --threads 4 --chdir backend wsgi:app
```

> `--workers 2 --threads 4` matters: the finding **retest** endpoint is
> synchronous, so retesting a finding whose page is this app's own URL makes
> the worker wait on a request back into the same worker pool.  With the
> default single sync worker that self-request can never be served and the
> retest reports *Unable to Verify — Request timed out*.  Retesting any other
> target works with the default, so this is only required if you intend to
> scan/retest the deployment itself.

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
| `TRUST_CREDENTIAL_KEY` | Fernet key for encrypting temporary scan credentials; generate with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `TRUST_CREDENTIAL_KEY_OLD` | optional previous key during rotation |
| `TRUST_CREDENTIAL_ALLOW_SELF_APPROVAL` | `false` (keep maker-checker) |
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

The current head is `d9f2a4c8b1e7` (invitation email binding); `c4d8f1a2b6e9` added
the temporary authenticated-scan credentials.
`aaf9e35de1fe` is the base Trust Boundary migration. The local `.env` points at
LocalDB, so running `flask db upgrade` locally does **not** migrate Azure SQL.

### Simplest path (no Azure CLI)

1. Azure Portal → SQL server `vulnscan` → **Networking** → **Add current client IP**.
2. Azure Portal → App Service `vulnscan` → **Configuration → Environment
   variables** → copy `DATABASE_URL`.
3. In PowerShell, with the App Service connection string (this machine only has
   ODBC Driver 17, so the 18 in the copied value is substituted automatically):

```powershell
cd C:\FYP\VulnScan\backend

# Paste the URL at the prompt (not inside the quotes), then press Enter.
$url = Read-Host "Paste Azure DATABASE_URL"
$env:DATABASE_URL = $url.Replace(
    'ODBC%20Driver%2018%20for%20SQL%20Server',
    'ODBC%20Driver%2017%20for%20SQL%20Server'
).Replace(
    'ODBC+Driver+18+for+SQL+Server',
    'ODBC+Driver+17+for+SQL+Server'
)

# Both must be non-zero / True before continuing.
$env:DATABASE_URL.Length
$env:DATABASE_URL -match 'database\.windows\.net'

..\.venv\Scripts\python.exe -m flask --app run.py db current
..\.venv\Scripts\python.exe -m flask --app run.py db upgrade
..\.venv\Scripts\python.exe -m flask --app run.py db current   # expect d9f2a4c8b1e7 (head)
Remove-Item Env:DATABASE_URL
```

The `DATABASE_URL` value is percent-encoded, so the spaces are `%20`, not `+`.
The replacement above handles both forms.

4. Restart the Azure Web App.
5. Verify `GET /api/v1/organisations` returns **401** (schema present), not **503**.

If the first `db current` cannot connect, the cause is almost always the SQL
firewall (step 1) or a missing ODBC driver. The error does not contain the
password, so it is safe to paste the message (never the connection string).

### Alternative: migration script (requires `az login`)

The repository script reads the Web App's `DATABASE_URL` (never prints it),
takes a pre-migration database copy, upgrades to head, generates
`TRUST_CREDENTIAL_KEY` if it is missing, restarts the app and checks that
`/api/v1` no longer returns `503`:

```powershell
$env:PATH = "C:\FYP\azurecli-venv\Scripts;$env:PATH"   # local Azure CLI venv
az login
cd C:\FYP\VulnScan
.\scripts\azure_trust_migration.ps1
```

Then restart the Web App so the in-process schema check is re-evaluated. Seed
only if the database has no users:

```powershell
python -m flask --app run.py seed
```

### If `az login` is blocked by MFA or the account has no subscriptions

Use the App Service's own environment instead — it already has
`DATABASE_URL` and the ODBC drivers, and the SQL firewall already allows the
Web App:

1. Azure Portal → App Service `vulnscan` → **Development Tools → SSH → Go**.
2. Find the app root (it is not `/backend`):

   ```bash
   ls -la /home/site/wwwroot
   find /home/site/wwwroot -maxdepth 3 -name run.py
   ```

3. `cd` to the directory that contains `run.py`, then run:

   ```bash
   python -c "import flask, sqlalchemy; print('python ok')"
   python -m flask --app run.py db current
   python -m flask --app run.py db upgrade
   python -m flask --app run.py db current     # expect d9f2a4c8b1e7 (head)
   ```

4. Restart the Web App from the portal.
4. Verify `GET /api/v1/organisations` returns **401** (schema present) instead
   of **503**.

If SSH is unavailable, temporarily prepend the migration to the startup
command, restart once, then restore the original gunicorn command:

```text
bash -c "cd /home/site/wwwroot/backend && python -m flask --app run.py db upgrade && gunicorn --bind=0.0.0.0:8000 --timeout 600 --workers 2 --threads 4 wsgi:app"
```

The schema migration is additive (two new tables). For a rollback point, copy
the Azure SQL database in the portal before running it.

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

### 8a. Running database migrations from GitHub Actions

`deploy.yml` deploys code but does not change the schema. Schema changes are applied
by the separate, **manual** workflow `.github/workflows/migrate.yml`
(*Actions → Database migration (Azure SQL) → Run workflow*):

| Input | Effect |
| --- | --- |
| `dry-run` (default) | prints the current `alembic_version`; changes nothing |
| `apply` | runs `flask db upgrade`, prints the resulting revision and verifies the live app |

It is safe by construction:

* it authenticates with **GitHub OIDC** — no Azure credential is stored in GitHub;
* it reads `DATABASE_URL` from the App Service settings and masks it (never printed);
* it opens the SQL firewall for the runner's public IP only, then deletes that rule
  in an `always()` step so a failed run cannot leave the database exposed;
* it only runs committed migrations (`flask db upgrade`), never `flask db migrate`.

**One-time setup** (already done for this deployment):

```powershell
# 1. App registration + service principal
$app = az ad app create --display-name "vulnscan-github-oidc" --query appId -o tsv
az ad sp create --id $app

# 2. Federated credentials trusting this repository
#    (JSON files avoid PowerShell quoting problems with `az --parameters`)
#    subject 1: repo:Justin050430/VulnScan:ref:refs/heads/main
#    subject 2: repo:Justin050430/VulnScan:environment:production
az ad app federated-credential create --id $app --parameters .\main.json
az ad app federated-credential create --id $app --parameters .\env.json

# 3. Least-privilege roles on the resource group that holds the app and SQL server
$scope = "/subscriptions/<subscription-id>/resourceGroups/vulnscan"
az role assignment create --assignee-object-id $app --assignee-principal-type ServicePrincipal `
    --role "Website Contributor" --scope $scope
az role assignment create --assignee-object-id $app --assignee-principal-type ServicePrincipal `
    --role "SQL Server Contributor" --scope $scope
```

`Website Contributor` lets the job read the App Service settings; `SQL Server
Contributor` lets it add and remove the temporary firewall rule. Nothing else is
granted.

Optionally set these repository **Variables** to override the defaults baked into the
workflow: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`.

Current values for this deployment: client id `696caaef-a481-47cd-a664-f8050351d9e8`,
tenant `9be0bd27-8c02-4993-8d86-2975ccc9ae1e`, subscription
`2e4ea030-fd2b-46af-a753-12f96bd10f23`.

> **Order for a schema-changing release:** run the migration workflow (`apply`) and
> confirm `d9f2a4c8b1e7 (head)`, then deploy the code — or deploy first and migrate
> immediately, as happened on 2026-11-13. Additive migrations keep the old code
> working, so either order is safe; the app answers `503 TRUST_BOUNDARY_UNAVAILABLE`
> naming the missing migration if the two get out of step.

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
| Retest of a finding fails with `Unable to Verify — Request timed out` | The retest is synchronous and the target is the app's own URL, so the single gunicorn sync worker deadlocks on itself. Add `--workers 2 --threads 4` to the startup command (§2). Retests of external targets are unaffected |
