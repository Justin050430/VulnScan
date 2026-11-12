# Local test environment (full Trust Boundary flow, no legal risk)

This guide runs the **entire product flow** — organisation, roles, verified asset,
authorisation attestation, mock credit, gated scan, findings, exports, audit — on your
own machine, against targets that ship with the repository. No third-party system is
ever contacted, so there is no authorisation question.

Everything below was executed and verified on Windows against commit
`2018ab0`+ (schema `aaf9e35de1fe`).

---

## 1. What "the same as Azure" means

The local environment runs the **same application code** and the **same database
schema** as the deployed app. Behaviour of the trust boundary therefore cannot drift.

| Layer | Azure | Local | Identical? |
| --- | --- | --- | --- |
| Application code | `main` branch | working tree of `main` | yes |
| Schema / migration | `aaf9e35de1fe` | `aaf9e35de1fe` | yes |
| Database engine | Azure SQL (MSSQL) | SQL Server LocalDB (MSSQL) | same dialect + constraints |
| Trust boundary mode | `enforce` | `enforce` (production **and** development default) | yes |
| Trust API (`/api/v1/...`) | enabled | enabled | yes |
| Legacy `POST /api/scans` | `410` | `410` | yes |
| Mock payments | "No real money" | "No real money" | yes |
| Scan engine / profiles / exports | same modules | same modules | yes |
| Serving process | gunicorn, 2 workers × 4 threads | 1 Werkzeug process, threaded | **differs** (see §7) |

Two deliberate, documented deviations:

| Setting | Azure | Local | Why |
| --- | --- | --- | --- |
| `SCANNER_ALLOW_PRIVATE_TARGETS` | `false` | `true` | the local targets are on loopback; production must never reach loopback/RFC1918/`169.254.169.254` |
| `TRUST_WEBFILE_PORT` | `0` (default 443/80) | `5001` | assets store a hostname only, so the verifier needs to know the demo target's port |

Both are configuration, not code. The scan gate, permissions, credit rules and audit
chain are byte-for-byte the production logic.

---

## 2. Prerequisites (one time)

* Python 3.13 + the repo virtualenv at `.venv`
* SQL Server LocalDB (`(localdb)\MSSQLLocalDB`) with the `VulnScan` database
* ODBC **Driver 17** (or 18) for SQL Server

```powershell
cd C:\FYP\VulnScan
.\.venv\Scripts\python.exe --version          # 3.13.x
Get-OdbcDriver | Where-Object { $_.Name -match 'SQL Server' } | Select-Object -ExpandProperty Name -Unique
```

---

## 3. One-time database setup

```powershell
cd C:\FYP\VulnScan\backend
..\.venv\Scripts\python.exe -m flask --app run.py db upgrade   # -> aaf9e35de1fe
..\.venv\Scripts\python.exe -m flask --app run.py seed          # admin + developer + profiles
```

Verify the schema matches Azure exactly:

```powershell
..\.venv\Scripts\python.exe -m flask --app run.py db current    # aaf9e35de1fe (head)
```

> `flask db migrate` is **not** used here. The migration is committed; `db upgrade`
> only applies it.

---

## 4. Start the environment (three terminals)

### Terminal 1 — controlled vulnerable target (the "website you are allowed to scan")

```powershell
cd C:\FYP\VulnScan\testing\vuln_test_app
C:\FYP\VulnScan\.venv\Scripts\python.exe run.py
```

Expected: `Test shop on http://localhost:5001/ (INTENTIONALLY VULNERABLE, local only)`

This app is intentionally buggy (SQL injection, reflected XSS, missing headers) and
lives entirely in this repository.

### Terminal 2 — VulnScan itself

```powershell
cd C:\FYP\VulnScan\backend
..\.venv\Scripts\python.exe -m flask --app run.py run --host 127.0.0.1 --port 5000 --no-reload
```

Open <http://127.0.0.1:5000/>.

> `--no-reload` matters: the auto-reloader restarts the process when a file changes,
> which kills any scan thread that is still running.

### Terminal 3 (optional) — SQLi attack lab

```powershell
cd C:\FYP\VulnScan\testing\sqli_lab
C:\FYP\VulnScan\.venv\Scripts\python.exe app.py
```

Open <http://localhost:5003/>. This lab has no `/.well-known/vulnscan.txt` endpoint,
so the trust gate cannot verify it; use it to practise manual SQL injection, or scan
it through the gate after adding that route.

---

## 5. The full flow, click by click

Sign in with the seeded developer account. Read the credentials from
`backend/.env` (`SEED_DEVELOPER_EMAIL` / `SEED_DEVELOPER_PASSWORD`).

| # | Screen | Action | Expected result |
| --- | --- | --- | --- |
| 1 | **Organisations** | *Create organisation* → "TAR UMT" | You become `ORG_OWNER` |
| 2 | Organisation detail | *Create project* → "Student Portal" | You become `PROJECT_OWNER` |
| 3 | Project → **Assets** | Register hostname `localhost`, scheme `http` | Asset `Unverified` |
| 4 | Asset → **Verify** | Choose **HTTPS well-known file** | Wizard shows a `vulnscan-verify=...` value and the URL `http://localhost:5001/.well-known/vulnscan.txt` |
| 5 | Test shop tab | Open <http://localhost:5001/__test__/verification>, paste the value, **Publish** | The token is now served at `/.well-known/vulnscan.txt` |
| 6 | VulnScan | Click **Verify** | Asset becomes `Verified`, expires in 90 days |
| 7 | Asset → **Attestation** | Acknowledge the statement, 7 days, optional reference | `Active` attestation, stored with statement hash |
| 8 | Project → **Credits** | *Buy credit* → `SCAN_CREDIT_1` | Mock checkout page ("No real money") → complete → 1 `Available` credit |
| 9 | Project → **New scan** | Pick the verified asset, profile **OWASP Top 10 Full Scan**, the credit | Readiness panel shows all five checks green |
| 10 | **Start scan** | — | Scan created, credit `Reserved` → `Consumed` |
| 10a | *(Optional)* authenticated scan | Asset → **Credentials** → create with login URL `http://localhost:5001/login`, account `pentester@example.test` / `Temporary!Pass123`, success URL `/dashboard`; invite a second `PROJECT_OWNER`, log in as them and **Approve**; **Test login**; start the scan at `http://localhost:5001/dashboard` and select the credential | Protected pages (`/dashboard`, `/dashboard/search`, `/dashboard/reports`) are discovered; the XSS on `/dashboard/search` is reported; the credential becomes `Used` and the report shows the authentication context without the password |
| 11 | Scan detail | Watch progress | ~9 pages, 45 findings, **Critical**, SQLi 9.8 confirmed, XSS, header gaps |
| 12 | Scan detail | **CSV** / **PDF** | 57 KB CSV, 68 KB PDF |
| 13 | Project → **Audit** | — | `ASSET_REGISTERED`, `ASSET_VERIFIED`, `ATTESTATION_CREATED`, `PAYMENT_*`, `CREDIT_ISSUED`, `CREDIT_RESERVED`, `SCAN_STARTED`, `CREDIT_CONSUMED`, `SCAN_DENIED` (hash-chained) |

### Proof the gate actually works (do these too)

| Try this | Expected |
| --- | --- |
| Start a scan with no attestation and no active one | `403 ATTESTATION_REQUIRED` |
| Revoke the attestation, then start a scan | `403` immediately, audit `SCAN_DENIED` |
| Start a scan with no credit | `402 CREDIT_REQUIRED` |
| Target URL `http://127.0.0.1:5001/` while the asset is `localhost` | `400 TARGET_HOST_MISMATCH` |
| Register `127.0.0.1` or `*.localhost` as an asset | `400 HOSTNAME_INVALID` |
| Second scan while one is running for the same asset | `409 ACTIVE_SCAN_EXISTS` |
| Invite a colleague as `VIEWER`, log in as them | New scan hidden, API `403 PERMISSION_DENIED` |
| Log in as the seeded **Administrator** (not a project member) | project API returns `404` (tenant isolation) |
| Call `POST /api/scans` | `410 LEGACY_SCAN_ENDPOINT_DISABLED` |

---

## 6. Reset between runs

```powershell
cd C:\FYP\VulnScan\backend

# 1. throw away the trust + scan data and reseed reference data
..\.venv\Scripts\python.exe -m flask --app run.py seed-reset

# 2. re-apply the migration head (seed-reset drops and recreates via SQLAlchemy,
#    so stamp the current head afterwards)
..\.venv\Scripts\python.exe -m flask --app run.py db stamp head
```

If the test shop is still serving an old token, restart terminal 1 (the published
challenge lives in memory) — or just publish the new value again.

---

## 7. Known differences from Azure (be honest in the report)

1. **Process model.** Azure runs `gunicorn --workers 2 --threads 4`; locally it is one
   threaded process. Live progress and token revocation are held in memory, so with
   two workers Azure can briefly show progress from a different worker. Durable
   progress/queueing is future work for both.
2. **Private targets.** Azure must run with `SCANNER_ALLOW_PRIVATE_TARGETS=false`.
   Local runs with `true` so loopback demo targets work. Never copy the local value
   into App Settings.
3. **Verification method.** Local demos use the `/.well-known/vulnscan.txt` method on
   `localhost`. DNS TXT verification needs a real public domain and public DNS; it
   cannot be demonstrated on loopback.
4. **Assets are host-only.** `TRUST_WEBFILE_PORT=5001` exists only so the verifier can
   reach the demo target. Set it back to `0` when testing a real domain.
5. **gunicorn does not run on Windows**, so the Azure startup command cannot be
   reproduced locally. Application behaviour is unaffected.
6. **Database.** LocalDB vs Azure SQL — same dialect and constraints, different
   hosting, backups and latency.

---

## 8. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `Error: An internal server error occurred.` on Organisations | trust tables missing | `flask db upgrade` |
| `503 TRUST_BOUNDARY_UNAVAILABLE` from `/api/v1/*` | same | `flask db upgrade` |
| Verify fails with *"no challenge configured"* | the test shop still serves the placeholder | publish the current token at `/__test__/verification` (the token expires after 30 min) |
| Verify fails with *"different value"* | an old token was published | publish the newest value, then retry |
| Scan stuck `Pending` | server started with `--reload` and restarted | restart with `--no-reload` |
| `410 LEGACY_SCAN_ENDPOINT_DISABLED` | correct behaviour in `enforce` mode | use project → New scan |
| Everything takes ~2 s per page | a target bound only to `127.0.0.1` while `localhost` resolves to `::1` | the bundled targets already bind both stacks; keep them that way |
| `Can't open lib 'ODBC Driver 18 for SQL Server'` | driver 18 missing | use Driver 17 in `MSSQL_DRIVER` / `DATABASE_URL` |

---

## 9. Why this is legally safe

* Both targets are files in this repository (`testing/vuln_test_app`, `testing/sqli_lab`)
  and run on your machine only.
* The only outbound requests are loopback requests to those targets.
* No real money: the payment provider is `MOCK`, signature-verified but entirely local.
* Do not point the scanner at a domain you do not own — the audit trail is permanent
  and hash-chained.

---

## 10. Cleanup

* `C:\FYP\VulnScan\.well-known\vulnscan.txt` is committed but **unused** — the app never
  serves it and the token has expired. Safe to delete.
* Stop the three terminals; nothing persists except the LocalDB database.
