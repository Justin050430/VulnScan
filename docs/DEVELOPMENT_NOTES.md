# VulnScan Development Notes (for later FYP chapters)

These notes record how the approved Chapters 1–4 specification was translated
into the working implementation, the validation evidence produced, and every
place where a documented detail required an implementation decision or was
found to be inconsistent. Nothing in this file changes the design; it is
intended to feed the Implementation / Testing / Discussion chapters.

## Implementation status (at time of writing)

All documented subsystems are implemented and verified end-to-end:

- **Database** – the 8 ERD entities created on Microsoft SQL Server
  (LocalDB locally, Azure SQL for deployment) via Alembic migrations
  (`backend/migrations`). Reference data is idempotently seeded
  (`flask seed`): 8 knowledge-base entries, 3 scan profiles, default users.
- **Authentication & RBAC** – email + password (hashed with Werkzeug),
  JWT bearer tokens (Flask-JWT-Extended), two roles
  (Administrator / Developer) enforced server-side, logout token revocation.
- **Google Sign-In** – real OAuth 2.0 authorization-code flow
  (`POST /api/auth/google`), official `google-auth` ID-token verification.
  Requires real credentials; disabled cleanly when unset (never faked).
- **Management APIs** – users, vulnerabilities (knowledge base),
  configurable scan profiles, audit logs (Table 4.2 endpoints).
- **Scanner engine** – bounded, scope-restricted crawler; SQL Injection
  (error-based + boolean heuristic), reflected XSS, HTTP security-header
  modules; findings stored per page with severity / risk / confidence /
  evidence; async execution with status transitions.
- **Scan management & reporting** – create/list/detail scans, triage
  finding status (FR-08), PDF and CSV report export (FR-13).
- **Frontend** – SPA following the approved UI mockups; role-based
  navigation; dashboards with metrics/charts; live scan polling.
- **Tests** – 95 pytest cases (authentication, JWT tampering/expiry/revocation,
  RBAC, Google OAuth with the IdP mocked at the network boundary, database
  schema, management APIs, scanner scope/SSRF/limits/redirects, SQLi/XSS/header
  detection incl. false-positive control, CVSS scoring, report content, audit
  events, timeout handling, concurrent scans). All pass.

## Test evidence (kept for the Testing chapter)

- Scanner against the controlled vulnerable target
  (`testing/vuln_test_app`, local only):
  - SQL Injection detected (Critical, risk 9.8) on `/product?id=`.
  - Reflected XSS detected (High) on `/search?q=`; **not** flagged on the
    escaped control page `/safe_search`.
  - Missing HTTP Security Headers detected (Medium) on pages without
    headers; **not** flagged on `/headers_ok`.
  - 7 pages discovered, 9 findings; Overall Risk = Critical.
- RBAC: a Developer is denied user management / profile creation /
  audit-log endpoints (403) and cannot view other users' scans.
- Auth: wrong password and unknown email return the same 401;
  a logged-out (revoked) token is rejected; failed logins are audited.
- Reports: PDF and CSV both generated for a completed scan.
- Full suite: `python -m pytest testing -q` → **95 passed**.
- Database evidence: SQLAlchemy inspector against the running SQL Server shows
  dialect `mssql`, driver `pyodbc`, database `VulnScan`, the eight ERD tables
  (plus `alembic_version`) with live rows (e.g. 6 scans, 65 discovered pages,
  68 findings, 20 audit records) and the documented foreign keys.

## Detection quality and risk scoring (verification round 2)

The first implementation assigned risk scores as illustrative constants. This
was replaced with a **spec-correct CVSS v3.1 base-score calculator**
(`backend/app/scanner/cvss.py`, validated against reference vectors such as
9.8 / 8.8 / 6.1 / 0.0). Severity is derived from the score using the bands in
Report Table 2.2. Each detection maps to a documented CVSS vector:

| Detection | CVSS v3.1 vector | Score | Severity | Evidence class |
| --- | --- | --- | --- | --- |
| SQL Injection (error-based) | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 | Critical | Confirmed |
| SQL Injection (boolean differential) | AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N | 5.9 | Medium | Suspected |
| Reflected XSS | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | 6.1 | Medium | Confirmed |
| Missing HTTP security headers | AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N | 5.4 | Medium | Confirmed |

The `Confidence` value (0–1) is independent of the score; a derived
`Classification` (Confirmed ≥ 0.80 / Suspected otherwise) is exposed by the
API and shown in the UI, so confirmed evidence and suspected findings are
clearly distinguished.

**SQLi reliability improvements.** A response-length difference is no longer
used as proof. The boolean technique now:
  1. masks reflected payload text from responses,
  2. repeats the true/false requests and requires each to be stable,
  3. compares content with token-set Jaccard similarity and requires the true
     response to resemble the baseline while the false response clearly
     differs.
Error-based detection additionally requires the database-error signature to be
**absent from the baseline response**, preventing false positives on pages
that legitimately display SQL-like text. Findings from the differential
technique are labelled SUSPECTED with confidence 0.60.

**Note on severities.** Because severity is now derived from CVSS, reflected
XSS is Medium (6.1) rather than the "High" label used in the illustrative
Chapter 4 mockup. This is a deliberate, documented correction to give the risk
value a defensible basis; it does not change the project scope.

## Hardening and audit improvements (verification round 2)

- **Redirect-based SSRF / scope escape.** The HTTP client no longer follows
  redirects automatically. Every redirect target is validated against the
  scan scope and the SSRF guard before being requested; blocked redirects are
  recorded as an error and never contacted.
- **Unreachable targets.** A scan whose start page cannot be reached is now
  marked **Failed** (previously it could be reported as Completed with no
  findings).
- **Scan lifecycle auditing.** `SCAN_STARTED`, `SCAN_COMPLETED` and
  `SCAN_FAILED` audit records are written by the engine; report generation
  writes `REPORT_EXPORTED`.

## Verification round 3 — hardening, CI and evidence

**Scanner quality**
- Reflected XSS now requires the payload to be reflected in an *executable*
  HTML context; un-encoded reflection inside HTML comments, `<textarea>`,
  `<title>`, `<xmp>`, `<noscript>` or `<template>` is **not** reported
  (false-positive control, verified with dedicated test endpoints).
- HTTP security-header analysis now checks **values**, not just presence:
  `X-Frame-Options` (DENY/SAMEORIGIN), `X-Content-Type-Options` (nosniff),
  `Referrer-Policy` (safe policies) and HSTS (positive `max-age`) are flagged
  as "improperly configured" when insecure. Severity/CVSS remain 5.4 Medium.
- Host comparison in the scope check is now case-insensitive (a legitimate
  same-host link with different case is no longer treated as out of scope).

**Reports** now include OWASP category, CVSS score, confidence and the derived
evidence classification in CSV, and the evidence class/CVSS/confidence in the
PDF, in addition to the existing description, impact, remediation and raw
evidence.

**Error handling / robustness**
- Production refuses to start without `SECRET_KEY`/`JWT_SECRET_KEY`
  (`REQUIRE_SECRET`), and unhandled errors return a generic JSON 500 without
  leaking internals.
- Verified safe behaviour for: invalid/unsupported target URLs, unreachable
  targets (Failed scan), timeouts, malformed HTML, binary responses, missing
  resources (404/400), invalid/expired/revoked JWTs, unauthorised access (403)
  and database failure (generic 500). Verified with `test_error_handling.py`.

**Database** — `test_sqlserver_integration.py` runs against a real Microsoft
SQL Server / LocalDB instance (creating and dropping an isolated `VulnScanTest`
database): dialect confirmation, unique constraints, foreign-key enforcement,
transaction rollback, delete-blocked-when-referenced and concurrent scans.
These tests skip automatically where no SQL Server is available (e.g. Linux CI).

**Continuous integration** — `.github/workflows/ci.yml` installs
`requirements.txt` + `requirements-dev.txt` and runs `pytest` on push/PR,
uploading `testing/results.xml` as evidence.

**Frontend** — fixed a genuine reliability bug in the scan-result auto-refresh:
a rendering error could permanently stop the polling loop, leaving a completed
scan displayed as "Running". The poller now owns its scheduling and survives
transient fetch/render errors.

**Evidence** — `screenshots/` contains 11 genuine UI screenshots (login,
developer dashboard, scan configuration, completed scan result, finding
evidence, knowledge base, administrator dashboard, user/scan-profile/
vulnerability management, audit logs) plus real exported report artefacts
(`report_scan8.pdf`, `report_scan8.csv`). `docs/DEMO_SCRIPT.md` documents the
demonstration workflow.

**Final automated test result**
```
python -m pytest testing -q
122 passed
```

## Verified vs. not yet verified

| Area | Status |
| --- | --- |
| Database schema / CRUD (SQL Server) | Verified |
| Authentication, JWT, RBAC, audit | Verified |
| Google OAuth (implementation + mocked IdP boundary) | Tested |
| Google OAuth against the **live** Google IdP | **Not yet verified** (no credentials in this environment) |
| Scanner detection + false-positive controls | Verified |
| Scope / SSRF / redirect safety | Verified |
| Reports (PDF/CSV content) | Verified |
| Frontend screens (real API data) | Verified (browser + screenshots) |
| Concurrent scans (SQLite file + SQL Server) | Verified |
| Azure deployment / CI deployment pipeline | **Not yet verified** (CI test workflow added; deployment is Chapter 6) |

## Documented decisions / interpretations

These do not change the documented design but are worth stating:

1. **Module identity without a schema change.** The final ERD has no
   "module code" column. Detection modules are therefore keyed to the
   canonical `Vulnerability.Name` via a registry (`app/utils/modules.py`).
   Only the three implemented modules produce findings; administrators
   manage knowledge-base content but (as documented) cannot create new
   detection algorithms. Renaming a built-in module entry is blocked so
   profiles keep working.
2. **Scan safety / scope.** `FollowExternalLinks` is stored as documented
   but never extends crawling to arbitrary third-party hosts. When enabled
   the scope is widened to the target's registrable domain (sub-domains)
   only. SSRF guard blocks private/loopback targets unless
   `SCANNER_ALLOW_PRIVATE_TARGETS=true` (default in dev for local targets;
   set false in production).
3. **Async scans.** Scans run in a background worker so the API returns
   202 and the UI polls Pending → Running → Completed/Failed.
4. **Soft delete for users.** `DELETE /api/users/{id}` disables the
   account (keeps scan/audit history, cannot lock out the last admin).

## Inconsistencies found and resolutions (smallest change chosen)

1. **Google sign-in endpoint.** The auth sequence diagram (Fig 4.9) labels
   the code-exchange message `POST /api/auth/google/code`, while the final
   Table 4.2 API blueprint names the endpoint `POST /api/auth/google`.
   → Implemented **`/api/auth/google`** (the authoritative endpoint table).
   The callback route that receives Google's redirect is
   `GET /api/auth/google/callback`.
2. **New-Scan "Description" field.** The UI mockup shows an optional
   description on the new-scan form, but the final `Scan` ERD entity has no
   description column. → The ERD is the database source of truth, so no
   column was added; the form provides an optional scan *name* only.
3. **Admins viewing scans.** Table 4.2 lists `GET /api/scans` as
   "Developer", but the documented Administrator dashboard shows "recent
   scanning activities". → `GET /api/scans` returns the caller's scans for
   Developers and all scans for Administrators (a strict superset needed by
   the documented admin dashboard).
4. **Finding triage.** FR-08 ("manage scan results … status") and the scan
   result mockup show Open/Resolved/False-Positive, but Table 4.2 has no
   finding endpoint. → Minimal resource extension
   `PUT /api/scans/{id}/findings/{fid}` added to satisfy FR-08.

## Environment

- Python 3.13 venv at `.venv`; deps in `requirements.txt`.
- Local DB: SQL Server LocalDB instance `MSSQLLocalDB`, database
  `VulnScan`; ODBC Driver 17.
- Secrets live only in `backend/.env` (see `backend/.env.example`);
  nothing is hard-coded.

## Enhancement round 4 — detection quality (2026-10-09)

Enhancement programme plan documented in the session workspace
(`System_Enhancement_Assessment.md`, `Research_Log.md`); first increment
implemented, tested and committed:

- **SQLi evidence & reliability (A1)**
  - Error-based findings now REQUIRE the database-error signature to
    reproduce on the identical repeated request before being reported as
    CONFIRMED; a one-shot error page is reported as SUSPECTED (confidence
    0.65) with an explicit "did NOT reproduce" note.
  - Payloads are ordered by the parameter's input type (numeric values try
    numeric-context payloads first).
  - Three read-only DB-specific error payloads added (SQL Server
    `CONVERT(int, @@version)`, MySQL `extractvalue`, PostgreSQL `CAST`).
  - Every SQLi finding stores structured evidence: verdict line, baseline
    vs test request lines, reproducibility, why/alternatives/limitations,
    remediation, references and verification status.
- **CVSS vector exposure (A6)**
  - Every scored finding embeds `DETECTION TECHNIQUE:` and
    `CVSS Vector:` lines in its evidence (written centrally by the engine,
    so all modules benefit).
  - `GET /api/scans/{id}` additionally returns `CVSSVector` and
    `Technique` per finding (parsed from evidence; no schema change).
- **Verification** — new tests:
  `test_error_based_evidence_contains_reproducibility_and_vector` and
  `test_unreproduced_error_signature_is_suspected` (backed by the new
  controlled endpoint `/flaky_error` in `testing/vuln_test_app`).

### Second increment (A2 + A4) — 2026-10-09

- **Conditional-error SQLi (A2).** A payload pair that triggers a database
  error only when an injected condition is true (`... AND 1=CASE WHEN 1=1
  THEN 1/0 ELSE 1 END--` vs the `1=2` variant) proves the database evaluated
  attacker-controlled SQL logic. Only the true variant may produce a matched
  error signature (the false variant must not), the error must be absent from
  the baseline and must reproduce; read-only, no data extraction.
  Evidence class CONFIRMED (confidence 0.90, CVSS 9.8); runs between the
  error-based and boolean passes so the strongest available evidence wins.
- **Context-aware XSS analysis (A4).** New module
  `backend/app/scanner/html_context.py` parses the response structure
  (tags, attribute values, raw-text blocks, comments) and classifies every
  raw reflection: HTML text (executable when it can open markup), attribute
  values (executable only on a proven breakout, or a `javascript:` URL
  attribute), `<script>` blocks (executable only with a terminator + new
  markup; otherwise SUSPECTED 0.55), comments and raw-text elements
  (inert). Payloads added for attribute/event-handler and script-terminator
  breakouts. A reflection that cannot be shown to be executable is no longer
  reported (removes attribute-context false positives).
- **Controlled endpoints added:** `/error_cond`, `/attr_reflect`,
  `/attr_safe`, `/attr_events`, `/script_reflect`.
- **Verification** — 5 new tests (conditional error confirmed; attribute
  breakout confirmed; event-handler injection confirmed with angle brackets
  encoded; script terminator breakout confirmed; encoded attribute control
  stays clean). Full suite: **129 passed**.

### Third increment (A5) — 2026-10-09

- **Header policy evaluation, per-rule findings.** The HTTP security-header
  module now emits **one finding per failing rule** (previously one aggregate
  finding per page with a uniform 5.4 score), each carrying:
  - its own CVSS v3.1 vector and severity: CSP 5.4 Medium, framing 4.3
    Medium, MIME 4.3 Medium, HSTS 4.2 Medium, Referrer-Policy 3.1 Low,
    Permissions-Policy 3.1 Low;
  - `Parameter` = the header name; `Payload` = the actual value (or
    "missing");
  - a structured evidence block (current value, recommended value, security
    concern, impact/limitations, remediation example, references, verification
    status) and a `TECHNIQUE` label.
- **Policy-strength checks (not just presence):**
  - CSP present but weak is now reported when `default-src`/`script-src`
    allow `unsafe-inline`, `unsafe-eval`, `*` or `http:` sources;
  - X-Frame-Options findings are **suppressed when the CSP defines
    `frame-ancestors`** (the modern equivalent, per OWASP);
  - HSTS (HTTPS responses only) is weak when `max-age` is absent, non-positive
    or below 6 months (`HSTS_MIN_MAX_AGE`);
  - Referrer-Policy is weak for unsafe values; Permissions-Policy remains a
    presence check (documented).
- **Controlled endpoints added:** `/csp_weak` (weak CSP, everything else
  secure), `/frame_ok` (framing protected via `frame-ancestors` only).
- **Behaviour change (documented):** finding granularity and severities for
  this module changed; existing tests were updated accordingly
  (`test_header_detection_confirmed_with_control_page`,
  `test_weak_header_values_are_reported` now assert per-rule output), and
  three new tests were added (`test_weak_csp_directives_are_reported`,
  `test_xfo_mitigated_by_frame_ancestors`,
  `test_header_findings_carry_technique_and_vector`).
  Full suite: **132 passed**.
