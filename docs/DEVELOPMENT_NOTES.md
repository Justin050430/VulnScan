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

### Fourth increment (A3) — 2026-10-09

- **Time-based SQLi (opt-in, bounded, last resort).** New fourth technique in
  `sqli.py`, executed only when `SCANNER_ENABLE_TIME_BASED=true` (default
  **false**) and only after error-based, conditional-error and boolean
  techniques are inconclusive.  Protocol: two fast control requests establish
  a timing baseline; a single controlled read-only wait payload
  (`SLEEP` / `WAITFOR DELAY` / `pg_sleep`, 3 s) is sent twice and the finding
  requires **both** test responses to be ≥ 2.5 s slower than the slowest
  control.  Baselines slower than 5 s abort the technique (unreliable timing
  environment).  CONFIRMED (0.85), CVSS 9.8; structured evidence includes the
  measured durations, the control requests and the limitations.
- Configuration: `SCANNER_ENABLE_TIME_BASED` added to `config.py` and
  `backend/.env.example` (documented as slow: ≈ +6 s per tested parameter).
- Controlled endpoint: `/time_blind` (bounded wait simulation) in
  `testing/vuln_test_app`.
- **Verification** — new tests:
  `test_time_based_disabled_by_default` (no probes unless enabled) and
  `test_time_based_detects_delay_when_enabled` (confirmed finding with
  reproducible delay + no finding on the `/safe_search` control).
  Full suite: **134 passed**.

### Fifth increment (B1 + B2) — 2026-10-09

- **Scan progress registry (`app/scanner/progress.py`, B1).** The engine now
  publishes real counters while a scan runs: stage
  (`queued → crawling → analysing → finalising → completed/failed`), pages
  found/analysed, findings, per-module/step errors, failure reason and the
  scanner's real request count. The registry is in-memory and per-process;
  the API reports `LiveAvailable: false` and database-derived values when the
  scan ran in another process (honest fallback - nothing is fabricated).
- **`GET /api/scans/<id>/progress` (B1).** Authenticated (owner or admin),
  returns: Status, Stage, LiveAvailable, PagesFound, PagesAnalysed,
  PageCount, FindingCount, FindingsByModule, RequestsIssued, Errors,
  FailureReason, StartedAt/FinishedAt, ElapsedSeconds.
- **Coverage transparency on scan detail (B2).** `GET /api/scans/<id>` now
  also returns `AnalysedPages`, `SkippedPages` (pages stored but not tested,
  with HTTP status), `TestedParameters` (the GET query-string parameters the
  modules could test) and a `CoverageNote` stating exactly what was and was
  not tested (no POST bodies, form submission, JS-rendered content or
  authenticated pages).
- **Verification** — new suite `testing/test_scan_observability.py` (4 tests):
  live stage/counters after completion, progress access control, coverage
  fields, and the skip path (a 404 start page is stored, skipped and
  disclosed). Full suite: **138 passed**.

### Sixth increment (C1 + C2) — 2026-10-09

- **Live scan monitor (C1, `static/js/views.js` + `static/css/style.css`).**
  While a scan runs, the result page polls `GET /api/scans/<id>/progress`
  every 2.5 s and updates a dedicated panel in place:
  stage text (`queued → crawling → analysing → finalising`), elapsed time,
  progress bar (pages analysed / found), findings count, HTTP requests
  issued and per-module finding counts.  The panel is `aria-live="polite"`.
  A full page re-render only happens when the visible counts change or the
  scan reaches a terminal state, so findings filters and expanded rows are
  no longer torn down on every poll.  Honest fallback: when
  `LiveAvailable` is false (scan started before a restart / handled by
  another worker) the panel says so explicitly and never fabricates request
  counts.
- **Findings explorer upgrades (C2).** New filters (classification,
  detection technique - populated from the findings' parsed `Technique`
  values), search now also matches technique text, and grouping modes
  (`Group: Vulnerability` / `Group: Page`) render collapsible sections with
  finding counts, location counts, worst severity and confirmed/suspected
  tallies.  The finding detail pane now shows the detection-technique badge,
  the raw CVSS v3.1 vector (from the additive `CVSSVector` key), confidence
  percentage and detection time; stored evidence is rendered with its
  section headers bolded (`CONFIRMED:`, `BASELINE REQUEST:`, `WHY ...`,
  `REMEDIATION:`, `REFERENCES:`, ...) so the proof structure is visible at
  a glance.
- No backend or schema changes were needed: this increment consumes the B1
  progress endpoint, the B2 coverage keys and the parsed evidence fields
  added by earlier increments.
- **Verification** — frontend behaviour verified against the local
  deployment (scan 17 against the controlled vulnerable app): live updates
  observed as `Queued → Analysing`, counters climbing
  (`0/0 → 1/9 → 2/9` pages, `5 → 11` findings, `13 → 51` requests), panel
  replaced by the final render on completion; technique filter lists 4
  techniques; `Suspected` filter isolates the 1 differential SQLi finding;
  vulnerability grouping shows
  `SQL Injection 3 findings · 3 locations · Critical · 2 confirmed · 1 suspected`;
  detail pane shows the technique badge, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
  and bolded evidence sections. Full test suite: **138 passed** (no Python
  changes in this increment).

### Seventh increment (C3 + C4) — 2026-10-09

- **Pre-scan summary / scan plan (C3).** New endpoint
  `GET /api/scan-profiles/<id>/preview` (authenticated) returns a
  machine-derived plan for the selected profile: enforced limits (depth,
  page cap, request delay, external-link policy), the selected modules with
  the concrete detection techniques each will run
  (`app/utils/modules.py::MODULE_TECHNIQUES` — kept in sync with the
  implementations: error-based / conditional-error / boolean / opt-in
  time-based for SQLi, executable-context reflection analysis for XSS,
  per-rule header policy evaluation), an explicit *what will be tested*
  list and an equally explicit *what will NOT be tested* list (no POST
  bodies/forms, no JavaScript execution, no authenticated pages, error
  pages stored but skipped, non-query-string values untouched, time-based
  SQLi only when the operator enables it), plus an honest request-budget
  note (exact request counts depend on the target and are reported live by
  the monitor - never estimated as fact). The **New Scan** page renders
  this as a live "scan plan" panel that follows the profile selection
  (stale responses discarded).
- **Knowledge-base code examples (C4).** `SecurityCodingPractice` text now
  renders through a small safe formatter: blocks beginning with
  `Unsafe:` / `Safe:` become labelled code panels (red / green) with the
  code fully escaped inside `<pre>`; remaining text stays escaped prose.
  The SQL Injection, XSS and Missing HTTP Security Headers seed entries
  were enriched with concrete unsafe/safe examples (fresh installs pick
  them up; existing databases keep their content, and the examples can be
  pasted through the admin KB editor).
- **Verification** — 2 new tests (`test_profile_preview_lists_plan`,
  `test_profile_preview_unknown_id`): the preview exposes profile limits,
  all three module keys with techniques, the will/will-not lists and the
  budget note; unknown profile returns 404. Full suite: **140 passed**.
  Browser checks (local): the New Scan plan panel follows the profile
  selector (1-module headers profile → 3 will-test / 6 will-not-test;
  full profile → 4 SQLi techniques + time-based note / 7 will-not-test);
  KB modals render the unsafe/safe examples with raw HTML proven inert
  (`&lt;p&gt;` escaped, no injected element).

### Eighth increment (D1) — 2026-10-09

- **Finding retest / verification workflow (D1).** New
  `POST /api/scans/<scanId>/findings/<fid>/retest` (owner or admin)
  synchronously re-runs the finding's **original detection module** against
  its **exact page** and classifies the outcome honestly:
  * **Resolved** - the module ran cleanly and the original parameter shows
    no detectable signal (verified absence; the finding is auto-marked
    Resolved),
  * **Still Detected** - the module re-detected the same parameter (the
    finding is re-opened),
  * **Inconclusive** - the module itself failed while re-testing,
  * **Unable to Verify** - the page is unreachable/no longer analysable or
    the vulnerability has no implemented module (status left unchanged for
    manual review).
  Implementation: `app/scanner/retest.py` reuses the scan's SSRF/scope
  validator (`make_url_validator`), keeps the profile's politeness delay
  (capped at 1 s) and reports the real request count it issued.  A RETEST
  stanza is appended to the finding evidence (verdict, technique,
  confidence, requests, explicit status note); the original proof is never
  modified.  `Finding.to_dict()` now exposes additive `Retests` /
  `LatestRetestVerdict` keys parsed from the stanzas; every retest writes a
  `FINDING_RETESTED` audit record.
- **UI.** Findings rows gain a `🔁 Retest` button; the detail pane shows a
  colour-coded verification-history chip per retest (green Resolved, red
  Still Detected, grey otherwise) next to the original evidence.
- **Verification** — new suite `testing/test_retest.py` (4 tests):
  Still Detected on an unfixed page (status re-opened, history keys),
  Resolved after the page is pointed at a safe variant (status auto-closed,
  "verified absence" stanza), Unable to Verify when the page 404s (status
  unchanged, honest reason), and access control (401 unauthenticated,
  400 unknown finding, 404 unknown scan, 403 another developer, 200 admin).
  Browser-verified end to end: retest of finding 304 (scan 17) →
  `Still Detected` toast + stanza with technique/confidence/4 requests;
  retest of finding 253 (scan 16, page pointed at the safe variant) →
  `Resolved` toast, status auto-changed to Resolved, green history chip and
  the RETEST stanza appended to the original evidence.

### Ninth increment (D2 + E1) — 2026-10-09

- **Before/after verification view (D2).** `Finding.retest_entries()` now
  parses each RETEST stanza - verdict, message, technique, confidence and
  request count - and `evidence_technique()` / `evidence_vector()` factor the
  evidence parsing into one place (used by `to_dict` and the reports).  The
  finding detail pane renders re-tested findings as a colour-bordered
  **Original detection → Latest verification** comparison (severity/CVSS/
  confidence/technique vs verdict badge, checked time, requests and the
  verdict message), with a chip history when there is more than one retest.
- **Report upgrades (E1).**
  * CSV: the findings table gains `Technique`, `CVSS Vector`,
    `Latest Verdict` and `Retest Count` columns, plus a
    `VERIFICATION (RETESTS)` section listing every retest event (finding,
    vulnerability, parameter, checked-at, verdict, confidence, requests).
  * PDF: new **Risk Overview** (overall risk, confirmed/suspected counts,
    highest-risk finding, verification tally), **Methodology and Coverage**
    (crawl limits from the profile, analysed vs skipped pages, tested GET
    parameters, detection techniques used, explicit limitations list) and
    **Verification (Retests)** table; each finding detail block now also
    prints its CVSS vector, detection technique and retest history lines.
- **Verification** — `testing/test_reports_content.py` updated for the new
  columns/sections and extended with `test_reports_include_retest_results`
  (retests a SQLi finding, then asserts the CSV verification row and the PDF
  sections/verdict text); `testing/test_retest.py` now asserts the parsed
  retest-entry detail (message, technique, confidence, requests).
  Full suite: **145 passed**.  Browser-verified locally: finding 253 shows
  the green `ba-resolved` comparison ("Resolved · 19 requests · No
  detectable signal ..."), the CSV verification row
  `253,SQL Injection,id,2026-10-09 15:05 UTC,Resolved,,19`, the findings
  header carries the new columns, and the PDF starts `%PDF-` (68.6 kB).

### Tenth increment (F1–F4) — 2026-10-09

- **F1 - orphan scan recovery.** `create_app()` now runs
  `recover_orphan_scans()` at startup: scans left `Pending`/`Running` by a
  previous process are marked `Failed` (with `FinishedAt` and a
  `System`/`ORPHAN_SCANS_RECOVERED` audit record) so users are never stuck
  with a permanently running scan.  Scans that are alive in the current
  process are detected through the in-memory progress registry and never
  touched.  Non-fatal by design (the schema may not exist before the first
  `init-db`/migration) and toggleable via `SCANNER_RECOVER_ORPHAN_SCANS`.
- **F2 - active-scan concurrency caps.** `start_scan` now rejects new scans
  once `SCAN_MAX_ACTIVE_PER_USER` (default 3) or `SCAN_MAX_ACTIVE_GLOBAL`
  (default 5) `Pending`/`Running` scans exist, counted from the database so
  the caps hold across workers; completed/failed scans never count, and
  orphan recovery keeps the counts honest after restarts.  Error messages
  state the limit and current count; `0` disables a cap.
- **F3 - dependency security audit.** `requirements.txt` bumped to fully
  patched versions after a `pip-audit` scan found 18 advisories in 4
  packages: Werkzeug 3.1.8→3.1.9, cryptography 45.0.0→50.0.0,
  requests 2.32.4→2.33.0, python-dotenv 1.1.0→1.2.2.  `pip-audit -r
  requirements.txt` now reports **no known vulnerabilities**, and the new
  `Dependency Security Audit` workflow (`.github/workflows/security-audit.yml`)
  runs pip-audit on every push/PR so a vulnerable pin cannot land unnoticed.
- **F4 - post-deploy behavioural smoke check.**
  `.github/workflows/post-deploy-smoke.yml` triggers on completion of the
  deploy workflow, checks out the deployed commit, hashes
  `backend/app/static/js/views.js` and polls the live app (health, SPA and
  the exact served bundle hash) for up to ~13 minutes - absorbing the
  observed App Service restart lag - and fails if the new build never goes
  live.  It deliberately leaves `deploy.yml` untouched.
- **Verification** — new `testing/test_hardening.py` (5 tests): orphan
  Running + Pending scans are failed with an audit record (and recovery is
  idempotent), a live in-process scan is not recovered, per-user and global
  caps reject with 400, and finished scans never count towards the caps.
  The MSSQL integration test that previously left an async scan running now
  waits for it so the caps stay deterministic.  Full suite re-run after the
  increment (including the upgraded dependencies).
