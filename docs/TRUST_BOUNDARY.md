# VulnScan — Trust Boundary Extension

This document describes the additive **Trust Boundary Extension** implemented for the
FYP vertical slice. It wraps the frozen eight-entity core ERD without modifying it.

> VulnScan is positioned as a scanner for websites a user **owns or is explicitly
> authorised to test**. It is not a "scan any website" service and must not be exposed
> publicly on the strength of this slice alone.

---

## 1. Scope of this slice

Implemented:

- Organisations, projects and memberships with server-side permissions.
- Separate permission for **starting a scan** vs **viewing results**.
- Exact-hostname asset registration with DNS TXT / `/.well-known/vulnscan.txt` verification.
- Explicit, revocable, expiring authorisation attestation per asset.
- Organisation-approved temporary credentials for authenticated FORM-login scans
  (maker-checker, encrypted at rest, expiring, single-use).
- Mock-only single-use scan credits with atomic reservation.
- Gated scan start (permission + asset + attestation + credit + host match + no active scan).
- Append-only trust audit.
- Permission-aware SPA screens.

Explicitly **not** implemented (future work):

- Real payment gateways, real money, billing, invoices, refunds.
- Durable queues/isolated workers, controlled egress proxy, autoscaling.
- Multi-tenant commercial model, SSO, API keys, scheduling, scan diffs.
- Additional detection modules, JavaScript rendering, MFA/CAPTCHA/SSO login flows.
- Public deployment and its legal/abuse operations.

---

## 2. Table layout (additive)

| Table | Purpose |
| --- | --- |
| `TrustOrganisation` | Tenant boundary |
| `TrustProject` | Project inside an organisation |
| `TrustOrganisationMembership` | User ↔ organisation role (`ORG_OWNER`) |
| `TrustProjectMembership` | User ↔ project role |
| `TrustAsset` | Registered hostname + verification state |
| `TrustAuthorizationAttestation` | Authorisation statement per asset |
| `TrustPaymentTransaction` | Mock payment record |
| `TrustScanCredit` | Single-use entitlement |
| `TrustCreditRedemption` | Immutable reservation/consumption ledger |
| `TrustScanContext` | Bridge from core `Scan` to project/asset/attestation/credit |
| `TrustScanCredential` | Encrypted, expiring, org-approved test-account credential |
| `TrustScanCredentialBinding` | Single-use binding of one credential to one scan |
| `TrustAuditEvent` | Append-only audit ledger |

The frozen core tables (`User`, `Scan`, `ScanProfile`, `ProfileModule`,
`Vulnerability`, `DiscoveredPage`, `Finding`, `SecurityAuditLog`) are unchanged;
`test_trust_migration.py` asserts their exact column sets.

Invitation columns (additive, migration `d9f2a4c8b1e7`): both membership tables carry
`InviteTokenHash` (SHA-256 of the one-time token, indexed), `InviteEmail` (the address
the invitation is bound to) and `InviteExpiresAt`. See §3a.

---

## 3. Roles and permissions

| Permission | Platform Admin | Org Owner | Project Owner | Scan Operator | Analyst | Viewer |
| --- | --- | --- | --- | --- | --- | --- |
| `org.read` | ◐ audited only if member | ✅ | ✅ | ✅ | ✅ | ✅ |
| `org.manage` / `org.members.manage` | — | ✅ | — | — | — | — |
| `project.read` | ◐ if member | ✅ | ✅ | ✅ | ✅ | ✅ |
| `project.manage` / `project.members.manage` | — | ✅ | ✅ | — | — | — |
| `asset.read` | ◐ if member | ✅ | ✅ | ✅ | ✅ | ✅ |
| `asset.register` / `asset.verify` / `asset.revoke` | — | ✅ | ✅ | — | — | — |
| `attestation.read` | ◐ if member | ✅ | ✅ | ✅ | ✅ | ✅ |
| `attestation.create` / `attestation.revoke` | — | ✅ | ✅ | — | — | — |
| `credit.read` | ◐ if member | ✅ | ✅ | ✅ | ✅ | ✅ |
| `credit.purchase` | — | ✅ | ✅ | — | — | — |
| `credit.refund` | — | ✅ | — | — | — | — |
| `scan.read` / `report.download` | ◐ if member | ✅ | ✅ | ✅ | ✅ | ✅ |
| **`scan.start`** | — | — unless also a project scan role | ✅ | ✅ | — | — |
| `scan.cancel` | — | ✅ | ✅ | ✅ | — | — |
| `scan.retest` (also finding triage) | — | ✅ | ✅ | — | ✅ | — |
| `trust_audit.view` | — | ✅ | ✅ | — | — | — |
| `credential.read` | ◐ if member | ✅ | ✅ | ✅ | ✅ | — |
| `credential.create` | — | ✅ | ✅ | ✅ | — | — |
| `credential.approve` / `credential.revoke` | — | ✅ | ✅ | — | — | — |

Key rules:

1. **Organisation ownership never implies `scan.start`.** The user must also hold
   `PROJECT_OWNER` or `SCAN_OPERATOR` in the project.
2. **Viewers and analysts can never start a scan**, even by calling the API directly.
3. A platform administrator is **not** a customer super-user: trust-scoped scans and
   project resources are only visible through membership. Cross-tenant resources return
   `404` rather than confirming existence.
4. Every denial is recorded as `SCAN_DENIED` / `ACCESS_DENIED` with a reason code.

Permission resolution lives in `backend/app/trust/permissions.py`; the effective role
set is returned per project by `GET /api/v1/projects/{id}`.

---

## 3a. Invitation links and acceptance

An invitation is a **direct, clickable URL** that an owner shares with the invitee.
There is no copy-and-paste of a bare token into an authenticated session: the link
carries the token in the URL fragment (`/#/invitations/accept?token=…`), so it never
reaches the server in a request line or access log and is never sent as a `Referer`.

Flow:

1. The owner enters the invitee's email (the account must already exist) and a role.
2. The API returns `InviteURL` (absolute), plus `InviteEmail` and `InviteExpiresAt`.
3. The inviter shares the URL.
4. The invitee opens it. The SPA always redirects an unauthenticated visitor to the
   login screen with the invitation preserved as `next` — including through the Google
   OAuth round trip — so nothing is lost.
5. After sign-in the invitation page calls `POST /api/v1/invitations/preview`, which
   validates server-side before showing what the link grants.
6. Accepting calls `POST /api/v1/invitations/accept`, which re-validates and activates
   the membership with the assigned role.
7. Rejection reasons are explicit: `INVITATION_EMAIL_MISMATCH` (403),
   `INVITATION_EXPIRED` / `INVITATION_ALREADY_USED` (409), `NOT_FOUND` (404).

Security properties:

* tokens come from `secrets.token_urlsafe(32)` (256-bit) and are stored only as a
  SHA-256 hash (`InviteTokenHash`, indexed);
* each invitation row records the invited address (`InviteEmail`); acceptance requires
  the authenticated session to own that address *and* map to the invited user row —
  holding the link is not sufficient;
* single use: accepting sets `Status = Active`, after which the same link returns
  `INVITATION_ALREADY_USED`;
* expiry defaults to 72 h (`TRUST_INVITATION_TTL_HOURS`);
* re-inviting rotates the token (the previous link dies), revoking clears it;
* re-inviting an **active** member returns `ALREADY_MEMBER` instead of silently
  demoting them, so existing membership/authorisation rules are preserved;
* a mismatched attempt is audited as a `Denied` event without the token.

`TRUST_INVITE_BASE_URL` overrides the link base when the public URL differs from the
request host (for example behind Azure's proxy).

---

## 4. Asset verification

- Only **exact hostnames** are accepted. IP literals, wildcards (`*.example.com`),
  schemes, ports, paths and credentials are rejected with `HOSTNAME_INVALID`.
- Verification methods:
  - `DNS_TXT` — TXT record `_vulnscan-challenge.<host>` containing
    `vulnscan-verify=<token>`;
  - `WEB_FILE` — `https://<host>/.well-known/vulnscan.txt` containing the same value.
- Only a **SHA-256 hash** of the challenge token is stored; the plaintext token is
  returned to the caller once.
- The web-file fetch uses the hardened HTTP client: strict timeout, response-size cap,
  **no redirects**, no cookies or credentials, and the existing private/loopback SSRF
  guard.
- Stored evidence is a fixed human-readable statement (e.g. `TXT record matched at …`)
  and never contains the token.
- Verified assets expire after `TRUST_ASSET_VERIFICATION_DAYS` (default 90). Expired,
  revoked or unverified assets block active scans with
  `ASSET_VERIFICATION_EXPIRED` / `ASSET_REVOKED` / `ASSET_NOT_VERIFIED`.

**Sub-domain limitation:** a verified `example.com` does **not** authorise
`shop.example.com`. Each exact hostname must be registered and verified.

---

## 5. Authorisation attestation

- Creation requires an owner role, a *verified* asset, and is limited to
  `TRUST_ATTESTATION_MAX_DAYS` (default 90; default 30).
- The server stores the versioned statement text, its SHA-256, the attesting user,
  timestamp, expiry, optional reference, IP address and a hash of the user agent.
- Only one active attestation exists per asset (a filtered unique index enforces this).
- Revocation blocks later scans immediately. Expired attestations are rejected with
  `ATTESTATION_EXPIRED`; a missing one returns `ATTESTATION_REQUIRED`.

The statement is versioned (`v1`); unknown versions are rejected.

---

## 6. Credits and mock payment

- Products are defined **server-side** (`SCAN_CREDIT_1` = 1000 MYR minor units,
  `SCAN_CREDIT_5` = 4500). Client-supplied amounts are ignored.
- `POST .../payments/checkout` creates a `PendingPayment` transaction with an
  idempotency key.
- **A browser return never issues a credit.** Only the signed callback path can turn a
  payment into credits:
  - `POST /api/v1/payments/webhooks/MOCK` with an `X-VulnScan-Signature` HMAC, or
  - `POST .../payments/{uuid}/mock-complete`, which builds the same signed payload
    server-side for the demonstration.
- The callback is validated for signature, amount, currency, product, quantity and
  project before `PaymentVerified` and credit issuance.
- Duplicate callbacks are idempotent (200, `Duplicate: true`, no extra credit). A
  unique constraint on `(PaymentTransactionID, CreditSequence)` also protects against
  concurrent duplicate delivery.
- No card data, gateway secret or unnecessary customer data is stored or logged.

### Credit lifecycle

```
PendingPayment → PaymentVerified → Available → Reserved → Consumed
                                     │           │
                                     ▼           ▼
                                  Expired     Released
```

Credits are **project-scoped** and expire after `TRUST_CREDIT_VALIDITY_DAYS`
(default 180).

---

## 7. Gated scan start (atomic)

`POST /api/v1/projects/{project_id}/scans` requires **all** of:

1. active membership with `scan.start`;
2. asset in the project, `Verified` and unexpired;
3. active, unexpired attestation for that asset;
4. an `Available`, unexpired project credit;
5. target URL whose host **exactly** equals the verified asset;
6. no other `Pending`/`Running` scan for that asset.

The credit is reserved with a single conditional `UPDATE ... WHERE Status='Available'`
and the scan, `TrustScanContext` and redemption are created in the same transaction.
A second concurrent attempt affects zero rows and receives `CREDIT_NOT_AVAILABLE`
(verified by a two-thread race test on SQL Server).

The credit is **consumed when the worker actually starts** (the engine calls
`consume_credit_for_scan` after transitioning to `Running`). If the worker cannot be
started, or the reservation times out before a worker starts, the credit is released
back to `Available`.

Cancellation is best-effort: `POST .../scans/{scan_id}/cancel` sets `Cancelled`, and
the engine stops between pages.

---

## 7a. Temporary scan credentials (authenticated scans)

Protected pages cannot be assessed anonymously.  A project may therefore register a
**dedicated test account** as a temporary credential:

1. A `SCAN_OPERATOR` or `PROJECT_OWNER` creates the credential (`credential.create`)
   for one verified asset: login URL (exact host/scheme), username, encrypted password,
   optional field names, extra form fields, and an explicit success indicator
   (`success_url_contains` or `success_text`).
2. A **different** `PROJECT_OWNER` approves it (`credential.approve`) after acknowledging
   the approval statement.  Self-approval is disabled in production.
3. Starting a scan with `credential_id` reserves the credential atomically and binds it
   to that scan in `TrustScanCredentialBinding` (unique per credential).  The scan gate
   still requires permission, verified asset, active attestation, credit and no active
   scan.
4. The worker performs one FORM login on the scan's hardened HTTP session (CSRF hidden
   fields are preserved; the form must post to the same host), then crawls and tests
   with that session.  A lost session triggers at most one re-login.  Sign-out and
   login URLs are excluded from crawling.
5. The credential is **single-use** for new scans.  It remains decryptable for retests
   of its bound scan until it expires; revoking or expiring it destroys the secret.

Security controls:

- secret encrypted with Fernet/AES (`TRUST_CREDENTIAL_KEY`, rotatable with
  `TRUST_CREDENTIAL_KEY_OLD`); plaintext exists only in worker memory;
- expiry is mandatory (default 4 h, maximum 24 h);
- the API never returns the secret; audit metadata, evidence and reports contain only
  the credential ID/name/approver, never the password or session cookie;
- login failure fails the scan **before** credit consumption and releases the reserved
  credit; the single-use credential is consumed and its secret purged;
- login URL must match the verified asset exactly and passes the same private-address
  SSRF guard; the form action must stay on the same origin;
- revocation is audited and stops a running authenticated scan at the next page
  boundary.

Not supported: MFA, CAPTCHA, SSO/OAuth form automation, cookie/header credential types
(v1 supports `FORM` only), and multi-account differential testing.

## 8. Audit

`TrustAuditEvent` is insert-only. There is no update or delete route; a test asserts
that `PUT`/`DELETE` cannot match an endpoint and that the row is unchanged.

Recorded events include: organisation/project creation, member invite/accept/revoke,
asset registration/verification/failure/revocation, attestation create/revoke,
payment checkout/verified/failed/duplicate, credit issued/reserved/consumed/released/
expired, scan denied/started/cancelled, and credential created/approved/rejected/
revoked/tested/used/released/login-failed/secret-purged.

An invitation attempted from an account that does not own the invited email address is
recorded as `ORG_MEMBER_INVITE_DENIED` / `PROJECT_MEMBER_INVITE_DENIED` with
`Outcome = Denied` and `ReasonCode = INVITATION_EMAIL_MISMATCH`.

Metadata is filtered: keys containing `token`, `secret`, `password`, `authorization`,
`cookie`, `signature`, `card`, `cvv`, `pan` or `credential` are replaced with
`[redacted]`, and values are truncated. Events also carry a `PrevEventHash`/`EventHash`
chain for tamper evidence.

---

## 9. Trust modes

| Mode | Behaviour |
| --- | --- |
| `enforce` (default, forced in production) | Project-scoped gated scanning only. Legacy `POST /api/scans` returns `410 LEGACY_SCAN_ENDPOINT_DISABLED`. |
| `legacy` | Historical endpoint remains available for local compatibility and the pre-existing regression suite. Never a production default. |

`ProductionConfig.TRUST_BOUNDARY_MODE = "enforce"` overrides any environment value.

If trust services or tables are unavailable the request fails closed rather than
falling back to the legacy path.

---

## 10. Known limitations (current slice)

- Invitations require the invitee to already have a VulnScan account; the one-time
  link is shown to the inviter (no email delivery).
- No sub-domain or wildcard assets; each hostname is verified separately.
- Assets have no port field: non-default ports must be supplied explicitly as the
  scan `target_url` (host must still match), and `TRUST_WEBFILE_PORT` tells the
  verifier which port to fetch `/.well-known/vulnscan.txt` from (0 = URL default).
- The mock checksum secret is a configuration value, not a real gateway secret.
- Credit consumption happens at worker start, so a scan that crashes immediately after
  starting still consumes its credit (refunds are future work).
- Cancellation is best-effort between pages; a long single module call still completes.
- Platform administrators have no break-glass access to customer evidence.
- Trust sessions are still JWT-in-`localStorage`; HttpOnly cookies + CSRF + CSP remain
  future hardening work.
- Scans still run in-process threads; durable workers and egress control remain future
  work.
- Authenticated scanning supports FORM login only. MFA, CAPTCHA, SSO/OAuth, cookie or
  header credentials, and JavaScript-rendered pages are not supported. The test
  account's own permissions still bound what can be discovered.
- A temporary credential is single-use for new scans and remains usable only for
  retests of its bound scan until it expires. A failed login consumes it; create and
  approve a new one after fixing the configuration.
- Credential plaintext exists in worker memory during the login handshake (Python
  cannot guarantee memory zeroisation); only one re-login is attempted if the session
  is lost mid-scan.
