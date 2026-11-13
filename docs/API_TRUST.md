# VulnScan — Trust Boundary API (`/api/v1`)

All endpoints require `Authorization: Bearer <jwt>` unless stated otherwise.
Cross-tenant resources return `404` so their existence is not disclosed.
Errors use a consistent envelope:

```json
{
  "message": "The asset must be verified before an active scan can start.",
  "code": "ASSET_NOT_VERIFIED",
  "details": {"asset_id": 12, "status": "PendingVerification"}
}
```

Existing `/api/*` endpoints (auth, users, vulnerabilities, scan profiles, scans,
audit logs, health) are unchanged.

---

## 1. Organisation and project endpoints

| Method | Path | Permission |
| --- | --- | --- |
| GET | `/api/v1/organisations` | authenticated |
| POST | `/api/v1/organisations` | authenticated |
| GET | `/api/v1/organisations/{org_id}` | `org.read` (membership) |
| GET | `/api/v1/organisations/{org_id}/members` | org membership |
| POST | `/api/v1/organisations/{org_id}/members` | org owner |
| DELETE | `/api/v1/organisations/{org_id}/members/{membership_id}` | org owner |
| GET | `/api/v1/projects` | authenticated (own projects) |
| POST | `/api/v1/projects` | org membership |
| GET | `/api/v1/projects/{project_id}` | `project.read` |
| GET | `/api/v1/projects/{project_id}/members` | `project.read` |
| POST | `/api/v1/projects/{project_id}/members` | `project.members.manage` |
| PATCH | `/api/v1/projects/{project_id}/members/{membership_id}` | `project.members.manage` |
| DELETE | `/api/v1/projects/{project_id}/members/{membership_id}` | `project.members.manage` |
| GET | `/api/v1/projects/{project_id}/permissions` | `project.read` |
| POST | `/api/v1/invitations/preview` | authenticated invited user |
| POST | `/api/v1/invitations/accept` | authenticated invited user |

**Create organisation**

```http
POST /api/v1/organisations
{"name": "Acme Sdn Bhd", "slug": "acme"}

201 {"Organisation": {...}, "Membership": {...}}
```

**Invite member (organisation or project)**

```http
POST /api/v1/projects/1/members
{"email": "analyst@example.com", "role": "ANALYST"}

201 {"Membership": {...},
     "InviteToken": "<one-time token>",
     "InviteURL": "http://127.0.0.1:5000/#/invitations/accept?token=<token>",
     "InviteEmail": "analyst@example.com",
     "InviteExpiresAt": "2026-11-16T09:00:00"}
```

`InviteURL` is an absolute, directly clickable link the inviter shares with the
invitee. The token is carried in the URL **fragment**, so it never reaches the
server in a request line or an access log and is never sent as a `Referer`.

Binding and lifetime rules:

* the invitee must already have a VulnScan account (no self-registration);
* the invitation is bound to the invitee's **email address** (`InviteEmail`); only
  a session authenticated as that account can preview or accept it;
* the raw token is returned once and stored only as a SHA-256 hash;
* single use — accepting moves the membership to `Active` and the link then fails
  with `INVITATION_ALREADY_USED`;
* expiry defaults to 72 hours (`TRUST_INVITATION_TTL_HOURS`);
* re-inviting an `Invited`/`Revoked` member rotates the token and invalidates the
  previous link; re-inviting an `Active` member is rejected with `ALREADY_MEMBER`
  (no silent demotion);
* `TRUST_INVITE_BASE_URL` overrides the base URL of `InviteURL` when the external
  deployment URL differs from the request host.

**Preview invitation** (authenticated as the invited account)

```http
POST /api/v1/invitations/preview
{"token": "<one-time token>"}

200 {"Invitation": {
       "Kind": "Project",                 // or "Organisation"
       "Role": "ANALYST",
       "Email": "analyst@example.com",
       "ExpiresAt": "2026-11-16T09:00:00",
       "Organisation": {...}, "Project": {...}, "Membership": {...}}}
```

**Accept invitation**

```http
POST /api/v1/invitations/accept
{"token": "<one-time token>"}

200 {"Membership": {... "Status": "Active"},
     "Invitation": {...}}
```

**Invitation errors** (all enforced server-side)

| Status | Code | Meaning |
| --- | --- | --- |
| 400 | `VALIDATION_ERROR` | token missing |
| 401 | `token_missing` / `token_invalid` | not signed in |
| 403 | `INVITATION_EMAIL_MISMATCH` | signed-in account does not own the invited email |
| 404 | `NOT_FOUND` | unknown, revoked or superseded token |
| 409 | `INVITATION_EXPIRED` | expired (or no longer pending) invitation |
| 409 | `INVITATION_ALREADY_USED` | invitation was already accepted |
| 409 | `ALREADY_MEMBER` | invitee is already an active member |

Every email-mismatch attempt is recorded as a `Denied` audit event
(`ORG_MEMBER_INVITE_DENIED` / `PROJECT_MEMBER_INVITE_DENIED`) without the token.

**Permissions**

```http
GET /api/v1/projects/1/permissions
200 {"ProjectID": 1, "OrgRole": "ORG_OWNER", "ProjectRole": "SCAN_OPERATOR",
     "Permissions": ["scan.read", "scan.start", ...], "CanStartScan": true}
```

Roles: `ORG_OWNER`, `PROJECT_OWNER`, `SCAN_OPERATOR`, `ANALYST`, `VIEWER`.

---

## 2. Assets and verification

| Method | Path | Permission |
| --- | --- | --- |
| GET | `/api/v1/projects/{project_id}/assets` | `asset.read` |
| POST | `/api/v1/projects/{project_id}/assets` | `asset.register` |
| GET | `/api/v1/projects/{project_id}/assets/{asset_id}` | `asset.read` |
| POST | `/api/v1/projects/{project_id}/assets/{asset_id}/verification` | `asset.verify` |
| POST | `/api/v1/projects/{project_id}/assets/{asset_id}/verification/check` | `asset.verify` |
| POST | `/api/v1/projects/{project_id}/assets/{asset_id}/revoke` | `asset.revoke` |

**Register asset**

```http
POST /api/v1/projects/1/assets
{"hostname": "shop.example.com", "scheme": "https"}

201 {"Asset": {"AssetID": 10, "Hostname": "shop.example.com",
               "VerificationStatus": "Unverified", ...}}
```

Rejected: IP literals, wildcards, schemes/ports/paths, duplicates
(`HOSTNAME_INVALID`, `DUPLICATE_ASSET`).

**Start verification**

```http
POST /api/v1/projects/1/assets/10/verification
{"method": "DNS_TXT"}

200 {"Asset": {... "VerificationStatus": "PendingVerification"},
     "Challenge": {"Method": "DNS_TXT",
                   "RecordName": "_vulnscan-challenge.shop.example.com",
                   "RecordType": "TXT",
                   "RecordValue": "vulnscan-verify=<token>",
                   "ExpiresAt": "..."}}
```

`WEB_FILE` returns `FileURL` and `FileContent` instead.

**Check verification**

```http
POST /api/v1/projects/1/assets/10/verification/check

200 {"Asset": {"VerificationStatus": "Verified",
               "VerifiedAt": "...", "VerificationExpiresAt": "..."},
     "Verification": {"Method": "DNS_TXT", "Evidence": "TXT record matched at …",
                      "CheckedAt": "..."}}
```

**Revoke asset**

```http
POST /api/v1/projects/1/assets/10/revoke
{"reason": "ownership changed"}
```

---

## 3. Attestations

| Method | Path | Permission |
| --- | --- | --- |
| GET | `/api/v1/projects/{project_id}/assets/{asset_id}/attestations` | `attestation.read` |
| POST | `/api/v1/projects/{project_id}/assets/{asset_id}/attestations` | `attestation.create` |
| POST | `/api/v1/projects/{project_id}/assets/{asset_id}/attestations/{attestation_id}/revoke` | `attestation.revoke` |

```http
POST /api/v1/projects/1/assets/10/attestations
{"expires_in_days": 30, "reference": "CHG-1234", "statement_version": "v1"}

201 {"Attestation": {"AttestationID": 5, "Status": "Active",
                     "StatementVersion": "v1", "StatementHash": "<sha256>",
                     "AttestedAt": "...", "ExpiresAt": "..."}}
```

Creating a new attestation automatically expires the previous active one.
`expires_in_days` must be 1–90.

---

## 3a. Temporary scan credentials

| Method | Path | Permission |
| --- | --- | --- |
| GET | `/api/v1/projects/{project_id}/credentials?asset_id=` | `credential.read` |
| GET | `/api/v1/projects/{project_id}/assets/{asset_id}/credentials` | `credential.read` |
| POST | `/api/v1/projects/{project_id}/assets/{asset_id}/credentials` | `credential.create` |
| GET | `/api/v1/projects/{project_id}/credentials/{credential_id}` | `credential.read` |
| POST | `/api/v1/projects/{project_id}/credentials/{credential_id}/approve` | `credential.approve` |
| POST | `/api/v1/projects/{project_id}/credentials/{credential_id}/reject` | `credential.approve` |
| POST | `/api/v1/projects/{project_id}/credentials/{credential_id}/revoke` | `credential.revoke` |
| POST | `/api/v1/projects/{project_id}/credentials/{credential_id}/test-login` | `credential.create` |

```http
POST /api/v1/projects/1/assets/10/credentials
{
  "name": "Pentest test account",
  "auth_type": "FORM",
  "login_url": "https://shop.example.com/login",
  "username": "vulnscan.tester@example.com",
  "password": "<test-account password>",
  "success_url_contains": "/dashboard",
  "expires_in_minutes": 240
}

201 {"Credential": {"CredentialID": 3, "Status": "PendingApproval",
                    "HasSecret": true, "ExpiresAt": "...", ...}}
```

The password is **never** returned. Only the creator or another member with
`credential.create` may run `POST .../test-login`; it performs the login handshake
without starting a scan or consuming a credit (cooldown:
`TRUST_CREDENTIAL_TEST_COOLDOWN_SECONDS`).

```http
POST /api/v1/projects/1/credentials/3/approve
{"acknowledge": true}
```

Approval requires a **different** `PROJECT_OWNER` (unless
`TRUST_CREDENTIAL_ALLOW_SELF_APPROVAL=true` for local demos), a verified asset and an
active attestation.  `POST .../reject` and `POST .../revoke` destroy the stored secret
immediately.  Expired credentials are marked `Expired` and purged opportunistically.

Start a scan with the credential:

```http
POST /api/v1/projects/1/scans
{"asset_id": 10, "scan_profile_id": 2, "credit_id": "<uuid>",
 "credential_id": 3, "target_url": "https://shop.example.com/dashboard"}

409 {"code": "CREDENTIAL_NOT_APPROVED" | "CREDENTIAL_EXPIRED" |
              "CREDENTIAL_ALREADY_USED" | "CREDENTIAL_LOGIN_FAILED"}
```

A credential is single-use for new scans.  If the login handshake fails, the scan fails
with `CREDENTIAL_LOGIN_FAILED`, the reserved credit is released and the credential is
consumed (its secret purged).  Readiness (`GET .../scan-readiness?asset_id=&credential_id=`)
adds a `Credential` check and `NextAction: APPROVE_CREDENTIAL` when needed.

---

## 4. Products, payments and credits

| Method | Path | Permission |
| --- | --- | --- |
| GET | `/api/v1/products` | authenticated |
| POST | `/api/v1/projects/{project_id}/payments/checkout` | `credit.purchase` |
| GET | `/api/v1/projects/{project_id}/payments/{payment_uuid}` | `credit.read` |
| POST | `/api/v1/projects/{project_id}/payments/{payment_uuid}/mock-complete` | `credit.purchase` |
| POST | `/api/v1/payments/webhooks/{provider}` | provider signature |
| GET | `/api/v1/projects/{project_id}/credits` | `credit.read` |
| GET | `/api/v1/projects/{project_id}/credit-redemptions` | `credit.read` |
| GET | `/api/v1/mock-checkout/{payment_uuid}` | none (labelled mock page) |

**Products**

```json
{"Products": [
  {"ProductCode": "SCAN_CREDIT_1", "Name": "Single scan credit",
   "Credits": 1, "AmountMinor": 1000, "Currency": "MYR"},
  {"ProductCode": "SCAN_CREDIT_5", "Name": "Five scan credits",
   "Credits": 5, "AmountMinor": 4500, "Currency": "MYR"}],
 "Provider": "MOCK", "Mock": true,
 "Notice": "Mock provider - no real money is processed."}
```

**Checkout**

```http
POST /api/v1/projects/1/payments/checkout
{"product_code": "SCAN_CREDIT_1", "quantity": 1,
 "idempotency_key": "optional-uuid"}

201 {"Payment": {"PaymentUUID": "...", "Status": "PendingPayment",
                 "AmountMinor": 1000, "Currency": "MYR"},
     "CheckoutURL": "/api/v1/mock-checkout/...",
     "Mock": true, "IdempotentReplay": false}
```

Amounts always come from the server catalogue.

**Mock completion (server-side only)**

```http
POST /api/v1/projects/1/payments/{uuid}/mock-complete
{"outcome": "success"}

200 {"Payment": {... "Status": "PaymentVerified"},
     "CreditsIssued": 1, "Duplicate": false}
```

A browser redirect alone never calls this path; it requires an authenticated caller
and the server builds the signed payload.

**Provider webhook**

```http
POST /api/v1/payments/webhooks/MOCK
X-VulnScan-Signature: <hmac-sha256>

200 {"received": true, "CreditsIssued": 1, "Duplicate": false}
```

Signature = HMAC-SHA256 over
`payment_uuid|provider_transaction_id|amount_minor|currency|product_code|quantity|status`
using `TRUST_MOCK_PAYMENT_SECRET`. Duplicate deliveries return `Duplicate: true` and
issue no extra credits.

**Credits**

```json
{"Credits": [
   {"CreditUUID": "...", "Status": "Available",
    "IssuedAt": "...", "ExpiresAt": "...",
    "PurchasePriceMinor": 1000, "Currency": "MYR"}],
 "AvailableCount": 1, "Total": 1}
```

---

## 5. Gated scans

| Method | Path | Permission |
| --- | --- | --- |
| GET | `/api/v1/projects/{project_id}/scan-readiness?asset_id=` | `scan.read` |
| GET | `/api/v1/projects/{project_id}/scans` | `scan.read` |
| POST | `/api/v1/projects/{project_id}/scans` | `scan.start` |
| POST | `/api/v1/projects/{project_id}/scans/{scan_id}/cancel` | `scan.cancel` |
| GET | `/api/v1/projects/{project_id}/audit-events` | `trust_audit.view` |

**Readiness**

```json
{"Readiness": {
  "Ready": false,
  "Checks": {
    "Permission": {"Ok": true, "Code": null},
    "Asset": {"Ok": true, "Status": "Verified", "ExpiresAt": "..."},
    "Attestation": {"Ok": false, "AttestationID": null, "ExpiresAt": null},
    "Credit": {"Ok": true, "AvailableCount": 1},
    "ActiveScan": {"Ok": true, "ScanID": null}},
  "NextAction": "CREATE_ATTESTATION",
  "Asset": {...}}}
```

**Start scan**

```http
POST /api/v1/projects/1/scans
{"asset_id": 10, "scan_profile_id": 2,
 "scan_name": "Storefront weekly",
 "credit_id": "<CreditUUID>",
 "attestation_id": 5,            // optional; defaults to the active one
 "target_url": "https://shop.example.com/",   // optional; defaults to asset root
 "idempotency_key": "optional-uuid"}

202 {"Scan": {"ScanID": 42, "Status": "Pending", "TargetURL": "..."},
     "Credit": {"CreditUUID": "...", "Status": "Reserved"},
     "Redemption": {"RedemptionID": 7, "Status": "Reserved"},
     "IdempotentReplay": false}
```

Repeating the same `idempotency_key` returns the original scan with
`IdempotentReplay: true`.

**Cancel**

```http
POST /api/v1/projects/1/scans/42/cancel
200 {"Scan": {"ScanID": 42, "Status": "Cancelled", ...}}
```

**Audit events**

```http
GET /api/v1/projects/1/audit-events?per_page=100&outcome=Denied&event_type=SCAN_DENIED

200 {"Events": [{"EventType": "SCAN_DENIED", "Outcome": "Denied",
                 "ReasonCode": "CREDIT_REQUIRED", "ActorUserID": 2, ...}],
     "Total": 1}
```

---

## 6. Scan read/report/retest endpoints (existing paths, stronger isolation)

Trust-scoped scans are protected by project membership on the existing endpoints:

| Endpoint | Permission for trust-scoped scans |
| --- | --- |
| `GET /api/scans/{id}` | `scan.read` |
| `GET /api/scans/{id}/progress` | `scan.read` |
| `GET /api/scans/{id}/report?format=pdf\|csv` | `scan.read` |
| `PUT /api/scans/{id}/findings/{fid}` | `scan.retest` |
| `POST /api/scans/{id}/findings/{fid}/retest` | `scan.retest` |

Legacy (non-trust) scans keep the historical owner/administrator rule.

---

## 7. Error codes

| HTTP | Code | Meaning |
| --- | --- | --- |
| 400 | `VALIDATION_ERROR` | Malformed request/field |
| 400 | `HOSTNAME_INVALID` | Invalid hostname (IP, wildcard, scheme, port) |
| 400 | `TARGET_HOST_MISMATCH` | Scan target host ≠ verified asset |
| 400 | `USER_NOT_FOUND` | Invitee has no VulnScan account |
| 401 | `token_*` | Missing/invalid/expired/revoked JWT |
| 403 | `PERMISSION_DENIED` | Role lacks the permission |
| 403 | `INVITATION_EMAIL_MISMATCH` | Signed-in account does not own the invited email |
| 403 | `ASSET_NOT_VERIFIED` | Asset not verified |
| 403 | `ASSET_VERIFICATION_EXPIRED` | Verification lapsed |
| 403 | `ASSET_REVOKED` | Asset revoked |
| 403 | `ATTESTATION_REQUIRED` | No active attestation |
| 403 | `ATTESTATION_EXPIRED` | Attestation lapsed |
| 403 | `ATTESTATION_REVOKED` | Attestation revoked |
| 403 | `ATTESTATION_ASSET_MISMATCH` | Attestation belongs to another asset |
| 404 | `NOT_FOUND` | Missing or not visible (cross-tenant) |
| 402 | `CREDIT_REQUIRED` | No credit supplied |
| 409 | `CREDIT_NOT_AVAILABLE` | Credit reserved/consumed/expired |
| 409 | `ACTIVE_SCAN_EXISTS` | Another active scan for the asset |
| 409 | `IDEMPOTENCY_CONFLICT` | Same key, different payload/project |
| 409 | `DUPLICATE_ASSET` | Hostname already registered |
| 409 | `SLUG_CONFLICT` | Organisation/project slug exists |
| 409 | `INVITATION_EXPIRED` | Invitation expired or revoked |
| 409 | `INVITATION_ALREADY_USED` | Invitation was already accepted |
| 409 | `ALREADY_MEMBER` | Invitee is already an active member |
| 409 | `VERIFICATION_MISMATCH` | Published challenge did not match |
| 409 | `VERIFICATION_TOKEN_EXPIRED` | Challenge expired |
| 409 | `PAYMENT_AMOUNT_MISMATCH` | Callback amount/currency/product mismatch |
| 400 | `PAYMENT_NOT_VERIFIED` | Bad signature / unusable payment |
| 403 | `CREDENTIAL_SELF_APPROVAL_DENIED` | Creator tried to approve their own credential |
| 409 | `CREDENTIAL_NOT_APPROVED` | Credential is not approved (or already closed) |
| 409 | `CREDENTIAL_EXPIRED` | Credential expired; its secret was purged |
| 409 | `CREDENTIAL_ALREADY_USED` | Credential already bound to a scan |
| 409 | `CREDENTIAL_LOGIN_FAILED` | Login handshake failed (no secret in the response) |
| 429 | `RATE_LIMITED` | Login test cooldown still active |
| 503 | `CREDENTIAL_STORAGE_UNAVAILABLE` | Encryption key missing/invalid or ciphertext unusable |
| 410 | `LEGACY_SCAN_ENDPOINT_DISABLED` | `POST /api/scans` used in enforce mode |
| 503 | `CREDIT_NOT_AVAILABLE` | Worker could not start (credit released) |
