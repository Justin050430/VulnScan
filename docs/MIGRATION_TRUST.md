# VulnScan — Trust Boundary migration runbook

Migration: `aaf9e35de1fe_trust_boundary_extension.py`
Depends on: `8d677211ad51_initial_schema_8_entities.py`

## 1. What the migration does

Creates eleven **additive** tables:

1. `TrustOrganisation`
2. `TrustProject`
3. `TrustOrganisationMembership`
4. `TrustProjectMembership`
5. `TrustAsset`
6. `TrustAuthorizationAttestation`
7. `TrustPaymentTransaction`
8. `TrustScanCredit`
9. `TrustCreditRedemption`
10. `TrustScanContext`
11. `TrustAuditEvent`

It does **not** alter, rename or drop any column of the frozen eight core entities.
`testing/test_trust_migration.py` asserts the exact core column sets and the new
tables' presence.

Notable constraints:

- Composite tenant FKs: `(OrganisationID, ProjectID)` → `TrustProject`, and
  `(ProjectID, AssetID)` → `TrustAsset`.
- `ux_trust_attestation_active_asset` — filtered unique index: at most one `Active`
  attestation per asset.
- `ux_trust_redemption_active_credit` — filtered unique index: at most one
  `Reserved`/`Consumed` redemption per credit.
- `uq_trust_credit_payment_sequence` — one credit row per payment per sequence number.
- `TrustScanContext.ScanID` is the PK and an FK to `Scan.ScanID`
  (`ON DELETE CASCADE`); the bridge adds no column to `Scan`.
- `TrustAuditEvent` has no FKs by design (history survives entity deletion).

## 2. Verified locally

```powershell
# SQLite scratch database
$env:DATABASE_URL = "sqlite:///$env:TEMP/trust_mig.db"
cd backend
python -m flask --app run.py db upgrade
python -m flask --app run.py db downgrade
python -m flask --app run.py db upgrade
```

Both the upgrade and the downgrade complete; the SQL Server integration suite
(`testing/test_sqlserver_integration.py`) runs the full `create_all` schema against
LocalDB, including the new tables and constraints.

## 3. Production procedure (proposal — not executed)

> No Azure or production database was touched. The following must be approved and
> executed by the operator with a database reviewer.

### 3a. Automated runbook (requires Azure CLI + `az login`)

`scripts/azure_trust_migration.ps1` performs the whole procedure and stops at the
first failure:

```powershell
az login
.\scripts\azure_trust_migration.ps1 -DryRun     # show the plan, change nothing
.\scripts\azure_trust_migration.ps1             # backup -> migrate -> secret -> verify
```

It resolves the database from the `DATABASE_URL` App Service setting (the string is
never printed), creates a `VulnScan-backup-<timestamp>` database copy as the rollback
point, applies the migration, sets a random `TRUST_MOCK_PAYMENT_SECRET`, restarts the
app and then expects `/api/health` → `200` and `/api/v1/products` → `401`
(`401` proves the trust tables now exist; an un-migrated app answers `503`).

Useful switches: `-SkipSecret`, `-ResourceGroup`, `-WebAppName`, `-SqlServer`,
`-Database`, `-AppBaseUrl`.

### 3b. Manual procedure

1. **Backup** — take an Azure SQL restore point / full backup and record the LSN.
2. **Review** — DBA reviews the DDL (filtered indexes, composite FKs, collation).
3. **Staging restore** — restore the production backup into a staging database.
4. **Apply to staging** — run `flask db upgrade` against staging.
5. **Verify** — run `python -m pytest testing -q` plus a staging smoke check
   (`/api/health`, login, project creation, mock payment, gated scan against a
   controlled target).
6. **Deploy application code** with `TRUST_BOUNDARY_MODE=legacy` if a staged rollout is
   required — the new tables exist but are unused. No core column changes, so the old
   code keeps working.
7. **Enable enforcement** by setting `TRUST_BOUNDARY_MODE=enforce` during a maintenance
   window (production defaults to `enforce` in code regardless of the env value).
8. **Observe** — check audit events, error rate, and that legacy scans are rejected
   with `LEGACY_SCAN_ENDPOINT_DISABLED`.

## 4. Rollback

1. Set `TRUST_BOUNDARY_MODE=legacy` and redeploy **application code only**. This
   restores legacy behaviour without touching data.
2. If the schema must be removed:
   - only after a fresh backup and explicit approval;
   - `flask db downgrade` drops only the eleven extension tables;
   - core data is untouched.

Data loss on downgrade is limited to Trust Boundary records (organisations, projects,
memberships, assets, attestations, payments, credits, audit events).

## 5. Expand / contract compatibility

- The migration is purely additive (expand).
- No core column becomes `NOT NULL`, is renamed, or is dropped.
- Enforcement is a **deployment** decision (`TRUST_BOUNDARY_MODE`), not a schema one.
- A later release may contract unused legacy paths; that is out of scope for this slice.

## 6. Deployment pipeline note

`deploy.yml` currently does **not** run `flask db upgrade`. Until that is added (future
work), production migrations must be applied manually as described above. This is a
known gap recorded in `docs/TRUST_BOUNDARY.md`.

## 7. Post-migration smoke checklist

- [ ] `/api/health` returns `200 {"status":"ok"}`
- [ ] Login works for the seeded administrator
- [ ] `GET /api/v1/products` returns the mock catalogue
- [ ] Create organisation → project → asset succeeds
- [ ] DNS or well-known verification succeeds for an owned host
- [ ] Attestation creation succeeds
- [ ] Mock checkout + completion issues exactly one credit
- [ ] Gated scan starts, consumes the credit, and completes
- [ ] Duplicate mock completion issues no extra credit
- [ ] `POST /api/scans` returns `410 LEGACY_SCAN_ENDPOINT_DISABLED`
- [ ] `GET /api/v1/projects/{id}/audit-events` shows the expected events
