<#
.SYNOPSIS
    Apply the Trust Boundary migration to Azure SQL, with a pre-migration copy.

.DESCRIPTION
    Runs the additive Trust Boundary migrations through head (currently
    c4d8f1a2b6e9) against the database used by the VulnScan App Service.

    Steps:
      1. Verify Azure CLI login
      2. Create a pre-migration copy of the database (rollback point)
      3. Read DATABASE_URL from the App Service application settings
      4. Run `flask db upgrade` and print the resulting revision
      5. Ensure the mock-payment secret and TRUST_CREDENTIAL_KEY are set,
         then restart the web app
      6. Verify /api/health and /api/v1

    The migrations are additive: they create the Trust* tables (including the
    temporary-credential tables). The eight frozen core tables are not touched.

.PARAMETER DryRun
    Show what would happen without changing anything.

.EXAMPLE
    az login
    .\scripts\azure_trust_migration.ps1

.EXAMPLE
    .\scripts\azure_trust_migration.ps1 -DryRun
#>
[CmdletBinding()]
param(
    [string]$ResourceGroup = "vulnscan",
    [string]$WebAppName = "vulnscan",
    [string]$SqlServer = "vulnscan",
    [string]$Database = "vulnscandb",
    [string]$AppBaseUrl = "https://vulnscan-erehf4djeqg8dvbe.malaysiawest-01.azurewebsites.net",
    [switch]$SkipSecret,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$backend = Join-Path $repoRoot "backend"
$python = Join-Path $repoRoot ".venv\Scripts\python.exe"

function Step($n, $text) { Write-Host ""; Write-Host "[$n/6] $text" -ForegroundColor Cyan }

if (-not (Test-Path $python)) { Write-Host "ERROR: Python venv not found at $python" -ForegroundColor Red; exit 1 }
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    # Fall back to the repository's local Azure CLI virtual environment.
    $localAz = Join-Path (Split-Path -Parent $repoRoot) "azurecli-venv\Scripts"
    if (Test-Path (Join-Path $localAz "az.bat")) {
        $env:PATH = "$localAz;$env:PATH"
    }
}
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Azure CLI (az) is not installed. Install it, run 'az login', then re-run." -ForegroundColor Red
    exit 1
}

$accountJson = az account show -o json 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Not signed in. Run 'az login' first." -ForegroundColor Red
    exit 1
}
$account = $accountJson | ConvertFrom-Json
Write-Host "Subscription : $($account.name) ($($account.id))"
Write-Host "Web App      : $WebAppName ($ResourceGroup)"
Write-Host "SQL database : $SqlServer/$Database"
if ($DryRun) { Write-Host "MODE         : DRY RUN (no changes)" -ForegroundColor Yellow }

# ---------------------------------------------------------------- 1. backup
Step 1 "Create a pre-migration copy of the database"
$stamp = Get-Date -Format "yyyyMMddHHmmss"
$backupName = "$Database-backup-$stamp"
Write-Host "Copy target: $backupName (same server)"
if ($DryRun) {
    Write-Host "  [dry-run] az sql db copy --name $Database --dest-name $backupName"
} else {
    az sql db copy --resource-group $ResourceGroup --server $SqlServer --name $Database --dest-name $backupName --dest-server $SqlServer -o none
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: database copy failed; nothing was migrated." -ForegroundColor Red
        exit 1
    }
    Write-Host "Waiting for the copy to become Online..."
    $online = $false
    for ($i = 0; $i -lt 60; $i++) {
        $status = az sql db show --resource-group $ResourceGroup --server $SqlServer --name $backupName --query "status" -o tsv 2>$null
        if ($status -eq "Online") { $online = $true; break }
        Start-Sleep -Seconds 5
    }
    if (-not $online) {
        Write-Host "ERROR: backup copy did not reach Online state; check the portal." -ForegroundColor Red
        exit 1
    }
    Write-Host "Backup ready: $backupName" -ForegroundColor Green
}

# ---------------------------------------------------------------- 2. conn string
Step 2 "Read DATABASE_URL from the App Service application settings"
$conn = az webapp config appsettings list --name $WebAppName --resource-group $ResourceGroup --query "[?name=='DATABASE_URL'].value | [0]" -o tsv
if (-not $conn) {
    Write-Host "ERROR: DATABASE_URL app setting not found on $WebAppName." -ForegroundColor Red
    exit 1
}
Write-Host "Connection string retrieved ($($conn.Length) characters, not printed)."

# ---------------------------------------------------------------- 3 & 4
Step 3 "Current schema revision"
$env:DATABASE_URL = $conn
Push-Location $backend
try {
    & $python -m flask --app run.py db current
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: cannot connect. Add this machine's IP to the SQL server firewall, then retry." -ForegroundColor Red
        Pop-Location
        exit 1
    }

    Step 4 "Apply the additive Trust Boundary migrations"
    if ($DryRun) {
        Write-Host "  [dry-run] flask db upgrade  (expect ... -> c4d8f1a2b6e9)"
    } else {
        & $python -m flask --app run.py db upgrade
        if ($LASTEXITCODE -ne 0) {
            Write-Host "ERROR: migration failed. The database copy '$backupName' is the rollback point." -ForegroundColor Red
            Pop-Location
            exit 1
        }
        & $python -m flask --app run.py db current
    }
} finally {
    Pop-Location
}

# ---------------------------------------------------------------- 5. secrets
Step 5 "Ensure runtime secrets are set"
if ($SkipSecret) {
    Write-Host "  skipped (-SkipSecret)"
} elseif ($DryRun) {
    Write-Host "  [dry-run] ensure TRUST_MOCK_PAYMENT_SECRET and TRUST_CREDENTIAL_KEY exist"
} else {
    $settings = az webapp config appsettings list --name $WebAppName --resource-group $ResourceGroup -o json | ConvertFrom-Json
    $names = @($settings | ForEach-Object { $_.name })
    $toSet = @()

    if ($names -notcontains "TRUST_MOCK_PAYMENT_SECRET") {
        $bytes = New-Object byte[] 32
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($bytes)
        $secret = ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""
        $toSet += "TRUST_MOCK_PAYMENT_SECRET=$secret"
        Write-Host "  TRUST_MOCK_PAYMENT_SECRET: generating"
    } else {
        Write-Host "  TRUST_MOCK_PAYMENT_SECRET: already set"
    }

    if ($names -notcontains "TRUST_CREDENTIAL_KEY") {
        $credKey = & $python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
        if ($LASTEXITCODE -ne 0 -or -not $credKey) {
            Write-Host "ERROR: could not generate TRUST_CREDENTIAL_KEY." -ForegroundColor Red
            exit 1
        }
        $toSet += "TRUST_CREDENTIAL_KEY=$credKey"
        Write-Host "  TRUST_CREDENTIAL_KEY: generating"
    } else {
        Write-Host "  TRUST_CREDENTIAL_KEY: already set"
    }

    if ($toSet.Count -gt 0) {
        az webapp config appsettings set --name $WebAppName --resource-group $ResourceGroup --settings @toSet -o none
        if ($LASTEXITCODE -ne 0) {
            Write-Host "ERROR: could not update the app settings." -ForegroundColor Red
            exit 1
        }
        az webapp restart --name $WebAppName --resource-group $ResourceGroup -o none
        Write-Host "Settings set; app restarting."
    } else {
        Write-Host "  No secret changes required."
    }
}

# ---------------------------------------------------------------- 6. verify
Step 6 "Verify the live application"
if ($DryRun) {
    Write-Host "  [dry-run] GET $AppBaseUrl/api/health"
    Write-Host "  [dry-run] GET $AppBaseUrl/api/v1/products  (expect 401, not 503)"
    exit 0
}
Start-Sleep -Seconds 20
$health = curl.exe -s -o NUL -w "%{http_code}" "$AppBaseUrl/api/health"
$v1 = curl.exe -s -o NUL -w "%{http_code}" "$AppBaseUrl/api/v1/organisations"
Write-Host "  /api/health          -> $health   (expect 200)"
Write-Host "  /api/v1/organisations -> $v1   (expect 401 = schema present, auth required)"

if ($health -eq "200" -and $v1 -eq "401") {
    Write-Host ""
    Write-Host "SUCCESS: the Trust Boundary schema is live in Azure." -ForegroundColor Green
    Write-Host "Rollback if needed: restore database '$backupName' (or run 'flask db downgrade')."
} else {
    Write-Host ""
    Write-Host "Schema applied but verification is not clean; check the App Service logs." -ForegroundColor Yellow
    Write-Host "Rollback point: database copy '$backupName'."
    exit 1
}
