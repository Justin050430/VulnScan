<#
.SYNOPSIS
    Start, stop or inspect the complete VulnScan local test environment.

.DESCRIPTION
    Brings up both processes the local demo needs:

      * the controlled vulnerable target  (testing/vuln_test_app) on port 5001
      * VulnScan itself                   (backend)               on port 5000

    Before starting it checks the virtualenv and that the database schema is at
    the migration head, then reseeds reference data (idempotent).  After
    starting it waits until both HTTP endpoints answer and prints the sign-in
    credentials and the next steps.

.EXAMPLE
    .\scripts\start-local.ps1

.EXAMPLE
    .\scripts\start-local.ps1 -Action stop

.EXAMPLE
    .\scripts\start-local.ps1 -TargetPort 5003   # environment for the SQLi lab
#>
[CmdletBinding()]
param(
    [ValidateSet("start", "stop", "status")]
    [string]$Action = "start",
    [int]$AppPort = 5000,
    [int]$TargetPort = 5001,
    [switch]$SkipSeed
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $Root ".venv\Scripts\python.exe"
$Backend = Join-Path $Root "backend"
$Target = Join-Path $Root "testing\vuln_test_app"
$Logs = Join-Path $Root ".local-logs"
$StateFile = Join-Path $Root ".local-run.json"


function Get-DotEnvValue {
    param([string]$Name, [string]$Default)
    $envFile = Join-Path $Backend ".env"
    if (Test-Path $envFile) {
        foreach ($line in Get-Content $envFile) {
            if ($line -match "^\s*$([regex]::Escape($Name))\s*=\s*(.*)$") {
                $value = $Matches[1].Trim()
                if ($value) { return $value }
            }
        }
    }
    return $Default
}

function Test-PortListening {
    param([int]$Port)
    $existing = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    return [bool]$existing
}

function Invoke-Python {
    param([string[]]$Arguments)
    # Native commands write progress to stderr; capture it without letting
    # $ErrorActionPreference turn it into a terminating error.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    Push-Location $Backend
    try {
        $output = & $Python @Arguments 2>&1 | ForEach-Object { "$_" }
        $code = $LASTEXITCODE
    } finally {
        Pop-Location
        $ErrorActionPreference = $previous
    }
    return [pscustomobject]@{ ExitCode = $code; Output = $output }
}

function Wait-ForUrl {
    param([string]$Url, [int]$TimeoutSeconds = 40)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 3
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 500) {
                return $true
            }
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
    return $false
}

function Get-RunningState {
    if (-not (Test-Path $StateFile)) { return $null }
    try { return Get-Content $StateFile -Raw | ConvertFrom-Json } catch { return $null }
}

function Stop-TrackedProcess {
    param($ProcessId, [string]$Label)
    if (-not $ProcessId) { return }
    $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if ($process) {
        Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
        Write-Host "  stopped $Label (PID $ProcessId)"
    } else {
        Write-Host "  $Label was not running (PID $ProcessId)"
    }
}


if ($Action -eq "stop") {
    $state = Get-RunningState
    if (-not $state) {
        Write-Host "No tracked local environment (nothing to stop)."
        return
    }
    Write-Host "Stopping the VulnScan local environment..."
    Stop-TrackedProcess -ProcessId $state.AppPid -Label "VulnScan backend"
    Stop-TrackedProcess -ProcessId $state.TargetPid -Label "vulnerable target"
    Remove-Item $StateFile -Force -ErrorAction SilentlyContinue
    Write-Host "Done."
    return
}

if ($Action -eq "status") {
    $state = Get-RunningState
    if (-not $state) {
        Write-Host "No tracked local environment."
        return
    }
    $appAlive = [bool](Get-Process -Id $state.AppPid -ErrorAction SilentlyContinue)
    $targetAlive = [bool](Get-Process -Id $state.TargetPid -ErrorAction SilentlyContinue)
    Write-Host "VulnScan backend  PID $($state.AppPid)    running=$appAlive  http://127.0.0.1:$($state.AppPort)/"
    Write-Host "Vulnerable target PID $($state.TargetPid) running=$targetAlive  http://localhost:$($state.TargetPort)/"
    if ($appAlive) {
        try {
            $health = Invoke-WebRequest -Uri "http://127.0.0.1:$($state.AppPort)/api/health" -UseBasicParsing -TimeoutSec 3
            Write-Host "Health: $($health.Content)"
        } catch {
            Write-Host "Health: unreachable ($($_.Exception.Message))"
        }
    }
    return
}


# --------------------------------------------------------------------- start
if (-not (Test-Path $Python)) {
    throw "Virtualenv not found at $Python. Create it with: python -m venv .venv; .\.venv\Scripts\pip install -r requirements.txt"
}

Write-Host "Checking database schema..."
$schema = Invoke-Python -Arguments @("-m", "flask", "--app", "run.py", "db", "current")
if ($schema.ExitCode -ne 0) {
    $schema.Output | ForEach-Object { "  $_" }
    throw "Database is not reachable or not migrated. Run: cd backend; ..\.venv\Scripts\python.exe -m flask --app run.py db upgrade"
}
$head = ($schema.Output | Where-Object { $_ -and $_ -notmatch "^INFO" } | Select-Object -Last 1)
Write-Host "  schema: $head"

if (-not $SkipSeed) {
    Write-Host "Seeding reference data (idempotent)..."
    $seed = Invoke-Python -Arguments @("-m", "flask", "--app", "run.py", "seed")
    $seed.Output | ForEach-Object { if ($_ -and $_ -notmatch "^INFO") { "  $_" } }
    if ($seed.ExitCode -ne 0) { throw "flask seed failed." }
}

$already = Get-RunningState
if ($already) {
    $appAlive = [bool](Get-Process -Id $already.AppPid -ErrorAction SilentlyContinue)
    $targetAlive = [bool](Get-Process -Id $already.TargetPid -ErrorAction SilentlyContinue)
    if ($appAlive -or $targetAlive) {
        throw "An environment started by this script is already running. Use -Action stop first, or -Action status."
    }
    Remove-Item $StateFile -Force -ErrorAction SilentlyContinue
}

foreach ($port in @($AppPort, $TargetPort)) {
    if (Test-PortListening -Port $port) {
        throw "Port $port is already in use. Stop the process using it or choose another port."
    }
}

New-Item -ItemType Directory -Path $Logs -Force | Out-Null

# The verifier fetches the asset's /.well-known file on this port.
$env:TRUST_WEBFILE_PORT = "$TargetPort"

Write-Host "Starting the vulnerable target on port $TargetPort..."
$targetProcess = Start-Process -FilePath $Python `
    -ArgumentList "run.py" `
    -WorkingDirectory $Target `
    -PassThru `
    -RedirectStandardOutput (Join-Path $Logs "target.out.log") `
    -RedirectStandardError (Join-Path $Logs "target.err.log")

Write-Host "Starting VulnScan on port $AppPort..."
$appProcess = Start-Process -FilePath $Python `
    -ArgumentList @("-m", "flask", "--app", "run.py", "run", "--host", "127.0.0.1", "--port", "$AppPort", "--no-reload") `
    -WorkingDirectory $Backend `
    -PassThru `
    -RedirectStandardOutput (Join-Path $Logs "app.out.log") `
    -RedirectStandardError (Join-Path $Logs "app.err.log")

$state = [pscustomobject]@{
    AppPid     = $appProcess.Id
    TargetPid  = $targetProcess.Id
    AppPort    = $AppPort
    TargetPort = $TargetPort
    StartedAt  = (Get-Date).ToString("s")
}
$state | ConvertTo-Json | Set-Content -Path $StateFile -Encoding UTF8

$appReady = Wait-ForUrl -Url "http://127.0.0.1:$AppPort/api/health"
$targetReady = Wait-ForUrl -Url "http://localhost:$TargetPort/"

Write-Host ""
if (-not $appReady -or -not $targetReady) {
    Write-Host "ERROR: the environment did not become ready in time." -ForegroundColor Red
    Write-Host "  VulnScan ready = $appReady; target ready = $targetReady"
    Write-Host "  See $Logs\app.err.log and $Logs\target.err.log, then run -Action stop."
    exit 1
}

$adminEmail = Get-DotEnvValue -Name "SEED_ADMIN_EMAIL" -Default "admin@vulnscan.local"
$adminPassword = Get-DotEnvValue -Name "SEED_ADMIN_PASSWORD" -Default "Admin@VulnScan2025"
$devEmail = Get-DotEnvValue -Name "SEED_DEVELOPER_EMAIL" -Default "developer@vulnscan.local"
$devPassword = Get-DotEnvValue -Name "SEED_DEVELOPER_PASSWORD" -Default "Developer@VulnScan2025"

Write-Host "VulnScan local environment is ready." -ForegroundColor Green
Write-Host ""
Write-Host "  VulnScan UI      http://127.0.0.1:$AppPort/"
Write-Host "  Test shop        http://localhost:$TargetPort/  (intentionally vulnerable)"
Write-Host "  Health           http://127.0.0.1:$AppPort/api/health"
Write-Host "  Logs             $Logs"
Write-Host ""
Write-Host "  Credentials"
Write-Host "    Administrator  $adminEmail / $adminPassword"
Write-Host "    Developer      $devEmail / $devPassword"
Write-Host "    Test-shop user pentester@example.test / Temporary!Pass123"
Write-Host ""
Write-Host "  Next steps"
Write-Host "    1. Sign in as the Developer, create an organisation and a project."
Write-Host "    2. Register the asset hostname 'localhost' (scheme http), verify it via WEB_FILE,"
Write-Host "       then publish the challenge at http://localhost:$TargetPort/__test__/verification"
Write-Host "    3. Create an attestation, buy a mock credit, start the scan on"
Write-Host "       http://localhost:$TargetPort/"
Write-Host "    4. Or run the automated end-to-end check:"
Write-Host "       .\.venv\Scripts\python.exe scripts\local_smoke_test.py"
Write-Host ""
Write-Host "  Stop with: .\scripts\start-local.ps1 -Action stop"
