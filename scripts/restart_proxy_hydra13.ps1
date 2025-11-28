# HYDRA-13 Proxy Restart Script
# Stops existing proxy and restarts with HYDRA-13 enabled

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  HYDRA-13 Proxy Restart" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Find and kill existing proxy process
Write-Host "[1/4] Stopping existing proxy on port 8081..." -ForegroundColor Yellow
$process = Get-NetTCPConnection -LocalPort 8081 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique
if ($process) {
    Write-Host "    Found process PID: $process" -ForegroundColor Gray
    Stop-Process -Id $process -Force -ErrorAction SilentlyContinue
    Write-Host "    Process stopped." -ForegroundColor Green
    Start-Sleep -Seconds 2
} else {
    Write-Host "    No process found on port 8081." -ForegroundColor Gray
}

# Step 2: Verify port is free
Write-Host "[2/4] Verifying port 8081 is free..." -ForegroundColor Yellow
$check = Get-NetTCPConnection -LocalPort 8081 -ErrorAction SilentlyContinue
if ($check) {
    Write-Host "    WARNING: Port 8081 still in use!" -ForegroundColor Red
    Write-Host "    Attempting force kill..." -ForegroundColor Yellow
    $process = $check | Select-Object -ExpandProperty OwningProcess -Unique
    Stop-Process -Id $process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
} else {
    Write-Host "    Port 8081 is free." -ForegroundColor Green
}

# Step 3: Activate venv and start proxy
Write-Host "[3/4] Starting proxy server with HYDRA-13..." -ForegroundColor Yellow
$projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$venvPath = Join-Path (Split-Path -Parent $projectRoot) ".venv_hexa"
$proxyScript = Join-Path $projectRoot "standalone_packages\llm-security-firewall\src\proxy_server.py"

if (-not (Test-Path $venvPath)) {
    Write-Host "    ERROR: .venv_hexa not found at: $venvPath" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $proxyScript)) {
    Write-Host "    ERROR: proxy_server.py not found at: $proxyScript" -ForegroundColor Red
    exit 1
}

# Start proxy in new window
$pythonExe = Join-Path $venvPath "Scripts\python.exe"
if (-not (Test-Path $pythonExe)) {
    Write-Host "    ERROR: Python executable not found at: $pythonExe" -ForegroundColor Red
    exit 1
}

Write-Host "    Starting: $pythonExe $proxyScript" -ForegroundColor Gray
Start-Process -FilePath $pythonExe -ArgumentList $proxyScript -WindowStyle Normal

# Step 4: Wait and verify
Write-Host "[4/4] Waiting for proxy to start..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

$check = Get-NetTCPConnection -LocalPort 8081 -ErrorAction SilentlyContinue
if ($check) {
    Write-Host "    Proxy is running on port 8081!" -ForegroundColor Green
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Proxy Restarted Successfully" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "  1. Test HYDRA-13: .\scripts\test_hydra13.ps1" -ForegroundColor White
    Write-Host "  2. Check logs for: 'HYDRA-13 MetaExploitationGuard initialized'" -ForegroundColor White
    Write-Host ""
} else {
    Write-Host "    ERROR: Proxy did not start!" -ForegroundColor Red
    Write-Host "    Check the proxy window for errors." -ForegroundColor Yellow
    exit 1
}
