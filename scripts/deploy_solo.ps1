# HAK_GAL v2.3.3: Solo-Dev Quick Deploy
# =====================================
# Deploys everything in 5 minutes
# Author: Joerg Bollwahn
# Date: 2025-11-29

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "HAK_GAL v2.3.3 Solo-Dev Deployment" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check prerequisites
Write-Host "[1/5] Checking prerequisites..." -ForegroundColor Yellow

if (-not (Get-Command kubectl -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: kubectl not found. Please install Kubernetes CLI." -ForegroundColor Red
    exit 1
}

Write-Host "  ✓ kubectl found" -ForegroundColor Green

# Check if we're connected to cluster
Write-Host "[2/5] Checking Kubernetes connection..." -ForegroundColor Yellow
try {
    $cluster = kubectl cluster-info 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Not connected to Kubernetes cluster." -ForegroundColor Red
        Write-Host "  Run: kubectl config use-context <your-context>" -ForegroundColor Yellow
        exit 1
    }
    Write-Host "  ✓ Connected to cluster" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Cannot connect to Kubernetes cluster." -ForegroundColor Red
    exit 1
}

# Deploy secrets
Write-Host "[3/5] Deploying Redis Cloud secret..." -ForegroundColor Yellow
$secretPath = Join-Path $PSScriptRoot "..\k8s\redis-cloud-secret.yml"
if (Test-Path $secretPath) {
    kubectl apply -f $secretPath
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ✓ Secret deployed" -ForegroundColor Green
    } else {
        Write-Host "  ✗ Secret deployment failed" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "  ✗ Secret file not found: $secretPath" -ForegroundColor Red
    exit 1
}

# Deploy firewall
Write-Host "[4/5] Deploying HAK_GAL Firewall..." -ForegroundColor Yellow
$deployPath = Join-Path $PSScriptRoot "..\k8s\hakgal-deployment.yml"
if (Test-Path $deployPath) {
    kubectl apply -f $deployPath
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ✓ Deployment created" -ForegroundColor Green
    } else {
        Write-Host "  ✗ Deployment failed" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "  ✗ Deployment file not found: $deployPath" -ForegroundColor Red
    exit 1
}

# Deploy auto-monitor
Write-Host "[5/5] Deploying Auto-Monitor CronJob..." -ForegroundColor Yellow
$monitorPath = Join-Path $PSScriptRoot "..\k8s\auto-monitor-cronjob.yml"
if (Test-Path $monitorPath) {
    kubectl apply -f $monitorPath
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ✓ Auto-Monitor deployed" -ForegroundColor Green
    } else {
        Write-Host "  ✗ Auto-Monitor deployment failed" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "  ✗ Auto-Monitor file not found: $monitorPath" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Deployment Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Checking pod status..." -ForegroundColor Yellow
Write-Host ""
kubectl get pods -l app=hakgal-firewall
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Wait for pods to be 'Running' (kubectl get pods -w)" -ForegroundColor White
Write-Host "  2. Test MCP-Tools: 'Prüfe Firewall Health'" -ForegroundColor White
Write-Host "  3. Check logs: kubectl logs -l app=hakgal-firewall" -ForegroundColor White
Write-Host ""
Write-Host "Daily routine (10 minutes/day):" -ForegroundColor Cyan
Write-Host "  - Morning (09:00): Check MCP-Tools or Dashboard" -ForegroundColor White
Write-Host "  - Evening (18:00): Check MCP-Tools or Dashboard" -ForegroundColor White
Write-Host "  - On Alert: Follow runbooks in runbooks/ directory" -ForegroundColor White
Write-Host ""
Write-Host "After 72h: Scale to 10 pods:" -ForegroundColor Cyan
Write-Host "  kubectl scale deployment hakgal-firewall --replicas=10" -ForegroundColor White
Write-Host ""
