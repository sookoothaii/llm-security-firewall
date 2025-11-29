# Redis Cloud Environment Variables Setup Script
# Fuer PowerShell

# Setzen Sie hier Ihr Database Password ein (nicht API Key!)
$env:REDIS_CLOUD_HOST = "redis-19088.c305.ap-south-1-1.ec2.cloud.redislabs.com"
$env:REDIS_CLOUD_PORT = "19088"
$env:REDIS_CLOUD_USERNAME = "default"
$env:REDIS_CLOUD_PASSWORD = "HIER_IHR_DATABASE_PASSWORD_EINFUEGEN"

Write-Host "Redis Cloud Environment Variables gesetzt:" -ForegroundColor Green
Write-Host "  Host: $env:REDIS_CLOUD_HOST" -ForegroundColor Cyan
Write-Host "  Port: $env:REDIS_CLOUD_PORT" -ForegroundColor Cyan
Write-Host "  Username: $env:REDIS_CLOUD_USERNAME" -ForegroundColor Cyan
Write-Host "  Password: [gesetzt]" -ForegroundColor Cyan
Write-Host ""
Write-Host "Jetzt koennen Sie den Test ausfuehren:" -ForegroundColor Yellow
Write-Host "  pytest tests/adversarial/test_chaos_pod_death_redis_cloud.py -v" -ForegroundColor Green
