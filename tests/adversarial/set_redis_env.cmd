@echo off
REM Redis Cloud Environment Variables Setup Script
REM Fuer CMD

REM Setzen Sie hier Ihr Database Password ein (nicht API Key!)
set REDIS_CLOUD_HOST=redis-19088.c305.ap-south-1-1.ec2.cloud.redislabs.com
set REDIS_CLOUD_PORT=19088
set REDIS_CLOUD_USERNAME=default
set REDIS_CLOUD_PASSWORD=HIER_IHR_DATABASE_PASSWORD_EINFUEGEN

echo Redis Cloud Environment Variables gesetzt:
echo   Host: %REDIS_CLOUD_HOST%
echo   Port: %REDIS_CLOUD_PORT%
echo   Username: %REDIS_CLOUD_USERNAME%
echo   Password: [gesetzt]
echo.
echo Jetzt koennen Sie den Test ausfuehren:
echo   pytest tests/adversarial/test_chaos_pod_death_redis_cloud.py -v
