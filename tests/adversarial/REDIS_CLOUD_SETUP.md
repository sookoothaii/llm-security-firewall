# Redis Cloud Setup für Chaos Test

## Wichtig: Google OAuth Login

Wenn Sie sich mit Google in Redis Cloud eingeloggt haben, benötigen Sie **nicht** den API Key für die direkte Redis-Verbindung.

## Was Sie benötigen:

1. **Database Password** (nicht API Key!)
   - Gehen Sie zu: Redis Cloud Dashboard
   - Wählen Sie Ihre Database aus
   - Gehen Sie zu: **Configuration** -> **Default User Password**
   - Kopieren Sie das **Database Password**

2. **Connection Details**
   - Host: `redis-19088.c305.ap-south-1-1.ec2.cloud.redislabs.com`
   - Port: `19088`
   - Username: `default` (oder der in der Configuration angezeigte Username)

## Umgebungsvariablen setzen:

```powershell
$env:REDIS_CLOUD_HOST="redis-19088.c305.ap-south-1-1.ec2.cloud.redislabs.com"
$env:REDIS_CLOUD_PORT="19088"
$env:REDIS_CLOUD_USERNAME="default"
$env:REDIS_CLOUD_PASSWORD="Ihr_Database_Password_Hier"  # NICHT der API Key!
```

## Test ausführen:

```powershell
pytest tests/adversarial/test_chaos_pod_death_redis_cloud.py -v
```

## Unterschied: API Key vs Database Password

- **API Key**: Für Redis Cloud API-Zugriff (Management, nicht Datenbank-Verbindung)
- **Database Password**: Für direkte Redis-Verbindungen (das brauchen wir!)

## Wo finde ich das Database Password?

1. Redis Cloud Dashboard öffnen
2. Ihre Database auswählen
3. Tab "Configuration" öffnen
4. Unter "Default User" -> "Password" finden Sie das Database Password
5. Falls nicht sichtbar: Klicken Sie auf "Show" oder "Reveal"
