# Chaos Test mit Redis Cloud

## Voraussetzungen

1. Redis Cloud Account mit aktivem Subscription
2. Redis Cloud Database erstellt
3. Connection Details verfügbar

## Konfiguration

Setzen Sie die folgenden Umgebungsvariablen:

```powershell
# PowerShell
$env:REDIS_CLOUD_HOST="redis-19088.c305.ap-south-1-1.ec2.cloud.redislabs.com"
$env:REDIS_CLOUD_PORT="19088"
$env:REDIS_CLOUD_USERNAME="default"
$env:REDIS_CLOUD_PASSWORD="Ihr_Passwort_Hier"
```

## Test ausführen

```powershell
cd "d:\MCP Mods\HAK_GAL_HEXAGONAL\standalone_packages\llm-security-firewall"
pytest tests/adversarial/test_chaos_pod_death_redis_cloud.py -v
```

## Verfügbare Tests

1. `test_session_state_survives_pod_death_redis_cloud` - Einzelne Session überlebt Pod-Death
2. `test_multiple_sessions_survive_pod_death_redis_cloud` - 10 Sessions überleben Pod-Death

## Sicherheit

**WICHTIG:** Das Passwort sollte niemals in Code oder Git committed werden. Verwenden Sie:
- Umgebungsvariablen (wie oben gezeigt)
- Secret Management Tools (z.B. Vault, AWS Secrets Manager)
- `.env` Dateien (nicht in Git committed)

## Troubleshooting

**Test wird übersprungen:**
- Prüfen Sie, ob `REDIS_CLOUD_PASSWORD` gesetzt ist: `echo $env:REDIS_CLOUD_PASSWORD`

**Verbindungsfehler:**
- Prüfen Sie, ob Redis Cloud Database aktiv ist
- Prüfen Sie Firewall-Regeln (IP Whitelist)
- Prüfen Sie Credentials in Redis Cloud Dashboard
