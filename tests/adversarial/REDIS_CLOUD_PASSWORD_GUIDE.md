# Redis Cloud: Database Password finden

## WICHTIG: API Key ≠ Database Password

- **API Key** (`x-api-key`, `x-api-secret-key`): Für REST API Requests (Management)
- **Database Password**: Für direkte Redis-Verbindungen (das brauchen wir!)

## So finden Sie das Database Password:

### Methode 1: Redis Cloud Dashboard

1. **Redis Cloud Dashboard öffnen** (<https://redis.com/redis-enterprise-cloud/>)
2. **Ihre Database auswählen** (klicken Sie auf den Database-Namen)
3. **Tab "Configuration" öffnen**
4. **Unter "Default User" finden Sie:**
   - **Username**: Meist `default`, kann aber anders sein
   - **Password**: Klicken Sie auf **"Show"** oder **"Reveal"** um das Passwort anzuzeigen

### Methode 2: Connection String

1. **Redis Cloud Dashboard -> Ihre Database**
2. **Tab "Configuration" oder "Connect"**
3. **Suchen Sie nach "Connection String" oder "Redis URL"**

Format: `redis://username:password@host:port`

Beispiel:
```
redis://default:MeinPasswort123@redis-19088.c305.ap-south-1-1.ec2.cloud.redislabs.com:19088
```

Extrahieren Sie:
- **Username**: Teil vor dem ersten `:`
- **Password**: Teil zwischen `:` und `@`
- **Host**: Teil nach `@` und vor dem letzten `:`
- **Port**: Teil nach dem letzten `:`

### Methode 3: Redis CLI (falls installiert)

Falls Sie Redis CLI haben, können Sie den Connection String direkt verwenden:

```bash
redis-cli -u redis://default:password@redis-19088.c305.ap-south-1-1.ec2.cloud.redislabs.com:19088
```

## Umgebungsvariablen setzen:

```powershell
# PowerShell
$env:REDIS_CLOUD_HOST="redis-19088.c305.ap-south-1-1.ec2.cloud.redislabs.com"
$env:REDIS_CLOUD_PORT="19088"
$env:REDIS_CLOUD_USERNAME="default"  # Oder der in Configuration angezeigte Username
$env:REDIS_CLOUD_PASSWORD="Ihr_Database_Password_Hier"  # NICHT der API Key!
```

## Test-Verbindung:

```powershell
python tests/adversarial/test_redis_connection.py
```

Dieses Script testet die Verbindung und zeigt, welche Authentifizierungsmethode funktioniert.

## Häufige Fehler:

1. ❌ **API Key als Password verwendet** → Funktioniert nicht für Redis-Client-Verbindungen
2. ✅ **Database Password verwendet** → Das ist korrekt!

## IP Whitelist nicht vergessen!

Auch mit korrektem Passwort wird die Verbindung blockiert, wenn Ihre IP nicht in der Whitelist ist:

1. **Redis Cloud Dashboard -> Ihre Database**
2. **Tab "Security" oder "Access Control"**
3. **IP Access List**: Fügen Sie Ihre IP hinzu (`223.206.68.93`)
