# Redis Cloud Troubleshooting

## Problem: "invalid username-password pair"

### Schritt 1: Passwort überprüfen

1. **Redis Cloud Dashboard öffnen**
2. **Ihre Database auswählen**
3. **Tab "Configuration" öffnen**
4. **Unter "Default User" finden Sie:**
   - **Username** (kann "default" sein, muss aber nicht!)
   - **Password** (klicken Sie auf "Show" oder "Reveal")

### Schritt 2: IP Whitelist prüfen

Redis Cloud blockiert Verbindungen von nicht-whitelisteten IPs!

1. **Redis Cloud Dashboard -> Ihre Database**
2. **Tab "Security" oder "Access Control"**
3. **Prüfen Sie die IP Whitelist:**
   - Falls leer: Fügen Sie Ihre aktuelle IP hinzu
   - Oder: Fügen Sie `0.0.0.0/0` hinzu (ACHTUNG: Nur für Tests, nicht für Production!)

### Schritt 3: Username überprüfen

Der Username ist möglicherweise **nicht** "default"!

- Prüfen Sie in der Configuration, welcher Username angezeigt wird
- Setzen Sie: `$env:REDIS_CLOUD_USERNAME="Ihr_Username"`

### Schritt 4: Connection String prüfen

In Redis Cloud Dashboard finden Sie auch einen **Connection String**:

Format: `redis://username:password@host:port`

Beispiel:
```
redis://default:MeinPasswort@redis-19088.c305.ap-south-1-1.ec2.cloud.redislabs.com:19088
```

Extrahieren Sie daraus:
- Username: Teil vor dem `:`
- Password: Teil nach dem `:` und vor dem `@`
- Host: Teil nach dem `@` und vor dem `:`
- Port: Teil nach dem letzten `:`

### Schritt 5: Test-Script ausführen

```powershell
cd "d:\MCP Mods\HAK_GAL_HEXAGONAL\standalone_packages\llm-security-firewall"
python tests/adversarial/test_redis_connection.py
```

Dieses Script testet verschiedene Authentifizierungsmethoden.

## Häufige Fehler

1. **API Key statt Database Password verwendet**
   - API Key ist für Redis Cloud API, nicht für Datenbank-Verbindungen
   - Verwenden Sie das **Database Password** aus der Configuration

2. **IP nicht in Whitelist**
   - Ihre aktuelle IP muss in der Whitelist sein
   - Prüfen Sie: Redis Cloud Dashboard -> Security -> IP Access List

3. **Falscher Username**
   - Nicht immer "default"
   - Prüfen Sie in der Configuration

4. **Datenbank nicht aktiv**
   - Prüfen Sie, ob die Datenbank im Status "Active" ist

## Quick Check

Führen Sie aus, um Ihre aktuelle IP zu sehen:
```powershell
(Invoke-WebRequest -Uri "https://api.ipify.org").Content
```

Dann fügen Sie diese IP zur Redis Cloud Whitelist hinzu.
