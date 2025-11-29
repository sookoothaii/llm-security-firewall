# HAK_GAL Firewall MCP Monitoring Guide

**Version:** 1.0.0
**Date:** 2025-11-29
**Status:** Production-Ready

---

## Übersicht

Das HAK_GAL Firewall MCP Monitoring System bietet **vollautomatisches Monitoring** mit minimalem Aufwand. Alle Checks laufen automatisch, Alerts werden erkannt, Metriken werden gesammelt.

**Kein manuelles Log-Checking mehr nötig!**

---

## MCP-Tools

### 1. `firewall_health_check`

**Automatischer Health-Check für alle Komponenten**

```json
{
  "name": "firewall_health_check",
  "arguments": {
    "check_redis": true,
    "check_sessions": true,
    "check_guards": true
  }
}
```

**Ergebnis:**
- Redis-Verbindung
- Session Manager Status
- Guards Verfügbarkeit
- Gesamt-Status: `healthy`, `degraded`, oder `unhealthy`

---

### 2. `firewall_deployment_status`

**Aktueller Deployment-Status**

```json
{
  "name": "firewall_deployment_status",
  "arguments": {}
}
```

**Ergebnis:**
- Deployment-Phase (not_deployed, staging_canary, production_canary, etc.)
- Traffic-Prozent
- Deployment-Zeitpunkt
- Aktueller Health-Status

---

### 3. `firewall_metrics`

**Aktuelle Metriken abrufen**

```json
{
  "name": "firewall_metrics",
  "arguments": {
    "metric_type": "all"  // oder "sessions", "rate_limits", "blocks"
  }
}
```

**Ergebnis:**
- Session-Anzahl (total, by tenant)
- Rate Limit Metriken
- Block-Metriken
- Timestamp

---

### 4. `firewall_check_alerts`

**Kritische Alerts prüfen**

```json
{
  "name": "firewall_check_alerts",
  "arguments": {
    "alert_type": "all"  // oder "rate_limit", "session", "guard"
  }
}
```

**Ergebnis:**
- Alert-Count
- Liste aller Alerts (severity, type, message)
- Status: `ok` oder `alerts_present`

**Alert-Typen:**
- `redis_connection`: Redis-Verbindung fehlgeschlagen (CRITICAL)
- `redis_memory`: Redis Memory > 2GB (WARNING)
- `session_manager`: Session Manager unhealthy (CRITICAL)

---

### 5. `firewall_redis_status`

**Detaillierter Redis-Status**

```json
{
  "name": "firewall_redis_status",
  "arguments": {}
}
```

**Ergebnis:**
- Memory (used, peak, max)
- Connections (connected_clients, total_connections)
- Keys (total_hakgal, sessions)
- Timestamp

---

## Automatisches Monitoring

### Auto-Monitor Script

**Kontinuierliches Monitoring im Hintergrund:**

```powershell
# Start Auto-Monitor (prüft alle 60 Sekunden)
cd "d:\MCP Mods\HAK_GAL_HEXAGONAL\standalone_packages\llm-security-firewall"
.\.venv_hexa\Scripts\Activate.ps1
python scripts/auto_monitor.py
```

**Environment-Variablen:**
- `MONITOR_INTERVAL`: Prüf-Intervall in Sekunden (default: 60)

**Logs:**
- `monitoring/firewall_monitor.log`: Kontinuierliche Logs
- `monitoring/last_status.json`: Letzter Status (JSON)

---

## MCP-Server Setup

### 1. MCP-Config hinzufügen

Füge zu deiner MCP-Config hinzu:

```json
{
  "mcpServers": {
    "hak-gal-firewall-monitor": {
      "command": "python",
      "args": [
        "-u",
        "d:/MCP Mods/HAK_GAL_HEXAGONAL/standalone_packages/llm-security-firewall/mcp_firewall_monitor.py"
      ],
      "env": {
        "REDIS_CLOUD_HOST": "redis-19088.c305.ap-south-1-1.ec2.cloud.redislabs.com",
        "REDIS_CLOUD_PORT": "19088",
        "REDIS_CLOUD_USERNAME": "default",
        "REDIS_CLOUD_PASSWORD": "your_password"
      }
    }
  }
}
```

### 2. MCP-Tools verwenden

In Cursor/Claude kannst du jetzt einfach fragen:

- "Prüfe Firewall Health"
- "Zeige Deployment-Status"
- "Gibt es Alerts?"
- "Zeige Redis-Status"

**Alles automatisch, keine manuellen Commands nötig!**

---

## Workflow-Beispiele

### Täglicher Check (automatisch)

```python
# Auto-Monitor läuft kontinuierlich
# Status wird in monitoring/last_status.json gespeichert
# Bei Alerts: Logs werden geschrieben
```

### Vor Deployment

```python
# MCP-Tool: firewall_health_check
# Prüft: Redis, Sessions, Guards
# Ergebnis: healthy/degraded/unhealthy
```

### Nach Deployment

```python
# MCP-Tool: firewall_deployment_status
# Zeigt: Phase, Traffic-%, Health
# MCP-Tool: firewall_check_alerts
# Prüft: Kritische Alerts
```

### Bei Problemen

```python
# MCP-Tool: firewall_redis_status
# Detaillierter Redis-Status
# MCP-Tool: firewall_metrics
# Aktuelle Metriken
```

---

## Alert-Schwellwerte

| Alert | Schwellwert | Severity |
|-------|-------------|----------|
| Redis Connection | Failed | CRITICAL |
| Redis Memory | > 2GB | WARNING |
| Session Manager | Unhealthy | CRITICAL |
| Guards | Unavailable | CRITICAL |

---

## Vorteile

✅ **Vollautomatisch**: Kein manuelles Log-Checking
✅ **MCP-Integration**: Direkt in Cursor/Claude verfügbar
✅ **Kontinuierlich**: Auto-Monitor läuft im Hintergrund
✅ **Alerting**: Automatische Erkennung kritischer Probleme
✅ **Metriken**: Alle wichtigen Metriken auf einen Blick

---

## Troubleshooting

### MCP-Server startet nicht

1. Prüfe Environment-Variablen (REDIS_CLOUD_*)
2. Prüfe Python-Path (src/ muss im Path sein)
3. Prüfe Dependencies (redis, hak_gal modules)

### Keine Redis-Verbindung

1. Prüfe REDIS_CLOUD_PASSWORD (Database Password, nicht API Key!)
2. Prüfe IP Whitelist in Redis Cloud
3. Prüfe Host/Port

### Alerts werden nicht erkannt

1. Prüfe `monitoring/firewall_monitor.log`
2. Prüfe `monitoring/last_status.json`
3. Prüfe Redis-Verbindung manuell

---

**Last Updated:** 2025-11-29
**Status:** Production-Ready
