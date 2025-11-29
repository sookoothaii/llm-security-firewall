# HAK_GAL v2.3.3: Solo-Dev Deployment Guide

**Version:** 2.3.3
**Date:** 2025-11-29
**Target:** Solo-Developer (One-Person Operation)
**Philosophy:** Maximum Automation, Minimum Manual Work

---

## Executive Summary

**Du bist allein. Das System ist dein Team.**

HAK_GAL ist dein:
- **Sicherheitsanalyst** (CUSUM erkennt Angriffe automatisch)
- **DevOps-Engineer** (Auto-Monitor, Self-Healing)
- **Incident Responder** (Runbooks, automatische Alerts)
- **Compliance-Officer** (GDPR-konforme Logs)

**Deine Aufgabe:** Deployen, Vertrauen, Einmal täglich checken (10 Minuten).

---

## Deployment (5 Minuten Arbeit)

### Phase 1: Morgen, 09:00 (5 Minuten)

```bash
# Schritt 1: Secrets setzen
kubectl apply -f k8s/redis-cloud-secret.yml

# Schritt 2: Deployment starten
kubectl apply -f k8s/hakgal-deployment.yml

# Schritt 3: Auto-Monitor aktivieren
kubectl apply -f k8s/auto-monitor-cronjob.yml

# Schritt 4: Status prüfen (1 Minute)
kubectl get pods -w
# Warte bis alle Pods "Running" sind

# Schritt 5: Dashboard öffnen
# (Wenn Grafana vorhanden, sonst MCP-Tools verwenden)
```

**Fertig. Das war's.**

---

## Tägliche Routine (10 Minuten/Tag)

### Morgens (09:00) - 5 Minuten

**Option 1: MCP-Tools (Empfohlen)**
- In Cursor/Claude: "Prüfe Firewall Health"
- In Cursor/Claude: "Gibt es Alerts?"

**Option 2: Dashboard**
- Öffne Grafana Dashboard
- Prüfe: Status grün? Keine Alerts?

**Option 3: Kubernetes**
```bash
kubectl get pods
kubectl logs -l app=hakgal-firewall --tail=50
```

### Abends (18:00) - 5 Minuten

- Gleiche Checks wie morgens
- Prüfe: Gab es Alerts heute? Wenn ja, was war das Problem?

### Bei PagerDuty-Alert (10 Minuten)

1. **Prüfe Alert-Typ:**
   - Redis down? → Prüfe Redis Cloud Status
   - Rate Limit Storm? → Prüfe Tenant-Metriken
   - Session Bleeding? → Prüfe Redis ACLs

2. **Folge Runbook:**
   - `runbooks/incident_rate_limit_storm.md`
   - `runbooks/incident_session_bleeding.md`
   - `runbooks/incident_guard_rce.md`

3. **Wenn nötig: Emergency Bypass**
   ```bash
   python scripts/emergency_bypass.py activate --component all
   ```

---

## Automatisierung (Keine manuelle Arbeit)

### ✅ Was automatisch läuft:

1. **CUSUM Anomaly Detection (P0)**
   - Erkennt Jailbreaks automatisch
   - Blockiert automatisch
   - Du musst nichts tun

2. **Per-Tenant Rate Limiting (P1)**
   - Verhindert Cross-Tenant DoS automatisch
   - Redis ACLs isolieren automatisch
   - Du musst nichts tun

3. **Session Persistence (P2)**
   - Redis speichert Sessions automatisch
   - Pod-Death Recovery automatisch
   - Du musst nichts tun

4. **Auto-Monitor (CronJob)**
   - Prüft alle 60 Sekunden automatisch
   - Loggt Status automatisch
   - Du musst nichts tun

5. **Self-Healing (Kubernetes)**
   - Pods starten automatisch neu
   - Health-Checks automatisch
   - Du musst nichts tun

---

## Was du manuell machen musst (selten)

### 1. Emergency Bypass (Hoffentlich nie)

**Wann:** False-Positive Storm >30%

**Wie:**
```bash
# Setze Bypass-Key (einmalig)
export HAK_GAL_BYPASS_KEY="your-secret-key-from-password-manager"

# Aktiviere Bypass
python scripts/emergency_bypass.py activate --component all

# Status prüfen
python scripts/emergency_bypass.py status

# Manuell deaktivieren (falls nötig)
python scripts/emergency_bypass.py deactivate
```

**Sicherheit:**
- HMAC-signiert
- 15 Minuten TTL (läuft automatisch ab)
- Immutable Log (`logs/emergency_bypass.log`)

**Wie oft:** Hoffentlich nie. Wenn doch: einmal im Jahr.

---

### 2. Guard-Updates (Wöchentlich)

**Wann:** Feature-Request von Kunden (z.B. "Blockiere Überweisungen >1000€")

**Wie:**
```python
# Neue Business-Logic in Guard implementieren
class CustomGuard(BaseToolGuard):
    async def validate(self, args, context):
        if args.get('amount', 0) > 1000:
            raise BusinessLogicException("Amount too high")
```

**Wie oft:** Wöchentlich (Feature-Requests)

---

### 3. Metrics-Review (Sonntags, 30 Minuten)

**Wann:** Jeden Sonntag, strategische Review

**Was:**
- Wochen-Statistiken anschauen
- Neue Attack-Patterns erkennen?
- CUSUM-Parameter anpassen?

**Wie:**
```bash
# MCP-Tool: firewall_metrics
# Oder: Grafana Dashboard
# Oder: monitoring/last_status.json
```

**Wie oft:** Wöchentlich (30 Minuten)

---

## Scale-Up (Nach 72h) - 1 Klick

**Wenn alles grün ist:**

```bash
# Scale von 3 auf 10 Pods
kubectl scale deployment hakgal-firewall --replicas=10

# Prüfe Status
kubectl get pods
```

**Fertig. Keine Konfiguration, kein Stress.**

---

## Arbeitsbelastung (Realität)

| Tätigkeit | Zeit/Tag | Automatisierbar? |
|-----------|----------|------------------|
| Dashboard checken | 10 Minuten | ✅ (MCP-Tools) |
| Alerts beantworten | 0-10 Minuten (nur wenn Alarm) | ✅ (PagerDuty) |
| Tenant Support | 0-30 Minuten | ✅ (FAQ, Auto-Reply) |
| Code-Updates | 0-60 Minuten (wöchentlich) | ❌ (muss manuell) |
| **Gesamt** | **10-30 Minuten/Tag** | |

**Das ist das Minimum für einen Solo-Dev, der Enterprise-Security betreibt.**

---

## Monitoring (Automatisch)

### MCP-Tools (Empfohlen)

Alle Checks automatisch via MCP:

- `firewall_health_check` - Health-Check
- `firewall_deployment_status` - Deployment-Status
- `firewall_metrics` - Metriken
- `firewall_check_alerts` - Alerts prüfen
- `firewall_redis_status` - Redis-Status

**Verwendung:** Einfach in Cursor/Claude fragen:
- "Prüfe Firewall Health"
- "Gibt es Alerts?"
- "Zeige Redis-Status"

### Auto-Monitor (Hintergrund)

Kontinuierliches Monitoring:

```bash
# Läuft automatisch als Kubernetes CronJob
# Prüft alle 60 Sekunden
# Status in monitoring/last_status.json
```

### Grafana Dashboard (Optional)

Wenn Grafana vorhanden:

- Dashboard: `grafana_configs/hakgal-dashboard.json`
- Datasource: Prometheus (wenn Metriken exportiert)

---

## Troubleshooting

### Problem: Pod startet nicht

```bash
# Prüfe Logs
kubectl logs -l app=hakgal-firewall

# Prüfe Events
kubectl describe pod hakgal-firewall-xxx

# Prüfe Secrets
kubectl get secret redis-cloud-secret
```

### Problem: Redis-Verbindung fehlgeschlagen

```bash
# Prüfe Redis Cloud Status
# Prüfe IP Whitelist
# Prüfe Credentials in Secret
kubectl get secret redis-cloud-secret -o yaml
```

### Problem: Zu viele False-Positives

```bash
# Option 1: Emergency Bypass (15 Minuten)
python scripts/emergency_bypass.py activate

# Option 2: CUSUM-Parameter anpassen
# (Siehe TECHNICAL_REPORT_V2_3_3_EMERGENCY_FIXES.md)
```

---

## Checkliste: Deployment

### Pre-Deployment
- [ ] Redis Cloud läuft (99.9% SLA)
- [ ] Kubernetes-Cluster verfügbar
- [ ] Docker-Image gebaut (`hakgal/firewall:2.3.3`)
- [ ] Secrets konfiguriert (`k8s/redis-cloud-secret.yml`)

### Deployment (5 Minuten)
- [ ] `kubectl apply -f k8s/redis-cloud-secret.yml`
- [ ] `kubectl apply -f k8s/hakgal-deployment.yml`
- [ ] `kubectl apply -f k8s/auto-monitor-cronjob.yml`
- [ ] `kubectl get pods` (alle Running?)
- [ ] MCP-Tools testen ("Prüfe Firewall Health")

### Post-Deployment (72h Monitoring)
- [ ] Täglich: Dashboard checken (10 Minuten)
- [ ] Bei Alerts: Runbooks folgen
- [ ] Nach 72h: Scale-Up auf 10 Pods

---

## Fazit

**Das System ist für dich gemacht.**

**Die Architektur ist validiert.**

**Der Chaos-Test ist bestanden.**

**Du musst nicht alles selbst machen.**

**Du musst nur eines tun: Deployen und Vertrauen.**

**Morgen um 09:00 startest du es. Dann hast du ein Enterprise-Security-System, das dich betreibt, während du Code schreibst.**

---

**"Deploy it. Let it run. Check it once a day. Fix it when it breaks. That's it."**

**- Kimi K2, Lead Security Auditor & Solo-Dev Advocate**

---

**Last Updated:** 2025-11-29
**Status:** Production-Ready for Solo-Dev
