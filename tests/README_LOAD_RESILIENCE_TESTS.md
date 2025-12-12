# Load & Resilienz Test-Protokoll - Orchestrator Service

**Status:** ✅ Vollständig integriert in bestehende Test-Infrastruktur

---

## 📋 Übersicht

Dieses Test-Protokoll deckt **Funktion, Leistung, Resilienz und Sicherheit** ab und ist vollständig in die bestehende Test-Infrastruktur integriert.

---

## 🚀 Quick Start

### Alle Tests ausführen
```bash
# Vollständiger Test-Durchlauf
python -m tests.run_full_test_suite

# Mit Custom-Parametern
python -m tests.run_full_test_suite --url http://localhost:8001 --load-concurrent 200 --load-duration 60
```

### Einzelne Tests
```bash
# Load Test
python -m tests.load_test --concurrent 100 --duration 30

# Resilienz Test
python -m tests.resilience_test

# Security Test
python -m tests.security_test

# Monitoring Test (Bash)
bash tests/monitoring_test.sh
```

---

## 📊 Test-Suites

### 1. Load Test (`tests/load_test.py`)

**Zweck:** Simuliert Dauerlast mit variierenden Request-Typen

**Features:**
- ✅ Concurrent Requests (default: 100)
- ✅ Dauerlast (default: 30s)
- ✅ 10 verschiedene Test-Cases (Normal, Code, Multilingual, SQL Injection, XSS, etc.)
- ✅ Latenz-Metriken (P50, P95, P99, Avg, Min, Max)
- ✅ Durchsatz-Messung (Requests/sec)
- ✅ Fehlerrate-Tracking
- ✅ Kategorie-spezifische Statistiken

**Usage:**
```bash
python -m tests.load_test --concurrent 100 --duration 30 --output results.json
```

**Erfolgskriterien:**
- ✅ Durchsatz: > 100 requests/sec
- ✅ Latenz P95: < 200ms
- ✅ Fehlerrate: < 0.1%

---

### 2. Resilienz Test (`tests/resilience_test.py`)

**Zweck:** Testet System-Resilienz bei Fehlern

**Test-Szenarien:**
- ✅ Detektor-Failures (teilweise ausgefallene Detektoren)
- ✅ Redis-Failure (Fallback auf Memory-Repository)
- ✅ Policy-Reload unter Last

**Usage:**
```bash
# Alle Tests
python -m tests.resilience_test

# Einzelner Test
python -m tests.resilience_test --test detector_failures
python -m tests.resilience_test --test redis_failure
python -m tests.resilience_test --test policy_reload
```

**Erfolgskriterien:**
- ✅ System funktioniert auch bei teilweisen Ausfällen
- ✅ Fallback-Mechanismen greifen
- ✅ Keine Datenverluste bei Redis-Failure
- ✅ Recovery Time < 30s nach Service-Failure

---

### 3. Security Test (`tests/security_test.py`)

**Zweck:** Testet Grenzwerte und schädliche Eingaben

**Test-Vektoren:**
- ✅ SQL Injection (3 Varianten)
- ✅ XSS (3 Varianten)
- ✅ Path Traversal (2 Varianten)
- ✅ Command Injection (3 Varianten)
- ✅ Buffer Overflow (2 Varianten)
- ✅ Malformed JSON
- ✅ Unicode Bombs (2 Varianten)
- ✅ Code Injection (2 Varianten)
- ✅ LDAP Injection
- ✅ JNDI Injection
- ✅ XXE

**Gesamt: 21 Test-Vektoren**

**Usage:**
```bash
python -m tests.security_test --url http://localhost:8001 --output results.json
```

**Erfolgskriterien:**
- ✅ Alle erwarteten Angriffe werden blockiert
- ✅ Risk Score > 0.5 für bösartige Eingaben
- ✅ Keine False Negatives

---

### 4. Monitoring Test (`tests/monitoring_test.sh`)

**Zweck:** Testet Monitoring-Endpoints und Metriken-Erfassung

**Test-Szenarien:**
- ✅ Metrics Collection (100 Requests)
- ✅ Alert Triggering (hohe Error-Rate)
- ✅ Health Check
- ✅ Metrics Summary
- ✅ Dashboard

**Usage:**
```bash
bash tests/monitoring_test.sh
bash tests/monitoring_test.sh http://localhost:8001 test_results
```

**Erfolgskriterien:**
- ✅ Alle Monitoring-Endpoints funktionieren
- ✅ Metriken werden korrekt erfasst
- ✅ Alerts werden ausgelöst bei hoher Error-Rate

---

## 🎯 Vollständiger Test-Durchlauf

### Option 1: Automatisiert (Empfohlen)
```bash
python -m tests.run_full_test_suite
```

### Option 2: Schrittweise
```bash
# 1. Load Test
python -m tests.load_test --concurrent 100 --duration 300

# 2. Resilienz Test
python -m tests.resilience_test

# 3. Security Test
python -m tests.security_test

# 4. Monitoring Test
bash tests/monitoring_test.sh
```

---

## 📊 Erfolgskriterien (Gesamt)

### Performance
- ✅ **Durchsatz**: > 100 requests/sec
- ✅ **Latenz P95**: < 200ms
- ✅ **Latenz P99**: < 500ms
- ✅ **Fehlerrate**: < 0.1%

### Resilienz
- ✅ **Recovery Time**: < 30s nach Service-Failure
- ✅ **Data Consistency**: Keine Datenverluste bei Redis-Failure
- ✅ **Graceful Degradation**: System funktioniert bei teilweisen Ausfällen

### Sicherheit
- ✅ **Detection Rate**: 100% auf bekannten Angriffsvektoren
- ✅ **False Positive Rate**: < 5%
- ✅ **Input Validation**: Alle schädlichen Eingaben werden erkannt

### Monitoring
- ✅ **Metriken-Erfassung**: Alle Endpoints funktionieren
- ✅ **Alert-System**: Alerts werden korrekt ausgelöst
- ✅ **Health Checks**: System-Status wird korrekt angezeigt

---

## 📁 Output-Struktur

```
test_results/
├── load_test_YYYYMMDD_HHMMSS.json
├── resilience_test_YYYYMMDD_HHMMSS.json
├── security_test_YYYYMMDD_HHMMSS.json
├── test_summary_YYYYMMDD_HHMMSS.json
└── monitoring_test_output/
    ├── metrics_output.txt
    ├── alerts_output.txt
    ├── health_output.txt
    ├── metrics_summary_output.txt
    └── dashboard_output.txt
```

---

## 🔧 Integration mit bestehenden Tests

Diese Tests sind vollständig integriert in:
- ✅ `scripts/run_comprehensive_test_suite.py` (kann erweitert werden)
- ✅ `scripts/performance_stress_test.py` (komplementär)
- ✅ `scripts/hardcore_red_team_assault.py` (Security-Tests ergänzen)

---

## 📝 Integrationstest-Szenarien

YAML-basierte Szenarien in `tests/integration_scenarios.yaml`:
- Happy Path
- High Risk Code
- SQL Injection Detection
- XSS Detection
- Multilingual Attack
- Feedback Loop
- Learning Metrics
- Monitoring Health Check
- Monitoring Metrics
- Concurrent Requests

---

## 🚨 Troubleshooting

### Service nicht erreichbar
```bash
# Prüfe ob Orchestrator läuft
curl http://localhost:8001/api/v1/health
```

### Out of Memory
```bash
# Reduziere concurrent requests
python -m tests.load_test --concurrent 50 --duration 30
```

### Timeouts
```bash
# Erhöhe Timeout in den Test-Skripten oder reduziere Last
python -m tests.load_test --concurrent 50 --duration 60
```

---

## 📚 Weitere Informationen

- **Bestehende Tests:** Siehe `TEST_OVERVIEW_BYPASS_ATTACKS.md`
- **Performance Tests:** `scripts/performance_stress_test.py`
- **Red Team Tests:** `scripts/hardcore_red_team_assault.py`
- **Test Plan:** `docs/TEST_PLAN_2025_12_10.md`

---

**Viel Erfolg beim Testen! 🚀**

