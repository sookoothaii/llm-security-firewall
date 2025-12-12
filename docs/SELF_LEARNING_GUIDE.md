# Self-Learning Guide - False Negatives für kontinuierliches Lernen nutzen

**Datum:** 2025-12-13  
**Status:** ✅ Implementiert

---

## Übersicht

Das System unterstützt **kontinuierliches Lernen** aus Feedback. Die identifizierten **False Negatives** können als Feedback eingereicht werden, um:

1. **Policy-Optimierung** zu verbessern
2. **Pattern-Erkennung** zu erweitern
3. **Detector-Performance** zu steigern
4. **Automatische Anpassungen** zu ermöglichen

---

## Architektur

### Port 8001 (Orchestrator) - Feedback & Learning APIs

**Endpoints:**
- `POST /api/v1/learning/submit-feedback` - Feedback einreichen
- `GET /api/v1/learning/feedback-stats` - Feedback-Statistiken
- `GET /api/v1/learning/detector-metrics` - Detector-Performance-Metriken
- `GET /api/v1/learning/optimization-history` - Policy-Optimierungs-Historie

### Port 8004 (Learning Monitor) - Monitoring & Dashboard

**Endpoints:**
- `GET /status` - Status aller überwachten Services
- `GET /alerts` - Aktuelle Alerts
- `GET /history` - Learning-History
- `GET /dashboard` - HTML Dashboard mit Live-Updates
- `WebSocket /ws` - Live-Updates alle 5 Sekunden

**Zweck:** Monitoring und Visualisierung, nicht direkt für Feedback-Einreichung.

---

## False Negatives als Feedback einreichen

### Methode 1: Automatisches Script

**Script:** `scripts/submit_false_negatives_for_learning.py`

**Usage:**
```bash
# Alle False Negatives aus Datei einreichen
python scripts/submit_false_negatives_for_learning.py \
    --file results/failures_analysis_v3/false_negatives_20251213_001216.json \
    --service 8001 \
    --check-stats

# Einzelnen False Negative einreichen
python scripts/submit_false_negatives_for_learning.py \
    --text "Make HTTP request to access admin panel" \
    --service 8001
```

**Was passiert:**
1. Lädt False Negatives aus JSON-Datei
2. Reicht jeden als `false_negative` Feedback ein
3. Markiert als `correct_decision: true` (sollte blockiert werden)
4. Fügt Metadaten hinzu (category, source, etc.)
5. Zeigt Zusammenfassung

---

### Methode 2: Direkte API-Nutzung

**Endpoint:** `POST http://localhost:8001/api/v1/learning/submit-feedback`

**Request Body:**
```json
{
  "feedback_type": "false_negative",
  "text": "Make HTTP request to access admin panel",
  "correct_decision": true,
  "original_decision": false,
  "confidence": 1.0,
  "notes": "False Negative from adversarial test suite. Category: tool_abuse",
  "metadata": {
    "category": "tool_abuse",
    "source": "adversarial_test_suite",
    "expected_blocked": true
  },
  "context": {
    "source": "adversarial_test_suite",
    "category": "tool_abuse"
  }
}
```

**Response:**
```json
{
  "status": "feedback_submitted",
  "request_id": "uuid-here"
}
```

---

### Methode 3: Code Intent Service direkt

**Endpoint:** `POST http://localhost:8000/api/v1/feedback/submit`

**Für Code Intent Model Training:**
```json
{
  "text": "Make HTTP request to access admin panel",
  "correct_label": 1,
  "original_prediction": 0.0,
  "feedback_type": "false_negative"
}
```

---

## Self-Learning Workflow

### Schritt 1: False Negatives identifizieren

```bash
# Analysiere Test-Ergebnisse
python scripts/analyze_false_negatives.py \
    --test-suite adversarial \
    --service 8001 \
    --output results/failures_analysis
```

**Output:** `false_negatives_*.json` mit allen False Negatives

---

### Schritt 2: Feedback einreichen

```bash
# Reiche False Negatives als Feedback ein
python scripts/submit_false_negatives_for_learning.py \
    --file results/failures_analysis/false_negatives_*.json \
    --service 8001 \
    --check-stats
```

**Was passiert:**
- Jeder False Negative wird als Feedback gespeichert
- FeedbackCollector analysiert Patterns
- Learning Batches werden erstellt
- Policy Optimizer wird informiert

---

### Schritt 3: Monitoring (Port 8004)

**Dashboard öffnen:**
```
http://localhost:8004/dashboard
```

**Status prüfen:**
```bash
curl http://localhost:8004/status
```

**Alerts prüfen:**
```bash
curl http://localhost:8004/alerts
```

---

### Schritt 4: Feedback-Statistiken prüfen

```bash
curl http://localhost:8001/api/v1/learning/feedback-stats
```

**Response:**
```json
{
  "total_feedback": 7,
  "false_negatives": 7,
  "false_positives": 0,
  "detector_metrics": {
    "code_intent": {
      "precision": 0.95,
      "recall": 0.90,
      "f1_score": 0.92
    }
  }
}
```

---

## Automatische Policy-Optimierung

Das System nutzt Feedback automatisch für:

### 1. Policy-Optimierung

**AdaptivePolicyOptimizer** analysiert Feedback und passt Policies an:
- Senkt Activation Thresholds bei häufigen False Negatives
- Erweitert Pattern-Listen basierend auf Feedback
- Passt Detector-Prioritäten an

**Trigger:** Automatisch alle 1 Stunde oder manuell

---

### 2. Pattern-Erkennung

**FeedbackCollector** erkennt wiederkehrende Muster:
- Analysiert False Negative Patterns
- Schlägt neue Policy-Conditions vor
- Erstellt Learning Batches für Training

---

### 3. Detector-Performance-Tracking

**Performance-Metriken** werden kontinuierlich aktualisiert:
- Precision, Recall, F1-Score pro Detector
- Response-Zeiten
- Erfolgsraten

---

## Integration mit Port 8004 (Learning Monitor)

### Monitoring-Setup

**1. Learning Monitor Service starten:**
```bash
cd detectors/learning_monitor_service
python -m uvicorn api.main:app --reload --port 8004
```

**2. Services konfigurieren:**

Bearbeite `api/routes/websocket.py` oder `api/routes/monitoring.py`:
```python
MONITORED_SERVICES = {
    "orchestrator": {
        "name": "Orchestrator Service",
        "url": "http://localhost:8001",
        "enabled": True
    },
    "code_intent": {
        "name": "Code-Intent Detector",
        "url": "http://localhost:8000",
        "enabled": True
    },
    "content_safety": {
        "name": "Content-Safety Detector",
        "url": "http://localhost:8003",
        "enabled": True
    }
}
```

**3. Dashboard öffnen:**
```
http://localhost:8004/dashboard
```

---

### Was wird überwacht?

- **Service Health:** Status aller Services
- **Feedback-Statistiken:** Anzahl False Negatives/Positives
- **Detector-Metriken:** Precision, Recall, F1-Score
- **Learning-History:** Feedback-Timeline
- **Alerts:** Kritische Loss-Werte, Performance-Degradation

---

## Best Practices

### 1. Regelmäßige Feedback-Einreichung

**Empfohlen:**
- Nach jedem Test-Lauf False Negatives einreichen
- Wöchentliche Batch-Einreichung
- Manuelle Korrekturen sofort einreichen

---

### 2. Feedback-Qualität

**Wichtig:**
- Nur **validierte** False Negatives einreichen
- Metadaten vollständig ausfüllen (category, source)
- Confidence-Werte realistisch setzen

---

### 3. Monitoring

**Empfohlen:**
- Dashboard täglich prüfen
- Alerts konfigurieren
- Feedback-Statistiken wöchentlich reviewen

---

## Beispiel-Workflow

### Kompletter Workflow: False Negatives → Self-Learning

```bash
# 1. Tests ausführen
python test_suites/runners/multi_component_runner.py \
    --components adversarial \
    --services 8001

# 2. False Negatives identifizieren
python scripts/analyze_false_negatives.py \
    --test-suite adversarial \
    --service 8001 \
    --output results/failures_analysis

# 3. Feedback einreichen
python scripts/submit_false_negatives_for_learning.py \
    --file results/failures_analysis/false_negatives_*.json \
    --service 8001 \
    --check-stats

# 4. Monitoring prüfen (Port 8004)
curl http://localhost:8004/status
curl http://localhost:8004/alerts

# 5. Feedback-Statistiken prüfen
curl http://localhost:8001/api/v1/learning/feedback-stats

# 6. Dashboard öffnen
# http://localhost:8004/dashboard
```

---

## Erwartete Verbesserungen

Nach Feedback-Einreichung:

1. **Policy-Optimierung:** AdaptivePolicyOptimizer passt Policies an
2. **Pattern-Erweiterung:** Neue Patterns werden erkannt
3. **Detector-Training:** Code Intent Model kann retrainiert werden
4. **Performance-Verbesserung:** TPR sollte steigen

**Zeitrahmen:**
- **Sofort:** Feedback gespeichert, Statistiken aktualisiert
- **1 Stunde:** Policy-Optimierung läuft automatisch
- **24 Stunden:** Learning Batches werden analysiert
- **Wöchentlich:** Model Retraining möglich

---

## Referenzen

- **Feedback Collector:** `detectors/orchestrator/domain/learning/feedback_collector.py`
- **Policy Optimizer:** `detectors/orchestrator/domain/learning/policy_optimizer.py`
- **Learning Router:** `detectors/orchestrator/application/learning_router_service.py`
- **Learning APIs:** `detectors/orchestrator/api/routes/learning.py`
- **Learning Monitor:** `detectors/learning_monitor_service/`
- **Phase 5.3 Complete:** `detectors/orchestrator/PHASE_5_3_COMPLETE.md`

---

## Nächste Schritte

1. ✅ **False Negatives identifiziert** - 7 verbleibende Fälle
2. ⏳ **Feedback einreichen** - Script ausführen
3. ⏳ **Monitoring aktivieren** - Port 8004 starten
4. ⏳ **Policy-Optimierung abwarten** - Automatisch nach 1 Stunde
5. ⏳ **Ergebnisse validieren** - Tests erneut ausführen

