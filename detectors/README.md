# Detector Microservices - LLM Firewall Battle Plan
**Date:** 2025-12-07  
**Status:** Phase 2 - Microservices Implementation  
**Version:** 1.0

---

## Übersicht

Detector Microservices für das **Two-Ring Defense System**:
- **Code-Intent Detector**: Erkennt bösartige Code-Intentionen (Cybercrime, SQL Injection, etc.)
- **Persuasion/Misinfo Detector**: Erkennt persuasive Rhetorik und Fehlinformationen

---

## Services

### 1. Code-Intent Detector Service

**Port:** 8001  
**Endpoint:** `POST /v1/detect`

**Features:**
- Rule-based Pattern Matching (Shell, SQL, Code Execution)
- Optional ML Model (CodeBERT) für erweiterte Erkennung
- Prometheus Metrics
- Health Check Endpoint

**Start:**
```bash
cd code_intent_service
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8001
```

### 2. Persuasion/Misinfo Detector Service

**Port:** 8002  
**Endpoint:** `POST /v1/detect`

**Features:**
- Rule-based Pattern Matching (Persuasion, Misinformation)
- Deutsche Patterns ("die Medien verschweigen", etc.)
- Context-aware Scoring (Health, Finance, Politics)
- Prometheus Metrics
- Health Check Endpoint

**Start:**
```bash
cd persuasion_service
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8002
```

---

## Testing

### Test Client

```bash
# Start services first
cd code_intent_service && uvicorn main:app --port 8001 &
cd persuasion_service && uvicorn main:app --port 8002 &

# Run tests
python test_client.py
```

### Manual Testing

```bash
# Health Check
curl http://localhost:8001/health
curl http://localhost:8002/health

# Test Code Intent
curl -X POST http://localhost:8001/v1/detect \
  -H "Content-Type: application/json" \
  -d '{"text": "rm -rf /", "context": {"tool": "shell"}}'

# Test Persuasion
curl -X POST http://localhost:8002/v1/detect \
  -H "Content-Type: application/json" \
  -d '{"text": "Die Medien verschweigen die Wahrheit", "context": {"topic": "politics"}}'
```

---

## Integration mit FirewallEngineV3

Die Services werden automatisch über `DetectorOrchestrationLayer` aufgerufen, wenn:

1. **Risk Score** > Threshold (konfiguriert in `config/policy.yml`)
2. **Category Match** (Cybercrime → Code-Intent, Misinformation → Persuasion)
3. **Tool Risk Profile** (High-Risk Tools → Code-Intent)

**Konfiguration aktivieren:**

```yaml
# config/detectors.yml
detectors:
  code_intent:
    enabled: true
    endpoint: "http://localhost:8001/v1/detect"
  
  persuasion_misinfo:
    enabled: true
    endpoint: "http://localhost:8002/v1/detect"
```

---

## API Format

### Request

```json
{
  "text": "user input text",
  "context": {
    "topic": "health",
    "tool": "shell"
  },
  "risk_score": 0.6,
  "categories": ["cybercrime"],
  "tools": ["vm_shell"]
}
```

### Response

```json
{
  "detector_name": "code_intent",
  "risk_score": 0.85,
  "category": "cybercrime",
  "confidence": 0.90,
  "matched_patterns": ["destructive_file_operation", "remote_code_fetch"],
  "metadata": {
    "method": "rule_based",
    "context": {}
  },
  "error": null,
  "latency_ms": 12.5
}
```

---

## Performance

- **Latency:** < 50ms (rule-based), < 200ms (with ML model)
- **Throughput:** > 100 req/s per service
- **Resource Usage:** ~50MB RAM (rule-based), ~500MB (with ML model)

---

## Deployment

### Development

```bash
# Terminal 1: Code Intent Service
cd detectors/code_intent_service
uvicorn main:app --reload --port 8001

# Terminal 2: Persuasion Service
cd detectors/persuasion_service
uvicorn main:app --reload --port 8002

# Terminal 3: Test
cd detectors
python test_client.py
```

### Production

Für Production-Deployment:
- Use process manager (systemd, supervisor)
- Add reverse proxy (nginx)
- Enable Prometheus metrics scraping
- Set up health check monitoring

---

## Troubleshooting

### Service nicht erreichbar

```bash
# Check if service is running
curl http://localhost:8001/health

# Check logs
# (logs are printed to stdout/stderr)
```

### High Latency

- Rule-based detection: < 50ms
- ML model loading: First request may be slow
- Consider caching for repeated patterns

### False Positives

- Adjust pattern weights in `analyze_code_rules()` / `analyze_persuasion_patterns()`
- Add whitelist patterns for common false positives
- Use context information to reduce false positives

---

## Next Steps

1. **Fine-tune ML Models** (optional)
2. **Add more patterns** based on bypass analysis
3. **Implement caching** for common patterns
4. **Add A/B testing** framework
5. **Observability** (Prometheus + Grafana)

---

**Document Version:** 1.0  
**Last Updated:** 2025-12-07  
**Status:** Phase 2 - Microservices Complete ✅
