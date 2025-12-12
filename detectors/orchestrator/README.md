# LLM Firewall Orchestrator

**Hierarchischer Router für Detektor-Orchestrierung**

Intelligenter Router-Service, der dynamisch entscheidet, welche Detektoren für einen gegebenen Request ausgeführt werden sollen, basierend auf Kontext-Analyse, dynamischen Policies und kontinuierlichem Lernen.

---

## 🚀 Quick Start

### Installation

```bash
cd detectors/orchestrator
pip install -r requirements.txt
```

### Start Service

```bash
# Mit Learning aktiviert
export ENABLE_ADAPTIVE_LEARNING=true
export FEEDBACK_REPOSITORY_TYPE=memory  # oder: hybrid, redis, postgres

python -m uvicorn api.main:app --reload --port 8001
```

### Testen

```bash
# Phase 5.3 Tests
python scripts/test_phase_5_3.py

# API testen
curl http://localhost:8001/api/v1/route-and-detect \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "text": "import os; os.system(\"rm -rf /\")",
    "source_tool": "code_interpreter",
    "user_risk_tier": 1
  }'
```

---

## 📋 Features

### Phase 5.1: Foundation ✅
- Basis-Router mit fester Policy
- Einfache Detektor-Orchestrierung
- API-Endpoints

### Phase 5.2: Intelligence ✅
- **Erweiterte Kontextanalyse**
  - Sprache, Lesbarkeit, Komplexität
  - Code-Patterns, Multilingual, Obfuskation
- **Dynamische Policies** (YAML, Hot-Reload)
- **Intelligente Routing-Entscheidungen**
- **Optimierte Ausführung** (parallel/sequential)

### Phase 5.3: Learning ✅
- **Automatische Feedback-Collection**
- **Performance-Metriken** (Precision, Recall, F1)
- **Policy-Optimierung** basierend auf Feedback
- **Pattern Detection**
- **Manuelles Human-Feedback**

---

## 🔧 Konfiguration

### Environment Variables

```bash
# Router-Typ
USE_INTELLIGENT_ROUTER=true          # Phase 5.2
ENABLE_ADAPTIVE_LEARNING=true        # Phase 5.3

# Feedback Repository
FEEDBACK_REPOSITORY_TYPE=hybrid      # memory, redis, postgres, hybrid

# Redis (für hybrid/redis)
REDIS_CLOUD_HOST=...
REDIS_CLOUD_PORT=19088
REDIS_CLOUD_PASSWORD=...

# PostgreSQL (für hybrid/postgres)
POSTGRES_CONNECTION_STRING=postgresql://user:pass@host:port/db

# Detector URLs
CODE_INTENT_URL=http://localhost:8000
PERSUASION_URL=http://localhost:8002
CONTENT_SAFETY_URL=http://localhost:8003
```

### Policy-Konfiguration

Policies werden in `config/advanced_policies.yaml` definiert:

```yaml
policies:
  - name: "code_intensive_workflow"
    priority: 100
    enabled: true
    activation_threshold: 0.8
    conditions:
      - type: "simple"
        expression: "context.get('source_tool') in ['code_interpreter', 'shell']"
        weight: 0.4
    detectors:
      - name: "code_intent"
        mode: "required"
        timeout_ms: 800
        priority: 1
    strategy: "parallel"
    max_latency: 1300
```

---

## 📡 API-Endpoints

### Routing

**POST `/api/v1/route-and-detect`**
- Hauptendpunkt für Routing und Detektion
- Request: `RouterRequest` (text, context, source_tool, etc.)
- Response: `RouterResponse` (blocked, risk_score, detector_results)

### Learning (Phase 5.3)

**GET `/api/v1/learning/metrics`**
- Lern-Metriken (Feedback, Detektor-Performance)

**GET `/api/v1/learning/optimization-history`**
- Optimierungsverlauf

**POST `/api/v1/learning/submit-feedback`**
- Manuelles Feedback einreichen

**POST `/api/v1/learning/trigger-optimization`**
- Manuelle Optimierung auslösen

**GET `/api/v1/learning/detector-performance`**
- Detaillierte Detektor-Performance

---

## 🏗️ Architektur

```
Orchestrator Service
├── LearningRouterService (Phase 5.3)
│   ├── IntelligentRouterService (Phase 5.2)
│   │   ├── AdvancedContextAnalyzer
│   │   └── DynamicPolicyEngine
│   ├── FeedbackCollector
│   └── AdaptivePolicyOptimizer
└── FeedbackRepository
    ├── Redis (Echtzeit)
    ├── PostgreSQL (Persistent)
    └── Memory (Fallback)
```

---

## 📚 Dokumentation

- **Phase 5.1:** Foundation - Basis-Router
- **Phase 5.2:** Intelligence - Erweiterte Kontextanalyse
- **Phase 5.3:** Learning - Kontinuierliches Lernen
- **Phase 5 Complete:** Vollständige Übersicht

Siehe:
- `PHASE_5_1_ORCHESTRATOR_COMPLETE.md`
- `PHASE_5_2_COMPLETE.md` (falls vorhanden)
- `PHASE_5_3_COMPLETE.md`
- `PHASE_5_COMPLETE.md`

---

## 🧪 Tests

```bash
# Phase 5.3 Tests
python scripts/test_phase_5_3.py

# Integration Tests
python scripts/test_integration.py
```

---

## 📦 Dependencies

### Required
- `fastapi>=0.104.0`
- `uvicorn>=0.24.0`
- `aiohttp>=3.9.0`
- `pydantic>=2.5.0`
- `pyyaml>=6.0`

### Optional (Phase 5.2)
- `textstat>=0.7.3` - Text analysis
- `language-tool-python>=2.7.1` - Language analysis

### Optional (Phase 5.3 - für Redis/PostgreSQL)
- `redis` - Redis client
- `sqlalchemy` - PostgreSQL ORM
- `psycopg2-binary` oder `pg8000` - PostgreSQL driver

---

## 🎯 Status

**Phase 5: Hierarchischer Router** ✅ **COMPLETE**

- ✅ Phase 5.1: Foundation
- ✅ Phase 5.2: Intelligence
- ✅ Phase 5.3: Learning

**Status:** ✅ **PRODUKTIONSBEREIT**

---

**Version:** 1.0  
**Datum:** 2025-12-11
