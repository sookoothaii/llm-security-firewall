# Shared Components - Detector Services

**Version:** 1.0.0  
**Status:** ✅ Implemented  
**Purpose:** Gemeinsame hexagonale Architektur-Komponenten für alle Detector Services

---

## Übersicht

Die Shared Components bieten eine einheitliche Basis für alle Detector Services:
- ✅ **Shared Domain** - Gemeinsame Entities, Value Objects, Ports
- ✅ **Shared Infrastructure** - Base Composition Root, Adapters
- ✅ **Shared API** - Gemeinsame Request/Response Models, Middleware

---

## Struktur

```
shared/
├── domain/                      # Shared Domain Layer (PURE)
│   ├── entities/               # DetectionResult, FeedbackSample
│   ├── value_objects/          # RiskScore, Confidence
│   └── ports/                  # DetectorPort, CachePort, DecoderPort, FeedbackRepositoryPort
│
├── infrastructure/             # Shared Infrastructure
│   ├── composition/            # BaseCompositionRoot
│   ├── gates/                 # (Platzhalter für Root-Gates)
│   ├── detectors/             # (Platzhalter für Root-Detectors)
│   └── adapters/              # (Platzhalter für Root-Adapters)
│
└── api/                        # Shared API Components
    ├── models/                 # BaseDetectionRequest, BaseDetectionResponse
    └── middleware/             # LoggingMiddleware, ErrorHandlerMiddleware
```

---

## Verwendung

### 1. Shared Domain Objects

```python
from detectors.shared.domain.value_objects import RiskScore
from detectors.shared.domain.entities import DetectionResult

# RiskScore erstellen
risk = RiskScore.create(value=0.85, confidence=0.9, source="code_intent")

# DetectionResult erstellen
result = DetectionResult(
    risk_score=risk,
    is_blocked=True,
    detector_name="code_intent",
    matched_patterns=["destructive_command"]
)
```

### 2. Shared Ports

```python
from detectors.shared.domain.ports import DetectorPort, CachePort

# Service implementiert DetectorPort
class MyDetectorService:
    def detect(self, text: str, context: dict = None) -> DetectionResult:
        # Implementation
        ...
    
    def get_name(self) -> str:
        return "my_detector"
```

### 3. Base Composition Root

```python
from detectors.shared.infrastructure.composition import BaseCompositionRoot

class MyServiceCompositionRoot(BaseCompositionRoot):
    """Service-spezifische Composition Root"""
    
    def create_my_service(self):
        # Nutzt Base-Methoden
        cache = self.create_cache_adapter()  # Aus Base
        decoder = self.create_decoder()      # Aus Base
        
        # Service-spezifische Komponenten
        # ...
        
        return MyService(cache=cache, decoder=decoder)
```

### 4. Shared API Models

```python
from detectors.shared.api.models import BaseDetectionRequest, BaseDetectionResponse

# Request Model
class MyDetectionRequest(BaseDetectionRequest):
    """Service-spezifische Erweiterung"""
    custom_field: Optional[str] = None

# Response Model
class MyDetectionResponse(BaseDetectionResponse):
    """Service-spezifische Erweiterung"""
    pass
```

### 5. Shared Middleware

```python
from detectors.shared.api.middleware import LoggingMiddleware, ErrorHandlerMiddleware
from fastapi import FastAPI

app = FastAPI()

# Logging Middleware
app.add_middleware(LoggingMiddleware)

# Error Handler
app.add_exception_handler(
    RequestValidationError,
    ErrorHandlerMiddleware.validation_exception_handler
)
app.add_exception_handler(
    Exception,
    ErrorHandlerMiddleware.general_exception_handler
)
```

---

## Integration mit Root-Projekt

Die Shared Components nutzen bewährte Patterns aus dem Root-Projekt:

1. **Protocol Definitions** - Analog zu `src/llm_firewall/core/ports/`
2. **Composition Root** - Analog zu `src/llm_firewall/app/composition_root.py`
3. **Cache Adapter** - Nutzt `DecisionCacheAdapter` aus Root (falls verfügbar)
4. **Normalization** - Nutzt `NormalizationLayer` oder `NormalizationGuard` aus Root (falls verfügbar)

**Graceful Fallback:** Wenn Root-Komponenten nicht verfügbar sind, werden Null-Adapter verwendet.

---

## Vorteile

1. **Konsistenz** - Alle Services nutzen die gleichen Patterns
2. **Wiederverwendbarkeit** - Einmal implementiert, überall nutzbar
3. **Wartbarkeit** - Änderungen an Shared Components profitieren alle Services
4. **Testbarkeit** - Domain Layer ist pure, einfach zu mocken
5. **Erweiterbarkeit** - Neue Services folgen dem gleichen Muster

---

## Nächste Schritte

1. ✅ Shared Components erstellt
2. 🔄 Code Intent Service auf Shared Components umstellen
3. 🔄 Andere Services refactoren (Persuasion, Content Safety, Learning Monitor)
4. 🔄 Root-Elemente integrieren (Gates, Detectors)

---

**Status:** Phase 1 Complete ✅  
**Nächster Schritt:** Code Intent Service Integration

