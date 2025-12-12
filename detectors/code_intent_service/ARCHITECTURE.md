# Hexagonale Architektur - Code Intent Service

## 📁 Projektstruktur

```
code_intent_service/
├── api/                          # Äußere Schicht - HTTP Interface
│   ├── controllers/              # Request Handler
│   ├── models/                   # Request/Response DTOs
│   └── middleware/               # Cross-cutting Concerns (Logging, Validation)
│
├── application/                  # Anwendungslogik
│   ├── services/                 # Orchestriert Domänenlogik
│   └── use_cases/                # Application-specific Workflows
│
├── domain/                       # Kern-Domäne (PURE - keine Abhängigkeiten)
│   ├── entities/                 # Core Business Objects
│   │   └── detection_result.py
│   ├── value_objects/            # Immutable Value Objects
│   │   └── risk_score.py
│   ├── services/                 # Domain Service Interfaces (Protocols)
│   │   └── benign_validator.py
│   └── repositories/             # Repository Interfaces (Protocols)
│
├── infrastructure/               # Äußere Schicht - External Dependencies
│   ├── ml_models/                # ML Model Loaders & Inference
│   ├── rule_engines/             # Pattern Matchers & Validators
│   │   ├── benign_validators/    # Spezialisierte Validatoren
│   │   │   ├── temporal_execution_validator.py
│   │   │   ├── zero_width_validator.py
│   │   │   ├── question_context_validator.py
│   │   │   ├── jailbreak_validator.py
│   │   │   └── harmful_metaphor_validator.py
│   │   ├── benign_validator_composite.py
│   │   └── benign_validator_factory.py
│   ├── repositories/             # Concrete Repository Implementations
│   └── config/                   # Configuration
│       └── settings.py           # Pydantic Settings
│
└── main.py                       # FastAPI App Builder
```

## 🏗️ Architektur-Prinzipien

### 1. **Domain Layer (PURE)**
- **Keine Abhängigkeiten** auf Infrastructure, API oder Application
- Nur Business Logic
- Verwendet **Protocols** (structural typing) statt Interfaces für Performance
- Entities und Value Objects sind immutable wo möglich

### 2. **Infrastructure Layer**
- Implementiert Domain Interfaces/Protocols
- Konkrete Implementierungen (ML Models, Rule Engines, Repositories)
- Kann ausgetauscht werden ohne Domain zu ändern

### 3. **Application Layer**
- Orchestriert Domain Services
- Use Cases für spezifische Workflows
- Abhängig von Domain, aber nicht von Infrastructure

### 4. **API Layer**
- HTTP Interface (FastAPI)
- Request/Response DTOs
- Middleware für Cross-cutting Concerns
- Abhängig von Application Layer

## 🔄 Dependency Flow

```
API → Application → Domain ← Infrastructure
```

**Wichtig:** Domain importiert **NICHTS** von außen!

## 📊 Aktueller Status

### ✅ Erstellt:
- [x] Projektstruktur (alle Ordner)
- [x] Config ausgelagert (`infrastructure/config/settings.py`)
- [x] Domain Entities (`DetectionResult`)
- [x] Domain Value Objects (`RiskScore`)
- [x] Domain Services Protocols (`BenignValidator`)
- [x] Infrastructure Validators (5 spezialisierte Validatoren)
- [x] Composite Validator Pattern
- [x] Validator Factory

### 🚧 In Arbeit:
- [ ] Weitere Validatoren aus `is_likely_benign()` extrahieren
- [ ] ML Model Interfaces & Implementations
- [ ] Rule Engine Interfaces & Implementations
- [ ] Repository Interfaces & Implementations
- [ ] Application Services
- [ ] Use Cases
- [ ] API Controllers & DTOs
- [ ] Dependency Injection Container
- [ ] main.py Refactoring

## 🎯 Nächste Schritte

1. **Weitere Validatoren extrahieren** aus `is_likely_benign()`:
   - Content Safety Validator
   - Poetic Context Validator
   - Documentation Context Validator
   - Technical Discussion Validator

2. **ML Model Interfaces** definieren:
   - `IntentClassifier` Protocol
   - `QuantumModelLoader` Implementation
   - `CodeBERTClassifier` Implementation

3. **Rule Engine Interfaces**:
   - `RuleEngine` Protocol
   - `PatternMatcher` Implementation

4. **Application Service**:
   - `DetectionService` - orchestriert alle Komponenten

5. **Dependency Injection**:
   - Container für alle Abhängigkeiten
   - Factory Pattern für Komponenten

6. **main.py Refactoring**:
   - FastAPI App Builder
   - Endpoints delegieren an Controllers
   - Keine Business Logic in main.py

## 🔍 Beispiel: Validator Pattern

**Vorher (monolithisch):**
```python
def is_likely_benign(text: str) -> bool:
    # 600+ Zeilen Code
    # Alles in einer Funktion
    ...
```

**Nachher (hexagonal):**
```python
# Domain Protocol
class BenignValidator(Protocol):
    def is_benign(self, text: str) -> bool: ...

# Infrastructure Implementation
class TemporalExecutionValidator:
    def is_benign(self, text: str) -> bool:
        # Nur temporale Patterns
        ...

# Composite
validators = [
    TemporalExecutionValidator(),
    ZeroWidthValidator(),
    QuestionContextValidator(),
    ...
]
composite = BenignValidatorComposite(validators)
```

## 📈 Vorteile

1. **Wartbarkeit**: Änderungen isoliert in einem Modul
2. **Testbarkeit**: Einfache Mocking von Abhängigkeiten
3. **Erweiterbarkeit**: Neue Validatoren als Plugins
4. **Deployability**: Unabhängiges Scaling von Komponenten
5. **Observability**: Strukturierte Logs, bessere Metriken

