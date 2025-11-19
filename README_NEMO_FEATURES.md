# NVIDIA NeMo-inspired Features

## Übersicht

Dieses Dokument beschreibt die Integration von NVIDIA NeMo-inspirierten Performance-Features in die llm-security-firewall.

## Implementierte Komponenten

### 1. Topic Fence (`src/llm_firewall/input_protection/topic_fence.py`)

**Zweck:** Schneller Vorfilter für Topic-Validierung

**Features:**
- Nutzt `sentence-transformers/all-MiniLM-L6-v2` (klein & schnell)
- Singleton-Pattern für Performance (Modell wird nur einmal geladen)
- Cosine-Similarity zwischen User-Input und erlaubten Topics
- Konfigurierbarer Threshold (Standard: 0.3)

**Verwendung:**
```python
from llm_firewall.input_protection.topic_fence import TopicFence

fence = TopicFence()
is_on_topic = fence.is_on_topic(
    user_input="Was ist 2+2?",
    allowed_topics=["Mathe", "Physik"],
    threshold=0.3
)
```

### 2. Canned Responses (`kids_policy/response_templates.py`)

**Zweck:** Deterministische, pädagogisch wertvolle Absagen

**Features:**
- Statische Templates für verschiedene Block-Gründe
- Unterstützt Deutsch und Englisch
- Templates für: OFF_TOPIC, UNSAFE_CONTENT, TRUTH_VIOLATION, VIOLENCE, HATE_SPEECH, SEXUAL_CONTENT

**Verwendung:**
```python
from kids_policy.response_templates import SafetyTemplates

response = SafetyTemplates.get_template("OFF_TOPIC", language="de")
```

### 3. Fallback Judge (`kids_policy/fallback_judge.py`)

**Zweck:** LLM-as-a-Judge für fehlende YAML canonical facts

**Features:**
- Mock-Modus mit Keyword-Heuristiken (für Demo)
- Vorbereitet für echte LLM-Integration
- Altersgruppen-spezifische System-Prompts (6-8, 9-12, 13-15)

**Verwendung:**
```python
from kids_policy.fallback_judge import SafetyFallbackJudge

judge = SafetyFallbackJudge(llm_provider=None)  # Mock mode
is_safe = judge.evaluate_safety("Was ist 2+2?", age_band="9-12")
```

### 4. Proxy Server (`src/proxy_server.py`)

**Zweck:** HTTP-Proxy mit integrierten NeMo-Features

**Architektur:**
1. **Layer 1 (Fast Check):** TopicFence prüft On-Topic
2. **Layer 2 (Deep Check):** Platzhalter für RC10b/KidsValidator
3. **Layer 3 (Fallback):** SafetyFallbackJudge wenn kein YAML existiert

**Verwendung:**

**FastAPI-Modus (empfohlen):**
```bash
pip install fastapi uvicorn
python src/proxy_server.py
```

**CLI-Modus (für Tests ohne FastAPI):**
```bash
python src/proxy_server.py
```

**API-Endpoint:**
```bash
curl -X POST http://localhost:8080/proxy/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Was ist 2+2?", "age_band": "9-12"}'
```

## Test-Skripte

### Demo-Skript
```bash
python scripts/demo_nemo_features.py
```

### Einfacher Topic-Fence-Test
```bash
python scripts/test_topic_fence_simple.py
```

## Bekannte Probleme

### TensorFlow/Keras Dependency-Konflikt

**Problem:** `sentence-transformers` benötigt `tf-keras`, aber Keras 3 ist installiert.

**Lösung (optional):**
```bash
pip install tf-keras
```

**Hinweis:** Dies ist nur ein Dependency-Konflikt, kein Code-Problem. Die Logik funktioniert korrekt, sobald die Dependencies korrekt installiert sind.

## Nächste Schritte

1. **Layer 2 Integration:** RC10b AgenticCampaignDetector oder KidsValidator einbinden
2. **Fallback Judge "scharf schalten":** Echte LLM-Integration (OpenAI, Anthropic, Ollama)
3. **Performance-Optimierung:** Caching, Batch-Processing für TopicFence
4. **Monitoring:** Metriken für Response-Zeiten, Block-Rates, etc.

## Referenzen

- NVIDIA NeMo Guardrails: https://github.com/NVIDIA/NeMo-Guardrails
- sentence-transformers: https://www.sbert.net/

