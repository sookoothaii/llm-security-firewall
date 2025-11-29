# Core Firewall v2.0 - Diagnose & Gap-Analysis
**Date:** 2025-11-29
**Status:** DIAGNOSIS COMPLETE - Ready for Strategy Decision

---

## 1. Bestandsaufnahme: Verzeichnisstruktur

### `src/` Hauptverzeichnis
- **`firewall_engine.py`** (1070 Zeilen) - Alte Core Engine (FastAPI Proxy Server)
- **`proxy_server.py`** - Zusätzlicher Proxy-Wrapper (vermutlich Legacy)
- **`kids_policy/`** - Kids Policy Engine (v2.1.0-HYDRA) als Submodul
- **`layer15/`** - Spezialisierte Layer-15-Komponenten (Age Router, Crisis, etc.)

### `src/llm_firewall/` Modulare Architektur
- **`detectors/`** - 25+ Detektoren (Unicode, Bidi, Encoding, Jailbreak, etc.)
- **`gates/`** - 10+ Gate-Komponenten (Steganography, Normalization, Safety Sandwich, etc.)
- **`agents/`** - Agentic Campaign Detection (RC10b), Memory, Inspector
- **`safety/`** - Ensemble Validator, Pattern Detector, Embedding Detector
- **`pipeline/`** - Pipeline-Orchestrierung
- **`tools/`** - **1 Datei** (Tool-bezogene Logik - vermutlich minimal)

**Kritische Beobachtung:** `tools/` enthält nur 1 Datei - **keine umfassende Tool-Call-Sicherheit vorhanden!**

---

## 2. Code-Analyse: Alte Core Engine (`src/firewall_engine.py`)

### Pipeline-Struktur (Sequentiell, Verschachtelt)

```
1. DoS Protection (Layer -1)
   └─ Character Limit (500 chars)
   └─ Fast Regex Precheck (SecurityUtils)

2. Layer 0: SafetyFallbackJudge (Hardened Regex)
   └─ Command Injection Detection (inlined patterns)

3. NormalizationGuard
   └─ Encoding Detection & Decoding

4. Layer 0.5: Kids Policy Engine (INPUT)
   └─ validate_input() → Grooming Detection (TAG-3)
   └─ Topic Detection (für TopicFence Override)

5. SteganographyGuard
   └─ Defensive Paraphrasing (nach Kids Policy, um Grooming-Patterns zu erhalten)

6. Layer 1: TopicFence
   └─ Topic Classification
   └─ Privileged Topic Override (wenn Kids Policy Topic erkannt hat)

7. Layer 2: RC10b Campaign Detection
   └─ ArgumentInspector (DLP Lite)
   └─ AgenticCampaignDetector (Kill-Chain, Budget, Multi-Target)

8. Layer 3: LLM Generation
   └─ Ollama Cloud (Primary)
   └─ Ollama Local (Fallback 1)
   └─ LM Studio (Fallback 2)
   └─ Mock Echo (Final Fallback)

9. Layer 0.5: Kids Policy Engine (OUTPUT)
   └─ validate_output() → Truth Preservation (TAG-2)
   └─ Topic Routing für Gates/Canonical Facts

10. Fallback Safety Check (wenn Kids Policy disabled)
```

### Architektur-Charakteristika

**Stärken:**
- ✅ Modulare Komponenten (Gates, Detectors, Agents)
- ✅ Hexagonal Architecture (Kids Policy als Plugin)
- ✅ RC10b Campaign Detection integriert
- ✅ Bidirektionale Sicherheit (Input + Output)

**Schwächen:**
- ❌ **Keine Tool-Call-Erkennung** - LLM-Output wird nur als Text behandelt
- ❌ **Keine JSON-Parsing/Validierung** - Function Calling nicht abgefangen
- ❌ **Verschachtelte Pipeline** - Schwer zu erweitern (keine klare Layer-Abstraktion)
- ❌ **FastAPI-spezifisch** - Nicht als reine Engine verwendbar
- ❌ **Output-Validierung nur für Kids Policy** - Keine generische Tool-Call-Validierung

### LLM-Output-Verarbeitung

**Aktuell:**
```python
# Zeile 799-805: LLM Generation
llm_output = self._generate_llm_response(user_input)
# Zeile 811-876: Kids Policy Output Validation (nur wenn policy_engine aktiv)
if self.policy_engine:
    policy_decision = self.policy_engine.validate_output(...)
```

**Problem:**
- `llm_output` ist immer `str` (Text)
- Keine Parsing-Logik für JSON/Function Calls
- Keine Tool-Call-Extraktion
- Keine Argument-Validierung für Tool-Calls

---

## 3. Vergleich: Kids Policy v2 Engine vs. Core Firewall

### Kids Policy `firewall_engine_v2.py` (v2.1.0-HYDRA)

**Architektur:**
- ✅ **Saubere Layer-Pipeline** (Linear, nicht verschachtelt)
- ✅ **Klare Abstraktion** - Jeder Layer ist eine Komponente
- ✅ **Reine Engine** - Kein HTTP-Server, wiederverwendbar
- ✅ **Bidirektional** - `process_request()` (Input) + `validate_output()` (Output)

**Pipeline:**
```
Layer 0: UnicodeSanitizer
Layer 1-A: PersonaSkeptic
Layer 1.2: MetaExploitationGuard (HYDRA-13)
Layer 1.5: TopicRouter + ContextClassifier
Layer 1-B: SemanticGroomingGuard
Layer 4: SessionMonitor
Layer 2: TruthPreservationValidator (TAG-2) - Output
```

**Design-Prinzipien:**
- **Fast Fail** - MetaExploitationGuard vor TopicRouter
- **Adaptive Memory** - SessionMonitor trackt Violations
- **Context-Aware** - Gaming Exception (ContextClassifier)
- **Modular** - Optional Components (TopicRouter, SemanticGuard, TruthValidator)

### Core Firewall `firewall_engine.py` (v1.0)

**Architektur:**
- ❌ **Verschachtelte Pipeline** - Viele if/else-Blöcke
- ❌ **HTTP-Server gekoppelt** - FastAPI-spezifisch
- ❌ **Keine klare Layer-Abstraktion** - Hard-coded Sequenz
- ✅ **Bidirektional** - Input + Output Checks

**Gap für Protocol HEPHAESTUS:**
- ❌ **Keine Tool-Call-Pipeline** - Output wird nicht auf JSON/Function Calls geprüft
- ❌ **Keine Argument-Validierung** - Tool-Parameter werden nicht validiert
- ❌ **Keine Tool-Whitelist** - Alle Tools werden durchgelassen (wenn überhaupt erkannt)

---

## 4. Strategie-Empfehlung

### Option A: Refactoring der alten Engine (NICHT EMPFOHLEN)

**Pro:**
- Bestehende Integration bleibt erhalten
- Keine Breaking Changes für aktuelle Nutzer

**Contra:**
- ❌ **Massive Code-Changes** - 1070 Zeilen umstrukturieren
- ❌ **Verschachtelte Pipeline schwer refactorbar** - Viele Abhängigkeiten
- ❌ **FastAPI-Kopplung** - Engine nicht wiederverwendbar
- ❌ **Hohes Risiko** - Bestehende Funktionalität könnte brechen

**Aufwand:** 3-5 Tage + umfangreiche Tests

---

### Option B: Neue Core Engine v2 (EMPFOHLEN) ✅

**Vorgehen:**
1. **Erstelle `src/llm_firewall/core/firewall_engine_v2.py`**
   - Basierend auf Kids Policy `firewall_engine_v2.py` Architektur
   - **Aber:** Generisch (nicht Kids-spezifisch)
   - **Aber:** Tool-Call-Pipeline integriert

2. **Architektur-Design:**
```
Layer 0: UnicodeSanitizer (aus kids_policy)
Layer 1-A: PersonaSkeptic (aus kids_policy) - Optional
Layer 1.2: MetaExploitationGuard (HYDRA-13) - Optional
Layer 1.5: TopicRouter (aus kids_policy) - Optional
Layer 1-B: SemanticGroomingGuard (aus kids_policy) - Optional
Layer 2: ToolCallValidator (NEU - Protocol HEPHAESTUS)
   └─ JSON Parsing
   └─ Function Call Detection
   └─ Argument Validation
   └─ Tool Whitelist
   └─ Argument Sanitization
Layer 3: RC10b Campaign Detection (aus agents/)
Layer 4: SessionMonitor (aus kids_policy)
Layer 5: OutputValidator (Generisch, nicht nur Truth Preservation)
```

3. **Integration in `firewall_engine.py`:**
   - Alte Engine bleibt als Legacy-Wrapper
   - Neue Engine wird als Option aktivierbar (`use_v2_engine=True`)
   - Migration schrittweise möglich

**Pro:**
- ✅ **Saubere Architektur** - Basierend auf bewährter v2-Engine
- ✅ **Protocol HEPHAESTUS ready** - Tool-Call-Pipeline von Anfang an
- ✅ **Wiederverwendbar** - Reine Engine, kein HTTP-Server
- ✅ **Modular** - Optional Components (Kids Policy, RC10b, etc.)
- ✅ **Testbar** - Einfach zu unit-testen (keine FastAPI-Abhängigkeit)
- ✅ **Rückwärtskompatibel** - Alte Engine bleibt funktionsfähig

**Contra:**
- ⚠️ **Zwei Engines parallel** - Migration nötig (aber schrittweise möglich)
- ⚠️ **Initialer Aufwand** - 2-3 Tage für Core-Engine + Tool-Call-Layer

**Aufwand:** 2-3 Tage für Core-Engine + 1-2 Tage für Tool-Call-Layer = **3-5 Tage total**

---

### Option C: Hybrid (Kids Policy Engine erweitern)

**Vorgehen:**
- Kids Policy Engine um Tool-Call-Layer erweitern
- Als "Generic Policy Engine" umbenennen
- Core Firewall nutzt diese Engine

**Pro:**
- ✅ Nutzt bestehende v2-Architektur
- ✅ Schnell umsetzbar

**Contra:**
- ❌ **Naming-Problem** - "Kids Policy" ist nicht generisch
- ❌ **Vermischte Verantwortlichkeiten** - Kids-spezifische Logik + generische Tool-Calls
- ❌ **Schlechte Abstraktion** - Engine sollte generisch sein

**Aufwand:** 2-3 Tage, aber schlechtes Design

---

## 5. Finale Empfehlung: **Option B (Neue Core Engine v2)**

### Begründung

1. **Protocol HEPHAESTUS erfordert Tool-Call-Pipeline:**
   - JSON Parsing
   - Function Call Detection
   - Argument Validation
   - Tool Whitelist
   - Argument Sanitization

   Diese Features passen **nicht** in die verschachtelte Pipeline der alten Engine.

2. **Bewährte Architektur:**
   - Kids Policy v2 Engine hat bereits bewiesen, dass die Layer-Pipeline funktioniert
   - Wir können diese Architektur als Vorlage nehmen und generisch machen

3. **Zukunftssicher:**
   - Neue Engine ist modular und erweiterbar
   - Alte Engine bleibt als Legacy-Wrapper
   - Migration schrittweise möglich

4. **Testbarkeit:**
   - Reine Engine ohne HTTP-Server = einfache Unit-Tests
   - Tool-Call-Layer kann isoliert getestet werden

### Konkreter Plan

**Phase 1: Core Engine v2 (2-3 Tage)**
- Erstelle `src/llm_firewall/core/firewall_engine_v2.py`
- Basierend auf Kids Policy `firewall_engine_v2.py`
- Generisch machen (keine Kids-spezifische Logik)
- Optional Components: PersonaSkeptic, MetaExploitationGuard, TopicRouter, etc.

**Phase 2: Tool-Call-Layer (1-2 Tage)**
- Erstelle `src/llm_firewall/detectors/tool_call_validator.py`
- JSON Parsing für LLM-Output
- Function Call Detection
- Argument Validation
- Tool Whitelist
- Argument Sanitization

**Phase 3: Integration (1 Tag)**
- Integriere Tool-Call-Layer in Core Engine v2
- Integration in `firewall_engine.py` als Option
- Tests

**Total: 4-6 Tage**

---

## 6. Offene Fragen

1. **Tool-Whitelist-Format:** YAML, JSON, oder Code-basiert?
2. **Argument-Validierung:** Schema-basiert (JSON Schema) oder Pattern-basiert?
3. **Tool-Call-Extraktion:** Soll die Engine auch Tool-Calls aus Text extrahieren (z.B. "execute ls -la")?
4. **RC10b Integration:** Soll Tool-Call-Layer mit RC10b Campaign Detection integriert werden?

---

## 7. Nächste Schritte

1. ✅ **Diagnose abgeschlossen** - Dieser Report
2. ⏳ **Strategie-Entscheidung** - Option B empfohlen
3. ⏳ **Implementation Plan** - Detaillierter Plan für Phase 1-3
4. ⏳ **Prototype** - Core Engine v2 + Tool-Call-Layer (Minimal Viable)

---

**Status:** READY FOR IMPLEMENTATION
**Empfehlung:** Option B (Neue Core Engine v2)
**Aufwand:** 4-6 Tage
**Risiko:** Niedrig (alte Engine bleibt funktionsfähig)
