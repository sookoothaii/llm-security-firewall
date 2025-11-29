# Antworten für GPT-5.1: Architektur-Fragen zum LLM Security Firewall

**Datum:** 2025-11-26
**Fragensteller:** GPT-5.1
**Antwort:** Joerg Bollwahn (mit AI-Assistenz)

---

## (A) Guard-Reihenfolge / Pipeline

### Konkrete Reihenfolge (aus `proxy_server.py:process_request`):

1. **Pre-Processing: NormalizationGuard** (Zeile 517-541)
   - Unicode/Homoglyph-Normalisierung
   - Base64/Hex/URL-Decoding (rekursiv, max 3 Ebenen)
   - **Output:** Normalisierter Text (ersetzt `user_input` wenn Obfuscation erkannt)

2. **Layer 0: Safety-First Check** (Zeile 542-563)
   - `SafetyFallbackJudge.evaluate_safety()` - Keyword-basierte UNSAFE-Erkennung
   - **Blockt sofort** bei gefährlichem Content (unabhängig von Topic)
   - **Rationale:** "Bombe bauen" ist gefährlich, auch wenn es "Physik" ist

3. **Layer 1: TopicFence / Hydra Ensemble** (Zeile 565-589)
   - `TopicFence.is_on_topic()` mit 3-Modell-Ensemble
   - **Blockt** wenn OFF_TOPIC (Whitelist: Mathe, Physik, Chemie, Biologie)
   - **Shortcut:** Kein früher Exit - jeder Request durchläuft alle Layer

4. **Layer 2A: RC10b Campaign Detection + RC10c Argument Inspection** (Zeile 591-750)
   - **RC10c (ArgumentInspector):** Prüft zuerst auf sensitive Daten in Arguments
     - Wenn BLOCK → sofortiger Exit (Phase 4 Event wird trotzdem in Memory gespeichert)
   - **RC10b (AgenticCampaignDetector):** Kill-Chain-Analyse
     - Erstellt `ToolEvent` aus `user_input`
     - Lädt Session-History aus `HierarchicalMemory`
     - Berechnet Risk-Score mit High-Watermark-Logik
     - **Blockt** wenn `final_risk >= threshold_block (0.55)`

5. **Layer 2B: Kids Policy Input Safety** (Zeile 744-764)
   - Redundanter Check (bereits in Layer 0)
   - **Hinweis:** Wird als "redundant" markiert im Code

6. **Layer 3: Kids Policy Truth Preservation** (Zeile 765-808)
   - **Nur aktiv** wenn `self.truth_validator` vorhanden UND `topic_id` gesetzt
   - **Aktuell:** `⚠️ disabled` (siehe Frage D)

7. **Ollama LLM Call** (Zeile 810-817)
   - Nur wenn alle Layer PASSED
   - `llama3.1` via HTTP (`http://localhost:11434`)

### Antworten zu deinen Fragen:

**Q: Gibt es frühe Shortcuts?**
**A:** Nein. Jeder Request durchläuft alle Layer seriell. **Ausnahme:** Layer 0 und RC10c können früh blocken (sicherheitskritisch).

**Q: Wie kombiniert TopicFence und RC10b?**
**A:** **Strikt seriell:**
- TopicFence → BLOCK → Exit (kein RC10b)
- TopicFence → PASS → RC10b läuft
- **Keine parallele Auswertung** - RC10b sieht nur Requests, die TopicFence passiert haben

---

## (B) EnsembleFence – "Gradient Disagreement Mode"

### Aktuelle Implementierung (aus `topic_fence.py:128-172`):

**Kurzantwort:** Es sind **keine echten Gradienten**, sondern **L2-Distanz zwischen Embeddings** als Proxy für "Disagreement".

### Detaillierte Erklärung:

1. **Embedding-Generierung:**
   ```python
   embeddings = {}
   for name, encoder in self.encoders.items():
       emb = encoder.encode(user_input, convert_to_tensor=False)  # NumPy array
       embeddings[name] = np.array(emb)
   ```

2. **Dimension-Normalisierung:**
   - Problem: `all-MiniLM-L6-v2` = 384 dim, `all-mpnet-base-v2` = 768 dim
   - Lösung: Truncate auf `min_dim` (384) für alle Modelle
   - **Fix vom 2025-11-26:** Shape-Mismatch behoben

3. **L2-Distanz-Berechnung:**
   ```python
   distances = []
   for (n1, e1), (n2, e2) in combinations(normalized_embeddings.items(), 2):
       dist = np.linalg.norm(e1 - e2)  # L2-Norm, nicht Cosine!
       distances.append(dist)
   ```

4. **Uncertainty-Metrik:**
   ```python
   mean_dist = np.mean(distances)
   uncertainty = np.var(distances) / (mean_dist + 1e-8)  # Relative Varianz
   ```

5. **Crisis Brake:**
   - Wenn `uncertainty > 0.12` → BLOCK (Adversarial Perturbation vermutet)

### Warum "Gradient Disagreement"?

**Marketing-Label:** Der Begriff suggeriert "Gradienten", aber es sind **Embedding-Distanzen**.
**Rationale:** Hohe Varianz der L2-Distanzen = Modelle "disagree" über die semantische Repräsentation = Epistemic Uncertainty.

**Empfehlung für Paper:**
- **Präziser Begriff:** "Embedding Disagreement" oder "Ensemble Uncertainty"
- **Oder:** "L2-Distance Variance" als Proxy für Epistemic Uncertainty
- **Vermeiden:** "Gradient Disagreement" (irreführend, wenn keine Gradienten)

---

## (C) RC10b – Health Check / Model Versioning

### Aktueller Status:

**Im Log:** Nur `RC10b detector: ✅ enabled`
**Im Code:** Keine Self-Test-Routine, keine Versionierung, keine Checksum

### Was fehlt:

1. **Model Versioning:**
   - Kein `rc10b_v1.3` oder Hash im Log
   - RC10b ist aktuell **heuristisch** (kein geladenes TF-Modell im klassischen Sinne)
   - Implementierung: `AgenticCampaignDetector` mit `RC10bConfig` (Thresholds, Phase-Floors)

2. **Self-Test:**
   - **Kein Startup-Test** vorhanden
   - "enabled" bedeutet nur: `AgenticCampaignDetector` wurde instanziiert, keine Exception

3. **Threshold-Logging:**
   - Thresholds sind in `RC10bConfig` definiert:
     - `threshold_warn = 0.35`
     - `threshold_block = 0.55`
   - **Aber:** Werden nicht im Startup-Log ausgegeben

### Empfehlung:

**Implementiere Startup-Self-Test:**
```python
# In proxy_server.py __init__
test_events = [
    ToolEvent(timestamp=time.time(), tool="chat", category="user_input", ...),
    ToolEvent(timestamp=time.time(), tool="chat", category="exfiltration", ...),
]
test_result = self.agent_detector.detect(test_events)
assert test_result.score > 0.0, "RC10b self-test failed"
logger.info(f"RC10b self-test: PASS (test_score={test_result.score:.3f})")
```

**Log-Ergänzung:**
```
RC10b detector: ✅ enabled
  └─ Version: heuristic_v1.0 (config-based)
  └─ Thresholds: warn=0.35, block=0.55
  └─ Self-test: PASS (test_score=0.85)
```

---

## (D) Kids Policy Truth Validator – bewusst "off"?

### Aktueller Status:

**Im Log:** `Kids Policy Truth Validator: ⚠️ disabled`
**Grund:** TensorFlow-Import-Fehler (siehe `proxy_server.py:57-97`)

### Code-Analyse:

```python
# proxy_server.py:57-97
try:
    # Import direkt aus Dateien, um __init__.py zu vermeiden
    # (welches TruthPreservationValidator lädt)
    ...
    HAS_TRUTH_VALIDATOR = True
except (ImportError, Exception) as e:
    HAS_TRUTH_VALIDATOR = False
    logger.warning(f"Could not import kids_policy modules: {e}")
```

**Problem:** `TruthPreservationValidator` benötigt TensorFlow, aber TF-Import schlägt fehl (vermutlich Version-Konflikt oder fehlende Dependencies).

### Konfiguration:

**Aktuell:** Kein explizites Config-Flag für "Kids Policy Mode"
**Empfehlung:** Environment-Variable oder Config-File:
```python
KIDS_POLICY_MODE = os.getenv("KIDS_POLICY_MODE", "disabled")  # "enabled" | "disabled" | "adult_only"
```

**Log-Ergänzung:**
```
Kids Policy Truth Validator: ⚠️ disabled
  └─ Reason: TensorFlow import failed (ImportError: ...)
  └─ Mode: adult_only (no truth validation)
  └─ Config: KIDS_POLICY_MODE=disabled
```

---

## (E) SQLite – Schema- und Config-Version

### Aktueller Status:

**Im Log:** `Storage: Using SQLite with JSON` + `Tables created/verified`
**Im Code:** Kein Schema-Versioning, keine Config-ID

### Was fehlt:

1. **Schema-Version:**
   - Keine `schema_version` Tabelle oder Migration-Tracking
   - `Tables created/verified` bedeutet nur: CREATE TABLE IF NOT EXISTS

2. **Config-ID:**
   - Keine `config_profile` oder `config_hash`
   - Keine Reproduzierbarkeits-Metadaten

### Empfehlung:

**Schema-Versioning:**
```python
# In storage.py
SCHEMA_VERSION = 1
CONFIG_HASH = hashlib.sha256(json.dumps(config_dict, sort_keys=True).encode()).hexdigest()[:8]

logger.info(f"Storage: Schema v{SCHEMA_VERSION}, Config: {CONFIG_HASH}")
```

**Log-Ergänzung:**
```
Storage: Initialized (SQLite)
  └─ Schema: v1 (2025-11-26)
  └─ Config: rc10b_mathe_only_kids_off (hash=a3f2b1c4)
  └─ Database: hakgal_firewall.db
```

---

## (F) Ressourcenplanung – 3x ST + TF + Ollama auf einer GPU?

### Aktuelle Device-Zuweisung:

**Aus `topic_fence.py:44-45`:**
```python
device = "cuda" if torch.cuda.is_available() else "cpu"
logger.info(f"   Using device: {device}")
```

**Alle 3 SentenceTransformer-Modelle:** `device=device` (gemeinsam auf CUDA)

**RC10b:** Heuristisch (kein TF-Modell, keine GPU-Nutzung)

**Ollama:** Läuft als separater Prozess (vermutlich CPU, kann aber GPU nutzen wenn konfiguriert)

### Antworten:

**Q: Läuft alles auf derselben GPU?**
**A:**
- **SentenceTransformer-Ensemble:** Ja, alle 3 auf `cuda:0` (default)
- **RC10b:** Nein (heuristisch, CPU-only)
- **Ollama:** Unbekannt (separater Prozess, vermutlich CPU)

**Q: Harte Device-Zuweisung?**
**A:** Nein. Nur `device = "cuda" if torch.cuda.is_available() else "cpu"` - keine explizite `cuda:0` vs `cuda:1` Zuweisung.

### Risiken:

1. **Out-of-Memory:** 3x ST-Modelle + Ollama auf RTX 3080 Ti (17GB) könnte bei hoher Last knapp werden
2. **Preemption:** Keine Priorisierung (alle Modelle gleichberechtigt)
3. **Latenzspitzen:** Wenn Ollama GPU nutzt, könnte ST-Ensemble verlangsamt werden

### Empfehlung:

**Device-Zuweisung explizit machen:**
```python
# In topic_fence.py
device = os.getenv("ST_DEVICE", "cuda:0")  # Explizit cuda:0
logger.info(f"   Using device: {device} (explicit)")
```

**Memory-Monitoring:**
```python
if torch.cuda.is_available():
    gpu_memory = torch.cuda.get_device_properties(0).total_memory / 1e9
    logger.info(f"   GPU Memory: {gpu_memory:.1f} GB available")
```

---

## Zusammenfassung: Empfohlene Log-Verbesserungen

### 1. Versionen & Hashes

```
Guardian Firewall v0.10.3 (config=rc10b_mathe_only_kids_off)
RC10b detector: ✅ enabled
  └─ Version: heuristic_v1.0 (config-based)
  └─ Thresholds: warn=0.35, block=0.55
  └─ Self-test: PASS (test_score=0.85)
EnsembleFence models: [MiniLM-L6-v2 (384d), mpnet-base-v2 (768d), e5-small-v2 (384d)]
```

### 2. Mode-Line

```
MODE: production, tenant=local_lab, audience=adults_only, logging=full, stats_sampling=1.0
Kids Policy Truth Validator: ⚠️ disabled
  └─ Reason: TensorFlow import failed
  └─ Mode: adult_only (no truth validation)
```

### 3. Self-Test Summary

```
Self-test: 4/4 guards passed
  └─ NormalizationGuard: PASS (test: Base64 decode)
  └─ EnsembleFence: PASS (test: topic similarity)
  └─ RC10b: PASS (test: kill-chain detection)
  └─ Ollama: PASS (test: health check)
```

### 4. Storage & Config

```
Storage: Initialized (SQLite)
  └─ Schema: v1 (2025-11-26)
  └─ Config: rc10b_mathe_only_kids_off (hash=a3f2b1c4)
  └─ Database: hakgal_firewall.db
```

### 5. Resource Planning

```
GPU Resources:
  └─ Device: cuda:0 (RTX 3080 Ti, 17.2 GB)
  └─ ST Ensemble: 3 models on cuda:0
  └─ RC10b: CPU-only (heuristic)
  └─ Ollama: separate process (device unknown)
```

---

## Offene Punkte für zukünftige Implementierung

1. **RC10b Self-Test:** Startup-Test-Routine implementieren
2. **Schema-Versioning:** Migration-Tracking für SQLite
3. **Config-Hashing:** Reproduzierbarkeits-Metadaten
4. **Device-Management:** Explizite GPU-Zuweisung und Memory-Monitoring
5. **Kids Policy Mode:** Config-Flag für "enabled/disabled/adult_only"
6. **Terminologie:** "Gradient Disagreement" → "Embedding Disagreement" (präziser)

---

**Status:** Diese Antworten basieren auf Code-Analyse vom 2025-11-26. Empfohlene Verbesserungen sind als TODO markiert und können schrittweise implementiert werden.
