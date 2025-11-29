# Gemini 3: RC10b False Positives - Persistent After Fixes

**Datum:** 2025-11-26
**Status:** CRITICAL - False Positives blockieren normale Requests trotz Fixes
**Priorität:** P0 - Production-Blocker

---

## Problem-Beschreibung

Nach Implementierung der Gemini 3 Fixes (State Leaking Prevention, High-Watermark Floor Fix, Latent Risk Multiplier Skip) schlagen **zwei Tests weiterhin fehl**:

1. **Happy Path Test 1:** `"Erkläre mir Photosynthese"` → `BLOCKED_CAMPAIGN`
2. **NormalizationGuard Test 4:** `"Erkläre mir Photosynthese"` (normal safe content) → `BLOCKED_CAMPAIGN`

**Erwartetes Verhalten:** Beide Requests sollten `ALLOWED` sein (normale, harmlose Anfragen).

**Tatsächliches Verhalten:** Beide werden als `BLOCKED_CAMPAIGN` blockiert.

---

## Bereits Implementierte Fixes

### Fix 1: High-Watermark Floor (detector.py)
```python
# 3. High-Watermark Application (The GTG-1002 Fix)
if self.config.use_phase_floor:
    floor = (
        self._compute_high_watermark(
            events, max_reached_phase=max_reached_phase
        )
        if self.config.use_high_watermark
        else 0.0
    )

    # FIX (Gemini 3): Only apply floor if:
    # 1. Floor > 0 (there was a critical phase)
    # 2. AND we have more than 1 event (not a new session with single event)
    # This prevents false positives for new sessions with low-risk events
    if floor > 0.0 and len(events) > 1 and floor > final_risk:
        final_risk = floor
        reasons.append(
            f"High-Watermark enforced (Phase {current_max_phase} severity)"
        )
```

**Status:** ✅ Implementiert

### Fix 2: Latent Risk Multiplier Skip (proxy_server.py)
```python
# FIX (Gemini 3): Only apply latent risk multiplier if we have history
# For new sessions with single event, skip multiplier to prevent false positives
if len(all_events) > 1:
    final_risk = memory.get_adjusted_risk(base_risk)
else:
    # New session, single event: use base_risk directly (no multiplier)
    final_risk = base_risk
```

**Status:** ✅ Implementiert

### Fix 3: Base Risk Reduction (detector.py)
```python
# 1. Base Heuristics
# FIX: Lower base risk for new sessions to reduce false positives
# Single event in new session = very low risk (0.05)
if len(events) == 1:
    base_risk = 0.05  # Very low risk for first event
else:
    base_risk = 0.1 + (len(events) * 0.01)  # Slightly higher for multiple events
```

**Status:** ✅ Implementiert

### Fix 4: State Leaking Prevention (_compute_high_watermark)
```python
def _compute_high_watermark(
    self, events: List[ToolEvent], max_reached_phase: Optional[int] = None
) -> float:
    """
    FIX (Gemini 3): State Leaking Prevention
    - Wenn max_reached_phase None ist, darf NICHT der globale maximale Wert genommen werden
    - Muss zwingend session-spezifisch sein (wird von außen übergeben)
    - Falls nicht übergeben, wird 0.0 zurückgegeben (kein Floor für neue Sessions)
    """
    if not self.config.use_high_watermark:
        return 0.0

    # FIX (Gemini 3): Wenn max_reached_phase None ist, NICHT aus globalem State nehmen
    if max_reached_phase is not None and max_reached_phase > 0:
        # Use provided max_reached_phase (from session-specific memory)
        return self.config.phase_floors.get(max_reached_phase, 0.0)

    # Fallback: Scan events to find max phase (only for THIS request's events)
    if not events:
        return 0.0

    max_phase = 0
    for event in events:
        phase = self._get_phase_for_event(event)
        if phase > max_phase:
            max_phase = phase

    return self.config.phase_floors.get(max_phase, 0.0)
```

**Status:** ✅ Implementiert

---

## Test-Setup

### Test 1: Happy Path
```python
safe_requests = [
    "Erkläre mir Photosynthese",  # ← FAILS
    "Was ist die Formel für die Fläche eines Kreises?",  # ← PASSES
    "Wie funktioniert ein Atom?",  # ← PASSES
]

# Each request uses unique session ID:
session_id = f"test-happy-{int(time.time())}-{i}"
```

### Test 2: NormalizationGuard
```python
tests = [
    {
        "name": "Normal safe content",
        "input": "Erkläre mir Photosynthese",  # ← FAILS
        "expected_block": False,
    },
    # ... other tests (Base64, Hex, URL) all PASS
]

# Each request uses unique session ID:
session_id = f"test-norm-{int(time.time())}-{i}"
```

**Beobachtung:** Nur der **erste Request** in beiden Tests schlägt fehl. Die folgenden Requests mit derselben Logik passieren.

---

## Architektur-Kontext

### RC10b Detection Flow (proxy_server.py)
```python
# 1. Get or create hierarchical memory for this session
memory = self._get_or_create_memory(session_id)

# 2. Load session history (from tactical buffer)
history = memory.get_history()
all_events = history + [current_event]

# 3. Run RC10b detection (base risk calculation)
campaign_result = self.agent_detector.detect(
    all_events, max_reached_phase=memory.max_phase_ever
)

# 4. Apply latent risk multiplier (if history exists)
base_risk = campaign_result.score
if len(all_events) > 1:
    final_risk = memory.get_adjusted_risk(base_risk)
else:
    final_risk = base_risk

# 5. Decision Check
if final_risk >= 0.55:  # Threshold for BLOCK
    return ProxyResponse(status="BLOCKED_CAMPAIGN", ...)
```

### HierarchicalMemory Initialization
```python
@dataclass
class HierarchicalMemory:
    session_id: str
    max_phase_ever: int = 0
    latent_risk_multiplier: float = 1.0
    tactical_buffer: deque = field(default_factory=lambda: deque(maxlen=50))
    # ...
```

**Wichtig:** Neue Sessions starten mit `max_phase_ever = 0` und `latent_risk_multiplier = 1.0`.

---

## Mögliche Ursachen (Hypothesen)

### Hypothese 1: Memory wird zwischen Tests geteilt
- **Problem:** `_get_or_create_memory()` könnte Memory aus Storage laden, die von vorherigen Tests stammt
- **Symptom:** `max_phase_ever` oder `latent_risk_multiplier` sind > 0 für "neue" Sessions
- **Prüfung:** Storage-Manager lädt persistierte Memory, auch wenn Session-ID eindeutig ist?

### Hypothese 2: Base Risk ist höher als erwartet
- **Problem:** `base_risk = 0.05` wird überschrieben durch Scope Mismatch oder andere Heuristiken
- **Symptom:** `base_risk` > 0.55, obwohl nur ein Event vorhanden ist
- **Prüfung:** Scope Mismatch Detection oder andere Risiko-Boosts greifen?

### Hypothese 3: Phase-Mapping ist falsch
- **Problem:** `"user_input"` wird nicht korrekt als Phase 1 gemappt
- **Symptom:** Event wird als höhere Phase klassifiziert → Floor wird angewendet
- **Prüfung:** `_get_phase_for_event()` gibt falsche Phase zurück?

### Hypothese 4: Decision wird vor RC10b getroffen
- **Problem:** Ein anderer Layer (z.B. TopicFence, SafetyFallback) blockiert vor RC10b
- **Symptom:** Status ist `BLOCKED_CAMPAIGN`, aber RC10b wurde nie ausgeführt
- **Prüfung:** Layer-Reihenfolge oder Early-Exit-Logik?

---

## Code-Snippets für Diagnose

### RC10bConfig (config.py)
```python
@dataclass
class RC10bConfig:
    threshold_block: float = 0.55
    threshold_warn: float = 0.35

    phase_floors: Dict[int, float] = field(
        default_factory=lambda: {
            3: 0.50,  # Collection, Credential Access
            4: 0.85,  # Exfiltration, Impact
        }
    )

    category_map: Dict[str, int] = field(
        default_factory=lambda: {
            "user_input": 1,  # Explicit mapping for chat/user input
            "recon": 1,
            "discovery": 1,
            # ... other mappings
        }
    )
```

### ToolEvent Creation (proxy_server.py)
```python
# Create ToolEvent for RC10b
current_event = ToolEvent(
    tool="chat",
    category="user_input",  # Should map to Phase 1
    target=None,
    timestamp=time.time(),
    success=True,
    metadata={"user_input": user_input[:100]},
)
```

---

## Frage an Gemini 3

**Hauptfrage:**

Warum werden normale, harmlose Requests wie `"Erkläre mir Photosynthese"` weiterhin als `BLOCKED_CAMPAIGN` blockiert, obwohl:

1. ✅ `base_risk = 0.05` für einzelne Events in neuen Sessions
2. ✅ `latent_risk_multiplier` wird für neue Sessions übersprungen (`final_risk = base_risk`)
3. ✅ High-Watermark Floor wird nur angewendet, wenn `len(events) > 1`
4. ✅ `max_reached_phase` ist session-spezifisch isoliert
5. ✅ Jeder Test verwendet eindeutige Session-IDs

**Spezifische Fragen:**

1. **Memory-Isolation:** Könnte `_get_or_create_memory()` persistierte Memory aus Storage laden, die von vorherigen Tests stammt? Sollte ich die Storage vor jedem Test leeren oder Session-IDs mit Timestamp verwenden?

2. **Base Risk Calculation:** Gibt es andere Code-Pfade, die `base_risk` erhöhen könnten (z.B. Scope Mismatch, Pretext Signals), die ich übersehen habe?

3. **Phase Mapping:** Wird `"user_input"` korrekt als Phase 1 gemappt? Gibt es einen Fallback, der zu einer höheren Phase führt?

4. **Decision Logic:** Wird die Block-Entscheidung möglicherweise von einem anderen Layer getroffen, der `BLOCKED_CAMPAIGN` als Status zurückgibt, obwohl RC10b gar nicht blockiert hat?

5. **Timing/Concurrency:** Könnte es ein Race Condition geben, wenn mehrere Tests parallel laufen oder sehr schnell nacheinander?

**Erwartete Antwort:**

- Präzise Diagnose des Problems
- Konkrete Code-Fixes mit Zeilennummern
- Erklärung, warum die bisherigen Fixes nicht ausreichen
- Optional: Verbesserte Test-Strategie zur Reproduktion

---

## Zusätzlicher Kontext

**Test-Ergebnisse:**
- ✅ 5/7 Test Suites passieren
- ❌ `happy_path` (1/3 Requests fail)
- ❌ `normalization_guard` (1/4 Requests fail)

**Beobachtung:** Nur der **erste Request** in beiden Tests schlägt fehl. Dies deutet auf ein Initialisierungs- oder State-Leaking-Problem hin.

**Nächster Schritt:** Test-Suite wurde erweitert, um RC10b-Scores (`base_risk`, `adjusted_risk`, `multiplier`) in der Ausgabe anzuzeigen. Diese Werte werden beim nächsten Testlauf sichtbar sein.

---

**Priorität:** Beide Probleme verursachen False Positives in Production-Tests. RC10b-Problem ist kritischer (blockiert normale Requests).
