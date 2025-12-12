# Erweiterte Test-Suite: Mathematische & Multilinguale Angriffe

**Datum:** 2025-12-08  
**Status:** Production-Ready

---

## Übersicht

Diese erweiterte Test-Suite ermöglicht umfassende Tests der Firewall gegen:
- **Mathematische Notation Camouflage** (neu behoben)
- **Multilingual Code-Switching**
- Kombinierte Angriffstechniken

---

## Quick Start

### 1. Test-Suiten generieren

```powershell
# Mathematische Angriffe generieren (50 Varianten)
python scripts/generate_math_attacks.py --n 50

# Multilinguale Angriffe generieren (50 Varianten)
python scripts/generate_multilingual_attacks.py --n 50
```

**Output:** 
- `test_suites/math_attacks_advanced_*.json`
- `test_suites/multilingual_attacks_advanced_*.json`

### 2. Erweiterte Tests ausführen

```powershell
# Teste alle generierten Suiten
python scripts/run_advanced_bypass_tests.py

# Teste spezifische Suiten
python scripts/run_advanced_bypass_tests.py --input test_suites/math_attacks_*.json

# Mit mehreren Workern (schneller)
python scripts/run_advanced_bypass_tests.py --max-workers 20 --verbose
```

**Output:** `test_results/advanced_test_*.json`

### 3. Bypass-Patterns analysieren

```powershell
# Analysiere alle Test-Ergebnisse
python scripts/analyze_bypass_patterns.py

# Analysiere spezifische Ergebnisse
python scripts/analyze_bypass_patterns.py --pattern "test_results/advanced_test_*.json"
```

**Output:** `analysis/bypass_patterns_analysis_*.json`

### 4. Schnelltest für tägliche Überprüfung

```powershell
# Täglicher Schnelltest
python scripts/quick_bypass_check.py --math-samples 20 --multilingual-samples 20

# Mit custom Threshold
python scripts/quick_bypass_check.py --threshold 0.55 --math-samples 30
```

**Output:** `test_results/daily_check_YYYYMMDD.json`

---

## Detaillierte Verwendung

### generate_math_attacks.py

Generiert mathematische Angriffsvarianten mit verschiedenen Templates:

```powershell
# 50 Angriffe (Standard)
python scripts/generate_math_attacks.py

# 100 Angriffe
python scripts/generate_math_attacks.py --n 100

# Custom Output
python scripts/generate_math_attacks.py --output custom_math_attacks.json
```

**Features:**
- 10 verschiedene Templates
- Logische Symbole, Kalkül, Mengenlehre, Griechische Buchstaben
- Zufällige Kombinationen für Vielfalt

### generate_multilingual_attacks.py

Generiert multilinguale Angriffe mit Code-Switching:

```powershell
# 50 Angriffe (Standard)
python scripts/generate_multilingual_attacks.py

# 100 Angriffe
python scripts/generate_multilingual_attacks.py --n 100
```

**Features:**
- 9 Sprachen: DE, FR, ES, IT, NL, RU, JA, ZH, PT
- 2-4 Sprachen pro Angriff
- Verschiedene Code-Einbettungsformate

### run_advanced_bypass_tests.py

Testet generierte Angriffe gegen den Firewall:

```powershell
# Basis-Test
python scripts/run_advanced_bypass_tests.py

# Spezifische Suiten
python scripts/run_advanced_bypass_tests.py --input test_suites/math_attacks_*.json test_suites/multilingual_attacks_*.json

# Mit Pattern-Matching
python scripts/run_advanced_bypass_tests.py --pattern "test_suites/*_attacks_*.json"

# Custom Service URL
python scripts/run_advanced_bypass_tests.py --service-url http://localhost:8001/v1/detect

# Parallele Ausführung (schneller)
python scripts/run_advanced_bypass_tests.py --max-workers 20

# Verbose Output
python scripts/run_advanced_bypass_tests.py --verbose
```

**Features:**
- Parallele Ausführung (ThreadPoolExecutor)
- Detaillierte Statistiken
- Bypass-Erkennung und -Gruppierung
- JSON-Output für weitere Analyse

### analyze_bypass_patterns.py

Analysiert Bypasses auf gemeinsame Muster:

```powershell
# Standard (alle Result-Dateien)
python scripts/analyze_bypass_patterns.py

# Spezifische Dateien
python scripts/analyze_bypass_patterns.py --input test_results/advanced_test_20251208_*.json

# Mit Pattern
python scripts/analyze_bypass_patterns.py --pattern "test_results/*_test_*.json"
```

**Analysiert:**
- Score-Verteilung
- Häufigste Techniken
- Mathematische Symbole in Bypasses
- Sprach-Mixing-Patterns
- Code-Patterns
- Rule vs ML Score Vergleich
- Automatische Empfehlungen

### quick_bypass_check.py

Schnelltest für regelmäßige Überprüfung:

```powershell
# Standard (20 math + 20 multilingual)
python scripts/quick_bypass_check.py

# Mehr Samples
python scripts/quick_bypass_check.py --math-samples 30 --multilingual-samples 30

# Custom Threshold
python scripts/quick_bypass_check.py --threshold 0.55

# Custom Output
python scripts/quick_bypass_check.py --output daily_check_custom.json
```

**Features:**
- Schnelle Generierung (keine Datei-I/O)
- Ideal für CI/CD
- Tägliche Überprüfung

---

## Workflow-Beispiele

### Vollständiger Test-Workflow

```powershell
# 1. Generiere Test-Suiten
python scripts/generate_math_attacks.py --n 50
python scripts/generate_multilingual_attacks.py --n 50

# 2. Führe Tests aus
python scripts/run_advanced_bypass_tests.py --max-workers 20 --verbose

# 3. Analysiere Ergebnisse
python scripts/analyze_bypass_patterns.py

# 4. Prüfe Empfehlungen in analysis/bypass_patterns_analysis_*.json
```

### Täglicher Check (CI/CD)

```powershell
# In CI/CD Pipeline
python scripts/quick_bypass_check.py --math-samples 20 --multilingual-samples 20 --threshold 0.55

# Exit Code 1 wenn Bypasses gefunden
if ($LASTEXITCODE -ne 0) {
    Write-Error "Bypasses detected!"
    exit 1
}
```

### Fokus auf Mathematische Notation

```powershell
# Generiere viele mathematische Varianten
python scripts/generate_math_attacks.py --n 100

# Teste nur mathematische Angriffe
python scripts/run_advanced_bypass_tests.py --input test_suites/math_attacks_*.json --verbose

# Analysiere spezifisch
python scripts/analyze_bypass_patterns.py --input test_results/advanced_test_*.json
```

---

## Output-Format

### Test-Ergebnisse (advanced_test_*.json)

```json
{
  "timestamp": "2025-12-08T...",
  "stats": {
    "total": 100,
    "blocked": 95,
    "bypassed": 5,
    "false_negatives": 5,
    "by_category": {...}
  },
  "bypasses": [...],
  "results": [...]
}
```

### Analyse-Ergebnisse (bypass_patterns_analysis_*.json)

```json
{
  "total_bypasses": 5,
  "score_analysis": {...},
  "technique_analysis": {...},
  "pattern_analysis": {...},
  "recommendations": [...]
}
```

---

## Voraussetzungen

1. **Code Intent Service muss laufen:**
   ```powershell
   cd detectors/code_intent_service
   python -m uvicorn main:app --host 0.0.0.0 --port 8001
   ```

2. **Python-Pakete:**
   - `requests`
   - `json` (Standard)
   - `pathlib` (Standard)

---

## Erwartete Ergebnisse

Nach unseren Fixes sollten wir sehen:

- **Mathematische Angriffe:** 100% Block-Rate (Rule Engine erkennt Patterns)
- **Multilinguale Angriffe:** 100% Block-Rate (ML Model erkennt mit Score 0.80)

Falls Bypasses gefunden werden:
1. Prüfe `analysis/bypass_patterns_analysis_*.json` für Empfehlungen
2. Implementiere Fixes basierend auf Empfehlungen
3. Wiederhole Tests

---

## Troubleshooting

### "Connection failed - Service not running"
- Stelle sicher, dass Code Intent Service auf Port 8001 läuft

### "No test suites found"
- Generiere zuerst Test-Suiten mit `generate_math_attacks.py` und `generate_multilingual_attacks.py`

### "No result files found"
- Führe zuerst Tests mit `run_advanced_bypass_tests.py` aus

---

## Nächste Schritte

1. **Regelmäßige Tests:** Integriere `quick_bypass_check.py` in CI/CD
2. **Erweiterte Analyse:** Nutze `analyze_bypass_patterns.py` für kontinuierliche Verbesserung
3. **Neue Angriffe:** Erweitere Templates in Generatoren für neue Techniken
