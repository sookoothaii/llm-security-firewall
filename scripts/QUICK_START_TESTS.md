# 🚀 Quick Start: Hardcore Tests

## Service läuft bereits? Perfekt!

Wenn der Code Intent Service bereits läuft (wie bei dir), werden die Tests automatisch über HTTP API arbeiten.

## 1. Service starten (falls nicht läuft)

```bash
# Terminal 1: Start Service
python -m uvicorn detectors.code_intent_service.main:app --host 0.0.0.0 --port 8001
```

## 2. Tests ausführen

```bash
# Terminal 2: Run Tests
python scripts/run_hardcore_tests.py
```

Die Tests erkennen automatisch:
- ✅ Installiertes Package (`pip install llm-security-firewall`)
- ✅ Lokales Modul (`src/llm_firewall/`)
- ✅ HTTP API (`http://localhost:8001`) ← **Das wird bei dir funktionieren!**

## 3. Erwartete Ausgabe

```
✅ Firewall loaded via HTTP API (localhost:8001)
🚀 Running 60+ attacks in parallel (24 workers)...
```

## Troubleshooting

### Service nicht erreichbar?
```bash
# Test ob Service läuft
curl http://localhost:8001/health
```

### NumPy Warning?
Das ist nur eine Warnung - der Service läuft trotzdem. Für Production sollte man NumPy downgraden:
```bash
pip install "numpy<2"
```

### Tests zu langsam?
Reduziere Worker-Anzahl:
```bash
python scripts/run_hardcore_tests.py --workers 8
```

## Nächste Schritte

Nach den Tests:
1. **Bypass-Liste analysieren** (in JSON-Output)
2. **Kategorien priorisieren** (welche haben höchste Bypass-Rate?)
3. **P0-Fixes implementieren** (TOCTOU, Plain-Text Jailbreaks)
4. **Regression-Tests** (nach jedem Fix erneut ausführen)

---

**Viel Erfolg! 🎯**

