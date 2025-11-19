# Push Checklist für RC10b PR

## Pre-Push Validation

### 1. Branch Check
```bash
git branch
# Sollte zeigen: * feature/agent-behavioral-protection
```

Falls nicht:
```bash
git checkout -b feature/agent-behavioral-protection
```

### 2. Final Lint Check
```bash
# Python Linting (falls flake8/pylint installiert)
flake8 src/llm_firewall/agents/ --max-line-length=120
# oder
pylint src/llm_firewall/agents/

# Type Checking (falls mypy installiert)
mypy src/llm_firewall/agents/
```

### 3. Test Suite
```bash
# Alle Tests ausführen
pytest tests/agents/ -v

# Erwartetes Ergebnis:
# - test_rc10b_core.py: 4 passed
# - test_adversarial_bypass.py: 3 xfailed (expected)
```

### 4. Import Check
```bash
# Sicherstellen, dass Imports funktionieren
python -c "from llm_firewall.agents import AgenticCampaignDetector, RC10bConfig; print('OK')"
```

### 5. Dokumentation Check
```bash
# Sicherstellen, dass alle Docs vorhanden sind
ls docs/RC10B_*.md
# Sollte zeigen:
# - RC10B_TECH_REPORT.md
# - RC10B_EVALUATION_STATUS.md
# - RC10B_KNOWN_LIMITATIONS.md
```

## Commit & Push

### 6. Stage All Changes
```bash
git add .
```

### 7. Commit
```bash
git commit -m "feat(agents): Add RC10b behavioral detection layer

- Implement AgenticCampaignDetector with high-watermark logic
- Add phase-based risk floors (configurable)
- Include scope mismatch detection
- Add unit tests (4 passing) and adversarial tests (3 expected failures)
- Document known limitations (categorical masquerade bypass)
- Add stress probes for GTG-1002 attack simulation

Status: Not validated against real-world attacks or production traffic."
```

### 8. Push
```bash
git push origin feature/agent-behavioral-protection
```

## PR Creation

### 9. PR Title
```
feat(agents): Add RC10b behavioral detection layer
```

### 10. PR Body
Kopiere den Inhalt aus `PR_TEMPLATE.md` in die PR-Beschreibung.

## Post-Push

### 11. Verify PR
- [ ] PR wurde erstellt
- [ ] CI läuft (falls vorhanden)
- [ ] Alle Checks grün
- [ ] PR-Beschreibung vollständig

## Files Summary

### Neue Dateien
```
src/llm_firewall/agents/
├── __init__.py
├── config.py
├── detector.py
├── state.py
├── example_usage.py
└── README.md

tests/agents/
├── test_rc10b_core.py
└── test_adversarial_bypass.py

docs/
└── RC10B_KNOWN_LIMITATIONS.md

scripts/
└── attack_categorical_masquerade.py

PR_TEMPLATE.md
PR_README.md
PUSH_CHECKLIST.md
```

### Geänderte Dateien
```
src/llm_firewall/detectors/agentic_campaign.py
  - Erweitert um High-Watermark-Logik
  - CampaignDetectorConfig erweitert
```

## Final Notes

- ✅ Alle Tests bestehen
- ✅ Known Limitations dokumentiert
- ✅ Adversarial Tests als expectedFailure markiert
- ✅ Transparente Dokumentation
- ✅ Keine Breaking Changes

**Ready for PR!** 🚀

