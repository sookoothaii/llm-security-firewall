# Git Push Commands für Feature Branch

## Vorbereitung

1. **Prüfe aktuellen Branch:**
```bash
git branch --show-current
```

2. **Erstelle Feature Branch (falls noch nicht vorhanden):**
```bash
git checkout -b feature/code-intent-detection-standalone
```

## Dateien für Commit

Wichtige Dateien, die committed werden sollten:

- `detectors/code_intent_service/README.md` - Wissenschaftliche README
- `detectors/code_intent_service/BRANCH_MIGRATION.md` - Git Workflow Dokumentation
- `detectors/code_intent_service/PRE_CI_CHECK.md` - Pre-CI Check Report
- `detectors/code_intent_service/test_hardcore_attacks.py` - Direkter Test
- `detectors/code_intent_service/test_hardcore_attacks_api.py` - API Test
- `detectors/code_intent_service/domain/services/ports.py` - RiskScore Import Fix
- `scripts/pre_push_check.ps1` - Pre-Push Check Script

## Git Commands

### 1. Status prüfen
```bash
git status --short
```

### 2. Dateien hinzufügen
```bash
git add detectors/code_intent_service/README.md
git add detectors/code_intent_service/BRANCH_MIGRATION.md
git add detectors/code_intent_service/PRE_CI_CHECK.md
git add detectors/code_intent_service/test_hardcore_attacks.py
git add detectors/code_intent_service/test_hardcore_attacks_api.py
git add detectors/code_intent_service/domain/services/ports.py
git add scripts/pre_push_check.ps1
```

Oder alle auf einmal:
```bash
git add detectors/code_intent_service/README.md \
        detectors/code_intent_service/BRANCH_MIGRATION.md \
        detectors/code_intent_service/PRE_CI_CHECK.md \
        detectors/code_intent_service/test_hardcore_attacks.py \
        detectors/code_intent_service/test_hardcore_attacks_api.py \
        detectors/code_intent_service/domain/services/ports.py \
        scripts/pre_push_check.ps1
```

### 3. Commit
```bash
git commit -m "feat: Code Intent Detection Service - Feature Branch Setup

- Add comprehensive README.md (scientific, no marketing buzzwords)
- Add BRANCH_MIGRATION.md with Git workflow
- Add PRE_CI_CHECK.md with pre-push validation
- Add hardcore attack test scripts (direct and API)
- Fix RiskScore import in ports.py (mypy fix)
- Add pre_push_check.ps1 script for local CI validation

Test Results:
- Hardcore Attack Test: 0 bypasses, 88.9% success rate
- Benign Validation Suite: 3.4% FPR (1000 tests, 24 workers)
- All critical attacks blocked correctly
- API functional on port 8000

Status: Ready for feature branch creation"
```

### 4. Push
```bash
git push -u origin feature/code-intent-detection-standalone
```

## Alternative: Alle Änderungen committen

Falls Sie alle Änderungen committen möchten:
```bash
git add .
git commit -m "feat: Code Intent Detection Service - Feature Branch Setup"
git push -u origin feature/code-intent-detection-standalone
```

## Prüfung vor Push

1. **Prüfe .env ist nicht staged:**
```bash
git diff --cached --name-only | grep -i "\.env"
```
(Sollte nichts ausgeben)

2. **Prüfe auf große Dateien:**
```bash
git ls-files | xargs ls -lh | awk '$5 > 1048576 {print $5, $9}'
```

3. **Prüfe sensible Daten:**
```bash
git diff --cached | grep -i "password\|secret\|token" | head -20
```

## Nach dem Push

1. **Prüfe Remote Branch:**
```bash
git branch -r | grep feature/code-intent-detection-standalone
```

2. **Erstelle Pull Request (optional):**
- Gehen Sie zu GitHub Repository
- Erstellen Sie einen Pull Request von `feature/code-intent-detection-standalone` nach `main`

## Test-Ergebnisse (Referenz)

- **Hardcore Attack Test:** 0 Bypasses, 88.9% Success Rate
- **Benign Validation Suite:** 3.4% FPR (1000 tests, 24 workers)
- **API Test:** Alle Angriffe korrekt blockiert
- **Pre-Push Check:** Alle Checks bestanden

