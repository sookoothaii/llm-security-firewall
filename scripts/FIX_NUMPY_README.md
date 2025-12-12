# 🔧 NumPy Compatibility Fix

## Problem

NumPy 2.3.5 ist installiert, aber `scipy` und `sklearn` wurden mit NumPy 1.x kompiliert. Dies führt zu Import-Fehlern:

```
ImportError: A module that was compiled using NumPy 1.x cannot be run in NumPy 2.3.5
```

## Lösung

### Option 1: Automatisches Fix-Script (Empfohlen)

```bash
python scripts/fix_numpy_compatibility.py
```

Das Script:
1. Prüft die aktuelle NumPy-Version
2. Deinstalliert NumPy 2.x
3. Installiert NumPy <2.0
4. Verifiziert die Installation

### Option 2: Manuell

```bash
# NumPy 2.x deinstallieren
pip uninstall numpy -y

# NumPy <2.0 installieren
pip install "numpy<2.0" --upgrade

# Oder mit force-reinstall falls nötig
pip install "numpy<2.0" --force-reinstall
```

### Option 3: Requirements neu installieren

```bash
# Alle Dependencies neu installieren (mit korrekter NumPy-Version)
pip install -r requirements.txt --force-reinstall

# Oder nur Core
pip install -r requirements-core.txt --force-reinstall
```

## Verifizierung

Nach dem Fix:

```bash
python -c "import numpy; print(f'NumPy version: {numpy.__version__}')"
```

Sollte zeigen: `NumPy version: 1.26.x` (oder ähnlich, aber <2.0)

## Service starten

Nach dem Fix sollte der Service ohne Fehler starten:

```bash
python -m uvicorn detectors.code_intent_service.main:app --host 0.0.0.0 --port 8001
```

## Was wurde geändert?

- ✅ `requirements.txt`: `numpy>=1.24.0,<2.0.0`
- ✅ `requirements-core.txt`: `numpy>=1.24.0,<2.0.0`
- ✅ `pyproject.toml`: Alle NumPy-Referenzen auf `<2.0.0` beschränkt

## Warum NumPy <2.0?

- `scipy` und `sklearn` wurden mit NumPy 1.x kompiliert
- NumPy 2.x hat Breaking Changes in der C-API
- Viele wissenschaftliche Bibliotheken unterstützen NumPy 2.x noch nicht vollständig
- NumPy 1.26.x ist stabil und ausreichend für dieses Projekt

## Zukünftige Updates

Wenn NumPy 2.x vollständig unterstützt wird:
1. `scipy` und `sklearn` aktualisieren
2. Requirements auf `numpy>=2.0.0` ändern
3. Tests durchführen

---

**Status:** ✅ Fixed in requirements files
**Nächster Schritt:** `python scripts/fix_numpy_compatibility.py`

