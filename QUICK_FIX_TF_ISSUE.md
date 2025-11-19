# Quick Fix: TensorFlow/Keras Dependency-Problem

## Problem

Der Proxy-Server kann nicht starten, weil `sentence-transformers` (für TopicFence) ein TensorFlow/Keras-Problem hat:

```
ValueError: Your currently installed version of Keras is Keras 3, 
but this is not yet supported in Transformers. 
Please install the backwards-compatible tf-keras package.
```

## Lösung 1: tf-keras installieren (Schnellste Lösung)

```powershell
pip install tf-keras
```

**Dann Test ausführen:**
```powershell
python scripts/test_proxy_simple.py
```

## Lösung 2: Ollama installieren (Für echten Test)

1. **Download**: https://ollama.ai/download
2. **Installation**: `.exe` ausführen
3. **Modell laden**: `ollama pull llama3`
4. **Proxy starten**: `python src/proxy_server.py`

Der Proxy erkennt Ollama automatisch und läuft im **Mock-Modus**, wenn Ollama nicht verfügbar ist.

## Lösung 3: Beides (Empfohlen)

```powershell
# 1. Fix TF-Problem
pip install tf-keras

# 2. Installiere Ollama
# (Download von https://ollama.ai/download)

# 3. Lade Modell
ollama pull llama3

# 4. Teste Proxy
python scripts/test_proxy_simple.py

# 5. Starte Server
python src/proxy_server.py
```

## Was funktioniert OHNE Fix

- ✅ RC10b Detector (funktioniert ohne TF)
- ✅ Kids Policy Fallback Judge (funktioniert ohne TF)
- ✅ Session Management (funktioniert ohne TF)
- ❌ TopicFence (benötigt sentence-transformers → TF-Problem)

## Workaround: TopicFence deaktivieren

Falls du den Proxy OHNE TopicFence testen willst, kannst du in `proxy_server.py` Layer 1 temporär überspringen.

**Aber**: Das ist nicht empfohlen, da TopicFence der erste, schnelle Filter ist.

---

## Empfehlung

**Für den Victory Lap:**
1. `pip install tf-keras` (1 Minute)
2. `ollama pull llama3` (5-10 Minuten, einmalig)
3. `python src/proxy_server.py` (läuft dann perfekt)

**Alternative (nur Logik-Test):**
- `pip install tf-keras`
- `python scripts/test_proxy_simple.py`
- Siehst alle Layer in Aktion (ohne Ollama)

