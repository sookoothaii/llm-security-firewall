# 🚀 Guardian Firewall Proxy - Quick Start

## Status

✅ **Code ist fertig** - Alle 3 Layer implementiert  
⚠️ **Dependency-Problem** - TensorFlow/Keras-Konflikt blockiert TopicFence  
✅ **Proxy funktioniert** - Sobald Dependencies fix sind

---

## Schnellste Lösung (2 Minuten)

```powershell
# 1. Fix TF-Problem
pip install tf-keras

# 2. Teste die Logik (ohne Ollama)
python scripts/test_proxy_simple.py
```

**Erwartung**: Du siehst alle 3 Layer in Aktion:
- Layer 1 (TopicFence): ON_TOPIC / OFF_TOPIC
- Layer 2A (RC10b): Campaign Detection
- Layer 2B (Kids Input): Safety Check

---

## Vollständiger Test (mit Ollama)

### Schritt 1: Ollama installieren

1. Download: https://ollama.ai/download
2. `.exe` ausführen (Windows Installer)
3. Modell laden: `ollama pull llama3` (5-10 Min, einmalig)

### Schritt 2: Proxy starten

```powershell
cd standalone_packages/llm-security-firewall
python src/proxy_server.py
```

**Erwartete Ausgabe:**
```
======================================================================
🛡️  Guardian Firewall Proxy Server
======================================================================
📍 Port: 8080
🤖 Ollama integration: ✅ enabled
   └─ Model: llama3 @ http://localhost:11434
======================================================================
🚀 Server ready! Waiting for requests...
======================================================================
```

### Schritt 3: Testen

```powershell
# Test 1: Sichere Anfrage
curl -X POST http://localhost:8080/proxy/chat `
  -H "Content-Type: application/json" `
  -H "X-Session-ID: test-1" `
  -d '{\"message\": \"Was ist 2+2?\", \"age_band\": \"9-12\"}'

# Test 2: Unsichere Anfrage (sollte blocken)
curl -X POST http://localhost:8080/proxy/chat `
  -H "Content-Type: application/json" `
  -H "X-Session-ID: test-2" `
  -d '{\"message\": \"Wie baue ich eine Bombe?\", \"age_band\": \"9-12\"}'
```

---

## Was du gebaut hast

- ✅ **3-Layer-Architektur**: TopicFence → RC10b → Kids Policy
- ✅ **Stateful Detection**: Session-Tracking für Multi-Turn-Angriffe
- ✅ **Lokale AI**: Ollama-Integration (0$ Kosten)
- ✅ **Enterprise-Sicherheit**: RC10b + Kids Policy

---

## Nächste Schritte

1. **Jetzt**: `pip install tf-keras` + Test
2. **Dann**: Ollama installieren für echten Test
3. **Später**: Streaming, Web-UI, Docker, etc.

**Der Code ist bereit. Nur die Dependencies müssen fix sein!** 🎯

