# 🚀 Proxy Server starten

## Status

✅ **tf-keras installiert** - TensorFlow-Problem behoben  
✅ **Test erfolgreich** - Alle 3 Layer funktionieren  
⚠️ **FastAPI prüfen** - Möglicherweise nicht installiert

---

## Schnellstart

### Schritt 1: FastAPI installieren (falls nicht vorhanden)

```powershell
pip install fastapi uvicorn httpx
```

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
📚 Allowed topics: ['Mathe', 'Physik', 'Chemie', 'Biologie']
🔒 RC10b detector: ✅ enabled
👶 Kids Policy Truth Validator: ⚠️  disabled
🤖 Ollama integration: ⚠️  disabled (mock mode)
======================================================================
🚀 Server ready! Waiting for requests...
======================================================================
```

**Hinweis**: Wenn Ollama nicht installiert ist, läuft der Server im **Mock-Modus** (kein Problem für Tests).

### Schritt 3: Testen (in neuem Terminal)

```powershell
# Test 1: Sichere Anfrage
python scripts/test_proxy_live.py

# Oder manuell mit PowerShell:
$body = @{message="Was ist 2+2?"; age_band="9-12"} | ConvertTo-Json
Invoke-RestMethod -Uri "http://localhost:8080/proxy/chat" -Method Post -Body $body -ContentType "application/json"
```

---

## Was du siehst

### Bei sicheren Anfragen:
- ✅ Layer 1 (TopicFence): ON_TOPIC
- ✅ Layer 2A (RC10b): ALLOWED
- ✅ Layer 2B (Kids Input): SAFE
- ✅ Response: Mock-Response (oder Ollama, falls installiert)

### Bei unsicheren Anfragen:
- ✅ Layer 1: ON_TOPIC (kann passieren)
- ✅ Layer 2A: ALLOWED (Single-Request)
- ❌ Layer 2B: **BLOCKED** (Keyword erkannt)
- ✅ Response: Safety Template (keine LLM-Antwort)

---

## Nächste Schritte

1. **Jetzt**: Proxy starten und testen (Mock-Modus ist OK)
2. **Optional**: Ollama installieren für echte LLM-Responses
3. **Später**: Streaming, Web-UI, etc.

**Der Code ist bereit. Starte einfach den Server!** 🎯

