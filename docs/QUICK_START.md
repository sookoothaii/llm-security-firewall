# 🚀 Quick Start - Guardian Firewall Proxy

## Schritt 1: Proxy-Server starten

**Terminal 1** (Server):

```powershell
cd "D:\MCP Mods\HAK_GAL_HEXAGONAL\standalone_packages\llm-security-firewall"
python src/proxy_server.py
```

**Erwartete Ausgabe:**
```
======================================================================
🛡️  Guardian Firewall Proxy Server
======================================================================
📍 Port: 8080
🤖 Ollama integration: ⚠️  disabled (mock mode)
======================================================================
🚀 Server ready! Waiting for requests...
======================================================================
```

**Wichtig**: Lass dieses Terminal offen! Der Server läuft hier.

---

## Schritt 2: Testen (in neuem Terminal)

**Terminal 2** (Test):

```powershell
cd "D:\MCP Mods\HAK_GAL_HEXAGONAL\standalone_packages\llm-security-firewall"
python scripts/test_proxy_live.py
```

**Oder manuell mit PowerShell:**

```powershell
$body = @{
    message = "Was ist 2+2?"
    age_band = "9-12"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8080/proxy/chat" `
    -Method Post `
    -Body $body `
    -ContentType "application/json" `
    -Headers @{"X-Session-ID"="test-1"}
```

---

## Was du siehst

### Bei sicheren Anfragen:
- ✅ Status: `ALLOWED`
- ✅ Response: Mock-Response (oder Ollama, falls installiert)
- ✅ LLM Provider: `mock` oder `ollama`

### Bei unsicheren Anfragen:
- ❌ Status: `BLOCKED_UNSAFE` oder `BLOCKED_OFF_TOPIC`
- ✅ Response: Safety Template
- ✅ **Ollama wird NICHT aufgerufen!**

---

## Troubleshooting

### "Konnte nicht zum Proxy verbinden"

- Prüfe, ob der Server in Terminal 1 läuft
- Prüfe Port 8080: `netstat -ano | findstr :8080`
- Starte den Server neu: `python src/proxy_server.py`

### "ModuleNotFoundError: No module named 'fastapi'"

```powershell
pip install fastapi uvicorn httpx
```

### Ollama-Integration (Optional)

Falls du echte LLM-Responses willst:

1. Installiere Ollama: [Ollama Download](https://ollama.ai/download)
2. Lade Modell: `ollama pull llama3`
3. Starte Proxy neu → Erkennt Ollama automatisch

---

## Nächste Schritte

1. ✅ **Jetzt**: Server starten und testen
2. **Optional**: Ollama installieren für echte LLM-Responses
3. **Später**: Streaming, Web-UI, Docker, etc.

**Der Code ist bereit. Starte einfach den Server!** 🎯
