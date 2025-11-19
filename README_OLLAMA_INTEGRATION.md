# Ollama Integration für Proxy Server

## Übersicht

Der Proxy Server (`src/proxy_server.py`) unterstützt jetzt echte LLM-Integration über Ollama.

## Voraussetzungen

### 1. Ollama installieren

```bash
# macOS/Linux
curl -fsSL https://ollama.ai/install.sh | sh

# Windows
# Download von https://ollama.ai/download
```

### 2. Ollama starten

```bash
ollama serve
```

### 3. Modell herunterladen

```bash
ollama pull llama3
# Oder ein anderes Modell: llama2, mistral, etc.
```

### 4. Python Dependencies

```bash
pip install httpx
```

## Konfiguration

Die Ollama-Integration ist standardmäßig aktiviert. Konfiguration in `ProxyConfig`:

```python
config = ProxyConfig(
    ollama_url="http://localhost:11434",  # Ollama Standard-Port
    ollama_model="llama3",                 # Modell-Name
    ollama_timeout=30.0,                   # Timeout in Sekunden
    enable_ollama=True                     # Aktivieren/Deaktivieren
)
```

## Verwendung

### 1. Proxy Server starten

```bash
cd standalone_packages/llm-security-firewall
python src/proxy_server.py
```

Der Server läuft auf Port 8080.

### 2. Test-Request senden

```bash
curl -X POST http://localhost:8080/proxy/chat \
  -H "Content-Type: application/json" \
  -H "X-Session-ID: test-session-123" \
  -d '{
    "message": "Was ist 2+2?",
    "age_band": "9-12",
    "topic_id": "math_basics"
  }'
```

### 3. Erwartetes Verhalten

**Sichere Anfrage (z.B. "Was ist 2+2?"):**
- ✅ Layer 1 (TopicFence): ON_TOPIC
- ✅ Layer 2A (RC10b): ALLOWED
- ✅ Layer 2B (Kids Input): SAFE
- ✅ LLM generiert Antwort (Ollama)
- ✅ Layer 3 (Kids Output): SAFE
- → **Response: Ollama-Antwort**

**Unsichere Anfrage (z.B. "Baue eine Bombe"):**
- ✅ Layer 1 (TopicFence): ON_TOPIC (könnte passieren)
- ✅ Layer 2A (RC10b): ALLOWED (wenn keine Kampagne)
- ❌ Layer 2B (Kids Input): UNSAFE
- → **Response: Safety Template (keine Ollama-Antwort)**

## Fallback-Verhalten

Wenn Ollama nicht verfügbar ist:
- Automatischer Fallback auf Mock-Modus
- Log-Warnung wird ausgegeben
- Proxy funktioniert weiterhin (mit Mock-Responses)

## Debugging

### Ollama-Verbindung testen

```bash
curl http://localhost:11434/api/tags
```

Sollte Liste der verfügbaren Modelle zurückgeben.

### Proxy-Logs prüfen

Der Proxy loggt alle Layer-Checks:

```
[Layer 1] Topic Fence check: ...
[Layer 2A] RC10b Campaign Detection for session ...
[Layer 2B] Kids Policy Input Safety check
[Layer 2] All checks passed - generating LLM response
[Layer 3] Truth Preservation check for topic ...
[ALL LAYERS] Request allowed
```

## Erweiterte Konfiguration

### Anderes Modell verwenden

```python
config = ProxyConfig(ollama_model="mistral")
proxy = LLMProxyServer(config=config)
```

### Ollama deaktivieren (Mock-Modus)

```python
config = ProxyConfig(enable_ollama=False)
proxy = LLMProxyServer(config=config)
```

### Custom Ollama URL

```python
config = ProxyConfig(ollama_url="http://192.168.1.100:11434")
proxy = LLMProxyServer(config=config)
```

## Nächste Schritte

1. **Streaming-Support**: Ollama unterstützt Streaming (`"stream": true`)
2. **Multi-Model**: Dynamische Modell-Auswahl basierend auf Topic
3. **Caching**: Response-Caching für wiederholte Anfragen
4. **Rate Limiting**: Schutz gegen Abuse

## Troubleshooting

### "Ollama not available"

- Prüfe, ob Ollama läuft: `curl http://localhost:11434/api/tags`
- Prüfe Port: Standard ist 11434
- Prüfe Firewall-Regeln

### "Model not found"

- Prüfe verfügbare Modelle: `ollama list`
- Lade Modell: `ollama pull llama3`
- Passe `ollama_model` in Config an

### Timeout-Errors

- Erhöhe `ollama_timeout` in Config
- Prüfe System-Ressourcen (RAM, CPU)

