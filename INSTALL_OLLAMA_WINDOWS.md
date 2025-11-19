# Ollama Installation für Windows

## Schnell-Installation

### Schritt 1: Download

1. Gehe zu: https://ollama.ai/download
2. Lade die Windows-Version herunter (`.exe` Installer)

### Schritt 2: Installation

1. Führe die `.exe` Datei aus
2. Folge dem Installations-Assistenten
3. Ollama wird automatisch als Windows-Service installiert

### Schritt 3: Modell herunterladen

Öffne PowerShell oder CMD und führe aus:

```powershell
ollama pull llama3
```

**Hinweis**: Das erste Mal kann 5-10 Minuten dauern (Modell ist ~4.7GB).

### Schritt 4: Test

```powershell
ollama run llama3 "Hallo, wie geht es dir?"
```

Wenn du eine Antwort siehst → ✅ Ollama funktioniert!

---

## Alternative: Ollama als Service

Ollama läuft standardmäßig als Windows-Service. Du musst es nicht manuell starten.

**Prüfen, ob Ollama läuft:**

```powershell
curl http://localhost:11434/api/tags
```

Sollte eine JSON-Liste mit verfügbaren Modellen zurückgeben.

---

## Troubleshooting

### "ollama: command not found"

- Stelle sicher, dass Ollama installiert ist
- Starte PowerShell/CMD neu (für PATH-Updates)
- Prüfe, ob `ollama.exe` in `C:\Users\<DeinName>\AppData\Local\Programs\Ollama\` existiert

### Port 11434 bereits belegt

```powershell
# Prüfe, was auf Port 11434 läuft
netstat -ano | findstr :11434

# Falls nötig: Stoppe den Service
Stop-Service Ollama
```

### Modell-Download schlägt fehl

- Prüfe Internet-Verbindung
- Stelle sicher, dass genug Speicherplatz vorhanden ist (~5GB für llama3)
- Versuche es erneut: `ollama pull llama3`

---

## Nach der Installation

Sobald Ollama installiert ist, kannst du den Proxy starten:

```powershell
cd standalone_packages/llm-security-firewall
python src/proxy_server.py
```

Der Proxy erkennt Ollama automatisch und verbindet sich.

