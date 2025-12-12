# Learning Monitor Service (Optional)

**Port:** 8004  
**Status:** Optional - Basis-API bleibt in 8001

## Übersicht

Dieser Service ist **OPTIONAL** und bietet erweiterte Monitoring-Features für Online Learning:

- ✅ **Live Dashboard** mit WebSocket-Updates
- ✅ **Alert-System** für kritische Loss-Werte
- ✅ **Multi-Service-Monitoring** (Code-Intent, Persuasion, etc.)
- ✅ **History-Tracking** über mehrere Services

**Wichtig:** Die Basis-API (`/feedback/stats`, `/feedback/train`) bleibt in Port 8001. Dieser Service ist nur für erweiterte Features.

## Installation

```bash
cd learning_monitor_service
pip install fastapi uvicorn websockets requests
```

## Start

```bash
python main.py
# oder
uvicorn main:app --host 0.0.0.0 --port 8004
```

## Endpoints

### GET `/`
Service-Info und verfügbare Endpoints

### GET `/health`
Health Check

### GET `/status`
Status aller überwachten Services

### GET `/alerts`
Aktuelle Alerts (kritische Loss-Werte, etc.)

### GET `/history`
Learning-History

### GET `/dashboard`
HTML Dashboard mit Live-Updates

### WebSocket `/ws`
Live-Updates alle 5 Sekunden

## Konfiguration

Bearbeite `MONITORED_SERVICES` in `main.py`:

```python
MONITORED_SERVICES = {
    "code_intent": {
        "name": "Code-Intent Detector",
        "url": "http://localhost:8001",
        "enabled": True
    },
    # Weitere Services...
}
```

## Verwendung

### Einfaches Monitoring (ohne separaten Service)
```bash
# Nutze direkt die API in 8001
curl http://localhost:8001/feedback/stats
```

### Erweiterte Features (mit separatem Service)
```bash
# Starte Monitoring-Service
python main.py

# Öffne Dashboard
# http://localhost:8004/dashboard

# Prüfe Alerts
curl http://localhost:8004/alerts
```

## Empfehlung

**Für Produktion:**
- Basis-API in 8001 nutzen (einfach, schnell)
- Monitoring-Script (`scripts/monitor_learning.py`) für regelmäßige Checks
- Optional: Separater Service für Dashboard/Alerts

**Für Entwicklung:**
- Separater Service für Live-Dashboard
- WebSocket-Updates für Echtzeit-Monitoring

