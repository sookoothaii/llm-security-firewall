# API Server - Start Instructions

## Problem: ModuleNotFoundError

If you get `ModuleNotFoundError: No module named 'api'`, you are running uvicorn from the wrong directory.

## Solution: Run from Service Directory

The API must be started from the `detectors/code_intent_service` directory.

### Correct Way:

```powershell
# Navigate to service directory
cd detectors\code_intent_service

# Then start the server
python -m uvicorn api.main:app --reload --port 8000
```

### Or use the start script:

```powershell
# From project root
cd detectors\code_intent_service
.\start_api.ps1

# Or from service directory directly
.\start_api.ps1
```

## Alternative: Use Python Path

If you must run from project root, use PYTHONPATH:

```powershell
# From project root
$env:PYTHONPATH = "detectors\code_intent_service"
python -m uvicorn detectors.code_intent_service.api.main:app --reload --port 8000
```

## Verify Server is Running

After starting, verify with:

```powershell
# Health check
Invoke-WebRequest -Uri "http://localhost:8000/api/v1/health" | ConvertFrom-Json

# Or open in browser
Start-Process "http://localhost:8000/docs"
```

## Common Issues

1. **Wrong directory**: Always run from `detectors/code_intent_service`
2. **Port already in use**: Change port with `--port 8001`
3. **Import errors**: Check that you're in the correct directory

