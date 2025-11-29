# HAK_GAL System Audit Tool

**CRITICAL FIX (Solo-Dev):** Comprehensive system audit for production debugging.

## Overview

The System Audit Tool checks:
1. **Processes** - Is the firewall running?
2. **Filesystem** - Are critical files present?
3. **Network** - Is the API port open?
4. **API Logic** - Do endpoints respond correctly?
5. **Redis State** - Is Redis connected and populated?

## Installation

```bash
pip install psutil requests redis  # Already in requirements.txt
```

## Usage

### Basic Usage

```bash
# JSON output (for LLM analysis)
python -m cli.system_audit

# Pretty output (human-readable)
python -m cli.system_audit --format pretty
```

### Custom Configuration

```bash
# Custom firewall URL
python -m cli.system_audit --url http://localhost:8000

# Custom Redis host/port
python -m cli.system_audit --redis-host redis.cloud.com --redis-port 6379
```

### Full Options

```bash
python -m cli.system_audit \
    --url http://localhost:8081 \
    --redis-host localhost \
    --redis-port 6379 \
    --format json
```

## Output Format

### JSON Output (Default)

```json
{
  "timestamp": "2025-11-29T12:00:00",
  "process": {
    "active": true,
    "count": 1,
    "running_instances": [
      {
        "pid": 12345,
        "cmd": "python -m uvicorn main:app --port 8081",
        "memory_mb": 256.5,
        "cpu_percent": 2.3
      }
    ]
  },
  "filesystem": {
    "src/hak_gal/layers/inbound/vector_guard.py": {
      "exists": true,
      "size_bytes": 12345,
      "permissions": "644"
    }
  },
  "network": {
    "port_open": true,
    "target_port": 8081
  },
  "logic_tests": {
    "HEALTH_CHECK": {
      "status_code": 200,
      "latency_ms": 12.5,
      "success": true
    }
  },
  "redis_state": {
    "connected": true,
    "hak_gal_key_count": 42
  },
  "health_summary": {
    "process_running": true,
    "port_open": true,
    "redis_connected": true,
    "critical_files_exist": true
  }
}
```

### Pretty Output

```
============================================================
HAK_GAL System Audit Summary
============================================================
Timestamp: 2025-11-29T12:00:00

Process: ✅ Running
Network: ✅ Port open
Redis: ✅ Connected
Files: ✅ All critical files exist

API Tests: 3/4 successful (75.0%)
============================================================
```

## Integration with CI/CD

```bash
# Exit code 0 if all checks pass, 1 if any fail
python -m cli.system_audit --format json | jq -e '.health_summary.process_running == true and .health_summary.port_open == true'
```

## Troubleshooting

### "psutil not installed"

```bash
pip install psutil
```

### "Connection refused" in logic_tests

- Check if firewall is running: `ps aux | grep firewall`
- Check if port is correct: `netstat -an | grep 8081`
- Try different URL: `--url http://localhost:8000`

### "Redis not connected"

- Check Redis is running: `redis-cli ping`
- Check host/port: `--redis-host localhost --redis-port 6379`
- Check environment variables: `REDIS_HOST`, `REDIS_PORT`

## Use Cases

1. **Pre-Deployment Check**: Verify all components before deployment
2. **Post-Deployment Validation**: Confirm system is running correctly
3. **Debugging**: Identify which component is failing
4. **Monitoring**: Regular health checks via cron
5. **LLM Analysis**: JSON output for automated analysis

## Example: Automated Health Check

```bash
#!/bin/bash
# health_check.sh

python -m cli.system_audit --format json > /tmp/audit.json

if jq -e '.health_summary.process_running == true' /tmp/audit.json > /dev/null; then
    echo "✅ System healthy"
    exit 0
else
    echo "❌ System unhealthy"
    cat /tmp/audit.json
    exit 1
fi
```
