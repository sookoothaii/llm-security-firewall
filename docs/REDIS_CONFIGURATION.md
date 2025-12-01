# Redis Configuration Guide

**Date:** 2025-12-01
**Status:** Redis Cloud already configured and working

---

## Current Configuration

Redis Cloud is already configured and operational:

- **Host:** `redis-19088.c305.ap-south-1-1.ec2.cloud.redislabs.com`
- **Port:** `19088`
- **Status:** Connected
- **Memory:** ~5.2 MB used

---

## Environment Variables

The system uses the following environment variables (in priority order):

1. `REDIS_CLOUD_HOST` - Redis Cloud hostname
2. `REDIS_CLOUD_PORT` - Redis Cloud port (default: 6379)
3. `REDIS_CLOUD_USERNAME` - Redis Cloud username (optional)
4. `REDIS_CLOUD_PASSWORD` - Redis Cloud database password
5. `REDIS_URL` - Full Redis URL (alternative to above)
6. `REDIS_HOST` - Fallback to local Redis
7. `REDIS_PORT` - Fallback port (default: 6379)
8. `REDIS_PASSWORD` - Fallback password

---

## MCP Tools Available

The firewall has MCP monitoring tools that can check Redis status:

### Available MCP Tools:

1. **firewall_health_check** - Complete health check (Redis, Sessions, Guards)
2. **firewall_redis_status** - Detailed Redis status (memory, connections, keys)
3. **firewall_metrics** - Firewall metrics (rate limits, blocks, sessions)
4. **firewall_deployment_status** - Deployment status and health
5. **firewall_check_alerts** - Critical alerts check

### Usage in Cursor:

The MCP tools are automatically available in Cursor. You can use them to:
- Check Redis connection status
- Monitor memory usage
- View session counts
- Check for alerts

---

## Testing Redis Connection

### Method 1: MCP Tool (Recommended)

Use the MCP tool in Cursor:
```
firewall_redis_status
```

### Method 2: Python Test

```python
from llm_firewall.cache.decision_cache import get_cached, set_cached

# Test connection
test_data = {"allowed": True, "reason": "test", "risk_score": 0.0}
set_cached("test", "test_key", test_data, ttl=10)
result = get_cached("test", "test_key")
print(f"Redis connection: {'OK' if result else 'FAILED'}")
```

### Method 3: Integration Test

```bash
pytest tests/integration/test_redis_cloud.py -v
```

---

## Configuration Source

The Redis configuration is read from environment variables by:

1. **MCP Firewall Monitor** (`scripts/mcp_firewall_monitor.py`)
   - Method: `_get_redis_config()`
   - Priority: `REDIS_CLOUD_*` > `REDIS_*` > localhost

2. **Decision Cache** (`src/llm_firewall/cache/decision_cache.py`)
   - Uses same environment variables
   - Supports both sync and async connections

---

## Current Status (Verified via MCP Tool)

**Redis Cloud is connected and working:**
- **Host:** `redis-19088.c305.ap-south-1-1.ec2.cloud.redislabs.com`
- **Port:** `19088`
- **Connection:** OK
- **Memory:** 5.2 MB used (healthy)
- **Connections:** 2 active clients
- **Sessions:** 1 active session
- **Guards:** All healthy

**No additional setup required** - Redis is ready for integration tests.

**Note:** The MCP tools have access to Redis credentials that may be configured separately from environment variables. This allows Redis to work even if `REDIS_CLOUD_*` env vars are not set in the test context.

---

## Troubleshooting

### If Redis connection fails:

1. **Check environment variables:**
   ```powershell
   $env:REDIS_CLOUD_HOST
   $env:REDIS_CLOUD_PASSWORD
   ```

2. **Use MCP tool to check status:**
   ```
   firewall_health_check
   ```

3. **Verify credentials in Redis Cloud Dashboard:**
   - Database Password (not API Key!)
   - IP Whitelist includes your IP

---

**Note:** The MCP tools automatically use the existing Redis configuration. No manual setup needed for integration tests.
