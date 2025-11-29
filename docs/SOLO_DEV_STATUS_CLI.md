# Solo-Dev Status CLI

**CRITICAL FIX (Solo-Dev):** One command to show all relevant status. Replaces 6 Grafana dashboards with a single number: "OK" or "PANIK".

## Installation

```bash
pip install rich  # Optional but recommended for beautiful output
```

## Quick Start

### 1. Register Guards in Your Main Application

```python
# In your main.py or cli/start.py

import asyncio
from src.hak_gal.layers.inbound.vector_guard import SessionTrajectory
from src.hak_gal.utils.tenant_rate_limiter import TenantRateLimiter
from src.hak_gal.utils.tenant_redis_pool import TenantRedisPool
from cli.solo_dev_status import register_guards


async def init_guards():
    """Initialisiert Guards und registriert sie für Status-Monitoring"""

    # 1. Redis Pool initialisieren
    redis_pool = TenantRedisPool(
        base_host=os.getenv("REDIS_HOST", "localhost"),
        base_port=int(os.getenv("REDIS_PORT", "6379")),
    )

    # 2. CUSUM Vector Guard initialisieren
    vector_guard = SessionTrajectory(
        cusum_baseline=0.1,
        cusum_tolerance=0.05,
        cusum_threshold=0.3,
    )

    # 3. Rate Limiter initialisieren
    rate_limiter = TenantRateLimiter(
        tenant_redis_pool=redis_pool,
        window_ms=1000,
        max_requests=10,
    )

    # 4. ALLE Guards für Status-Monitoring registrieren
    register_guards(
        vector_guard=vector_guard,
        rate_limiter=rate_limiter,
        redis_pool=redis_pool,
        default_tenant_id="default",
    )

    return {
        "vector_guard": vector_guard,
        "rate_limiter": rate_limiter,
        "redis_pool": redis_pool,
    }


async def main():
    """Ihre App-Initialisierung"""

    # Guards initialisieren UND für Monitoring registrieren
    guards = await init_guards()

    # Status-CLI ist jetzt verfügbar via:
    # python -m cli.solo_dev_status

    # Ihre normale App-Logik hier...
    # await start_server(guards)


if __name__ == "__main__":
    asyncio.run(main())
```

### 2. Run Status CLI

```bash
# Terminal 1: Ihre App starten
python -m cli.start

# Terminal 2: Status-CLI laufen lassen (Auto-Refresh alle 5 Sekunden)
python -m cli.solo_dev_status --refresh 5
```

## Dashboard Features

The dashboard shows:

1. **Redis Cloud Health**
   - Connection pool usage
   - Latency (ms)
   - Pool health status

2. **CUSUM Guard (Oscillation Detection)**
   - False-Positive Rate (target <1%)
   - Total checks / False positives
   - Current threshold and score
   - Health status (OK/WARNING/CRITICAL)

3. **Rate Limiter (Per-Tenant)**
   - Block rate (target <5%)
   - Total requests / Blocked requests
   - Window size and max requests
   - Health status (OK/WARNING)

4. **System Health**
   - Overall status: ✅ SYSTEM OK or ❌ PANIK MODE

## Health Thresholds

- **CUSUM FP-Rate:**
  - OK: < 2%
  - WARNING: 2-5%
  - CRITICAL: > 5%

- **Rate Limiter Block-Rate:**
  - OK: < 10%
  - WARNING: > 10%

- **Redis Pool:**
  - OK: < 80% usage
  - WARNING: > 80% usage

## Actions

The dashboard suggests actions:

- **FP-Rate > 5%:** Increase CUSUM threshold
- **Block-Rate >10%:** Check tenant limits
- **Redis >80%:** Check connection pool

## Troubleshooting

### "Redis Pool nicht registriert!"

Make sure you call `register_guards()` in your main application before running the status CLI.

### "Guards können nicht importiert werden"

Make sure you're running from the project root directory:
```bash
cd standalone_packages/llm-security-firewall
python -m cli.solo_dev_status
```

### Rich not installed

The CLI works without `rich`, but output will be less beautiful. Install with:
```bash
pip install rich
```

## Integration Example

See `docs/SOLO_DEV_STATUS_CLI.md` for complete integration example.
