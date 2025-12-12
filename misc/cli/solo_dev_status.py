"""
Solo-Dev Status Dashboard - Production-Ready Metrics in einem Befehl

CRITICAL FIX (Solo-Dev): One command to show all relevant status.
Replaces 6 Grafana dashboards with a single number: "OK" or "PANIK".

Usage:
    python -m cli.solo_dev_status --refresh 5

Creator: Joerg Bollwahn
Date: 2025-11-29
Status: Solo-Dev Essential
License: MIT
"""

import asyncio
import sys
import argparse
from typing import Dict, Any, Optional
from datetime import datetime

try:
    from rich.console import Console

    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    Console = None

import os

# Add parent directory to path for imports
_current_dir = os.path.dirname(os.path.abspath(__file__))
_parent_dir = os.path.dirname(_current_dir)
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

# Import guards (relative imports from src)
try:
    from src.hak_gal.layers.inbound.vector_guard import SessionTrajectory
    from src.hak_gal.utils.tenant_rate_limiter import TenantRateLimiter
    from src.hak_gal.utils.tenant_redis_pool import TenantRedisPool

    HAS_GUARDS = True
except ImportError as e:
    HAS_GUARDS = False
    IMPORT_ERROR = str(e)

if HAS_RICH:
    console = Console()
else:
    # Fallback: simple print
    class SimpleConsole:
        def print(self, *args, **kwargs):
            print(*args)

        def clear(self):
            os.system("cls" if os.name == "nt" else "clear")

    console = SimpleConsole()


class SoloDevStatus:
    """Zentrale Status-Instanz für alle Guards"""

    def __init__(self):
        self.vector_guard: Optional[SessionTrajectory] = None
        self.rate_limiter: Optional[TenantRateLimiter] = None
        self.redis_pool: Optional[TenantRedisPool] = None
        self.default_tenant_id = "default"
        self.console = console

    def register_guards(
        self,
        vector_guard: SessionTrajectory,
        rate_limiter: TenantRateLimiter,
        redis_pool: TenantRedisPool,
        default_tenant_id: str = "default",
    ):
        """Dependency Injection für Guards"""
        self.vector_guard = vector_guard
        self.rate_limiter = rate_limiter
        self.redis_pool = redis_pool
        self.default_tenant_id = default_tenant_id

    async def get_redis_health(self) -> Dict[str, Any]:
        """Redis Cloud Health-Check mit Connection-Pooling Metriken"""
        if not self.redis_pool:
            return {
                "status": "ERROR",
                "connected_clients": 0,
                "error": "No Redis pool registered",
            }

        try:
            # Get tenant client (async)
            redis_client = await self.redis_pool.get_tenant_client(
                self.default_tenant_id
            )

            # Get Redis INFO (non-blocking via asyncio)
            info = await redis_client.info("clients")

            connected_clients = info.get("connected_clients", 0)

            # Get pool info from cached pool
            if self.default_tenant_id in self.redis_pool.tenant_pools:
                pool = self.redis_pool.tenant_pools[self.default_tenant_id]
                max_connections = pool.max_connections
            else:
                max_connections = 20  # Default from pool config

            # Performance-Metriken aus dem Pool
            usage_percent = (
                (connected_clients / max_connections) * 100
                if max_connections > 0
                else 0
            )
            pool_health = "OK" if usage_percent < 80 else "WARNING"

            # Latency-Test (async ping)
            start = asyncio.get_event_loop().time()
            await redis_client.ping()
            latency_ms = (asyncio.get_event_loop().time() - start) * 1000

            return {
                "status": "OK",
                "latency_ms": round(latency_ms, 2),
                "connected_clients": connected_clients,
                "max_connections": max_connections,
                "usage_percent": round(usage_percent, 1),
                "pool_health": pool_health,
            }

        except Exception as e:
            return {
                "status": "ERROR",
                "connected_clients": 0,
                "error": str(e),
            }

    async def get_cusum_metrics(self) -> Dict[str, Any]:
        """CUSUM False-Positive-Rate und Guard-Health"""
        if not self.vector_guard:
            return {
                "status": "ERROR",
                "false_positive_rate": 0.0,
                "total_checks": 0,
                "error": "Vector Guard not registered",
            }

        # Thread-safe Zugriff auf Guard-Metriken
        total = getattr(self.vector_guard, "cusum_total_checks", 0)
        false_positives = getattr(self.vector_guard, "cusum_false_positives", 0)

        fp_rate = false_positives / max(total, 1) if total > 0 else 0.0

        # Health-Bewertung
        health = "OK"
        if fp_rate > 0.05:  # >5% FP-Rate = PANIK
            health = "CRITICAL"
        elif fp_rate > 0.02:  # >2% = Warnung
            health = "WARNING"

        return {
            "status": "OK",
            "false_positive_rate": fp_rate,
            "false_positives": false_positives,
            "total_checks": total,
            "health": health,
            "threshold": getattr(self.vector_guard, "cusum_threshold", 0.3),
            "current_score": getattr(self.vector_guard, "cusum_score", 0.0),
        }

    async def get_rate_limit_metrics(self) -> Dict[str, Any]:
        """Rate Limiter Block-Rate und Tenant-Isolation"""
        if not self.rate_limiter:
            return {
                "status": "ERROR",
                "block_rate": 0.0,
                "error": "Rate Limiter not registered",
            }

        total = getattr(self.rate_limiter, "total_requests", 0)
        blocked = getattr(self.rate_limiter, "blocked_requests", 0)

        block_rate = blocked / max(total, 1) if total > 0 else 0.0

        # Health-Bewertung
        health = "OK"
        if block_rate > 0.10:  # >10% Block-Rate = Tenant hat Problem
            health = "WARNING"

        return {
            "status": "OK",
            "block_rate": block_rate,
            "blocked_requests": blocked,
            "total_requests": total,
            "health": health,
            "window_ms": getattr(self.rate_limiter, "window_ms", 1000),
            "max_requests": getattr(self.rate_limiter, "max_requests", 10),
        }

    def render_ascii_dashboard(
        self,
        redis_health: Dict[str, Any],
        cusum_metrics: Dict[str, Any],
        rate_limit_metrics: Dict[str, Any],
    ) -> str:
        """Rendert den ASCII-Dashboard für Terminal"""

        # System-Health (Gesamtbewertung)
        components = [
            redis_health.get("pool_health") == "OK",
            cusum_metrics.get("health") in ["OK", "WARNING"],
            rate_limit_metrics.get("health") in ["OK", "WARNING"],
        ]
        system_health = "✅ SYSTEM OK" if all(components) else "❌ PANIK MODE"

        # Format values safely
        redis_status = redis_health.get("status", "ERROR")
        redis_latency = redis_health.get("latency_ms", "N/A")
        redis_conn = f"{redis_health.get('connected_clients', 0)}/{redis_health.get('max_connections', 20)}"
        redis_usage = redis_health.get("usage_percent", 0)
        redis_pool_health = redis_health.get("pool_health", "ERROR")

        cusum_status = cusum_metrics.get("status", "ERROR")
        cusum_fp_rate = cusum_metrics.get("false_positive_rate", 0.0)
        cusum_fps = cusum_metrics.get("false_positives", 0)
        cusum_total = cusum_metrics.get("total_checks", 0)
        cusum_health = cusum_metrics.get("health", "ERROR")
        cusum_threshold = cusum_metrics.get("threshold", 0.3)
        cusum_score = cusum_metrics.get("current_score", 0.0)

        rate_status = rate_limit_metrics.get("status", "ERROR")
        rate_block_rate = rate_limit_metrics.get("block_rate", 0.0)
        rate_blocked = rate_limit_metrics.get("blocked_requests", 0)
        rate_total = rate_limit_metrics.get("total_requests", 0)
        rate_health = rate_limit_metrics.get("health", "ERROR")
        rate_window = rate_limit_metrics.get("window_ms", 1000)
        rate_max = rate_limit_metrics.get("max_requests", 10)

        dashboard = f"""
╔══════════════════════════════════════════════════════════════╗
║           HAK_GAL Solo-Dev Status Dashboard                  ║
║           {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}                              ║
╠══════════════════════════════════════════════════════════════╣
║ {system_health:<60} ║
╠══════════════════════════════════════════════════════════════╣
║ REDIS CLOUD                                                  ║
║  Status:        {redis_status:<47} ║
║  Latency:       {redis_latency:>6} ms{" " * 41} ║
║  Connections:   {redis_conn} ({redis_usage:>5.1f}%){" " * 28} ║
║  Pool Health:   {redis_pool_health:<47} ║
╠══════════════════════════════════════════════════════════════╣
║ CUSUM GUARD (Oscillation Detection)                          ║
║  Status:        {cusum_status:<47} ║
║  FP-Rate:       {cusum_fp_rate:>6.2%} ({cusum_fps}/{cusum_total}){" " * 21} ║
║  Health:        {cusum_health:<47} ║
║  Threshold:     {cusum_threshold:>6.2f}{" " * 40} ║
║  Current Score: {cusum_score:>6.2f}{" " * 40} ║
╠══════════════════════════════════════════════════════════════╣
║ RATE LIMITER (Per-Tenant)                                    ║
║  Status:        {rate_status:<47} ║
║  Block-Rate:    {rate_block_rate:>6.2%} ({rate_blocked}/{rate_total}){" " * 21} ║
║  Health:        {rate_health:<47} ║
║  Window:        {rate_window} ms{" " * 40} ║
║  Max Requests:  {rate_max:>6}{" " * 40} ║
╠══════════════════════════════════════════════════════════════╣
║ ACTIONS                                                      ║
║  • FP-Rate > 5%:   CUSUM Threshold erhöhen                  ║
║  • Block-Rate >10%: Tenant-Limit prüfen                     ║
║  • Redis >80%:     Connection Pool prüfen                   ║
╚══════════════════════════════════════════════════════════════╝
"""
        return dashboard

    async def run_dashboard(self, refresh_seconds: int = 5):
        """Live-Dashboard mit automatischem Refresh"""

        self.console.clear()

        try:
            while True:
                # Alle Metriken parallel abrufen (non-blocking)
                redis_task = asyncio.create_task(self.get_redis_health())
                cusum_task = asyncio.create_task(self.get_cusum_metrics())
                rate_limit_task = asyncio.create_task(self.get_rate_limit_metrics())

                redis_health, cusum_metrics, rate_limit_metrics = await asyncio.gather(
                    redis_task, cusum_task, rate_limit_task
                )

                # ASCII-Dashboard rendern
                dashboard = self.render_ascii_dashboard(
                    redis_health, cusum_metrics, rate_limit_metrics
                )

                # Terminal aktualisieren
                self.console.clear()
                self.console.print(dashboard)

                # Warten bis zum nächsten Refresh
                await asyncio.sleep(refresh_seconds)
        except KeyboardInterrupt:
            self.console.print(
                "\n[green]Status-CLI beendet.[/green]"
                if HAS_RICH
                else "\nStatus-CLI beendet."
            )


# Globaler Status-Handler (Singleton)
status_handler = SoloDevStatus()


def register_guards(
    vector_guard: SessionTrajectory,
    rate_limiter: TenantRateLimiter,
    redis_pool: TenantRedisPool,
    default_tenant_id: str = "default",
):
    """Globale Registrier-Funktion für Guards"""
    status_handler.register_guards(
        vector_guard, rate_limiter, redis_pool, default_tenant_id
    )


async def main():
    """Entrypoint für CLI"""
    parser = argparse.ArgumentParser(description="Solo-Dev Status Dashboard")
    parser.add_argument(
        "--refresh", type=int, default=5, help="Refresh interval in seconds"
    )
    args = parser.parse_args()

    # Guards müssen vorher registriert worden sein
    if not status_handler.redis_pool:
        console.print(
            "[red]FEHLER: Redis Pool nicht registriert![/red]"
            if HAS_RICH
            else "FEHLER: Redis Pool nicht registriert!"
        )
        console.print("Rufen Sie zuerst register_guards() aus Ihrer main.py auf")
        sys.exit(1)

    # Live-Dashboard starten
    await status_handler.run_dashboard(refresh_seconds=args.refresh)


if __name__ == "__main__":
    if not HAS_GUARDS:
        print(f"FEHLER: Guards können nicht importiert werden: {IMPORT_ERROR}")
        print("Stellen Sie sicher, dass Sie im richtigen Verzeichnis sind.")
        sys.exit(1)

    asyncio.run(main())
