#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAK_GAL Firewall Auto-Monitor
==============================

Kontinuierliches automatisches Monitoring mit Alerting.
Läuft im Hintergrund und prüft alle 60 Sekunden.

Author: Joerg Bollwahn
Date: 2025-11-29
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from mcp_firewall_monitor import FirewallMonitorMCPServer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("monitoring/firewall_monitor.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("AutoMonitor")


async def monitor_loop(interval: int = 60):
    """Kontinuierliches Monitoring-Loop"""
    server = FirewallMonitorMCPServer()

    logger.info("Starting auto-monitor (interval: %d seconds)", interval)

    while True:
        try:
            # Health Check
            health_result = await server._health_check(
                {"check_redis": True, "check_sessions": True, "check_guards": True}
            )
            health_data = json.loads(health_result["content"][0]["text"])

            # Check Alerts
            alerts_result = await server._check_alerts({"alert_type": "all"})
            alerts_data = json.loads(alerts_result["content"][0]["text"])

            # Log status
            status = health_data.get("status", "unknown")
            alert_count = alerts_data.get("alert_count", 0)

            logger.info("Status: %s, Alerts: %d", status, alert_count)

            # If alerts present, log details
            if alert_count > 0:
                logger.warning("ALERTS DETECTED:")
                for alert in alerts_data.get("alerts", []):
                    logger.warning(
                        "  [%s] %s: %s",
                        alert.get("severity", "unknown"),
                        alert.get("type", "unknown"),
                        alert.get("message", ""),
                    )

            # Save status to file
            status_file = Path("monitoring") / "last_status.json"
            status_file.parent.mkdir(exist_ok=True)

            with open(status_file, "w") as f:
                json.dump(
                    {
                        "timestamp": datetime.utcnow().isoformat(),
                        "status": status,
                        "health": health_data,
                        "alerts": alerts_data,
                    },
                    f,
                    indent=2,
                )

            await asyncio.sleep(interval)

        except KeyboardInterrupt:
            logger.info("Stopping auto-monitor")
            break
        except Exception as e:
            logger.exception("Error in monitor loop")
            await asyncio.sleep(interval)


if __name__ == "__main__":
    interval = int(os.getenv("MONITOR_INTERVAL", "60"))
    asyncio.run(monitor_loop(interval))
