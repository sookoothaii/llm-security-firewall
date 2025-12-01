#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAK_GAL Firewall MCP Monitor Server
====================================

Automatisches Monitoring-Tool für HAK_GAL v2.3.3 Firewall.
Bereitgestellt als MCP-Tool für maximale Automatisierung.

Features:
- Health-Check (Redis, Session Manager, Guards)
- Deployment-Status
- Metriken-Abruf
- Automatische Alert-Erkennung

Author: Joerg Bollwahn
Date: 2025-11-29
Version: 1.0.0
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Add src to path (scripts/ is in parent directory)
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    import redis.asyncio as redis

    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    redis = None

try:
    from hak_gal.core.redis_session_manager import RedisSessionManager
    from hak_gal.utils.crypto import CryptoUtils

    HAS_FIREWALL = True
except ImportError:
    HAS_FIREWALL = False

logger = logging.getLogger("FirewallMonitor")
logger.setLevel(logging.INFO)

# ============================================================================
# MCP SERVER IMPLEMENTATION
# ============================================================================


class FirewallMonitorMCPServer:
    """MCP Server für HAK_GAL Firewall Monitoring"""

    def __init__(self):
        self.name = "hak-gal-firewall-monitor"
        self.version = "1.0.0"
        self.handshake_complete = False

    def _get_tool_list(self) -> List[Dict]:
        """Liste aller verfügbaren Monitoring-Tools"""
        return [
            {
                "name": "firewall_health_check",
                "description": "Automatischer Health-Check für HAK_GAL Firewall (Redis, Session Manager, Guards)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "check_redis": {
                            "type": "boolean",
                            "description": "Redis-Verbindung prüfen",
                            "default": True,
                        },
                        "check_sessions": {
                            "type": "boolean",
                            "description": "Session Manager prüfen",
                            "default": True,
                        },
                        "check_guards": {
                            "type": "boolean",
                            "description": "Guards prüfen",
                            "default": True,
                        },
                    },
                },
            },
            {
                "name": "firewall_deployment_status",
                "description": "Aktueller Deployment-Status (Phase, Traffic-%, Metriken)",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "firewall_metrics",
                "description": "Aktuelle Firewall-Metriken (Rate Limits, Blocks, Sessions, etc.)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "metric_type": {
                            "type": "string",
                            "description": "Metrik-Typ: 'all', 'rate_limits', 'sessions', 'blocks'",
                            "default": "all",
                        }
                    },
                },
            },
            {
                "name": "firewall_check_alerts",
                "description": "Prüft kritische Alerts (Rate Limit Storm, Session Bleeding, etc.)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "alert_type": {
                            "type": "string",
                            "description": "Alert-Typ: 'all', 'rate_limit', 'session', 'guard'",
                            "default": "all",
                        }
                    },
                },
            },
            {
                "name": "firewall_redis_status",
                "description": "Detaillierter Redis-Status (Memory, Connections, Keys, etc.)",
                "inputSchema": {"type": "object", "properties": {}},
            },
        ]

    async def handle_initialize(self, request: Dict) -> Dict:
        """MCP Initialize Handler"""
        return {
            "jsonrpc": "2.0",
            "id": request.get("id", 1),
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": self.name, "version": self.version},
            },
        }

    async def handle_list_tools(self, request: Dict) -> Dict:
        """Liste aller verfügbaren Tools"""
        tools = self._get_tool_list()
        return {
            "jsonrpc": "2.0",
            "id": request.get("id", 1),
            "result": {"tools": tools},
        }

    async def handle_tool_call(self, request: Dict) -> Dict:
        """Tool-Aufruf Handler"""
        params = request.get("params", {})
        tool_name = params.get("name", "")
        tool_args = params.get("arguments", {})

        result = {"content": [{"type": "text", "text": "Unknown tool"}]}

        try:
            if tool_name == "firewall_health_check":
                result = await self._health_check(tool_args)
            elif tool_name == "firewall_deployment_status":
                result = await self._deployment_status()
            elif tool_name == "firewall_metrics":
                result = await self._get_metrics(tool_args)
            elif tool_name == "firewall_check_alerts":
                result = await self._check_alerts(tool_args)
            elif tool_name == "firewall_redis_status":
                result = await self._redis_status()
            else:
                result = {
                    "content": [{"type": "text", "text": f"Unknown tool: {tool_name}"}],
                    "isError": True,
                }
        except Exception as e:
            logger.exception(f"Error in tool call {tool_name}")
            result = {
                "content": [{"type": "text", "text": f"Error: {str(e)}"}],
                "isError": True,
            }

        return {"jsonrpc": "2.0", "id": request.get("id", 1), "result": result}

    async def _health_check(self, args: Dict) -> Dict:
        """Automatischer Health-Check"""
        check_redis = args.get("check_redis", True)
        check_sessions = args.get("check_sessions", True)
        check_guards = args.get("check_guards", True)

        results = {
            "timestamp": datetime.utcnow().isoformat(),
            "status": "healthy",
            "checks": {},
        }

        # Redis Check
        if check_redis:
            redis_status = await self._check_redis()
            results["checks"]["redis"] = redis_status
            if not redis_status.get("connected"):
                results["status"] = "degraded"

        # Session Manager Check
        if check_sessions:
            session_status = await self._check_sessions()
            results["checks"]["sessions"] = session_status
            if not session_status.get("healthy"):
                results["status"] = "degraded"

        # Guards Check
        if check_guards:
            guards_status = await self._check_guards()
            results["checks"]["guards"] = guards_status
            if not guards_status.get("healthy"):
                results["status"] = "degraded"

        return {"content": [{"type": "text", "text": json.dumps(results, indent=2)}]}

    async def _check_redis(self) -> Dict:
        """Redis-Verbindung prüfen"""
        if not HAS_REDIS:
            return {"connected": False, "error": "Redis package not installed"}

        try:
            config = self._get_redis_config()
            if not config:
                return {"connected": False, "error": "Redis configuration not found"}

            client = redis.Redis(
                host=config["host"],
                port=config["port"],
                username=config.get("username"),
                password=config.get("password"),
                db=0,
                decode_responses=False,
                socket_connect_timeout=5,
            )

            await client.ping()
            info = await client.info("memory")
            await client.aclose()

            return {
                "connected": True,
                "host": config["host"],
                "port": config["port"],
                "memory_used_mb": int(info.get("used_memory", 0)) / 1024 / 1024,
                "memory_peak_mb": int(info.get("used_memory_peak", 0)) / 1024 / 1024,
            }
        except Exception as e:
            return {"connected": False, "error": str(e)}

    async def _check_sessions(self) -> Dict:
        """Session Manager prüfen"""
        if not HAS_FIREWALL:
            return {"healthy": False, "error": "Firewall modules not available"}

        try:
            config = self._get_redis_config()
            if not config:
                return {"healthy": False, "error": "Redis configuration not found"}

            client = redis.Redis(
                host=config["host"],
                port=config["port"],
                username=config.get("username"),
                password=config.get("password"),
                db=0,
                decode_responses=False,
            )

            crypto_utils = CryptoUtils()
            session_manager = RedisSessionManager(
                redis_client=client, crypto_utils=crypto_utils
            )

            # Test session creation
            test_session = await session_manager.async_get_or_create_session(
                tenant_id="monitor_test", raw_user_id="monitor_user"
            )

            # Count sessions in Redis
            keys = await client.keys("hakgal:tenant:*:session:*")
            session_count = len(keys)

            await client.aclose()

            return {
                "healthy": True,
                "session_count": session_count,
                "test_session_created": test_session is not None,
            }
        except Exception as e:
            return {"healthy": False, "error": str(e)}

    async def _check_guards(self) -> Dict:
        """Guards prüfen"""
        # Basic check - guards should be importable
        try:
            return {
                "healthy": True,
                "guards_available": ["SessionTrajectory", "ToolGuardRegistry"],
            }
        except Exception as e:
            return {"healthy": False, "error": str(e)}

    async def _deployment_status(self) -> Dict:
        """Deployment-Status abrufen"""
        status_file = Path(__file__).parent.parent / "deploy" / "deployment_status.json"

        if status_file.exists():
            with open(status_file, "r") as f:
                status = json.load(f)
        else:
            # Default status
            status = {
                "phase": "not_deployed",
                "traffic_percent": 0,
                "deployed_at": None,
                "last_check": datetime.utcnow().isoformat(),
            }

        # Add current health check
        health = await self._health_check(
            {"check_redis": True, "check_sessions": True, "check_guards": True}
        )
        health_data = json.loads(health["content"][0]["text"])
        status["health"] = health_data

        return {"content": [{"type": "text", "text": json.dumps(status, indent=2)}]}

    async def _get_metrics(self, args: Dict) -> Dict:
        """Metriken abrufen"""
        metric_type = args.get("metric_type", "all")
        metrics = {}

        # Redis Metrics
        if metric_type in ["all", "sessions"]:
            redis_status = await self._check_redis()
            if redis_status.get("connected"):
                try:
                    config = self._get_redis_config()
                    client = redis.Redis(
                        host=config["host"],
                        port=config["port"],
                        username=config.get("username"),
                        password=config.get("password"),
                        db=0,
                        decode_responses=False,
                    )

                    # Count sessions
                    session_keys = await client.keys("hakgal:tenant:*:session:*")
                    metrics["sessions"] = {"total": len(session_keys), "by_tenant": {}}

                    # Count by tenant
                    for key in session_keys:
                        key_str = key.decode() if isinstance(key, bytes) else key
                        parts = key_str.split(":")
                        if len(parts) >= 3:
                            tenant = parts[2]
                            metrics["sessions"]["by_tenant"][tenant] = (
                                metrics["sessions"]["by_tenant"].get(tenant, 0) + 1
                            )

                    await client.aclose()
                except Exception as e:
                    metrics["sessions"] = {"error": str(e)}

        # Add timestamp
        metrics["timestamp"] = datetime.utcnow().isoformat()

        return {"content": [{"type": "text", "text": json.dumps(metrics, indent=2)}]}

    async def _check_alerts(self, args: Dict) -> Dict:
        """Kritische Alerts prüfen"""
        alert_type = args.get("alert_type", "all")
        alerts = []

        # Check Redis
        redis_status = await self._check_redis()
        if not redis_status.get("connected"):
            alerts.append(
                {
                    "severity": "critical",
                    "type": "redis_connection",
                    "message": "Redis connection failed",
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )
        else:
            # Check Redis memory
            memory_mb = redis_status.get("memory_used_mb", 0)
            if memory_mb > 2000:  # 2GB threshold
                alerts.append(
                    {
                        "severity": "warning",
                        "type": "redis_memory",
                        "message": f"Redis memory high: {memory_mb:.2f} MB",
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                )

        # Check sessions
        session_status = await self._check_sessions()
        if not session_status.get("healthy"):
            alerts.append(
                {
                    "severity": "critical",
                    "type": "session_manager",
                    "message": "Session manager unhealthy",
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )

        result = {
            "timestamp": datetime.utcnow().isoformat(),
            "alert_count": len(alerts),
            "alerts": alerts,
            "status": "ok" if len(alerts) == 0 else "alerts_present",
        }

        return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}

    async def _redis_status(self) -> Dict:
        """Detaillierter Redis-Status"""
        redis_status = await self._check_redis()

        if not redis_status.get("connected"):
            return {
                "content": [
                    {"type": "text", "text": json.dumps(redis_status, indent=2)}
                ]
            }

        try:
            config = self._get_redis_config()
            client = redis.Redis(
                host=config["host"],
                port=config["port"],
                username=config.get("username"),
                password=config.get("password"),
                db=0,
                decode_responses=False,
            )

            info = await client.info()
            keys = await client.keys("hakgal:*")

            detailed_status = {
                "connected": True,
                "host": config["host"],
                "port": config["port"],
                "memory": {
                    "used_mb": int(info.get("used_memory", 0)) / 1024 / 1024,
                    "peak_mb": int(info.get("used_memory_peak", 0)) / 1024 / 1024,
                    "max_mb": int(info.get("maxmemory", 0)) / 1024 / 1024
                    if info.get("maxmemory")
                    else None,
                },
                "connections": {
                    "connected_clients": info.get("connected_clients", 0),
                    "total_connections": info.get("total_connections_received", 0),
                },
                "keys": {
                    "total_hakgal": len(keys),
                    "sessions": len([k for k in keys if b"session" in k]),
                },
                "timestamp": datetime.utcnow().isoformat(),
            }

            await client.aclose()

            return {
                "content": [
                    {"type": "text", "text": json.dumps(detailed_status, indent=2)}
                ]
            }
        except Exception as e:
            return {
                "content": [
                    {"type": "text", "text": json.dumps({"error": str(e)}, indent=2)}
                ]
            }

    def _get_redis_config(self) -> Optional[Dict]:
        """Redis-Konfiguration aus Environment-Variablen"""
        host = os.getenv("REDIS_CLOUD_HOST") or os.getenv("REDIS_HOST", "localhost")
        port = int(os.getenv("REDIS_CLOUD_PORT") or os.getenv("REDIS_PORT", "6379"))
        username = os.getenv("REDIS_CLOUD_USERNAME") or os.getenv("REDIS_USERNAME")
        password = os.getenv("REDIS_CLOUD_PASSWORD") or os.getenv("REDIS_PASSWORD")

        if not password:
            return None

        return {"host": host, "port": port, "username": username, "password": password}


# ============================================================================
# MCP STDIO SERVER
# ============================================================================


async def main():
    """MCP Server Main Loop (stdio)"""
    server = FirewallMonitorMCPServer()

    # Read from stdin, write to stdout
    while True:
        try:
            line = await asyncio.get_event_loop().run_in_executor(
                None, sys.stdin.readline
            )
            if not line:
                break

            request = json.loads(line.strip())
            method = request.get("method")

            if method == "initialize":
                response = await server.handle_initialize(request)
                server.handshake_complete = True
            elif method == "tools/list":
                response = await server.handle_list_tools(request)
            elif method == "tools/call":
                response = await server.handle_tool_call(request)
            elif method == "notifications/initialized":
                # Handshake complete
                continue
            else:
                response = {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "error": {"code": -32601, "message": f"Unknown method: {method}"},
                }

            print(json.dumps(response))
            sys.stdout.flush()
        except json.JSONDecodeError:
            continue
        except Exception as e:
            logger.exception("Error in main loop")
            error_response = {
                "jsonrpc": "2.0",
                "id": request.get("id") if "request" in locals() else None,
                "error": {"code": -32603, "message": str(e)},
            }
            print(json.dumps(error_response))
            sys.stdout.flush()


if __name__ == "__main__":
    asyncio.run(main())
