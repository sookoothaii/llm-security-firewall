#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAK_GAL Emergency Bypass
=========================

NOTFALL-TOOL: Deaktiviert die Firewall temporär (15 Minuten TTL).

WARNUNG: Nur im absoluten Notfall verwenden (False-Positive Storm >30%).

Author: Joerg Bollwahn
Date: 2025-11-29
"""

import asyncio
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    import redis.asyncio as redis

    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    redis = None


class EmergencyBypass:
    """Emergency Bypass mit HMAC-Signierung und TTL"""

    def __init__(self, redis_client=None):
        self.redis_client = redis_client
        self.bypass_key = os.getenv("HAK_GAL_BYPASS_KEY", "")
        self.ttl_seconds = 15 * 60  # 15 Minuten

        if not self.bypass_key:
            raise ValueError("HAK_GAL_BYPASS_KEY environment variable not set!")

    def _generate_signature(self, action: str, timestamp: str) -> str:
        """HMAC-SHA256 Signatur generieren"""
        message = f"{action}:{timestamp}"
        return hmac.new(
            self.bypass_key.encode(), message.encode(), hashlib.sha256
        ).hexdigest()

    async def activate_bypass(self, component: str = "all") -> dict:
        """
        Aktiviert Emergency Bypass für 15 Minuten.

        Args:
            component: "inbound", "outbound", "rate_limit", oder "all"

        Returns:
            dict mit Status und Expiry
        """
        if not self.redis_client:
            raise RuntimeError("Redis client not available")

        timestamp = datetime.utcnow().isoformat()
        signature = self._generate_signature(f"bypass_{component}", timestamp)

        bypass_data = {
            "component": component,
            "activated_at": timestamp,
            "expires_at": (
                datetime.utcnow() + timedelta(seconds=self.ttl_seconds)
            ).isoformat(),
            "signature": signature,
            "activated_by": os.getenv("USER", "unknown"),
        }

        # Store in Redis with TTL
        key = f"hakgal:emergency:bypass:{component}"
        await self.redis_client.setex(key, self.ttl_seconds, json.dumps(bypass_data))

        # Log to immutable log file
        log_file = Path("logs") / "emergency_bypass.log"
        log_file.parent.mkdir(exist_ok=True)

        with open(log_file, "a") as f:
            f.write(json.dumps(bypass_data) + "\n")

        return {
            "status": "activated",
            "component": component,
            "expires_at": bypass_data["expires_at"],
            "ttl_seconds": self.ttl_seconds,
            "warning": "Bypass expires automatically in 15 minutes!",
        }

    async def check_bypass_status(self, component: str = "all") -> dict:
        """Prüft ob Bypass aktiv ist"""
        if not self.redis_client:
            return {"active": False, "error": "Redis not available"}

        key = f"hakgal:emergency:bypass:{component}"
        data = await self.redis_client.get(key)

        if not data:
            return {"active": False}

        bypass_data = json.loads(data.decode() if isinstance(data, bytes) else data)
        expires_at = datetime.fromisoformat(bypass_data["expires_at"])

        if datetime.utcnow() > expires_at:
            await self.redis_client.delete(key)
            return {"active": False, "expired": True}

        return {
            "active": True,
            "component": bypass_data["component"],
            "activated_at": bypass_data["activated_at"],
            "expires_at": bypass_data["expires_at"],
            "remaining_seconds": int((expires_at - datetime.utcnow()).total_seconds()),
        }

    async def deactivate_bypass(self, component: str = "all") -> dict:
        """Deaktiviert Bypass manuell (vor Ablauf)"""
        if not self.redis_client:
            return {"status": "error", "message": "Redis not available"}

        key = f"hakgal:emergency:bypass:{component}"
        deleted = await self.redis_client.delete(key)

        return {
            "status": "deactivated" if deleted else "not_found",
            "component": component,
        }


async def main():
    """CLI für Emergency Bypass"""
    import argparse

    parser = argparse.ArgumentParser(description="HAK_GAL Emergency Bypass")
    parser.add_argument(
        "action", choices=["activate", "status", "deactivate"], help="Action to perform"
    )
    parser.add_argument(
        "--component",
        default="all",
        choices=["all", "inbound", "outbound", "rate_limit"],
        help="Component to bypass",
    )
    parser.add_argument(
        "--redis-host", default=os.getenv("REDIS_CLOUD_HOST"), help="Redis host"
    )
    parser.add_argument(
        "--redis-port",
        type=int,
        default=int(os.getenv("REDIS_CLOUD_PORT", "19088")),
        help="Redis port",
    )
    parser.add_argument(
        "--redis-username",
        default=os.getenv("REDIS_CLOUD_USERNAME"),
        help="Redis username",
    )
    parser.add_argument(
        "--redis-password",
        default=os.getenv("REDIS_CLOUD_PASSWORD"),
        help="Redis password",
    )

    args = parser.parse_args()

    # Connect to Redis
    if not HAS_REDIS:
        print("ERROR: Redis package not installed")
        sys.exit(1)

    redis_client = redis.Redis(
        host=args.redis_host,
        port=args.redis_port,
        username=args.redis_username,
        password=args.redis_password,
        db=0,
        decode_responses=False,
    )

    try:
        await redis_client.ping()
    except Exception as e:
        print(f"ERROR: Cannot connect to Redis: {e}")
        sys.exit(1)

    bypass = EmergencyBypass(redis_client=redis_client)

    try:
        if args.action == "activate":
            print("=" * 60)
            print("WARNING: Emergency Bypass Activation")
            print("=" * 60)
            print("This will disable firewall protection for 15 minutes!")
            print("Only use in case of False-Positive Storm >30%")
            print("=" * 60)

            confirm = input("Type 'ACTIVATE' to confirm: ")
            if confirm != "ACTIVATE":
                print("Aborted.")
                sys.exit(0)

            result = await bypass.activate_bypass(args.component)
            print(json.dumps(result, indent=2))
            print("\nBypass activated. Expires automatically in 15 minutes.")

        elif args.action == "status":
            result = await bypass.check_bypass_status(args.component)
            print(json.dumps(result, indent=2))

        elif args.action == "deactivate":
            result = await bypass.deactivate_bypass(args.component)
            print(json.dumps(result, indent=2))
            print("\nBypass deactivated.")

    finally:
        await redis_client.aclose()


if __name__ == "__main__":
    asyncio.run(main())
