"""
Quick test script to verify Redis Cloud connection.
Run this to debug connection issues.
"""

import asyncio
import os
import sys

try:
    import redis.asyncio as redis
except ImportError:
    print("ERROR: redis package not installed")
    sys.exit(1)


async def test_connection():
    """Test Redis Cloud connection with different authentication methods."""

    host = os.getenv(
        "REDIS_CLOUD_HOST", "redis-19088.c305.ap-south-1-1.ec2.cloud.redislabs.com"
    )
    port = int(os.getenv("REDIS_CLOUD_PORT", "19088"))
    username = os.getenv("REDIS_CLOUD_USERNAME", "default")
    password = os.getenv("REDIS_CLOUD_PASSWORD") or os.getenv("REDIS_CLOUD_API_KEY")

    print(f"Testing connection to: {host}:{port}")
    print(f"Username: {username}")
    print(f"Password: {'[SET]' if password else '[NOT SET]'}")
    print()

    if not password:
        print("ERROR: REDIS_CLOUD_PASSWORD not set!")
        return

    # Test 1: With username
    print("Test 1: With username and password...")
    try:
        client1 = redis.Redis(
            host=host,
            port=port,
            username=username,
            password=password,
            db=0,
            decode_responses=False,
        )
        await client1.ping()
        print("SUCCESS: Connection with username works!")
        await client1.aclose()
        return
    except Exception as e:
        print(f"FAILED: {e}")

    # Test 2: Without username (password only)
    print("\nTest 2: Password only (no username)...")
    try:
        client2 = redis.Redis(
            host=host,
            port=port,
            password=password,
            db=0,
            decode_responses=False,
        )
        await client2.ping()
        print("SUCCESS: Connection without username works!")
        await client2.aclose()
        return
    except Exception as e:
        print(f"FAILED: {e}")

    # Test 3: Try with empty username
    print("\nTest 3: Empty username...")
    try:
        client3 = redis.Redis(
            host=host,
            port=port,
            username="",
            password=password,
            db=0,
            decode_responses=False,
        )
        await client3.ping()
        print("SUCCESS: Connection with empty username works!")
        await client3.aclose()
        return
    except Exception as e:
        print(f"FAILED: {e}")

    print("\nAll connection attempts failed!")
    print("\nTroubleshooting:")
    print(
        "1. Check if password is correct (from Redis Cloud Dashboard -> Database -> Configuration)"
    )
    print("2. Check if username is correct (might not be 'default')")
    print("3. Check if database is active in Redis Cloud")
    print("4. Check firewall/IP whitelist settings")


if __name__ == "__main__":
    asyncio.run(test_connection())
