"""
Detailed Redis Cloud connection test with verbose output.
"""

import asyncio
import os
import sys

try:
    import redis.asyncio as redis
except ImportError:
    print("ERROR: redis package not installed")
    sys.exit(1)


async def test_detailed():
    """Detailed connection test with verbose output."""

    host = os.getenv(
        "REDIS_CLOUD_HOST", "redis-19088.c305.ap-south-1-1.ec2.cloud.redislabs.com"
    )
    port = int(os.getenv("REDIS_CLOUD_PORT", "19088"))
    username = os.getenv("REDIS_CLOUD_USERNAME", "default")
    password = os.getenv("REDIS_CLOUD_PASSWORD") or os.getenv("REDIS_CLOUD_API_KEY")

    print("=" * 60)
    print("Redis Cloud Connection Test (Detailed)")
    print("=" * 60)
    print(f"\nHost: {host}")
    print(f"Port: {port}")
    print(f"Username: '{username}'")
    print(
        f"Password: {'[SET, length: ' + str(len(password)) + ']' if password else '[NOT SET]'}"
    )
    print()

    if not password:
        print("ERROR: REDIS_CLOUD_PASSWORD not set!")
        print("\nSet it with:")
        print('  $env:REDIS_CLOUD_PASSWORD="Ihr_Passwort"')
        return

    # Show first and last 4 chars of password for verification (not full password!)
    if len(password) > 8:
        pwd_preview = password[:4] + "..." + password[-4:]
    else:
        pwd_preview = "***"
    print(f"Password preview: {pwd_preview} (for verification)")
    print()

    # Test with username="default"
    print("Test 1: Username='default', Password from env...")
    try:
        client = redis.Redis(
            host=host,
            port=port,
            username="default",
            password=password,
            db=0,
            decode_responses=False,
            socket_connect_timeout=5,
        )
        result = await asyncio.wait_for(client.ping(), timeout=5.0)
        print(f"SUCCESS! Connection works! Ping result: {result}")

        # Test a simple operation
        await client.set("test_key", "test_value")
        value = await client.get("test_key")
        await client.delete("test_key")
        print("Test operation successful: set/get/delete works!")

        await client.aclose()
        print("\n" + "=" * 60)
        print("CONNECTION SUCCESSFUL!")
        print("=" * 60)
        return True
    except asyncio.TimeoutError:
        print("FAILED: Connection timeout (check IP whitelist!)")
    except redis.exceptions.AuthenticationError as e:
        print(f"FAILED: Authentication error: {e}")
        print("\nPossible causes:")
        print("  1. Wrong password")
        print("  2. Wrong username (might not be 'default')")
        print("  3. IP not in whitelist")
    except Exception as e:
        print(f"FAILED: {type(e).__name__}: {e}")

    print("\n" + "=" * 60)
    print("CONNECTION FAILED")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Verify password in Redis Cloud Dashboard -> Configuration")
    print("2. Check IP whitelist (your IP: 223.206.68.93)")
    print("3. Verify username (might not be 'default')")
    return False


if __name__ == "__main__":
    success = asyncio.run(test_detailed())
    sys.exit(0 if success else 1)
