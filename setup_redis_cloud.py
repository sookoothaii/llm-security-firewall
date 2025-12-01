"""
Setup Redis Cloud credentials for testing.

Usage:
    python setup_redis_cloud.py
"""

import os
import getpass
import sys
from pathlib import Path


def setup_redis_cloud():
    """Interactive setup for Redis Cloud credentials."""
    print("Redis Cloud Credentials Setup")
    print("=" * 40)

    host = input("Redis Cloud Host (e.g., host.redislabs.com): ").strip()
    if not host:
        print("ERROR: Host is required")
        return False

    port = input("Redis Cloud Port (default: 6379): ").strip() or "6379"

    username = input("Redis Cloud Username (optional): ").strip()

    password = getpass.getpass("Redis Cloud Password: ").strip()
    if not password:
        print("ERROR: Password is required")
        return False

    ssl = input("Use SSL? (y/n, default: y): ").strip().lower()
    use_ssl = ssl != "n"

    # Set environment variables
    os.environ["REDIS_CLOUD_HOST"] = host
    os.environ["REDIS_CLOUD_PORT"] = port
    if username:
        os.environ["REDIS_CLOUD_USERNAME"] = username
    os.environ["REDIS_CLOUD_PASSWORD"] = password
    os.environ["REDIS_CLOUD_SSL"] = "true" if use_ssl else "false"

    # Build Redis URL
    scheme = "rediss" if use_ssl else "redis"
    if username:
        redis_url = f"{scheme}://{username}:{password}@{host}:{port}"
    else:
        redis_url = f"{scheme}://:{password}@{host}:{port}"

    os.environ["REDIS_URL"] = redis_url

    print("\nRedis Cloud credentials set!")
    print(f"  Host: {host}")
    print(f"  Port: {port}")
    print(f"  SSL: {use_ssl}")
    print(f"  URL: {scheme}://***@{host}:{port}")

    # Test connection
    test_connection = input("\nTest connection? (y/n): ").strip().lower()
    if test_connection == "y":
        try:
            from llm_firewall.cache.decision_cache import get_cached, set_cached

            test_data = {
                "allowed": True,
                "reason": "Connection test",
                "risk_score": 0.0,
            }

            set_cached("test", "connection_test", test_data, ttl=10)
            result = get_cached("test", "connection_test")

            if result:
                print("SUCCESS: Connection test passed!")
                return True
            else:
                print("WARNING: Connection test returned None (may be cache miss)")
                return True
        except Exception as e:
            print(f"ERROR: Connection test failed: {e}")
            return False

    return True


def save_to_config_file():
    """Save credentials to config file (optional)."""
    config_dir = Path.home() / ".llm_firewall"
    config_dir.mkdir(exist_ok=True)

    config_file = config_dir / "redis_cloud.ini"

    save = input(f"\nSave to config file? ({config_file}) (y/n): ").strip().lower()
    if save != "y":
        return

    try:
        import configparser

        config = configparser.ConfigParser()
        config["redis_cloud"] = {
            "host": os.getenv("REDIS_CLOUD_HOST"),
            "port": os.getenv("REDIS_CLOUD_PORT", "6379"),
            "password": os.getenv("REDIS_CLOUD_PASSWORD"),
            "ssl": os.getenv("REDIS_CLOUD_SSL", "True"),
        }

        if os.getenv("REDIS_CLOUD_USERNAME"):
            config["redis_cloud"]["username"] = os.getenv("REDIS_CLOUD_USERNAME")

        with open(config_file, "w") as f:
            config.write(f)

        print(f"SUCCESS: Credentials saved to {config_file}")
    except Exception as e:
        print(f"ERROR: Failed to save config: {e}")


if __name__ == "__main__":
    if setup_redis_cloud():
        save_to_config_file()
        print("\nSetup complete! You can now run integration tests.")
    else:
        print("\nSetup failed. Please check your credentials.")
        sys.exit(1)
