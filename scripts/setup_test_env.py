"""
Setup environment variables for testing with Redis Cloud.

Usage:
    python setup_test_env.py
    # Then run tests:
    pytest tests/integration/test_redis_cloud.py -v
"""

import os
import sys
from pathlib import Path

try:
    import configparser

    HAS_CONFIGPARSER = True
except ImportError:
    HAS_CONFIGPARSER = False


def load_redis_cloud_credentials():
    """Load Redis Cloud credentials from config file or environment."""
    # Priority 1: Environment variables
    if os.getenv("REDIS_CLOUD_HOST"):
        return {
            "host": os.getenv("REDIS_CLOUD_HOST"),
            "port": int(os.getenv("REDIS_CLOUD_PORT", "6379")),
            "password": os.getenv("REDIS_CLOUD_PASSWORD"),
            "ssl": os.getenv("REDIS_CLOUD_SSL", "True").lower() == "true",
        }

    # Priority 2: Config file
    if HAS_CONFIGPARSER:
        config_path = Path.home() / ".llm_firewall" / "redis_cloud.ini"
        if config_path.exists():
            config = configparser.ConfigParser()
            config.read(config_path)
            if "redis_cloud" in config:
                return {
                    "host": config["redis_cloud"].get("host"),
                    "port": config["redis_cloud"].getint("port", 6379),
                    "password": config["redis_cloud"].get("password"),
                    "ssl": config["redis_cloud"].getboolean("ssl", True),
                }

    return None


def setup_test_environment():
    """Setup environment variables for tests."""
    credentials = load_redis_cloud_credentials()

    if credentials:
        # Build Redis URL
        if credentials["ssl"]:
            scheme = "rediss"
        else:
            scheme = "redis"

        redis_url = f"{scheme}://:{credentials['password']}@{credentials['host']}:{credentials['port']}"
        os.environ["REDIS_URL"] = redis_url
        os.environ["CACHE_MODE"] = "exact"  # Default for integration tests

        print(f"✅ Redis Cloud configured: {credentials['host']}:{credentials['port']}")
        return True
    else:
        print("⚠️  Redis Cloud credentials not found")
        print("Set environment variables:")
        print("  export REDIS_CLOUD_HOST='your-host.redislabs.com'")
        print("  export REDIS_CLOUD_PASSWORD='your-password'")
        return False


if __name__ == "__main__":
    if setup_test_environment():
        # Run tests
        import subprocess

        cmd = ["pytest", "tests/integration/test_redis_cloud.py", "-v"]
        subprocess.run(cmd)
    else:
        sys.exit(1)
