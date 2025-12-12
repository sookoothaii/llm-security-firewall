"""
Create .env file with LangCache credentials
==========================================

Usage:
    python create_env.py
"""

from pathlib import Path

def create_env_file():
    """Create .env file with LangCache credentials."""
    env_file = Path(__file__).parent / ".env"
    
    env_content = """# Code Intent Detection Service - Environment Configuration
# ===========================================================
# DO NOT COMMIT THIS FILE TO VERSION CONTROL

# ============================================================
# Feedback Repository Configuration
# ============================================================
DETECTION_FEEDBACK_REPOSITORY_TYPE=hybrid
DETECTION_ENABLE_FEEDBACK_COLLECTION=true
DETECTION_FEEDBACK_BUFFER_SIZE=10000

# ============================================================
# LangCache Configuration (Semantic Caching)
# ============================================================
LANGCACHE_API_KEY=wy4ECQMIL1OZ2u7-ccjgZs5I6tj-g97lGBuXTmwtwLEZO8mC2eNiOQN7Qu6eAFwE0oIBbwA5k9NmI0ErSERXpx0WlYth3INHj4-zI7RnTxdmkK5zrm521VOdGkWi0x33ReADB9Rwbij_HUNEss8Z4M101Pdu52846WCUxkmc8zcGUmD4VOI7g35sNTgmvp72mbNW6lT9cOnsEQVRKSEWWDWxAT6ijgIRovpiz_6sXSLgSDEs
LANGCACHE_SERVER_URL=https://aws-ap-south-1.langcache.redis.io
LANGCACHE_CACHE_ID=1a19dc89bf8741bdb5130c7de9cb2c88
LANGCACHE_SIMILARITY_THRESHOLD=0.92

# ============================================================
# Redis Cloud Configuration (for Feedback Repository)
# ============================================================
REDIS_CLOUD_HOST=redis-19088.c305.ap-south-1-1.ec2.cloud.redislabs.com
REDIS_CLOUD_PORT=19088
REDIS_CLOUD_USERNAME=default
# Try both passwords - one should work
# REDIS_CLOUD_PASSWORD=S412fwpiln77mzibshas4qzyqyjo0vby6sohfpnl17d4m3iecw0
# REDIS_CLOUD_PASSWORD=A1q9wt0vafjuvmgxl5q2lmv3f9q5go0xkqzyahen8b2mvqgcp52
REDIS_CLOUD_PASSWORD=gOhioz4jSQyNLpXkueEZaAK7BlNZTBFX

# ============================================================
# PostgreSQL Configuration (for Feedback Repository)
# ============================================================
# Password from KB: hakgal123 (confirmed working)
POSTGRES_CONNECTION_STRING=postgresql://hakgal:hakgal123@127.0.0.1:5172/hakgal

# ============================================================
# Detection Service Configuration
# ============================================================
DETECTION_USE_QUANTUM_MODEL=true
DETECTION_QUANTUM_THRESHOLD=0.60
DETECTION_USE_CODEBERT=true
DETECTION_SHADOW_MODE=false
DETECTION_ENABLE_RULE_ENGINE=true
DETECTION_RULE_ENGINE_THRESHOLD=0.5

# Performance
DETECTION_REQUEST_TIMEOUT_SECONDS=15.0
DETECTION_MAX_CONCURRENT_REQUESTS=100

# Logging
DETECTION_LOG_LEVEL=INFO
DETECTION_ENABLE_STRUCTURED_LOGGING=true

# Metrics
DETECTION_ENABLE_METRICS=true
"""
    
    try:
        env_file.write_text(env_content, encoding="utf-8")
        print("✅ .env file created successfully!")
        print(f"   Location: {env_file}")
        print()
        print("📊 Configuration Summary:")
        print("   ✅ LangCache API Key: Set")
        print("   ✅ LangCache Server URL: https://aws-ap-south-1.langcache.redis.io")
        print("   ✅ LangCache Cache ID: 1a19dc89bf8741bdb5130c7de9cb2c88")
        print("   ✅ PostgreSQL: Configured")
        print("   ⚠️  Redis Cloud: Not configured (optional)")
        print()
        print("Next steps:")
        print("1. Test the integration: python scripts/test_feedback_integration.py")
        print("2. Start the service: python -m uvicorn api.main:app --reload")
        return True
    except Exception as e:
        print(f"❌ Failed to create .env file: {e}")
        return False

if __name__ == "__main__":
    if create_env_file():
        print("=" * 70)
        print("✅ Setup Complete!")
        print("=" * 70)
    else:
        print("❌ Setup failed")
        exit(1)

