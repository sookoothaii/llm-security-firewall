"""
Complete Environment Setup Script
=================================

Creates a complete .env file with all necessary configuration for the
Code Intent Detection Service.

Usage:
    python setup_env_complete.py

This will create a .env file in the current directory with all production
values pre-filled.
"""

import os
from pathlib import Path

def create_env_file():
    """Create complete .env file with all configuration."""
    
    # Get current directory (should be code_intent_service)
    current_dir = Path(__file__).parent
    env_file = current_dir / ".env"
    
    # Check if .env already exists
    if env_file.exists():
        print(f".env file already exists at {env_file}. Overwriting...")
    
    # Complete .env content
    env_content = """# =============================================================================
# Code Intent Detection Service - Environment Configuration
# =============================================================================
# Date: 2025-12-10
# Status: Production Ready
# 
# This file contains all environment variables for the Code Intent Detection
# Service. Copy this file and adjust values as needed for your environment.
# =============================================================================

# =============================================================================
# ML Model Configuration
# =============================================================================

# Quantum-Inspired CNN Model
DETECTION_USE_QUANTUM_MODEL=true
# Path to trained Quantum-Inspired CNN model (relative to project root)
# Default: models/quantum_cnn_trained/best_model.pt
# DETECTION_QUANTUM_MODEL_PATH=models/quantum_cnn_trained/best_model.pt
DETECTION_QUANTUM_THRESHOLD=0.60
DETECTION_SHADOW_MODE=false
DETECTION_HYBRID_MODE=true

# CodeBERT Model (Fallback)
DETECTION_USE_CODEBERT=true
DETECTION_CODEBERT_MODEL_NAME=microsoft/codebert-base

# =============================================================================
# Rule Engine Configuration
# =============================================================================

DETECTION_ENABLE_RULE_ENGINE=true
DETECTION_RULE_ENGINE_THRESHOLD=0.5

# =============================================================================
# Feedback Collection Configuration
# =============================================================================

# Enable feedback collection (required for online learning)
DETECTION_ENABLE_FEEDBACK_COLLECTION=true
DETECTION_FEEDBACK_BUFFER_SIZE=10000

# Feedback Repository Type: "memory", "redis", "postgres", "hybrid"
# Recommended: "hybrid" (Redis + PostgreSQL + Memory fallback)
DETECTION_FEEDBACK_REPOSITORY_TYPE=hybrid

# =============================================================================
# Online Learning Configuration
# =============================================================================

# Enable online learning (requires model, tokenizer, and feedback collection)
DETECTION_ENABLE_ONLINE_LEARNING=false
DETECTION_ONLINE_LEARNING_BATCH_SIZE=32
DETECTION_ONLINE_LEARNING_UPDATE_INTERVAL=100
DETECTION_ONLINE_LEARNING_MIN_SAMPLES=10
DETECTION_ONLINE_LEARNING_RATE=0.00001

# =============================================================================
# Redis Cloud Configuration (for Feedback Repository)
# =============================================================================

# Redis Cloud Connection
REDIS_CLOUD_HOST=redis-19088.c305.ap-south-1-1.ec2.cloud.redislabs.com
REDIS_CLOUD_PORT=19088
REDIS_CLOUD_USERNAME=sookoothaii
REDIS_CLOUD_PASSWORD=6U4dOUyDUmQZN!7V*MQ3gne*Ow56KSQt

# Alternative: Standard Redis environment variables (also supported)
# REDIS_HOST=localhost
# REDIS_PORT=6379
# REDIS_PASSWORD=your_password
# REDIS_USERNAME=default

# Redis Configuration
# SSL is disabled for port 19088 (not required)
# TTL: 30 days (720 hours) for feedback samples
# DETECTION_REDIS_SSL=false
# DETECTION_REDIS_TTL_HOURS=720

# =============================================================================
# PostgreSQL Configuration (for Feedback Repository)
# =============================================================================

# PostgreSQL Connection String
# Format: postgresql://username:password@host:port/database
# Important: Use IPv4 (127.0.0.1) instead of localhost on Windows!
POSTGRES_CONNECTION_STRING=postgresql://hakgal:admin@127.0.0.1:5172/hakgal

# Alternative: Use DATABASE_URL (also supported)
# DATABASE_URL=postgresql://hakgal:admin@127.0.0.1:5172/hakgal

# Note: PostgreSQL uses pg8000 driver (UTF-8 safe on Windows)
# Password encoding is handled automatically via urllib.parse.quote_plus()

# =============================================================================
# LangCache Configuration (Optional)
# =============================================================================

LANGCACHE_API_KEY=wy4ECQMIL1OZ2u7-ccjgZs5I6tj-g97lGBuXTmwtwLEZO8mC2eNiOQN7Qu6eAFwE0oIBbwA5k9NmI0ErSERXpx0WlYth3INHj4-zI7RnTxdmkK5zrm521VOdGkWi0x33ReADB9Rwbij_HUNEss8Z4M101Pdu52846WCUxkmc8zcGUmD4VOI7g35sNTgmvp72mbNW6lT9cOnsEQVRKSEWWDWxAT6ijgIRovpiz_6sXSLgSDEs
LANGCACHE_SERVER_URL=https://aws-ap-south-1.langcache.redis.io
LANGCACHE_CACHE_ID=1a19dc89bf8741bdb5130c7de9cb2c88

# =============================================================================
# Performance Configuration
# =============================================================================

DETECTION_REQUEST_TIMEOUT_SECONDS=15.0
DETECTION_MAX_CONCURRENT_REQUESTS=100

# =============================================================================
# Logging Configuration
# =============================================================================

DETECTION_LOG_LEVEL=INFO
DETECTION_ENABLE_STRUCTURED_LOGGING=true

# =============================================================================
# Monitoring & Metrics
# =============================================================================

DETECTION_ENABLE_METRICS=true

# =============================================================================
# API Configuration
# =============================================================================

# API Server (configured in api/main.py)
# Default: http://localhost:8000
# Swagger UI: http://localhost:8000/docs
# ReDoc: http://localhost:8000/redoc

# =============================================================================
# Notes
# =============================================================================
#
# 1. Redis Cloud:
#    - Host: redis-19088.c305.ap-south-1-1.ec2.cloud.redislabs.com
#    - Port: 19088 (SSL not required)
#    - Username: sookoothaii
#    - Password: Set in REDIS_CLOUD_PASSWORD
#
# 2. PostgreSQL:
#    - Host: 127.0.0.1:5172 (use IPv4, not localhost on Windows!)
#    - Database: hakgal
#    - Username: hakgal
#    - Password: admin (tested and working)
#    - Driver: pg8000 (UTF-8 safe on Windows)
#
# 3. Feedback Repository:
#    - "memory": In-memory only (development)
#    - "redis": Redis Cloud only (fast, 30 days TTL)
#    - "postgres": PostgreSQL only (persistent, analytics)
#    - "hybrid": Redis + PostgreSQL + Memory (recommended for production)
#
# 4. Online Learning:
#    - Requires: enable_online_learning=true AND enable_feedback_collection=true
#    - Requires: Trained model (Quantum-Inspired CNN or CodeBERT)
#    - Automatically starts in background thread on API startup
#
# 5. Health Checks:
#    - GET /api/v1/health/repositories - Check all repository status
#    - GET /api/v1/health/redis - Check Redis connection
#    - GET /api/v1/health/postgres - Check PostgreSQL connection
#
# 6. Feedback Analytics:
#    - GET /api/v1/feedback/stats - Overall statistics
#    - GET /api/v1/feedback/high-risk - High-risk samples
#    - GET /api/v1/feedback/false-positives - False positives for retraining
#    - GET /api/v1/feedback/false-negatives - False negatives for retraining
#    - GET /api/v1/feedback/samples - Recent samples
#
# =============================================================================
"""
    
    # Write .env file
    try:
        with open(env_file, 'w', encoding='utf-8') as f:
            f.write(env_content)
        
        print(f"✓ Complete .env file created at: {env_file}")
        print(f"✓ File size: {env_file.stat().st_size} bytes")
        print(f"\nNext steps:")
        print(f"  1. Review the .env file and adjust values if needed")
        print(f"  2. Test configuration: python scripts/test_feedback_integration.py")
        print(f"  3. Start API server: python api/main.py")
        print(f"\n⚠️  IMPORTANT: .env contains sensitive data - never commit to version control!")
        
    except Exception as e:
        print(f"✗ Error creating .env file: {e}")
        return False
    
    return True


if __name__ == "__main__":
    print("=" * 60)
    print("Code Intent Detection Service - Environment Setup")
    print("=" * 60)
    print()
    
    create_env_file()

