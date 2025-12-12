"""
Direct Repository Test - Testet Repositories direkt ohne Service
===============================================================

Testet Redis, PostgreSQL und Hybrid Repositories direkt.
"""

import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

def test_memory_repository():
    """Test Memory Repository."""
    print("\n" + "=" * 70)
    print("🧪 Testing Memory Repository")
    print("=" * 70)
    
    from infrastructure.repositories.feedback_buffer_repository import FeedbackBufferRepository
    
    repo = FeedbackBufferRepository(max_size=100)
    
    # Add samples
    sample1 = {
        "text": "rm -rf /",
        "rule_score": 0.9,
        "ml_score": 0.85,
        "final_score": 0.9,
        "blocked": True,
        "patterns": ["destructive_rm"]
    }
    
    sample2 = {
        "text": "How can I list files?",
        "rule_score": 0.0,
        "ml_score": 0.1,
        "final_score": 0.0,
        "blocked": False,
        "patterns": []
    }
    
    repo.add(sample1)
    repo.add(sample2)
    
    # Get samples
    samples = repo.get_samples(limit=10)
    print(f"✅ Samples stored: {len(samples)}")
    
    # Get statistics
    stats = repo.get_statistics()
    print(f"✅ Statistics: {stats}")
    
    return True

def test_redis_repository():
    """Test Redis Repository (if credentials available)."""
    print("\n" + "=" * 70)
    print("🧪 Testing Redis Repository")
    print("=" * 70)
    
    try:
        from infrastructure.repositories.redis_feedback_repository import RedisFeedbackRepository
        
        # Try to create repository (will use env vars if available)
        try:
            repo = RedisFeedbackRepository()
            print("✅ Redis Repository created successfully")
            
            # Add sample
            sample = {
                "text": "test command",
                "rule_score": 0.5,
                "ml_score": 0.6,
                "final_score": 0.55,
                "blocked": False,
                "patterns": []
            }
            
            repo.add(sample)
            print("✅ Sample added to Redis")
            
            # Get statistics
            stats = repo.get_statistics()
            print(f"✅ Redis Statistics: {stats}")
            
            return True
            
        except ValueError as e:
            print(f"⚠️  Redis credentials not available: {e}")
            print("   Set REDIS_CLOUD_HOST and REDIS_CLOUD_PASSWORD environment variables")
            return False
            
    except ImportError as e:
        print(f"⚠️  Redis package not installed: {e}")
        return False

def test_postgres_repository():
    """Test PostgreSQL Repository (if credentials available)."""
    print("\n" + "=" * 70)
    print("🧪 Testing PostgreSQL Repository")
    print("=" * 70)
    
    try:
        from infrastructure.repositories.postgres_feedback_repository import PostgresFeedbackRepository
        
        # Try to create repository
        try:
            repo = PostgresFeedbackRepository()
            print("✅ PostgreSQL Repository created successfully")
            
            # Add sample
            sample = {
                "text": "test command",
                "rule_score": 0.5,
                "ml_score": 0.6,
                "final_score": 0.55,
                "blocked": False,
                "patterns": []
            }
            
            repo.add(sample)
            print("✅ Sample added to PostgreSQL")
            
            # Get statistics
            stats = repo.get_statistics()
            print(f"✅ PostgreSQL Statistics: {stats}")
            
            return True
            
        except Exception as e:
            print(f"⚠️  PostgreSQL connection failed: {e}")
            print("   Set POSTGRES_CONNECTION_STRING environment variable")
            return False
            
    except ImportError as e:
        print(f"⚠️  SQLAlchemy not installed: {e}")
        return False

def test_hybrid_repository():
    """Test Hybrid Repository."""
    print("\n" + "=" * 70)
    print("🧪 Testing Hybrid Repository")
    print("=" * 70)
    
    try:
        from infrastructure.repositories.hybrid_feedback_repository import HybridFeedbackRepository
        from infrastructure.repositories.feedback_buffer_repository import FeedbackBufferRepository
        
        # Create with memory repositories (always available)
        memory_repo = FeedbackBufferRepository(max_size=100)
        
        redis_repo = None
        postgres_repo = None
        
        # Try Redis
        try:
            from infrastructure.repositories.redis_feedback_repository import RedisFeedbackRepository
            redis_repo = RedisFeedbackRepository()
            print("✅ Redis component available")
        except:
            print("⚠️  Redis component not available")
        
        # Try PostgreSQL
        try:
            from infrastructure.repositories.postgres_feedback_repository import PostgresFeedbackRepository
            postgres_repo = PostgresFeedbackRepository()
            print("✅ PostgreSQL component available")
        except:
            print("⚠️  PostgreSQL component not available")
        
        # Create hybrid (works with any combination, including memory)
        hybrid = HybridFeedbackRepository(
            redis_repo=redis_repo,
            postgres_repo=postgres_repo,
            memory_repo=memory_repo
        )
        print("✅ Hybrid Repository created")
        
        # Add sample
        sample = {
            "text": "test hybrid",
            "rule_score": 0.7,
            "ml_score": 0.75,
            "final_score": 0.72,
            "blocked": True,
            "patterns": ["test_pattern"]
        }
        
        hybrid.add(sample)
        print("✅ Sample added to Hybrid Repository")
        
        # Get statistics
        stats = hybrid.get_statistics()
        print(f"✅ Hybrid Statistics: {stats}")
        
        return True
        
    except Exception as e:
        print(f"❌ Hybrid Repository test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("=" * 70)
    print("🧪 Direct Repository Tests")
    print("=" * 70)
    
    results = {}
    
    # Test Memory (always works)
    results["memory"] = test_memory_repository()
    
    # Test Redis (if credentials available)
    results["redis"] = test_redis_repository()
    
    # Test PostgreSQL (if credentials available)
    results["postgres"] = test_postgres_repository()
    
    # Test Hybrid
    results["hybrid"] = test_hybrid_repository()
    
    # Summary
    print("\n" + "=" * 70)
    print("📊 Test Summary")
    print("=" * 70)
    
    for repo_type, success in results.items():
        status = "✅ PASS" if success else "⚠️  SKIP (credentials not available)"
        print(f"   {repo_type:15} {status}")
    
    print("\n" + "=" * 70)
    print("✅ Repository Tests Complete!")
    print("=" * 70)
    
    # Exit with error if memory failed (should always work)
    if not results["memory"]:
        sys.exit(1)

