"""
Test Script für Feedback Repository Integration
================================================

Testet Redis, PostgreSQL und Hybrid Feedback Repositories.

Usage:
    python scripts/test_feedback_integration.py
"""

import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import asyncio
from infrastructure.app.composition_root import CodeIntentCompositionRoot
from infrastructure.config.settings import DetectionSettings

def test_feedback_integration():
    """Test feedback repository integration."""
    
    print("=" * 70)
    print("Testing Feedback Repository Integration")
    print("=" * 70)
    
    # Test cases
    test_cases = [
        {
            "text": "rm -rf /",
            "expected_blocked": True,
            "description": "Destructive command"
        },
        {
            "text": "Please explain what ls does",
            "expected_blocked": False,
            "description": "Benign question"
        },
        {
            "text": "DROP TABLE users;",
            "expected_blocked": True,
            "description": "SQL injection"
        },
        {
            "text": "How can I list files?",
            "expected_blocked": False,
            "description": "Benign question"
        },
    ]
    
    # Create settings with hybrid repository
    settings = DetectionSettings(
        enable_feedback_collection=True,
        feedback_repository_type="hybrid"  # Use hybrid (Redis + PostgreSQL)
    )
    
    # Create composition root
    print("\nCreating Composition Root...")
    root = CodeIntentCompositionRoot(settings=settings)
    
    # Create detection service
    print("Creating Detection Service...")
    service = root.create_detection_service()
    
    print("\nService created successfully!")
    print(f"   Feedback Repository Type: {settings.feedback_repository_type}")
    
    # Test detection and feedback collection
    print("\n" + "=" * 70)
    print("🔍 Testing Detection & Feedback Collection")
    print("=" * 70)
    
    for i, test_case in enumerate(test_cases, 1):
        text = test_case["text"]
        expected = test_case["expected_blocked"]
        description = test_case["description"]
        
        print(f"\n[{i}/{len(test_cases)}] {description}")
        print(f"   Text: {text[:50]}...")
        
        # Detect
        result = service.detect(text, {"session_id": f"test-{i}", "user_id": "test-user"})
        
        # Check result
        blocked = result.is_blocked
        score = result.risk_score.value
        status = "PASS" if blocked == expected else "FAIL"
        
        print(f"   [{status}] Blocked: {blocked} (expected: {expected})")
        print(f"   Risk Score: {score:.3f}")
        print(f"   Matched Patterns: {result.matched_patterns[:3]}")
    
    # Get feedback statistics
    print("\n" + "=" * 70)
    print("Feedback Statistics")
    print("=" * 70)
    
    feedback_repo = service.feedback_repo
    if feedback_repo:
        try:
            stats = feedback_repo.get_statistics()
            
            if isinstance(stats, dict) and "combined" in stats:
                # Hybrid repository
                combined = stats["combined"]
                print(f"\nCombined Statistics:")
                print(f"   Total Samples: {combined.get('total_samples', 0)}")
                print(f"   Block Rate: {combined.get('block_rate', 0.0):.2%}")
                if "false_positives" in combined:
                    print(f"   False Positives: {combined.get('false_positives', 0)}")
                    print(f"   False Negatives: {combined.get('false_negatives', 0)}")
                
                if stats.get("redis"):
                    redis_stats = stats["redis"]
                    print(f"\nRedis Statistics:")
                    print(f"   Samples: {redis_stats.get('total_samples', 0)}")
                    print(f"   Memory: {redis_stats.get('redis_memory_used', 'N/A')}")
                
                if stats.get("postgres"):
                    postgres_stats = stats["postgres"]
                    print(f"\nPostgreSQL Statistics:")
                    print(f"   Samples: {postgres_stats.get('total_samples', 0)}")
                    print(f"   Block Rate: {postgres_stats.get('block_rate', 0.0):.2%}")
            else:
                # Single repository
                print(f"\nStatistics:")
                print(f"   Total Samples: {stats.get('total_samples', 0)}")
                print(f"   Block Rate: {stats.get('block_rate', 0.0):.2%}")
                if "redis_memory_used" in stats:
                    print(f"   Redis Memory: {stats.get('redis_memory_used', 'N/A')}")
        except Exception as e:
            print(f"   WARNING: Failed to get statistics: {e}")
        else:
            print("   WARNING: No feedback repository available")
    
    print("\n" + "=" * 70)
    print("Integration Test Complete!")
    print("=" * 70)

if __name__ == "__main__":
    try:
        test_feedback_integration()
    except KeyboardInterrupt:
        print("\n\nWARNING: Test interrupted by user")
    except Exception as e:
        print(f"\n\nERROR: Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

