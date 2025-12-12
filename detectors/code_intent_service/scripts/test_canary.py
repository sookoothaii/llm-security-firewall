"""
Canary Deployment Test Script

Tests new validators with a small percentage of requests
to validate backward compatibility before full migration.
"""
import os
import random
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from main import is_likely_benign as is_likely_benign_old
from infrastructure.rule_engines.benign_validator_factory import BenignValidatorFactory


def test_canary_deployment(canary_percentage: float = 0.1):
    """
    Test canary deployment of new validators.
    
    Args:
        canary_percentage: Percentage of requests to route through new validators (0.0-1.0)
    """
    # Create new validator
    new_validator = BenignValidatorFactory.create_default()
    
    # Test cases
    test_cases = [
        ("What is ls?", True),
        ("Please run ls", False),
        ("How does ls work?", True),
        ("rm -rf /", False),
        ("ls -la", False),
        ("Can you explain ls?", True),
    ]
    
    mismatches = []
    canary_count = 0
    total_count = 0
    
    print(f"🧪 Testing Canary Deployment ({canary_percentage*100}% new validators)")
    print("=" * 60)
    
    for text, expected in test_cases:
        total_count += 1
        
        # Random routing (canary)
        use_new = random.random() < canary_percentage
        
        if use_new:
            canary_count += 1
            new_result = new_validator.is_benign(text)
            old_result = is_likely_benign_old(text)
            
            if new_result != old_result:
                mismatches.append({
                    "text": text[:50],
                    "old": old_result,
                    "new": new_result,
                    "expected": expected,
                    "route": "canary"
                })
        else:
            # Old implementation
            old_result = is_likely_benign_old(text)
    
    # Results
    print(f"\n📊 Results:")
    print(f"  Total requests: {total_count}")
    print(f"  Canary requests: {canary_count} ({canary_count/total_count*100:.1f}%)")
    print(f"  Mismatches: {len(mismatches)}")
    
    if mismatches:
        print(f"\n⚠️  Mismatches found:")
        for m in mismatches:
            print(f"  Text: {m['text']}...")
            print(f"    Old: {m['old']}, New: {m['new']}, Expected: {m['expected']}")
    else:
        print(f"\n✅ No mismatches - canary deployment successful!")
    
    return len(mismatches) == 0


if __name__ == "__main__":
    # Check environment variable
    use_new = os.getenv("USE_NEW_VALIDATORS", "false").lower() == "true"
    canary_pct = float(os.getenv("CANARY_PERCENTAGE", "0.1"))
    
    if use_new:
        print("🚀 Using NEW validators (100%)")
        canary_pct = 1.0
    else:
        print(f"🧪 Using CANARY deployment ({canary_pct*100}%)")
    
    success = test_canary_deployment(canary_pct)
    
    if success:
        print("\n✅ Canary test PASSED - ready for gradual rollout")
        sys.exit(0)
    else:
        print("\n❌ Canary test FAILED - review mismatches before rollout")
        sys.exit(1)

