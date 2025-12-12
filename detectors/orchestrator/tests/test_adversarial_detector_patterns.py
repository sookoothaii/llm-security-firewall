"""
Quick test of AdversarialInputDetector with new patterns.

Tests the patterns we just added to verify they detect the bypasses correctly.
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from detectors.orchestrator.domain.adversarial.adversarial_detector import AdversarialInputDetector

def test_patterns():
    """Test the new patterns against known bypass samples."""
    detector = AdversarialInputDetector()
    
    # Test samples from our baseline test
    test_cases = [
        # High special char ratio (55.3% of bypasses)
        ("SELECT * FROM users WHERE id=1 OR 1=1", True, "SQL injection with special chars"),
        ("DROP TABLE users;", True, "SQL DROP with special chars"),
        ("<script>alert('xss')</script>", True, "XSS with special chars"),
        ("rm -rf /", True, "Command injection with special chars"),
        ("*)(uid=*))(|(uid=*", True, "LDAP injection with special chars"),
        
        # SQL keywords (28.9% of bypasses)
        ("SELECT * FROM users", True, "SQL SELECT"),
        ("DROP TABLE users;", True, "SQL DROP"),
        ("DELETE FROM users WHERE id=1", True, "SQL DELETE"),
        ("INSERT INTO users VALUES (1, 'test')", True, "SQL INSERT"),
        
        # Character repetition (7.9% of bypasses)
        ("AAAAAA", True, "Character repetition"),
        ("A" * 10000, True, "Long character repetition"),
        
        # Zero-width characters (7.9% of bypasses)
        ("\u200b隐藏\u200b字符", True, "Zero-width characters"),
        
        # Benign samples (should NOT be detected)
        ("Hello, how are you?", False, "Benign text"),
        ("What is the weather today?", False, "Benign question"),
        ("Can you help me with Python?", False, "Benign question"),
    ]
    
    print("="*80)
    print("TESTING ADVERSARIAL INPUT DETECTOR PATTERNS")
    print("="*80)
    print()
    
    results = {
        "detected": 0,
        "missed": 0,
        "false_positives": 0,
        "correct": 0,
        "total": len(test_cases)
    }
    
    for sample, should_detect, description in test_cases:
        is_adversarial, score, metadata = detector.detect(sample)
        matched_patterns = metadata.get("matched_patterns", [])
        
        if should_detect:
            if is_adversarial:
                results["detected"] += 1
                results["correct"] += 1
                status = "✅ DETECTED"
            else:
                results["missed"] += 1
                status = "❌ MISSED"
        else:
            if is_adversarial:
                results["false_positives"] += 1
                status = "⚠️  FALSE POSITIVE"
            else:
                results["correct"] += 1
                status = "✅ CORRECT (benign)"
        
        print(f"{status}: {description}")
        print(f"  Sample: {sample[:60]}{'...' if len(sample) > 60 else ''}")
        print(f"  Score: {score:.3f} | Threshold: 0.5 | Detected: {is_adversarial}")
        if matched_patterns:
            print(f"  Patterns: {', '.join(matched_patterns[:5])}")
        print()
    
    # Summary
    print("="*80)
    print("SUMMARY")
    print("="*80)
    print(f"Total Tests: {results['total']}")
    print(f"Correct: {results['correct']} ({results['correct']/results['total']*100:.1f}%)")
    print(f"Detected (malicious): {results['detected']}")
    print(f"Missed (malicious): {results['missed']}")
    print(f"False Positives (benign): {results['false_positives']}")
    print()
    
    # Calculate metrics
    malicious_tests = sum(1 for _, should_detect, _ in test_cases if should_detect)
    detection_rate = results["detected"] / malicious_tests * 100 if malicious_tests > 0 else 0
    false_positive_rate = results["false_positives"] / (results["total"] - malicious_tests) * 100 if (results["total"] - malicious_tests) > 0 else 0
    
    print(f"Detection Rate (malicious): {detection_rate:.1f}%")
    print(f"False Positive Rate (benign): {false_positive_rate:.1f}%")
    print("="*80)
    
    return results

if __name__ == "__main__":
    test_patterns()

