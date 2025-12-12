"""
Test AdversarialInputDetector against actual baseline bypass samples.

This tests how many of the original bypasses would now be detected.
"""

import sys
import json
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from detectors.orchestrator.domain.adversarial.adversarial_detector import AdversarialInputDetector

def load_baseline_bypasses():
    """Load bypass samples from baseline test results."""
    bypass_samples = []
    
    # Load from the baseline test results
    results_dir = project_root / "test_results" / "adversarial"
    
    for results_file in results_dir.glob("baseline_*.json"):
        if "retest" in str(results_file):
            continue  # Skip retest results
            
        with open(results_file, 'r', encoding='utf-8') as f:
            results = json.load(f)
            
            for test_result in results.get("test_results", []):
                if test_result.get("bypass", False) and test_result.get("label") == 1:
                    sample = test_result.get("sample", "")
                    if sample and sample not in bypass_samples:
                        bypass_samples.append(sample)
    
    return bypass_samples

def test_against_baseline_bypasses():
    """Test detector against actual baseline bypasses."""
    detector = AdversarialInputDetector()
    bypass_samples = load_baseline_bypasses()
    
    print("="*80)
    print("TESTING AGAINST ACTUAL BASELINE BYPASSES")
    print("="*80)
    print(f"Loaded {len(bypass_samples)} unique bypass samples")
    print()
    
    detected = 0
    missed = 0
    results = []
    
    for i, sample in enumerate(bypass_samples, 1):
        is_adversarial, score, metadata = detector.detect(sample)
        matched_patterns = metadata.get("matched_patterns", [])
        
        if is_adversarial:
            detected += 1
            status = "✅ DETECTED"
        else:
            missed += 1
            status = "❌ MISSED"
        
        results.append({
            "sample": sample,
            "detected": is_adversarial,
            "score": score,
            "patterns": matched_patterns
        })
        
        if i <= 10 or not is_adversarial:  # Show first 10 and all misses
            print(f"{status}: {sample[:70]}{'...' if len(sample) > 70 else ''}")
            print(f"  Score: {score:.3f} | Patterns: {', '.join(matched_patterns[:5])}")
            print()
    
    # Summary
    detection_rate = (detected / len(bypass_samples)) * 100 if bypass_samples else 0
    
    print("="*80)
    print("SUMMARY")
    print("="*80)
    print(f"Total Baseline Bypasses: {len(bypass_samples)}")
    print(f"Now Detected: {detected} ({detection_rate:.1f}%)")
    print(f"Still Missed: {missed} ({(100-detection_rate):.1f}%)")
    print()
    
    # Show missed samples
    if missed > 0:
        print("Still Missed Samples:")
        for result in results:
            if not result["detected"]:
                print(f"  - {result['sample'][:70]}{'...' if len(result['sample']) > 70 else ''} (Score: {result['score']:.3f})")
        print()
    
    print("="*80)
    
    return {
        "total": len(bypass_samples),
        "detected": detected,
        "missed": missed,
        "detection_rate": detection_rate
    }

if __name__ == "__main__":
    test_against_baseline_bypasses()

