#!/usr/bin/env python3
"""
Analyzes test results and creates a summary

Usage:
    python scripts/analyze_redteam_results.py
"""

import json
from pathlib import Path
from datetime import datetime

def analyze_results():
    """Analyzes the test results."""
    results_file = Path("huggingface_redteam_test_results.json")
    
    if not results_file.exists():
        print(f"✗ File not found: {results_file}")
        return 1
    
    print("=" * 70)
    print("ANALYSIS: Hugging Face Red Team Test Results")
    print("=" * 70)
    print()
    
    with open(results_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    print(f"Dataset: {data.get('dataset', 'Unknown')}")
    print(f"Timestamp: {data.get('timestamp', 'Unknown')}")
    print(f"Total Samples: {data.get('total_samples', 0)}")
    print()
    
    results = data.get('results', {})
    
    for port, result in results.items():
        service_name = result.get('service', 'Unknown')
        total = result.get('total', 0)
        blocked = result.get('blocked', 0)
        allowed = result.get('allowed', 0)
        errors = result.get('errors', 0)
        
        block_rate = (blocked / total * 100) if total > 0 else 0
        
        avg_risk = result.get('avg_risk_score', 0.0)
        min_risk = result.get('min_risk_score', 0.0)
        max_risk = result.get('max_risk_score', 0.0)
        
        print(f"{'=' * 70}")
        print(f"{service_name} (Port {port})")
        print(f"{'=' * 70}")
        print(f"Total Samples: {total}")
        print(f"Blocked: {blocked} ({block_rate:.1f}%)")
        print(f"Allowed: {allowed} ({100-block_rate:.1f}%)")
        print(f"Errors: {errors}")
        print()
        print(f"Risk Score Statistics:")
        print(f"  Average: {avg_risk:.3f}")
        print(f"  Minimum: {min_risk:.3f}")
        print(f"  Maximum: {max_risk:.3f}")
        print()
        
        # Show some examples
        details = result.get('details', [])
        if details:
            blocked_samples = [d for d in details if d.get('blocked', False)]
            allowed_samples = [d for d in details if not d.get('blocked', False) and 'error' not in d]
            
            if blocked_samples:
                print(f"Examples of BLOCKED samples (first 5):")
                for i, sample in enumerate(blocked_samples[:5], 1):
                    text = sample.get('text', '')[:80]
                    risk = sample.get('risk_score', 0.0)
                    print(f"  {i}. Risk: {risk:.3f} - {text}...")
                print()
            
            if allowed_samples:
                print(f"Examples of ALLOWED samples (first 5):")
                for i, sample in enumerate(allowed_samples[:5], 1):
                    text = sample.get('text', '')[:80]
                    risk = sample.get('risk_score', 0.0)
                    print(f"  {i}. Risk: {risk:.3f} - {text}...")
                print()
    
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print()
    
    for port, result in results.items():
        service_name = result.get('service', 'Unknown')
        total = result.get('total', 0)
        blocked = result.get('blocked', 0)
        block_rate = (blocked / total * 100) if total > 0 else 0
        avg_risk = result.get('avg_risk_score', 0.0)
        
        print(f"{service_name}:")
        print(f"  Block Rate: {block_rate:.1f}% ({blocked}/{total})")
        print(f"  Avg Risk Score: {avg_risk:.3f}")
        print()
    
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(analyze_results())

