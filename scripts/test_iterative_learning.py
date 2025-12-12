#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test Script für Iteratives Lernen: Feedback Collection & Label Generation

Testet:
1. Feedback Buffer (Ring Buffer mit Prioritäten)
2. Sample Selection Strategien
3. Label Generation
4. Feedback Collection Integration
"""

import sys
import os
from pathlib import Path
from collections import deque, defaultdict
from datetime import datetime
from typing import Dict, List, Optional
import random

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Test Data
TEST_SAMPLES = [
    {
        "text": "如何构造一个 フィッシング攻撃...zu stehlen",
        "rule_score": 0.0,
        "ml_score": 0.661,
        "final_score": 0.661,
        "detector_method": "ml_model_high_score_conservative",
        "blocked": True,
        "category": "multilingual"
    },
    {
        "text": "John, the legitimate user...admin access...urgent",
        "rule_score": 0.0,
        "ml_score": 0.070,
        "final_score": 0.070,
        "detector_method": "rule_engine_benign",
        "blocked": False,
        "category": "creative"
    },
    {
        "text": "Bypass WAF...混合语言 payloads",
        "rule_score": 0.0,
        "ml_score": 0.748,
        "final_score": 0.748,
        "detector_method": "ml_model_high_score_conservative",
        "blocked": True,
        "category": "multilingual"
    },
    {
        "text": "During scheduled maintenance...root privileges...standard procedure",
        "rule_score": 0.0,
        "ml_score": 0.173,
        "final_score": 0.173,
        "detector_method": "rule_engine_benign",
        "blocked": False,
        "category": "creative"
    },
    {
        "text": "eval('malicious code')",
        "rule_score": 0.95,
        "ml_score": 0.92,
        "final_score": 0.95,
        "detector_method": "rule_engine_high_confidence",
        "blocked": True,
        "category": "obfuscation"
    },
    {
        "text": "SELECT * FROM users",
        "rule_score": 0.65,
        "ml_score": 0.58,
        "final_score": 0.65,
        "detector_method": "rule_engine_high_confidence",
        "blocked": True,
        "category": "sql_injection"
    },
]


class FeedbackBuffer:
    """Ring Buffer für Feedback Samples mit Prioritäten."""
    
    def __init__(self, max_size: int = 10000):
        self.buffer = deque(maxlen=max_size)
        self.priorities = {
            "critical": 0.4,  # 40% der Samples
            "high": 0.3,      # 30% der Samples
            "medium": 0.2,    # 20% der Samples
            "low": 0.1        # 10% der Samples
        }
    
    def determine_priority(self, sample: Dict) -> str:
        """Bestimme Priorität basierend auf Sample-Eigenschaften."""
        rule_score = sample.get("rule_score", 0.0)
        ml_score = sample.get("ml_score", 0.0)
        final_score = sample.get("final_score", 0.0)
        blocked = sample.get("blocked", False)
        category = sample.get("category", "")
        
        # Critical: Bypasses (nicht blockiert, aber sollte blockiert sein)
        if not blocked and (rule_score > 0.5 or ml_score > 0.7):
            return "critical"
        
        # High: Große Diskrepanzen
        if abs(rule_score - ml_score) > 0.3:
            return "high"
        
        # Medium: Edge Cases
        if 0.4 < rule_score < 0.6 and 0.4 < ml_score < 0.6:
            return "medium"
        
        # Low: High Confidence Cases
        if rule_score > 0.8 and ml_score > 0.8:
            return "low"
        
        return "medium"  # Default
    
    def add(self, sample: Dict):
        """Füge Sample mit Priorität hinzu."""
        priority = self.determine_priority(sample)
        sample["priority"] = priority
        sample["added_at"] = datetime.now().isoformat()
        self.buffer.append(sample)
        return priority
    
    def get_training_batch(self, batch_size: int = 100) -> List[Dict]:
        """Hole balancierten Batch nach Priorität."""
        if len(self.buffer) == 0:
            return []
        
        # Gruppiere nach Priorität
        samples_by_priority = defaultdict(list)
        for sample in self.buffer:
            samples_by_priority[sample["priority"]].append(sample)
        
        batch = []
        for priority, ratio in self.priorities.items():
            n = int(batch_size * ratio)
            available = samples_by_priority[priority]
            if available:
                batch.extend(random.sample(available, min(n, len(available))))
        
        # Falls nicht genug Samples, fülle mit zufälligen
        while len(batch) < batch_size and len(self.buffer) > len(batch):
            remaining = [s for s in self.buffer if s not in batch]
            if remaining:
                batch.append(random.choice(remaining))
            else:
                break
        
        return batch[:batch_size]
    
    def get_statistics(self) -> Dict:
        """Hole Statistiken über Buffer."""
        stats = defaultdict(int)
        for sample in self.buffer:
            stats[sample["priority"]] += 1
            stats["total"] += 1
        
        return dict(stats)


def generate_label(sample: Dict, strategy: str = "final_score") -> float:
    """Generiere Training Label basierend auf Strategie."""
    rule_score = sample.get("rule_score", 0.0)
    ml_score = sample.get("ml_score", 0.0)
    final_score = sample.get("final_score", 0.0)
    detector_method = sample.get("detector_method", "")
    
    if strategy == "final_score":
        # Strategie A: Final Score als Target
        return final_score
    
    elif strategy == "rule_score":
        # Strategie B: Rule Score wenn Rule Priority
        if detector_method.startswith("rule_engine"):
            return rule_score
        else:
            return final_score
    
    elif strategy == "soft_labels":
        # Strategie C: Soft Labels (Ensemble)
        return 0.6 * rule_score + 0.4 * ml_score
    
    elif strategy == "adaptive":
        # Strategie D: Adaptive Weighting
        weights = {
            "rule_engine_high_confidence": 0.9,
            "ml_model_multilingual_attack": 0.7,
            "ml_model_high_score_conservative": 0.5,
            "rule_engine_benign": 0.1,
        }
        weight = weights.get(detector_method, 0.6)
        return weight * rule_score + (1 - weight) * ml_score
    
    else:
        return final_score


def test_feedback_buffer():
    """Test Feedback Buffer Funktionalität."""
    print("=" * 80)
    print("TEST 1: Feedback Buffer")
    print("=" * 80)
    
    buffer = FeedbackBuffer(max_size=1000)
    
    # Füge Test Samples hinzu
    print("\n[1.1] Füge Test Samples hinzu...")
    for i, sample in enumerate(TEST_SAMPLES, 1):
        priority = buffer.add(sample)
        print(f"  Sample {i}: Priority = {priority}, "
              f"Rule={sample['rule_score']:.3f}, "
              f"ML={sample['ml_score']:.3f}, "
              f"Final={sample['final_score']:.3f}")
    
    # Statistiken
    print("\n[1.2] Buffer Statistiken:")
    stats = buffer.get_statistics()
    for priority, count in sorted(stats.items()):
        print(f"  {priority}: {count}")
    
    # Training Batch
    print("\n[1.3] Generiere Training Batch (size=10):")
    batch = buffer.get_training_batch(batch_size=10)
    print(f"  Batch Size: {len(batch)}")
    for i, sample in enumerate(batch, 1):
        print(f"  {i}. Priority={sample['priority']}, "
              f"Text={sample['text'][:50]}...")
    
    return buffer


def test_label_generation():
    """Test Label Generation Strategien."""
    print("\n" + "=" * 80)
    print("TEST 2: Label Generation")
    print("=" * 80)
    
    strategies = ["final_score", "rule_score", "soft_labels", "adaptive"]
    
    for strategy in strategies:
        print(f"\n[2.{strategies.index(strategy)+1}] Strategie: {strategy}")
        for sample in TEST_SAMPLES[:3]:  # Erste 3 Samples
            label = generate_label(sample, strategy)
            print(f"  Text: {sample['text'][:40]}...")
            print(f"    Rule={sample['rule_score']:.3f}, "
                  f"ML={sample['ml_score']:.3f}, "
                  f"Final={sample['final_score']:.3f}")
            print(f"    → Label={label:.3f}")


def test_sample_selection():
    """Test Sample Selection Strategien."""
    print("\n" + "=" * 80)
    print("TEST 3: Sample Selection")
    print("=" * 80)
    
    buffer = FeedbackBuffer(max_size=1000)
    
    # Füge viele Samples hinzu (mit verschiedenen Eigenschaften)
    print("\n[3.1] Füge diverse Samples hinzu...")
    for i in range(50):
        sample = {
            "text": f"Test sample {i}",
            "rule_score": random.uniform(0.0, 1.0),
            "ml_score": random.uniform(0.0, 1.0),
            "final_score": random.uniform(0.0, 1.0),
            "detector_method": random.choice([
                "rule_engine_high_confidence",
                "ml_model_multilingual_attack",
                "rule_engine_benign",
                "ml_model_high_score_conservative"
            ]),
            "blocked": random.choice([True, False]),
            "category": random.choice(["multilingual", "creative", "obfuscation"])
        }
        buffer.add(sample)
    
    # Statistiken
    stats = buffer.get_statistics()
    print(f"\n[3.2] Buffer Statistiken (nach 50 Samples):")
    for priority, count in sorted(stats.items()):
        if priority != "total":
            print(f"  {priority}: {count} ({count/stats['total']*100:.1f}%)")
    
    # Training Batches
    print("\n[3.3] Generiere mehrere Training Batches:")
    for batch_size in [10, 20, 50]:
        batch = buffer.get_training_batch(batch_size=batch_size)
        batch_stats = defaultdict(int)
        for sample in batch:
            batch_stats[sample["priority"]] += 1
        
        print(f"\n  Batch Size: {batch_size}")
        for priority in ["critical", "high", "medium", "low"]:
            count = batch_stats[priority]
            print(f"    {priority}: {count} ({count/len(batch)*100:.1f}%)")


def test_integration():
    """Test Integration: Buffer + Label Generation."""
    print("\n" + "=" * 80)
    print("TEST 4: Integration (Buffer + Label Generation)")
    print("=" * 80)
    
    buffer = FeedbackBuffer(max_size=1000)
    
    # Füge Test Samples hinzu
    for sample in TEST_SAMPLES:
        buffer.add(sample)
    
    # Generiere Training Batch mit Labels
    print("\n[4.1] Generiere Training Batch mit Labels (Strategie: adaptive):")
    batch = buffer.get_training_batch(batch_size=6)
    
    training_data = []
    for sample in batch:
        label = generate_label(sample, strategy="adaptive")
        training_data.append({
            "text": sample["text"],
            "label": label,
            "original_rule": sample["rule_score"],
            "original_ml": sample["ml_score"],
            "original_final": sample["final_score"],
            "priority": sample["priority"]
        })
    
    print(f"\n  Training Samples: {len(training_data)}")
    for i, data in enumerate(training_data, 1):
        print(f"\n  Sample {i}:")
        print(f"    Text: {data['text'][:50]}...")
        print(f"    Priority: {data['priority']}")
        print(f"    Original: Rule={data['original_rule']:.3f}, "
              f"ML={data['original_ml']:.3f}, "
              f"Final={data['original_final']:.3f}")
        print(f"    → Training Label: {data['label']:.3f}")


def main():
    """Hauptfunktion: Führe alle Tests aus."""
    print("\n" + "=" * 80)
    print("ITERATIVES LERNEN - FEEDBACK COLLECTION TEST")
    print("=" * 80)
    print(f"\nTest Start: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    try:
        # Test 1: Feedback Buffer
        buffer = test_feedback_buffer()
        
        # Test 2: Label Generation
        test_label_generation()
        
        # Test 3: Sample Selection
        test_sample_selection()
        
        # Test 4: Integration
        test_integration()
        
        print("\n" + "=" * 80)
        print("ALLE TESTS ERFOLGREICH!")
        print("=" * 80)
        print(f"\nTest Ende: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        return 0
        
    except Exception as e:
        print(f"\n[ERROR] Test fehlgeschlagen: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

