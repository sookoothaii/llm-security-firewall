"""Test if patterns load correctly"""
import sys
import logging
from pathlib import Path

logging.basicConfig(level=logging.DEBUG)

sys.path.insert(0, str(Path(__file__).parent / "src"))

from llm_firewall.safety.embedding_detector import EmbeddingJailbreakDetector

print("="*80)
print("TESTING PATTERN LOADING")
print("="*80)

detector = EmbeddingJailbreakDetector(threshold=0.60)

print(f"\nDetector available: {detector.available}")
print(f"Number of patterns: {len(detector.jailbreak_texts)}")
print(f"\nFirst 5 patterns:")
for i, pattern in enumerate(detector.jailbreak_texts[:5], 1):
    print(f"  {i}. {pattern[:60]}...")

print("\n" + "="*80)

