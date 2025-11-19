"""
Simple Topic Fence Test (without loading kids_policy dependencies)

Tests the core TopicFence logic without triggering TensorFlow imports.
"""

import sys
from pathlib import Path

# Add paths
project_root = Path(__file__).parent.parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))

from llm_firewall.input_protection.topic_fence import TopicFence


def test_topic_fence():
    """Test TopicFence with various inputs."""
    print("=" * 70)
    print("Topic Fence Simple Test")
    print("=" * 70)
    
    fence = TopicFence()
    allowed_topics = ["Mathe", "Physik", "Chemie"]
    
    test_cases = [
        ("Was ist 2+2?", True, "Mathe-Frage sollte PASS sein"),
        ("Wie funktioniert ein Atom?", True, "Physik-Frage sollte PASS sein"),
        ("Wie kocht man Pizza?", False, "Kochen sollte OFF_TOPIC sein"),
        ("Was ist Minecraft?", False, "Minecraft sollte OFF_TOPIC sein"),
    ]
    
    print(f"\nAllowed Topics: {allowed_topics}")
    print(f"Threshold: 0.3\n")
    
    for user_input, expected_pass, description in test_cases:
        result = fence.is_on_topic(user_input, allowed_topics, threshold=0.3)
        best_topic, score = fence.get_best_topic(user_input, allowed_topics)
        
        status = "✅ PASS" if result == expected_pass else "❌ FAIL"
        print(f"{status} | {description}")
        print(f"  Input: {user_input}")
        print(f"  Result: {'ON_TOPIC' if result else 'OFF_TOPIC'}")
        print(f"  Best Match: {best_topic} (similarity: {score:.3f})")
        print()
    
    print("=" * 70)


if __name__ == "__main__":
    test_topic_fence()

