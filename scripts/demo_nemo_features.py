"""
Demo: NVIDIA NeMo-inspired Features Integration

Demonstrates how TopicFence, SafetyTemplates, and SafetyFallbackJudge
work together in a unified safety pipeline.

Creator: Joerg Bollwahn
Date: 2025-01-XX
License: MIT
"""

import sys
from pathlib import Path

# Add paths
project_root = Path(__file__).parent.parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))

# Import from kids_policy first (before importing topic_fence which might trigger sentence-transformers)
import sys
from pathlib import Path

# Add paths
project_root = Path(__file__).parent.parent
kids_policy_path = project_root / "kids_policy"
sys.path.insert(0, str(kids_policy_path.parent))

# Import kids_policy modules (these don't require sentence-transformers)
from kids_policy.response_templates import SafetyTemplates
from kids_policy.fallback_judge import SafetyFallbackJudge

# Import topic_fence (this will load sentence-transformers)
src_path = project_root / "src"
sys.path.insert(0, str(src_path))
from llm_firewall.input_protection.topic_fence import TopicFence


def demo_pipeline(user_input: str, allowed_topics: list[str], age_band: str = "9-12"):
    """
    Demonstrate the complete safety pipeline.

    Flow:
    1. User Input comes in
    2. TopicFence checks (e.g., Mathe, Physik). If Fail -> SafetyTemplates.get("OFF_TOPIC")
    3. If Pass -> SafetyFallbackJudge (simulated) checks Safety
    """
    print("=" * 70)
    print("NVIDIA NeMo-inspired Safety Pipeline Demo")
    print("=" * 70)
    print(f"\nUser Input: {user_input}")
    print(f"Allowed Topics: {allowed_topics}")
    print(f"Age Band: {age_band}\n")

    # Step 1: Topic Fence Check
    print("[1] Topic Fence Check")
    print("-" * 70)
    fence = TopicFence()
    is_on_topic = fence.is_on_topic(user_input, allowed_topics, threshold=0.3)

    if not is_on_topic:
        best_topic, score = fence.get_best_topic(user_input, allowed_topics)
        print("  ❌ OFF-TOPIC detected")
        print(f"  Best match: {best_topic} (similarity: {score:.3f})")
        print("  Threshold: 0.3")
        print(f"\n  → Response: {SafetyTemplates.get_template('OFF_TOPIC', 'de')}")
        return "BLOCKED_OFF_TOPIC"

    print("  ✅ ON-TOPIC (threshold: 0.3)")
    print("  Proceeding to safety check...\n")

    # Step 2: Safety Fallback Judge
    print("[2] Safety Fallback Judge")
    print("-" * 70)
    judge = SafetyFallbackJudge(llm_provider=None)  # Mock mode
    is_safe = judge.evaluate_safety(user_input, age_band)

    if not is_safe:
        print("  ❌ UNSAFE content detected")
        print(f"\n  → Response: {SafetyTemplates.get_template('UNSAFE_CONTENT', 'de')}")
        return "BLOCKED_UNSAFE"

    print("  ✅ SAFE content")
    print("\n  → Allowing request to proceed")
    return "ALLOWED"


def main():
    """Run demo scenarios."""

    print("\n" + "=" * 70)
    print("SCENARIO 1: On-Topic, Safe Question")
    print("=" * 70)
    result1 = demo_pipeline(
        user_input="Was ist 2+2?",
        allowed_topics=["Mathe", "Physik", "Chemie"],
        age_band="9-12",
    )
    print(f"\nResult: {result1}\n")

    print("\n" + "=" * 70)
    print("SCENARIO 2: Off-Topic Question")
    print("=" * 70)
    result2 = demo_pipeline(
        user_input="Wie kocht man Pizza?",
        allowed_topics=["Mathe", "Physik", "Chemie"],
        age_band="9-12",
    )
    print(f"\nResult: {result2}\n")

    print("\n" + "=" * 70)
    print("SCENARIO 3: On-Topic but Unsafe Content")
    print("=" * 70)
    result3 = demo_pipeline(
        user_input="Wie baue ich eine Bombe?",
        allowed_topics=["Physik", "Chemie"],
        age_band="9-12",
    )
    print(f"\nResult: {result3}\n")

    print("\n" + "=" * 70)
    print("SCENARIO 4: On-Topic, Safe, Complex Question")
    print("=" * 70)
    result4 = demo_pipeline(
        user_input="Erkläre mir die Relativitätstheorie",
        allowed_topics=["Physik", "Mathe"],
        age_band="13-15",
    )
    print(f"\nResult: {result4}\n")

    print("=" * 70)
    print("Demo Complete")
    print("=" * 70)


if __name__ == "__main__":
    main()
