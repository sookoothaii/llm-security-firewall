#!/usr/bin/env python3
"""Quick test for Topic Router integration in Kids Policy Engine"""

from kids_policy.engine import KidsPolicyEngine

print("=" * 60)
print("Topic Router Integration Test")
print("=" * 60)

try:
    engine = KidsPolicyEngine()
    print("[OK] Engine initialized successfully")
    print(f"[OK] Topic Router available: {engine.topic_router is not None}")
    print(f"[OK] TAG-2 enabled: {engine.tag2_enabled}")

    # Test 1: Evolution topic routing
    print("\n" + "-" * 60)
    print("Test 1: Evolution topic routing")
    print("-" * 60)
    result = engine.check(
        "Where do humans come from? Did we evolve from monkeys?", age_band="9-12"
    )
    routed_topic = result.metadata.get("routed_topic")
    confidence = result.metadata.get("routing_confidence", 0)
    print("Input: 'Where do humans come from? Did we evolve from monkeys?'")
    print(f"Routed Topic: {routed_topic}")
    print(f"Confidence: {confidence:.2f}")
    print(f"Status: {result.status}")

    if routed_topic == "evolution_origins":
        print("[OK] Topic correctly routed to evolution_origins")
    else:
        print(f"[FAIL] Expected evolution_origins, got {routed_topic}")

    # Test 2: Religion topic routing
    print("\n" + "-" * 60)
    print("Test 2: Religion topic routing")
    print("-" * 60)
    result2 = engine.check("Who is God? Does God exist?", age_band="9-12")
    routed_topic2 = result2.metadata.get("routed_topic")
    confidence2 = result2.metadata.get("routing_confidence", 0)
    print("Input: 'Who is God? Does God exist?'")
    print(f"Routed Topic: {routed_topic2}")
    print(f"Confidence: {confidence2:.2f}")
    print(f"Status: {result2.status}")

    if routed_topic2 == "religion_god":
        print("[OK] Topic correctly routed to religion_god")
    else:
        print(f"[FAIL] Expected religion_god, got {routed_topic2}")

    # Test 3: Word boundary safety (Godzilla)
    print("\n" + "-" * 60)
    print("Test 3: Word boundary safety (Godzilla)")
    print("-" * 60)
    result3 = engine.check("I am fighting Godzilla in Minecraft!", age_band="9-12")
    routed_topic3 = result3.metadata.get("routed_topic")
    print("Input: 'I am fighting Godzilla in Minecraft!'")
    print(f"Routed Topic: {routed_topic3}")
    print(f"Status: {result3.status}")

    if routed_topic3 == "general_chat":
        print("[OK] Godzilla correctly ignored (word boundary safety)")
    else:
        print(f"[WARNING] Expected general_chat, got {routed_topic3}")

    print("\n" + "=" * 60)
    print("Integration test completed!")
    print("=" * 60)

except Exception as e:
    print(f"[ERROR] {e}")
    import traceback

    traceback.print_exc()
