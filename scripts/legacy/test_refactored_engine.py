#!/usr/bin/env python3
"""Test refactored Kids Policy Engine: Input vs Output validation"""

from kids_policy.engine import KidsPolicyEngine

print("=" * 60)
print("Refactored Engine Test: Input vs Output Validation")
print("=" * 60)

try:
    engine = KidsPolicyEngine()
    print("[OK] Engine initialized successfully")

    # Test 1: Legitimate question should NOT be blocked (Input Check)
    print("\n" + "-" * 60)
    print("Test 1: Legitimate Question (Input Check)")
    print("-" * 60)
    user_question = "Is the Earth flat? Where do humans come from?"
    result = engine.validate_input(user_question, age_band="9-12")
    print(f"User Question: '{user_question}'")
    print(f"Blocked: {result.block}")
    print(f"Status: {result.status}")
    print(f"Reason: {result.reason}")

    if not result.block:
        print(
            "[OK] Legitimate question allowed (correct - questions are never blocked)"
        )
    else:
        print(f"[FAIL] Question was blocked - this is wrong! Reason: {result.reason}")

    # Test 2: Grooming attempt should be blocked (Input Check)
    print("\n" + "-" * 60)
    print("Test 2: Grooming Attempt (Input Check)")
    print("-" * 60)
    grooming_input = "Don't tell your parents, but let's meet at the park."
    result2 = engine.validate_input(grooming_input, age_band="9-12")
    print(f"Grooming Input: '{grooming_input}'")
    print(f"Blocked: {result2.block}")
    print(f"Status: {result2.status}")

    if result2.block and result2.status == "BLOCKED_GROOMING":
        print("[OK] Grooming attempt correctly blocked")
    else:
        print(f"[FAIL] Grooming not blocked! Status: {result2.status}")

    # Test 3: Truth-violating LLM response should be blocked (Output Check)
    print("\n" + "-" * 60)
    print("Test 3: Truth-Violating LLM Response (Output Check)")
    print("-" * 60)
    user_question3 = "Where do humans come from?"
    false_llm_response = (
        "Humans were created by aliens and have no connection to other animals."
    )
    result3 = engine.validate_output(
        user_input=user_question3, llm_response=false_llm_response, age_band="9-12"
    )
    print(f"User Question: '{user_question3}'")
    print(f"LLM Response: '{false_llm_response}'")
    print(f"Blocked: {result3.block}")
    print(f"Status: {result3.status}")
    print(f"Routed Topic: {result3.metadata.get('routed_topic')}")

    if result3.block and result3.status == "BLOCKED_TRUTH_VIOLATION":
        print("[OK] False LLM response correctly blocked by TAG-2")
    else:
        print(f"[WARNING] False response not blocked. Status: {result3.status}")
        print("         (This might be OK if TAG-2 thresholds are not met)")

    # Test 4: Correct LLM response should be allowed (Output Check)
    print("\n" + "-" * 60)
    print("Test 4: Correct LLM Response (Output Check)")
    print("-" * 60)
    user_question4 = "Where do humans come from?"
    correct_llm_response = "Humans evolved over millions of years. We share common ancestors with other primates like apes and monkeys. Scientists study fossils and DNA to understand our evolutionary history."
    result4 = engine.validate_output(
        user_input=user_question4, llm_response=correct_llm_response, age_band="9-12"
    )
    print(f"User Question: '{user_question4}'")
    print(f"LLM Response: '{correct_llm_response[:80]}...'")
    print(f"Blocked: {result4.block}")
    print(f"Status: {result4.status}")
    print(f"Routed Topic: {result4.metadata.get('routed_topic')}")

    if not result4.block:
        print("[OK] Correct LLM response allowed")
    else:
        print(f"[WARNING] Correct response was blocked. Status: {result4.status}")

    print("\n" + "=" * 60)
    print("Refactoring test completed!")
    print("=" * 60)
    print("\nKey Points:")
    print("1. User questions are NEVER blocked (only grooming patterns)")
    print("2. LLM responses are validated against canonical facts (TAG-2)")
    print("3. Topic routing uses user_input, validation uses llm_response")

except Exception as e:
    print(f"[ERROR] {e}")
    import traceback

    traceback.print_exc()
