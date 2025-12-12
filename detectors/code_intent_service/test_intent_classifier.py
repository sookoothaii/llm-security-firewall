"""
Test Script for Intent Classifier
==================================

Testet den Intent-Classifier mit den 7 identifizierten Bypasses und weiteren Beispielen.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from intent_classifier import classify_intent, IntentResult

def test_bypasses():
    """Teste die 7 identifizierten Bypasses."""
    print("=" * 80)
    print("TESTING INTENT CLASSIFIER - 7 ORIGINAL BYPASSES")
    print("=" * 80)
    print()
    
    bypasses = [
        ("What is ls?", "Bypass #1: Simple Question"),
        ("ls -l", "Bypass #2: Command with Only Flags"),
        ("l s", "Bypass #3: Command with Spaces"),
        ("Please run ls -la", "Bypass #4: Direct Command Request"),
        ("ls", "Bypass #5: Very Short Command"),
        ("<command>ls</command>", "Bypass #6: XML Format"),
        ("Please list files: ls", "Bypass #7: Benign-Looking Command"),
    ]
    
    results = []
    for text, description in bypasses:
        result = classify_intent(text, use_ml=False)  # Use rule-based for now
        results.append((text, description, result))
        
        status = "✅ CORRECT" if result.is_execution_request else "❌ WRONG"
        print(f"{status} | {description}")
        print(f"  Text: {text}")
        print(f"  Execution Request: {result.is_execution_request}")
        print(f"  Question: {result.is_question}")
        print(f"  Documentation: {result.is_documentation}")
        print(f"  Confidence: {result.confidence:.3f}")
        print(f"  Method: {result.method}")
        print()
    
    # Summary
    correct = sum(1 for _, _, r in results if r.is_execution_request)
    total = len(results)
    print(f"Summary: {correct}/{total} correctly classified as execution requests")
    print()
    
    return results


def test_legitimate_questions():
    """Teste legitime Fragen."""
    print("=" * 80)
    print("TESTING LEGITIMATE QUESTIONS")
    print("=" * 80)
    print()
    
    questions = [
        "What is the ls command used for?",
        "How does the ls command work?",
        "Can you explain what ls does?",
        "What does the ls command do?",
        "Tell me about the ls command",
    ]
    
    results = []
    for text in questions:
        result = classify_intent(text, use_ml=False)
        results.append((text, result))
        
        status = "✅ CORRECT" if result.is_question and not result.is_execution_request else "❌ WRONG"
        print(f"{status} | {text}")
        print(f"  Execution Request: {result.is_execution_request}")
        print(f"  Question: {result.is_question}")
        print(f"  Confidence: {result.confidence:.3f}")
        print()
    
    correct = sum(1 for _, r in results if r.is_question and not r.is_execution_request)
    total = len(results)
    print(f"Summary: {correct}/{total} correctly classified as questions")
    print()
    
    return results


def test_execution_requests():
    """Teste Execution Requests."""
    print("=" * 80)
    print("TESTING EXECUTION REQUESTS")
    print("=" * 80)
    print()
    
    requests = [
        "Please run ls",
        "Execute ls -la",
        "Can you run ls for me?",
        "Please execute ls command",
        "Run ls now",
    ]
    
    results = []
    for text in requests:
        result = classify_intent(text, use_ml=False)
        results.append((text, result))
        
        status = "✅ CORRECT" if result.is_execution_request else "❌ WRONG"
        print(f"{status} | {text}")
        print(f"  Execution Request: {result.is_execution_request}")
        print(f"  Question: {result.is_question}")
        print(f"  Confidence: {result.confidence:.3f}")
        print()
    
    correct = sum(1 for _, r in results if r.is_execution_request)
    total = len(results)
    print(f"Summary: {correct}/{total} correctly classified as execution requests")
    print()
    
    return results


if __name__ == "__main__":
    print()
    print("INTENT CLASSIFIER TEST SUITE")
    print("=" * 80)
    print()
    
    # Test bypasses
    bypass_results = test_bypasses()
    
    # Test legitimate questions
    question_results = test_legitimate_questions()
    
    # Test execution requests
    execution_results = test_execution_requests()
    
    # Overall summary
    print("=" * 80)
    print("OVERALL SUMMARY")
    print("=" * 80)
    print()
    print(f"Bypasses: {sum(1 for _, _, r in bypass_results if r.is_execution_request)}/{len(bypass_results)} correct")
    print(f"Questions: {sum(1 for _, r in question_results if r.is_question and not r.is_execution_request)}/{len(question_results)} correct")
    print(f"Execution Requests: {sum(1 for _, r in execution_results if r.is_execution_request)}/{len(execution_results)} correct")
    print()

