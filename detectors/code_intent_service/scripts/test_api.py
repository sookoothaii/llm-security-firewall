"""
Test Script für API
===================

Testet die neuen API Endpoints.
"""

import requests
import json
import sys

BASE_URL = "http://localhost:8000"


def test_root():
    """Test root endpoint."""
    print("=" * 60)
    print("TEST: Root Endpoint")
    print("=" * 60)
    
    response = requests.get(f"{BASE_URL}/")
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    print()


def test_health():
    """Test health endpoint."""
    print("=" * 60)
    print("TEST: Health Check")
    print("=" * 60)
    
    response = requests.get(f"{BASE_URL}/api/v1/health")
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    print()


def test_detect_benign():
    """Test detection with benign text."""
    print("=" * 60)
    print("TEST: Detection - Benign Text")
    print("=" * 60)
    
    payload = {
        "text": "Hello, how are you?",
        "session_id": "test-123"
    }
    
    response = requests.post(
        f"{BASE_URL}/api/v1/detect",
        json=payload
    )
    
    print(f"Status: {response.status_code}")
    result = response.json()
    print(f"Response: {json.dumps(result, indent=2)}")
    print()


def test_detect_malicious():
    """Test detection with malicious text."""
    print("=" * 60)
    print("TEST: Detection - Malicious Text")
    print("=" * 60)
    
    test_cases = [
        "rm -rf /",
        "Please run ls",
        "DROP TABLE users;",
        "eval('malicious code')",
    ]
    
    for text in test_cases:
        payload = {
            "text": text,
            "session_id": "test-123"
        }
        
        response = requests.post(
            f"{BASE_URL}/api/v1/detect",
            json=payload
        )
        
        result = response.json()
        status = "✓" if result["data"]["should_block"] else "✗"
        print(f"{status} '{text[:40]:40}' -> Blocked: {result['data']['should_block']:5} | "
              f"Score: {result['data']['risk_score']:.3f} | "
              f"Method: {result['data']['method']}")
    
    print()


def test_info():
    """Test info endpoint."""
    print("=" * 60)
    print("TEST: Service Info")
    print("=" * 60)
    
    response = requests.get(f"{BASE_URL}/api/v1/info")
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    print()


def main():
    """Run all tests."""
    print("\n" + "=" * 60)
    print("API TEST SUITE")
    print("=" * 60 + "\n")
    
    try:
        # Check if server is running
        requests.get(f"{BASE_URL}/", timeout=2)
    except requests.exceptions.ConnectionError:
        print("❌ ERROR: API Server is not running!")
        print("Start the server with:")
        print("  python -m uvicorn api.main:app --reload --port 8000")
        print("\nOr:")
        print("  cd detectors/code_intent_service")
        print("  python api/main.py")
        return 1
    
    tests = [
        ("Root", test_root),
        ("Health", test_health),
        ("Info", test_info),
        ("Detect Benign", test_detect_benign),
        ("Detect Malicious", test_detect_malicious),
    ]
    
    passed = 0
    failed = 0
    
    for name, test_func in tests:
        try:
            test_func()
            passed += 1
        except Exception as e:
            print(f"❌ {name} test failed: {e}")
            failed += 1
    
    print("=" * 60)
    print(f"Ergebnis: {passed}/{len(tests)} Tests bestanden")
    
    if failed == 0:
        print("🎉 Alle API-Tests bestanden!")
        return 0
    else:
        print(f"⚠️  {failed} Test(s) fehlgeschlagen")
        return 1


if __name__ == "__main__":
    sys.exit(main())

