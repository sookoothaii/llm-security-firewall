"""Direkter Service-Test - Debug"""
import httpx
import time
import json

def test_service(url: str, text: str, method: str = "POST"):
    print(f"\nTesting: {url}")
    print(f"Method: {method}")
    if text:
        print(f"Text: {text[:50]}...")
    
    start = time.time()
    try:
        if method == "GET":
            response = httpx.get(url, timeout=2.0)
        else:
            response = httpx.post(
                url,
                json={"text": text},
                timeout=2.0
            )
        elapsed = (time.time() - start) * 1000
        print(f"Status: {response.status_code}")
        print(f"Time: {elapsed:.2f}ms")
        print(f"Response: {json.dumps(response.json(), indent=2)[:500]}")
        return True
    except httpx.TimeoutException:
        elapsed = (time.time() - start) * 1000
        print(f"TIMEOUT after {elapsed:.2f}ms")
        return False
    except Exception as e:
        elapsed = (time.time() - start) * 1000
        print(f"ERROR after {elapsed:.2f}ms: {type(e).__name__}: {e}")
        return False

# Test
print("="*80)
print("DIRECT SERVICE TEST")
print("="*80)

test_service("http://localhost:8000/api/v1/detect", "echo hello", "POST")
test_service("http://localhost:8000/api/v1/health", "", "GET")
