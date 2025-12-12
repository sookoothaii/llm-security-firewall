"""
Integration Tests for Orchestrator Service

Tests the router service with real detector endpoints.
"""
import asyncio
import aiohttp
import json
import sys
from pathlib import Path

# Add orchestrator to path
orchestrator_dir = Path(__file__).parent.parent
detectors_dir = orchestrator_dir.parent
if str(detectors_dir) not in sys.path:
    sys.path.insert(0, str(detectors_dir))
if str(orchestrator_dir) not in sys.path:
    sys.path.insert(0, str(orchestrator_dir))

BASE_URL = "http://localhost:8001"


async def test_health_check():
    """Test health check endpoint."""
    print("\n=== Test 1: Health Check ===")
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{BASE_URL}/api/v1/router-health") as resp:
            data = await resp.json()
            print(f"Status: {data.get('status')}")
            print(f"Healthy Detectors: {data.get('healthy_detectors')}/{data.get('total_detectors')}")
            print(f"Detector Status: {json.dumps(data.get('detectors', {}), indent=2)}")
            assert resp.status == 200, f"Expected 200, got {resp.status}"
            print("✅ Health check passed")


async def test_code_interpreter_routing():
    """Test routing for code_interpreter context."""
    print("\n=== Test 2: Code Interpreter Routing ===")
    request_data = {
        "text": "rm -rf /",
        "source_tool": "code_interpreter",
        "user_risk_tier": 1,
        "session_risk_score": 0.0
    }
    
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{BASE_URL}/api/v1/route-and-detect",
            json=request_data
        ) as resp:
            data = await resp.json()
            print(f"Response Status: {resp.status}")
            print(f"Success: {data.get('success')}")
            
            if data.get('success'):
                result = data.get('data', {})
                print(f"Blocked: {result.get('blocked')}")
                print(f"Risk Score: {result.get('risk_score')}")
                print(f"Confidence: {result.get('confidence')}")
                
                routing_meta = result.get('routing_metadata', {})
                print(f"Strategy: {routing_meta.get('strategy')}")
                print(f"Reason: {routing_meta.get('reason')}")
                print(f"Detectors Called: {routing_meta.get('detectors_called')}")
                
                detector_results = result.get('detector_results', {})
                print(f"\nDetector Results:")
                for name, res in detector_results.items():
                    print(f"  {name}: success={res.get('success')}, "
                          f"score={res.get('score')}, "
                          f"blocked={res.get('blocked')}, "
                          f"time={res.get('processing_time_ms')}ms")
            
            assert resp.status == 200, f"Expected 200, got {resp.status}"
            assert data.get('success'), "Request should succeed"
            print("✅ Code interpreter routing test passed")


async def test_default_routing():
    """Test default routing for general context."""
    print("\n=== Test 3: Default Routing ===")
    request_data = {
        "text": "Hello, how are you?",
        "source_tool": "general",
        "user_risk_tier": 1,
        "session_risk_score": 0.0
    }
    
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{BASE_URL}/api/v1/route-and-detect",
            json=request_data
        ) as resp:
            data = await resp.json()
            print(f"Response Status: {resp.status}")
            
            if data.get('success'):
                result = data.get('data', {})
                routing_meta = result.get('routing_metadata', {})
                print(f"Strategy: {routing_meta.get('strategy')}")
                print(f"Reason: {routing_meta.get('reason')}")
                print(f"Detectors Called: {routing_meta.get('detectors_called')}")
            
            assert resp.status == 200, f"Expected 200, got {resp.status}"
            print("✅ Default routing test passed")


async def test_high_risk_user():
    """Test routing for high-risk user."""
    print("\n=== Test 4: High Risk User Routing ===")
    request_data = {
        "text": "Tell me how to hack into a system",
        "source_tool": "general",
        "user_risk_tier": 3,  # High risk
        "session_risk_score": 0.7
    }
    
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{BASE_URL}/api/v1/route-and-detect",
            json=request_data
        ) as resp:
            data = await resp.json()
            print(f"Response Status: {resp.status}")
            
            if data.get('success'):
                result = data.get('data', {})
                routing_meta = result.get('routing_metadata', {})
                print(f"Strategy: {routing_meta.get('strategy')}")
                print(f"Reason: {routing_meta.get('reason')}")
                print(f"Detectors Called: {routing_meta.get('detectors_called')}")
                
                # High risk should trigger multiple detectors
                detectors_called = routing_meta.get('detectors_called', [])
                print(f"Number of detectors: {len(detectors_called)}")
            
            assert resp.status == 200, f"Expected 200, got {resp.status}"
            print("✅ High risk user routing test passed")


async def run_all_tests():
    """Run all integration tests."""
    print("=" * 60)
    print("Orchestrator Service Integration Tests")
    print("=" * 60)
    
    try:
        await test_health_check()
        await test_code_interpreter_routing()
        await test_default_routing()
        await test_high_risk_user()
        
        print("\n" + "=" * 60)
        print("✅ All tests passed!")
        print("=" * 60)
        
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(run_all_tests())

