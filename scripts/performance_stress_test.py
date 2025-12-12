#!/usr/bin/env python3
"""
PERFORMANCE STRESS TEST - Push your hardware to the limit
==========================================================

Stress tests the firewall with:
- High-frequency requests (1000+ req/s)
- Large payloads (10MB+)
- Complex Unicode sequences
- Concurrent sessions
- Memory pressure tests

Hardware Requirements:
- CPU: i9 12900HX (16 cores, 24 threads)
- GPU: RTX 3080TI (16GB VRAM)
- RAM: 32GB+ recommended

Author: Hardcore Red Team
Date: 2025-12-10
"""

import asyncio
import time
import sys
import random
import string
from typing import List, Dict
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import multiprocessing as mp

# Try to import firewall (local development path)
import sys
from pathlib import Path

# Add src directory to path for local development
script_dir = Path(__file__).parent
project_root = script_dir.parent
src_dir = project_root / "src"
if src_dir.exists():
    sys.path.insert(0, str(src_dir))

# Try multiple import paths
FIREWALL_AVAILABLE = False
guard = None

# Try 1: Installed package
try:
    from llm_firewall import guard
    FIREWALL_AVAILABLE = True
except ImportError:
    pass

# Try 2: Local development (src/llm_firewall)
if not FIREWALL_AVAILABLE:
    try:
        from llm_firewall import guard
        FIREWALL_AVAILABLE = True
    except ImportError:
        pass

# Try 3: Direct import from src/llm_firewall/guard.py
if not FIREWALL_AVAILABLE:
    try:
        import importlib.util
        guard_path = src_dir / "llm_firewall" / "guard.py"
        if guard_path.exists():
            spec = importlib.util.spec_from_file_location("llm_firewall.guard", guard_path)
            guard_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(guard_module)
            guard = guard_module
            FIREWALL_AVAILABLE = True
    except Exception:
        pass

# Try 4: hak_gal module (alternative path)
if not FIREWALL_AVAILABLE:
    try:
        from hak_gal.core.engine import FirewallEngine
        # Create a wrapper to match guard interface
        class GuardWrapper:
            def __init__(self):
                self.engine = FirewallEngine()
            
            def check_input(self, text: str, user_id: str = "test", tenant_id: str = "default"):
                import asyncio
                try:
                    result = asyncio.run(self.engine.process_inbound(user_id, text, tenant_id))
                    class Decision:
                        allowed = result
                        risk_score = None
                        reason = "hak_gal engine"
                    return Decision()
                except Exception as e:
                    class Decision:
                        allowed = False
                        risk_score = 1.0
                        reason = str(e)
                    return Decision()
        
        guard = GuardWrapper()
        FIREWALL_AVAILABLE = True
    except ImportError:
        pass

# Try 5: HTTP API (if service is running)
if not FIREWALL_AVAILABLE:
    try:
        import requests
        # Test if service is running
        response = requests.get("http://localhost:8001/health", timeout=2)
        if response.status_code == 200:
            # Create HTTP-based guard wrapper
            class HTTPGuard:
                def __init__(self, base_url: str = "http://localhost:8001"):
                    self.base_url = base_url
                    self.session = requests.Session()
                
                def check_input(self, text: str, user_id: str = "test", tenant_id: str = "default"):
                    try:
                        response = self.session.post(
                            f"{self.base_url}/v1/detect",
                            json={"text": text, "user_id": user_id, "tenant_id": tenant_id},
                            timeout=5.0
                        )
                        if response.status_code == 200:
                            data = response.json()
                            class Decision:
                                allowed = not data.get("blocked", False)
                                risk_score = data.get("risk_score", 0.0)
                                reason = data.get("reason", "HTTP API response")
                            return Decision()
                        else:
                            class Decision:
                                allowed = False
                                risk_score = 1.0
                                reason = f"HTTP {response.status_code}"
                            return Decision()
                    except Exception as e:
                        class Decision:
                            allowed = False
                            risk_score = 1.0
                            reason = f"HTTP Error: {str(e)}"
                        return Decision()
            
            guard = HTTPGuard()
            FIREWALL_AVAILABLE = True
            print("✅ Firewall loaded via HTTP API (localhost:8001)")
    except ImportError:
        pass
    except Exception:
        pass

if not FIREWALL_AVAILABLE:
    print("⚠️  WARNING: Firewall not available")
    print("   Options:")
    print("   - Install: pip install llm-security-firewall")
    print("   - Or start service: python -m uvicorn detectors.code_intent_service.main:app --host 0.0.0.0 --port 8001")


@dataclass
class StressTestResult:
    """Result of a stress test."""
    test_name: str
    requests: int
    success: int
    failed: int
    avg_latency_ms: float
    p50_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    max_latency_ms: float
    throughput_rps: float
    memory_mb: float = 0.0
    error: str = None


class PerformanceStressTest:
    """Performance stress test suite."""
    
    def __init__(self, max_workers: int = None):
        self.max_workers = max_workers or mp.cpu_count()
        self.firewall = guard if FIREWALL_AVAILABLE else None
    
    def generate_large_payload(self, size_mb: float) -> str:
        """Generate a large payload."""
        size_bytes = int(size_mb * 1024 * 1024)
        return "A" * size_bytes
    
    def generate_complex_unicode(self, length: int) -> str:
        """Generate complex Unicode sequence."""
        # Mix of various Unicode characters
        chars = []
        for _ in range(length):
            char_type = random.choice(['ascii', 'unicode', 'zero_width', 'bidi'])
            if char_type == 'ascii':
                chars.append(random.choice(string.ascii_letters))
            elif char_type == 'unicode':
                chars.append(chr(random.randint(0x1000, 0x1FFF)))
            elif char_type == 'zero_width':
                chars.append(chr(random.choice([0x200B, 0x200C, 0x200D, 0xFEFF])))
            elif char_type == 'bidi':
                chars.append(chr(random.choice([0x202E, 0x202D, 0x202A])))
        return ''.join(chars)
    
    def test_high_frequency(self, duration_seconds: int = 60, target_rps: int = 1000) -> StressTestResult:
        """Test high-frequency requests."""
        print(f"🔥 High-Frequency Test: {target_rps} req/s for {duration_seconds}s...")
        
        latencies = []
        success = 0
        failed = 0
        start_time = time.time()
        end_time = start_time + duration_seconds
        
        payload = "rm -rf /tmp"  # Simple payload
        
        while time.time() < end_time:
            batch_start = time.time()
            
            # Send batch of requests
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = []
                for _ in range(target_rps):
                    future = executor.submit(self._single_request, payload)
                    futures.append(future)
                
                for future in as_completed(futures):
                    try:
                        latency = future.result()
                        if latency is not None:
                            latencies.append(latency)
                            success += 1
                        else:
                            failed += 1
                    except Exception as e:
                        failed += 1
            
            # Sleep to maintain target RPS
            batch_time = time.time() - batch_start
            sleep_time = max(0, 1.0 - batch_time)
            time.sleep(sleep_time)
        
        total_time = time.time() - start_time
        total_requests = success + failed
        
        return self._calculate_stats("High-Frequency", latencies, success, failed, total_time)
    
    def test_large_payloads(self, sizes_mb: List[float] = [1, 5, 10, 50]) -> StressTestResult:
        """Test with large payloads."""
        print(f"📦 Large Payload Test: {sizes_mb} MB...")
        
        latencies = []
        success = 0
        failed = 0
        start_time = time.time()
        
        for size_mb in sizes_mb:
            payload = self.generate_large_payload(size_mb)
            
            for _ in range(10):  # 10 requests per size
                latency = self._single_request(payload)
                if latency is not None:
                    latencies.append(latency)
                    success += 1
                else:
                    failed += 1
        
        total_time = time.time() - start_time
        
        return self._calculate_stats("Large-Payloads", latencies, success, failed, total_time)
    
    def test_complex_unicode(self, lengths: List[int] = [100, 1000, 10000, 100000]) -> StressTestResult:
        """Test with complex Unicode sequences."""
        print(f"🔤 Complex Unicode Test: lengths {lengths}...")
        
        latencies = []
        success = 0
        failed = 0
        start_time = time.time()
        
        for length in lengths:
            payload = self.generate_complex_unicode(length)
            
            for _ in range(10):  # 10 requests per length
                latency = self._single_request(payload)
                if latency is not None:
                    latencies.append(latency)
                    success += 1
                else:
                    failed += 1
        
        total_time = time.time() - start_time
        
        return self._calculate_stats("Complex-Unicode", latencies, success, failed, total_time)
    
    def test_concurrent_sessions(self, num_sessions: int = 1000, requests_per_session: int = 10) -> StressTestResult:
        """Test concurrent sessions."""
        print(f"👥 Concurrent Sessions Test: {num_sessions} sessions, {requests_per_session} req/session...")
        
        latencies = []
        success = 0
        failed = 0
        start_time = time.time()
        
        def process_session(session_id: int):
            session_latencies = []
            for i in range(requests_per_session):
                payload = f"Session {session_id}, Request {i}: rm -rf /tmp"
                latency = self._single_request(payload)
                if latency is not None:
                    session_latencies.append(latency)
            return session_latencies
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(process_session, i) for i in range(num_sessions)]
            
            for future in as_completed(futures):
                try:
                    session_latencies = future.result()
                    latencies.extend(session_latencies)
                    success += len(session_latencies)
                except Exception as e:
                    failed += requests_per_session
        
        total_time = time.time() - start_time
        
        return self._calculate_stats("Concurrent-Sessions", latencies, success, failed, total_time)
    
    def _single_request(self, payload: str) -> float:
        """Execute a single request and return latency."""
        if not self.firewall:
            return None
        
        try:
            start = time.time()
            decision = self.firewall.check_input(payload)
            latency = (time.time() - start) * 1000  # Convert to ms
            return latency
        except Exception as e:
            return None
    
    def _calculate_stats(self, test_name: str, latencies: List[float], success: int, failed: int, total_time: float) -> StressTestResult:
        """Calculate statistics from latencies."""
        if not latencies:
            return StressTestResult(
                test_name=test_name,
                requests=success + failed,
                success=success,
                failed=failed,
                avg_latency_ms=0.0,
                p50_latency_ms=0.0,
                p95_latency_ms=0.0,
                p99_latency_ms=0.0,
                max_latency_ms=0.0,
                throughput_rps=0.0,
            )
        
        latencies_sorted = sorted(latencies)
        n = len(latencies_sorted)
        
        return StressTestResult(
            test_name=test_name,
            requests=success + failed,
            success=success,
            failed=failed,
            avg_latency_ms=sum(latencies) / n,
            p50_latency_ms=latencies_sorted[n // 2],
            p95_latency_ms=latencies_sorted[int(n * 0.95)],
            p99_latency_ms=latencies_sorted[int(n * 0.99)],
            max_latency_ms=max(latencies),
            throughput_rps=success / total_time if total_time > 0 else 0.0,
        )
    
    def print_results(self, results: List[StressTestResult]):
        """Print stress test results."""
        print("\n" + "=" * 80)
        print("  STRESS TEST RESULTS")
        print("=" * 80 + "\n")
        
        for result in results:
            print(f"📊 {result.test_name}:")
            print(f"   Requests: {result.requests} (Success: {result.success}, Failed: {result.failed})")
            print(f"   Avg Latency: {result.avg_latency_ms:.2f} ms")
            print(f"   P50: {result.p50_latency_ms:.2f} ms")
            print(f"   P95: {result.p95_latency_ms:.2f} ms")
            print(f"   P99: {result.p99_latency_ms:.2f} ms")
            print(f"   Max: {result.max_latency_ms:.2f} ms")
            print(f"   Throughput: {result.throughput_rps:.2f} req/s")
            if result.error:
                print(f"   Error: {result.error}")
            print()
    
    def run_all(self):
        """Run all stress tests."""
        if not FIREWALL_AVAILABLE:
            print("❌ Firewall not available")
            return
        
        print("🚀 Starting Performance Stress Tests...\n")
        
        results = []
        
        # High-frequency test
        results.append(self.test_high_frequency(duration_seconds=30, target_rps=500))
        
        # Large payloads
        results.append(self.test_large_payloads([1, 5, 10]))
        
        # Complex Unicode
        results.append(self.test_complex_unicode([100, 1000, 10000]))
        
        # Concurrent sessions
        results.append(self.test_concurrent_sessions(num_sessions=500, requests_per_session=5))
        
        # Print results
        self.print_results(results)
        
        return results


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Performance Stress Test")
    parser.add_argument("--workers", type=int, help="Number of parallel workers")
    
    args = parser.parse_args()
    
    tester = PerformanceStressTest(max_workers=args.workers)
    tester.run_all()


if __name__ == "__main__":
    main()

