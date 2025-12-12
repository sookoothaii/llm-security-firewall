#!/usr/bin/env python3
"""
Load Test Suite - Orchestrator Service
=======================================

Simuliert Dauerlast mit variierenden Request-Typen.
Testet Durchsatz, Latenz und Fehlerrate unter Last.

Usage:
    python -m tests.load_test --concurrent 100 --duration 300
    python -m tests.load_test --concurrent 50 --duration 60 --output results.json
"""

import asyncio
import aiohttp
import statistics
import argparse
import json
import time
from typing import List, Dict, Tuple
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict
import random
import sys

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


@dataclass
class LoadTestResult:
    """Ergebnis eines Load-Tests."""
    timestamp: str
    concurrent: int
    duration: int
    total_requests: int
    successful: int
    errors: int
    error_rate: float
    p50_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    avg_latency_ms: float
    max_latency_ms: float
    min_latency_ms: float
    requests_per_second: float
    by_category: Dict[str, Dict]


class LoadTester:
    """Load-Tester für Orchestrator Service."""

    def __init__(self, base_url: str = "http://localhost:8001"):
        self.base_url = base_url
        self.test_cases = [
            {
                "name": "Normal text",
                "text": "Hello, how are you?",
                "context": {"source_tool": "general", "user_risk_tier": 1}
            },
            {
                "name": "Code",
                "text": "import os; os.system('rm -rf /')",
                "context": {"source_tool": "code_interpreter", "user_risk_tier": 1}
            },
            {
                "name": "Multilingual",
                "text": "混合语言攻击测试",
                "context": {"source_tool": "general", "user_risk_tier": 1}
            },
            {
                "name": "Long text",
                "text": "a" * 1000,
                "context": {"source_tool": "general", "user_risk_tier": 1}
            },
            {
                "name": "JSON escape",
                "text": '{"test": "\u200bhidden"}',
                "context": {"source_tool": "general", "user_risk_tier": 1}
            },
            {
                "name": "SQL Injection",
                "text": "SELECT * FROM users WHERE id = 1; DROP TABLE users;",
                "context": {"source_tool": "general", "user_risk_tier": 1}
            },
            {
                "name": "XSS",
                "text": "<script>alert('xss')</script>",
                "context": {"source_tool": "general", "user_risk_tier": 1}
            },
            {
                "name": "Path Traversal",
                "text": "../../../etc/passwd",
                "context": {"source_tool": "general", "user_risk_tier": 1}
            },
            {
                "name": "Command Injection",
                "text": "; ls -la;",
                "context": {"source_tool": "code_interpreter", "user_risk_tier": 1}
            },
            {
                "name": "Unicode Bomb",
                "text": "\ufeff" * 1000,
                "context": {"source_tool": "general", "user_risk_tier": 1}
            }
        ]

    async def make_request(
        self,
        session: aiohttp.ClientSession,
        test_case: Dict
    ) -> Tuple[bool, float, int, str]:
        """Macht einen einzelnen Request."""
        start_time = time.time()
        status_code = 0
        error = None
        
        try:
            async with session.post(
                f"{self.base_url}/api/v1/route-and-detect",
                json={
                    "text": test_case["text"],
                    "context": test_case["context"]
                },
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                status_code = resp.status
                await resp.json()  # Read response
                latency = (time.time() - start_time) * 1000  # in ms
                success = status_code == 200
                return success, latency, status_code, test_case["name"]
        except asyncio.TimeoutError:
            latency = (time.time() - start_time) * 1000
            return False, latency, 0, f"Timeout: {test_case['name']}"
        except Exception as e:
            latency = (time.time() - start_time) * 1000
            return False, latency, 0, f"Error: {str(e)}"

    async def test_concurrent_requests(
        self,
        concurrent: int = 100,
        duration: int = 30
    ) -> LoadTestResult:
        """Simuliert Dauerlast mit variierenden Request-Typen."""
        print(f"\n🚀 Starting Load Test:")
        print(f"   Concurrent requests: {concurrent}")
        print(f"   Duration: {duration}s")
        print(f"   Base URL: {self.base_url}\n")

        latencies = []
        errors = 0
        successful = 0
        total_requests = 0
        category_stats = {}
        start_time = time.time()
        end_time = start_time + duration

        async with aiohttp.ClientSession() as session:
            # Create semaphore to limit concurrent requests
            semaphore = asyncio.Semaphore(concurrent)

            async def bounded_request():
                nonlocal successful, errors, latencies, category_stats
                async with semaphore:
                    test_case = random.choice(self.test_cases)
                    success, latency, status, category = await self.make_request(
                        session, test_case
                    )
                    
                    # Update stats
                    if category not in category_stats:
                        category_stats[category] = {
                            "total": 0,
                            "successful": 0,
                            "errors": 0,
                            "latencies": []
                        }
                    
                    category_stats[category]["total"] += 1
                    if success:
                        successful += 1
                        latencies.append(latency)
                        category_stats[category]["successful"] += 1
                        category_stats[category]["latencies"].append(latency)
                    else:
                        errors += 1
                        category_stats[category]["errors"] += 1
                    
                    return success

            # Start continuous load
            tasks = []
            request_count = 0

            while time.time() < end_time:
                # Keep pool of concurrent requests
                while len(tasks) < concurrent and time.time() < end_time:
                    task = asyncio.create_task(bounded_request())
                    tasks.append(task)
                    request_count += 1

                # Wait for some tasks to complete
                if len(tasks) >= concurrent:
                    done, pending = await asyncio.wait(
                        tasks, return_when=asyncio.FIRST_COMPLETED
                    )
                    tasks = list(pending)
                    total_requests += len(done)

            # Wait for remaining tasks
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
                total_requests += len(tasks)

        # Calculate statistics
        actual_duration = time.time() - start_time
        requests_per_second = total_requests / actual_duration if actual_duration > 0 else 0
        error_rate = errors / total_requests if total_requests > 0 else 0

        # Calculate percentiles
        if latencies:
            latencies_sorted = sorted(latencies)
            p50 = statistics.median(latencies_sorted)
            p95 = statistics.quantiles(latencies_sorted, n=20)[-1] if len(latencies_sorted) >= 20 else latencies_sorted[-1]
            p99 = statistics.quantiles(latencies_sorted, n=100)[-1] if len(latencies_sorted) >= 100 else latencies_sorted[-1]
            avg_latency = statistics.mean(latencies_sorted)
            max_latency = max(latencies_sorted)
            min_latency = min(latencies_sorted)
        else:
            p50 = p95 = p99 = avg_latency = max_latency = min_latency = 0.0

        # Calculate category statistics
        by_category = {}
        for category, stats in category_stats.items():
            if stats["latencies"]:
                by_category[category] = {
                    "total": stats["total"],
                    "successful": stats["successful"],
                    "errors": stats["errors"],
                    "avg_latency_ms": statistics.mean(stats["latencies"]),
                    "p95_latency_ms": statistics.quantiles(stats["latencies"], n=20)[-1] if len(stats["latencies"]) >= 20 else stats["latencies"][-1]
                }
            else:
                by_category[category] = {
                    "total": stats["total"],
                    "successful": stats["successful"],
                    "errors": stats["errors"],
                    "avg_latency_ms": 0.0,
                    "p95_latency_ms": 0.0
                }

        return LoadTestResult(
            timestamp=datetime.utcnow().isoformat(),
            concurrent=concurrent,
            duration=actual_duration,
            total_requests=total_requests,
            successful=successful,
            errors=errors,
            error_rate=error_rate,
            p50_latency_ms=round(p50, 2),
            p95_latency_ms=round(p95, 2),
            p99_latency_ms=round(p99, 2),
            avg_latency_ms=round(avg_latency, 2),
            max_latency_ms=round(max_latency, 2),
            min_latency_ms=round(min_latency, 2),
            requests_per_second=round(requests_per_second, 2),
            by_category=by_category
        )

    def print_results(self, result: LoadTestResult):
        """Druckt Test-Ergebnisse."""
        print("\n" + "=" * 80)
        print("📊 LOAD TEST RESULTS")
        print("=" * 80)
        print(f"Timestamp: {result.timestamp}")
        print(f"Duration: {result.duration:.2f}s")
        print(f"\n📈 Requests:")
        print(f"   Total: {result.total_requests}")
        print(f"   Successful: {result.successful}")
        print(f"   Errors: {result.errors}")
        print(f"   Error Rate: {result.error_rate * 100:.2f}%")
        print(f"   Requests/sec: {result.requests_per_second:.2f}")
        
        print(f"\n⏱️  Latency (ms):")
        print(f"   P50: {result.p50_latency_ms:.2f}")
        print(f"   P95: {result.p95_latency_ms:.2f}")
        print(f"   P99: {result.p99_latency_ms:.2f}")
        print(f"   Avg: {result.avg_latency_ms:.2f}")
        print(f"   Min: {result.min_latency_ms:.2f}")
        print(f"   Max: {result.max_latency_ms:.2f}")

        if result.by_category:
            print(f"\n📋 By Category:")
            for category, stats in result.by_category.items():
                print(f"   {category}:")
                print(f"      Total: {stats['total']}, Successful: {stats['successful']}, Errors: {stats['errors']}")
                print(f"      Avg Latency: {stats['avg_latency_ms']:.2f}ms, P95: {stats['p95_latency_ms']:.2f}ms")

        print("\n" + "=" * 80)

        # Success criteria check
        print("\n✅ Success Criteria:")
        criteria_met = True
        
        if result.requests_per_second < 100:
            print(f"   ❌ Throughput: {result.requests_per_second:.2f} req/s (target: >100 req/s)")
            criteria_met = False
        else:
            print(f"   ✅ Throughput: {result.requests_per_second:.2f} req/s")
        
        if result.p95_latency_ms > 200:
            print(f"   ❌ P95 Latency: {result.p95_latency_ms:.2f}ms (target: <200ms)")
            criteria_met = False
        else:
            print(f"   ✅ P95 Latency: {result.p95_latency_ms:.2f}ms")
        
        if result.error_rate > 0.001:
            print(f"   ❌ Error Rate: {result.error_rate * 100:.2f}% (target: <0.1%)")
            criteria_met = False
        else:
            print(f"   ✅ Error Rate: {result.error_rate * 100:.2f}%")
        
        if criteria_met:
            print("\n🎉 ALL SUCCESS CRITERIA MET!")
        else:
            print("\n⚠️  SOME SUCCESS CRITERIA NOT MET")
        
        print("=" * 80 + "\n")


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Load Test for Orchestrator Service")
    parser.add_argument(
        "--concurrent",
        type=int,
        default=100,
        help="Number of concurrent requests (default: 100)"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=30,
        help="Test duration in seconds (default: 30)"
    )
    parser.add_argument(
        "--url",
        type=str,
        default="http://localhost:8001",
        help="Base URL of orchestrator service (default: http://localhost:8001)"
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Output JSON file path (optional)"
    )
    
    args = parser.parse_args()
    
    tester = LoadTester(base_url=args.url)
    result = await tester.test_concurrent_requests(
        concurrent=args.concurrent,
        duration=args.duration
    )
    
    tester.print_results(result)
    
    # Save to JSON if requested
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(asdict(result), f, indent=2)
        print(f"📄 Results saved to: {output_path}")


if __name__ == "__main__":
    asyncio.run(main())

