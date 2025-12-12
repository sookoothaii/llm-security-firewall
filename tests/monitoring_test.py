#!/usr/bin/env python3
"""
Monitoring Test Suite - Orchestrator Service (Windows-compatible)
===================================================================

Testet Monitoring-Endpoints und Metriken-Erfassung.
Python-Version für Windows-Kompatibilität.

Usage:
    python -m tests.monitoring_test
    python -m tests.monitoring_test --url http://localhost:8001
"""

import asyncio
import aiohttp
import argparse
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List
import sys

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


class MonitoringTester:
    """Monitoring-Tester für Orchestrator Service."""

    def __init__(self, base_url: str = "http://localhost:8001", output_dir: str = "test_results"):
        self.base_url = base_url
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results = {}

    async def test_metrics_collection(self):
        """Test 1: Metrics Collection - Sendet 100 Requests."""
        print("\nTest 1: Metrics Collection")
        print("---------------------------")
        print("Sending 100 requests...")
        
        success_count = 0
        async with aiohttp.ClientSession() as session:
            for i in range(100):
                try:
                    async with session.post(
                        f"{self.base_url}/api/v1/route-and-detect",
                        json={
                            "text": "test request",
                            "context": {"source_tool": "general", "user_risk_tier": 1}
                        },
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            success_count += 1
                except Exception:
                    pass
                
                # Small delay
                await asyncio.sleep(0.1)
        
        print(f"Successful requests: {success_count}/100")
        
        # Check metrics endpoint
        print("\nChecking metrics endpoint...")
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.base_url}/api/v1/metrics",
                timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                if resp.status == 200:
                    metrics_text = await resp.text()
                    
                    # Save to file
                    metrics_file = self.output_dir / "metrics_output.txt"
                    with open(metrics_file, 'w', encoding='utf-8') as f:
                        f.write(metrics_text)
                    
                    # Check for expected metrics
                    has_router_requests = "router_requests_total" in metrics_text
                    has_detector_calls = "detector_calls_total" in metrics_text
                    
                    if has_router_requests:
                        print("✅ Metrics endpoint working - router_requests_total found")
                    else:
                        print("❌ Metrics endpoint issue - router_requests_total not found")
                    
                    if has_detector_calls:
                        print("✅ Metrics endpoint working - detector_calls_total found")
                    else:
                        print("❌ Metrics endpoint issue - detector_calls_total not found")
                    
                    self.results["metrics_collection"] = {
                        "success": has_router_requests and has_detector_calls,
                        "successful_requests": success_count,
                        "metrics_file": str(metrics_file)
                    }
                else:
                    print(f"❌ Metrics endpoint returned status {resp.status}")
                    self.results["metrics_collection"] = {
                        "success": False,
                        "error": f"HTTP {resp.status}"
                    }

    async def test_alert_triggering(self):
        """Test 2: Alert Triggering - Simuliert hohe Error-Rate."""
        print("\nTest 2: Alert Triggering")
        print("-------------------------")
        print("Simulating high error rate...")
        
        error_count = 0
        async with aiohttp.ClientSession() as session:
            for i in range(50):
                try:
                    async with session.post(
                        f"{self.base_url}/api/v1/route-and-detect",
                        json={"text": "", "context": {}},
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status != 200:
                            error_count += 1
                except Exception:
                    error_count += 1
                
                await asyncio.sleep(0.1)
        
        print(f"Errors generated: {error_count}/50")
        
        # Check alerts endpoint
        print("\nChecking alerts endpoint...")
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.base_url}/api/v1/alerts",
                timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                if resp.status == 200:
                    alerts_data = await resp.json()
                    
                    # Save to file
                    alerts_file = self.output_dir / "alerts_output.txt"
                    with open(alerts_file, 'w', encoding='utf-8') as f:
                        json.dump(alerts_data, f, indent=2)
                    
                    alert_count = alerts_data.get("count", 0)
                    print(f"✅ Alerts endpoint working")
                    print(f"   Active alerts: {alert_count}")
                    
                    self.results["alert_triggering"] = {
                        "success": True,
                        "errors_generated": error_count,
                        "active_alerts": alert_count,
                        "alerts_file": str(alerts_file)
                    }
                else:
                    print(f"❌ Alerts endpoint returned status {resp.status}")
                    self.results["alert_triggering"] = {
                        "success": False,
                        "error": f"HTTP {resp.status}"
                    }

    async def test_health_check(self):
        """Test 3: Health Check."""
        print("\nTest 3: Health Check")
        print("---------------------")
        
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.base_url}/api/v1/health",
                timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                if resp.status == 200:
                    health_data = await resp.json()
                    
                    # Save to file
                    health_file = self.output_dir / "health_output.txt"
                    with open(health_file, 'w', encoding='utf-8') as f:
                        json.dump(health_data, f, indent=2)
                    
                    status = health_data.get("status", "unknown")
                    print(f"✅ Health endpoint working")
                    print(f"   Status: {status}")
                    
                    self.results["health_check"] = {
                        "success": True,
                        "status": status,
                        "health_file": str(health_file)
                    }
                else:
                    print(f"❌ Health endpoint returned status {resp.status}")
                    self.results["health_check"] = {
                        "success": False,
                        "error": f"HTTP {resp.status}"
                    }

    async def test_metrics_summary(self):
        """Test 4: Metrics Summary."""
        print("\nTest 4: Metrics Summary")
        print("-----------------------")
        
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.base_url}/api/v1/metrics/summary",
                timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                if resp.status == 200:
                    summary_data = await resp.json()
                    
                    # Save to file
                    summary_file = self.output_dir / "metrics_summary_output.txt"
                    with open(summary_file, 'w', encoding='utf-8') as f:
                        json.dump(summary_data, f, indent=2)
                    
                    print("✅ Metrics summary endpoint working")
                    
                    self.results["metrics_summary"] = {
                        "success": True,
                        "summary_file": str(summary_file)
                    }
                else:
                    print(f"❌ Metrics summary endpoint returned status {resp.status}")
                    self.results["metrics_summary"] = {
                        "success": False,
                        "error": f"HTTP {resp.status}"
                    }

    async def test_dashboard(self):
        """Test 5: Dashboard."""
        print("\nTest 5: Dashboard")
        print("-----------------")
        
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.base_url}/api/v1/dashboard",
                timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                if resp.status == 200:
                    dashboard_data = await resp.json()
                    
                    # Save to file
                    dashboard_file = self.output_dir / "dashboard_output.txt"
                    with open(dashboard_file, 'w', encoding='utf-8') as f:
                        json.dump(dashboard_data, f, indent=2)
                    
                    print("✅ Dashboard endpoint working")
                    
                    self.results["dashboard"] = {
                        "success": True,
                        "dashboard_file": str(dashboard_file)
                    }
                else:
                    print(f"❌ Dashboard endpoint returned status {resp.status}")
                    self.results["dashboard"] = {
                        "success": False,
                        "error": f"HTTP {resp.status}"
                    }

    async def run_all_tests(self):
        """Führt alle Monitoring-Tests aus."""
        print("\n" + "=" * 80)
        print("📊 MONITORING TEST SUITE")
        print("=" * 80)
        print(f"Base URL: {self.base_url}")
        print(f"Output Dir: {self.output_dir}")
        print("=" * 80)
        
        await self.test_metrics_collection()
        await self.test_alert_triggering()
        await self.test_health_check()
        await self.test_metrics_summary()
        await self.test_dashboard()
        
        # Print summary
        print("\n" + "=" * 80)
        print("📊 TEST SUMMARY")
        print("=" * 80)
        
        passed = sum(1 for r in self.results.values() if r.get("success", False))
        total = len(self.results)
        
        for test_name, result in self.results.items():
            status = "✅ PASSED" if result.get("success", False) else "❌ FAILED"
            print(f"{status}: {test_name}")
        
        print(f"\nSummary: {passed}/{total} tests passed")
        print(f"All test outputs saved to: {self.output_dir}")
        print("=" * 80 + "\n")
        
        # Save results
        results_file = self.output_dir / f"monitoring_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump({
                "timestamp": datetime.utcnow().isoformat(),
                "base_url": self.base_url,
                "results": self.results,
                "summary": {
                    "passed": passed,
                    "total": total
                }
            }, f, indent=2)
        
        print(f"📄 Results saved to: {results_file}")


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Monitoring Test for Orchestrator Service")
    parser.add_argument(
        "--url",
        type=str,
        default="http://localhost:8001",
        help="Base URL of orchestrator service (default: http://localhost:8001)"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="test_results",
        help="Output directory for test results (default: test_results)"
    )
    
    args = parser.parse_args()
    
    tester = MonitoringTester(base_url=args.url, output_dir=args.output_dir)
    await tester.run_all_tests()


if __name__ == "__main__":
    asyncio.run(main())

