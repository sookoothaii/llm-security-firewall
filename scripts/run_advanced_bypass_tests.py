#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kombinierter Test-Läufer für erweiterte Bypass-Tests
====================================================

Testet mathematische und multilinguale Angriffe gegen den Firewall
mit paralleler Ausführung und detaillierter Analyse.
"""

import requests
import json
import time
import argparse
import glob
import sys
import io
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any

# Fix für Windows Unicode-Encoding
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')


class AdvancedBypassTester:
    def __init__(self, service_url: str = "http://localhost:8001/v1/detect"):
        self.service_url = service_url
        self.results = []
        self.stats = {
            "total": 0,
            "blocked": 0,
            "bypassed": 0,
            "false_positives": 0,
            "false_negatives": 0,
            "by_category": {}
        }
    
    def test_single_prompt(self, test_case: Dict[str, Any]) -> Dict[str, Any]:
        """Testet einen einzelnen Prompt"""
        payload_text = test_case.get("payload", "")
        
        if not payload_text:
            return None
        
        try:
            start_time = time.time()
            response = requests.post(
                self.service_url,
                json={"text": payload_text, "context": {}},
                timeout=10
            )
            latency = time.time() - start_time
            
            if response.status_code == 200:
                result = response.json()
                blocked = result.get("risk_score", 0.0) > 0.5
                risk_score = result.get("risk_score", 0.0)
                rule_score = result.get("metadata", {}).get("rule_score", 0.0)
                ml_score = result.get("metadata", {}).get("quantum_score") or result.get("metadata", {}).get("ml_score")
                matched_patterns = result.get("matched_patterns", [])
                
                # Auswertung
                expected_block = test_case.get("expected_block", True)
                is_bypass = (not blocked) and expected_block
                is_false_positive = blocked and (not expected_block)
                
                test_result = {
                    "id": test_case.get("id", "unknown"),
                    "payload": payload_text[:200] + "..." if len(payload_text) > 200 else payload_text,
                    "full_payload": payload_text,
                    "technique": test_case.get("technique", "unknown"),
                    "category": test_case.get("category", "unknown"),
                    "subcategory": test_case.get("subcategory", ""),
                    "expected_block": expected_block,
                    "actual_block": blocked,
                    "risk_score": risk_score,
                    "rule_score": rule_score,
                    "ml_score": ml_score,
                    "matched_patterns": matched_patterns,
                    "latency_ms": round(latency * 1000, 2),
                    "is_bypass": is_bypass,
                    "is_false_positive": is_false_positive,
                    "timestamp": datetime.now().isoformat()
                }
                
                # Update Stats
                self.stats["total"] += 1
                if blocked:
                    self.stats["blocked"] += 1
                else:
                    self.stats["bypassed"] += 1
                
                category = test_case.get("category", "unknown")
                if category not in self.stats["by_category"]:
                    self.stats["by_category"][category] = {"blocked": 0, "bypassed": 0}
                
                if blocked:
                    self.stats["by_category"][category]["blocked"] += 1
                else:
                    self.stats["by_category"][category]["bypassed"] += 1
                
                if is_bypass:
                    self.stats["false_negatives"] += 1
                elif is_false_positive:
                    self.stats["false_positives"] += 1
                
                return test_result
            else:
                print(f"[WARN] HTTP Error {response.status_code} for {test_case.get('id', 'unknown')}")
                return None
                
        except requests.exceptions.ConnectionError:
            print(f"[FAIL] Connection failed - Service not running at {self.service_url}")
            return None
        except Exception as e:
            print(f"[FAIL] Error testing {test_case.get('id', 'unknown')}: {str(e)}")
            return None
    
    def run_test_suite(self, test_suite_file: str, max_workers: int = 10, verbose: bool = False) -> List[Dict[str, Any]]:
        """Führt einen gesamten Test-Suite durch"""
        print(f"\n{'='*80}")
        print(f"Testing: {test_suite_file}")
        print(f"{'='*80}")
        
        suite_path = Path(test_suite_file)
        if not suite_path.exists():
            print(f"[FAIL] File not found: {test_suite_file}")
            return []
        
        with open(suite_path, 'r', encoding='utf-8') as f:
            test_cases = json.load(f)
        
        print(f"Running {len(test_cases)} test cases...")
        
        # Parallele Ausführung
        bypasses_found = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.test_single_prompt, tc): tc for tc in test_cases}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.results.append(result)
                    
                    if result['is_bypass']:
                        bypasses_found.append(result)
                        if verbose:
                            print(f"[FAIL] BYPASS: {result['id']} - Score: {result['risk_score']:.3f} (Rule: {result['rule_score']:.3f}, ML: {result['ml_score'] if result['ml_score'] else 'None'})")
                    elif result['is_false_positive']:
                        if verbose:
                            print(f"[WARN] False Positive: {result['id']}")
                    elif verbose:
                        print(f"[OK] {result['id']} - Score: {result['risk_score']:.3f}")
        
        # Zusammenfassung
        print(f"\n{'='*80}")
        print("TEST SUMMARY")
        print(f"{'='*80}")
        suite_total = len(test_cases)
        suite_blocked = sum(1 for r in self.results if r.get('actual_block') and r.get('id', '').startswith(Path(test_suite_file).stem.split('_')[0]))
        suite_bypassed = sum(1 for r in self.results if not r.get('actual_block') and r.get('id', '').startswith(Path(test_suite_file).stem.split('_')[0]))
        
        print(f"Total tests: {suite_total}")
        if suite_total > 0:
            print(f"Blocked: {suite_blocked} ({suite_blocked/suite_total*100:.1f}%)")
            print(f"Bypassed: {suite_bypassed} ({suite_bypassed/suite_total*100:.1f}%)")
            print(f"False Negatives: {len(bypasses_found)}")
        
        # Bypasses auflisten
        if bypasses_found:
            print(f"\n[FAIL] ACTIVE BYPASSES FOUND ({len(bypasses_found)}):")
            for bypass in bypasses_found[:10]:  # Erste 10 zeigen
                print(f"  - {bypass['id']}: {bypass['technique']}")
                print(f"    Score: {bypass['risk_score']:.3f} (Rule: {bypass['rule_score']:.3f}, ML: {bypass['ml_score'] if bypass['ml_score'] else 'None'})")
                print(f"    Sample: {bypass['payload']}")
        
        return bypasses_found
    
    def save_results(self, output_file: str = None) -> Path:
        """Speichert Ergebnisse"""
        # Erstelle output directory
        output_dir = Path("test_results")
        output_dir.mkdir(exist_ok=True)
        
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = output_dir / f"advanced_test_{timestamp}.json"
        else:
            output_file = Path(output_file)
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "stats": self.stats,
            "bypasses": [r for r in self.results if r.get('is_bypass')],
            "results": self.results
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return output_file


def main():
    parser = argparse.ArgumentParser(description="Run advanced bypass tests")
    parser.add_argument("--input", type=str, nargs="+", help="Input JSON test suite files")
    parser.add_argument("--pattern", type=str, help="Glob pattern for test suite files")
    parser.add_argument("--service-url", type=str, default="http://localhost:8001/v1/detect", help="Firewall service URL")
    parser.add_argument("--output", type=str, default=None, help="Output JSON file")
    parser.add_argument("--max-workers", type=int, default=10, help="Max parallel workers")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Finde Test-Suiten
    test_suites = []
    
    if args.input:
        test_suites = args.input
    elif args.pattern:
        test_suites = glob.glob(args.pattern)
    else:
        # Standard: Suche nach generierten Test-Suiten
        test_suites = list(glob.glob("test_suites/math_attacks_*.json")) + \
                     list(glob.glob("test_suites/multilingual_attacks_*.json"))
    
    if not test_suites:
        print("[FAIL] No test suites found!")
        print("   Generate test suites first:")
        print("   python scripts/generate_math_attacks.py")
        print("   python scripts/generate_multilingual_attacks.py")
        return
    
    print("="*80)
    print("ADVANCED BYPASS TEST RUNNER")
    print("="*80)
    print(f"Test Suites: {len(test_suites)}")
    print(f"Service URL: {args.service_url}")
    print(f"Max Workers: {args.max_workers}")
    print("="*80)
    
    tester = AdvancedBypassTester(service_url=args.service_url)
    
    all_bypasses = []
    
    for suite in test_suites:
        bypasses = tester.run_test_suite(suite, max_workers=args.max_workers, verbose=args.verbose)
        all_bypasses.extend(bypasses)
        time.sleep(0.5)  # Kurze Pause zwischen Suiten
    
    # Gesamtbericht
    print("\n" + "="*80)
    print("FINAL SUMMARY")
    print("="*80)
    print(f"Total Tests: {tester.stats['total']}")
    if tester.stats['total'] > 0:
        print(f"Blocked: {tester.stats['blocked']} ({tester.stats['blocked']/tester.stats['total']*100:.1f}%)")
        print(f"Bypassed: {tester.stats['bypassed']} ({tester.stats['bypassed']/tester.stats['total']*100:.1f}%)")
        print(f"False Negatives: {tester.stats['false_negatives']}")
        print(f"False Positives: {tester.stats['false_positives']}")
    
    print("\nBy Category:")
    for category, stats in tester.stats["by_category"].items():
        total = stats["blocked"] + stats["bypassed"]
        if total > 0:
            print(f"  {category}: {stats['blocked']}/{total} blocked ({stats['blocked']/total*100:.1f}%)")
    
    if all_bypasses:
        print(f"\n{'!'*80}")
        print(f"[WARN] CRITICAL: {len(all_bypasses)} TOTAL BYPASSES FOUND")
        print(f"{'!'*80}")
        
        # Bypasses nach Typ gruppieren
        bypass_types = {}
        for bypass in all_bypasses:
            btype = bypass['technique']
            bypass_types.setdefault(btype, []).append(bypass)
        
        print("\nBypasses by Technique:")
        for btype, cases in bypass_types.items():
            print(f"\n  {btype} ({len(cases)} cases):")
            for case in cases[:3]:  # Erste 3 zeigen
                print(f"    - {case['id']}: Score {case['risk_score']:.3f}")
    else:
        print(f"\n[SUCCESS] ALL TESTS PASSED! No bypasses found.")
    
    # Speichere Ergebnisse
    output_path = tester.save_results(args.output)
    print(f"\n[OK] Results saved to: {output_path}")


if __name__ == "__main__":
    main()
