#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Master Test Runner - Führt alle wichtigen Tests aus
====================================================

Führt alle wichtigen Test-Suites nacheinander aus:
1. Quick Bypass Check (schneller Test)
2. Erweiterte Bypass Tests (mathematisch + multilingual)
3. ML Direct Tests (spezifische Bypass-Fälle)
4. DeepSeek Red Team Test (optional)
5. Service Integration Tests
"""

import subprocess
import sys
import time
import argparse
import io
import os
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

# Fix für Windows Unicode-Encoding
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Farben für Output (optional)
try:
    from colorama import init, Fore, Style
    init()
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
    # Fallback ohne Farben
    class Fore:
        GREEN = ""
        RED = ""
        YELLOW = ""
        BLUE = ""
        CYAN = ""
        RESET = ""
    class Style:
        RESET_ALL = ""
        BRIGHT = ""

def print_header(text: str):
    """Druckt einen formatierten Header."""
    print(f"\n{'='*80}")
    print(f"{Fore.CYAN}{Style.BRIGHT}{text}{Style.RESET_ALL}")
    print(f"{'='*80}\n")

def print_success(text: str):
    """Druckt Erfolgsmeldung."""
    print(f"{Fore.GREEN}[OK] {text}{Fore.RESET}")

def print_error(text: str):
    """Druckt Fehlermeldung."""
    print(f"{Fore.RED}[FAIL] {text}{Fore.RESET}")

def print_warning(text: str):
    """Druckt Warnung."""
    print(f"{Fore.YELLOW}[WARN] {text}{Fore.RESET}")

def print_info(text: str):
    """Druckt Info."""
    print(f"{Fore.BLUE}[INFO] {text}{Fore.RESET}")

def run_test(
    script_path: str,
    args: List[str] = None,
    description: str = None,
    required: bool = True,
    timeout: int = 300
) -> Dict[str, Any]:
    """Führt ein Test-Skript aus."""
    if args is None:
        args = []
    
    script_name = Path(script_path).name
    if description:
        print_header(f"TEST: {description}")
    else:
        print_header(f"TEST: {script_name}")
    
    print_info(f"Running: python {script_path} {' '.join(args)}")
    
    start_time = time.time()
    
    try:
        # Setze UTF-8 Encoding für Subprocess auf Windows
        env = os.environ.copy()
        if sys.platform == 'win32':
            env['PYTHONIOENCODING'] = 'utf-8'
        
        result = subprocess.run(
            [sys.executable, script_path] + args,
            cwd=Path(__file__).parent.parent,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=timeout,
            env=env
        )
        
        duration = time.time() - start_time
        
        # Output anzeigen
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        
        if result.returncode == 0:
            print_success(f"{script_name} completed successfully ({duration:.2f}s)")
            return {
                "success": True,
                "returncode": 0,
                "duration": duration,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
        else:
            if required:
                print_error(f"{script_name} failed with return code {result.returncode}")
            else:
                print_warning(f"{script_name} failed (non-critical)")
            return {
                "success": False,
                "returncode": result.returncode,
                "duration": duration,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
    
    except subprocess.TimeoutExpired:
        print_error(f"{script_name} timed out after {timeout}s")
        return {
            "success": False,
            "returncode": -1,
            "duration": timeout,
            "error": "timeout"
        }
    except Exception as e:
        print_error(f"{script_name} crashed: {str(e)}")
        return {
            "success": False,
            "returncode": -1,
            "error": str(e)
        }

def check_service_running() -> bool:
    """Prüft ob der Code Intent Service läuft."""
    try:
        import requests
        response = requests.get("http://localhost:8001/health", timeout=2)
        return response.status_code == 200
    except:
        return False

def main():
    parser = argparse.ArgumentParser(description="Run all firewall tests")
    parser.add_argument("--skip-quick", action="store_true", help="Skip quick bypass check")
    parser.add_argument("--skip-advanced", action="store_true", help="Skip advanced bypass tests")
    parser.add_argument("--skip-ml-direct", action="store_true", help="Skip ML direct tests")
    parser.add_argument("--skip-deepseek", action="store_true", help="Skip DeepSeek red team test")
    parser.add_argument("--skip-service", action="store_true", help="Skip service integration tests")
    parser.add_argument("--skip-benign", action="store_true", help="Skip extreme benign test")
    parser.add_argument("--deepseek-rounds", type=int, default=3, help="DeepSeek test rounds")
    parser.add_argument("--deepseek-attacks", type=int, default=10, help="Attacks per round for DeepSeek")
    parser.add_argument("--math-samples", type=int, default=20, help="Math samples for quick check")
    parser.add_argument("--multilingual-samples", type=int, default=20, help="Multilingual samples for quick check")
    parser.add_argument("--benign-samples", type=int, default=1000, help="Number of benign samples (default: 1000)")
    parser.add_argument("--check-service", action="store_true", help="Check if service is running before tests")
    parser.add_argument("--stop-on-failure", action="store_true", help="Stop on first test failure")
    
    args = parser.parse_args()
    
    print_header("FIREWALL TEST SUITE - MASTER RUNNER")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Python: {sys.version}")
    print()
    
    # Service-Check
    if args.check_service:
        print_info("Checking Code Intent Service status...")
        if not check_service_running():
            print_error("Code Intent Service is not running on port 8001!")
            print_warning("Please start the service:")
            print("  cd detectors/code_intent_service")
            print("  python -m uvicorn main:app --host 0.0.0.0 --port 8001")
            if args.stop_on_failure:
                sys.exit(1)
        else:
            print_success("Service is running")
    
    results = []
    total_start = time.time()
    
    # 1. Quick Bypass Check (schnell)
    if not args.skip_quick:
        result = run_test(
            "scripts/quick_bypass_check.py",
            [
                "--math-samples", str(args.math_samples),
                "--multilingual-samples", str(args.multilingual_samples)
            ],
            description="Quick Bypass Check (Daily Test)",
            required=True
        )
        results.append(("Quick Bypass Check", result))
        if not result["success"] and args.stop_on_failure:
            print_error("Stopping due to failure in Quick Bypass Check")
            sys.exit(1)
    
    # 2. Erweiterte Bypass Tests (mathematisch + multilingual)
    if not args.skip_advanced:
        # Prüfe ob Test-Suiten existieren
        test_suites_dir = Path("test_suites")
        math_suites = list(test_suites_dir.glob("math_attacks_*.json"))
        multilingual_suites = list(test_suites_dir.glob("multilingual_attacks_*.json"))
        
        if not math_suites and not multilingual_suites:
            print_warning("No test suites found. Generating them first...")
            # Generiere Test-Suiten
            run_test("scripts/generate_math_attacks.py", ["--n", "50"], required=False)
            run_test("scripts/generate_multilingual_attacks.py", ["--n", "50"], required=False)
        
        result = run_test(
            "scripts/run_advanced_bypass_tests.py",
            ["--max-workers", "10"],
            description="Advanced Bypass Tests (Mathematical + Multilingual)",
            required=True,
            timeout=600
        )
        results.append(("Advanced Bypass Tests", result))
        if not result["success"] and args.stop_on_failure:
            print_error("Stopping due to failure in Advanced Bypass Tests")
            sys.exit(1)
    
    # 3. ML Direct Tests (spezifische Bypass-Fälle)
    if not args.skip_ml_direct:
        result = run_test(
            "scripts/test_ml_direct.py",
            ["--attack", "mathematical"],
            description="ML Direct Test (Mathematical Bypass)",
            required=True
        )
        results.append(("ML Direct Test (Mathematical)", result))
        
        result2 = run_test(
            "scripts/test_ml_direct.py",
            ["--attack", "multilingual"],
            description="ML Direct Test (Multilingual Bypass)",
            required=True
        )
        results.append(("ML Direct Test (Multilingual)", result2))
        
        if args.stop_on_failure:
            for name, res in [("ML Direct Test (Mathematical)", result), ("ML Direct Test (Multilingual)", result2)]:
                if not res["success"]:
                    print_error(f"Stopping due to failure in {name}")
                    sys.exit(1)
    
    # 4. DeepSeek Red Team Test (optional, kann lange dauern)
    if not args.skip_deepseek:
        result = run_test(
            "scripts/redteam_deepseek_firewall.py",
            [
                "--focus", "mathematical",
                "--rounds", str(args.deepseek_rounds),
                "--attacks-per-round", str(args.deepseek_attacks)
            ],
            description=f"DeepSeek Red Team Test ({args.deepseek_rounds} rounds, {args.deepseek_attacks} attacks/round)",
            required=False,
            timeout=1800  # 30 Minuten
        )
        results.append(("DeepSeek Red Team Test", result))
    
    # 5. Extreme Benign Test (False Positive Rate)
    if not args.skip_benign:
        result = run_test(
            "scripts/extreme_benign_test.py",
            [
                "--samples", str(args.benign_samples),
                "--max-workers", "20"
            ],
            description=f"Extreme Benign Test ({args.benign_samples} samples, FPR measurement)",
            required=False,
            timeout=1800  # 30 Minuten für 1000+ Samples
        )
        results.append(("Extreme Benign Test", result))
    
    # 6. Service Integration Tests
    if not args.skip_service:
        result = run_test(
            "scripts/test_service_integration.py",
            description="Service Integration Tests",
            required=False
        )
        results.append(("Service Integration Tests", result))
    
    # Zusammenfassung
    total_duration = time.time() - total_start
    
    print_header("TEST SUMMARY")
    
    passed = sum(1 for _, r in results if r.get("success", False))
    failed = len(results) - passed
    
    print(f"\nTotal Tests: {len(results)}")
    print_success(f"Passed: {passed}")
    if failed > 0:
        print_error(f"Failed: {failed}")
    print(f"Total Duration: {total_duration:.2f}s")
    print()
    
    # Detaillierte Ergebnisse
    print("Detailed Results:")
    print("-" * 80)
    for name, result in results:
        status = "[PASS]" if result.get("success", False) else "[FAIL]"
        duration = result.get("duration", 0)
        print(f"  {status} {name:50s} ({duration:.2f}s)")
        if not result.get("success", False) and result.get("stderr"):
            print(f"    Error: {result['stderr'][:200]}...")
    
    print()
    
    # Exit Code
    if failed > 0:
        print_error("Some tests failed!")
        sys.exit(1)
    else:
        print_success("All tests passed!")
        sys.exit(0)

if __name__ == "__main__":
    main()
