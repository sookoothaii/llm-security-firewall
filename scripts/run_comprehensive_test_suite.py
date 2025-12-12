#!/usr/bin/env python3
"""
Comprehensive Test Suite Runner
================================

Führt alle Test-Phasen automatisch durch:
- Phase 1: Basis-Validierung
- Phase 2: Hardcore Red Team Tests
- Phase 3: Adversarial Red-Teaming
- Phase 4: False Positive Rate Validation
- Phase 5: Performance & Stress Testing

Creator: HAK_GAL Security Team
Date: 2025-12-10
"""

import subprocess
import sys
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

# Project root
PROJECT_ROOT = Path(__file__).parent.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
RESULTS_DIR = PROJECT_ROOT / "test_results"
RESULTS_DIR.mkdir(exist_ok=True)

# Colors for output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_header(text: str):
    """Print formatted header."""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*80}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text.center(80)}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*80}{Colors.RESET}\n")

def print_success(text: str):
    """Print success message."""
    print(f"{Colors.GREEN}[OK] {text}{Colors.RESET}")

def print_error(text: str):
    """Print error message."""
    print(f"{Colors.RED}[ERROR] {text}{Colors.RESET}")

def print_warning(text: str):
    """Print warning message."""
    print(f"{Colors.YELLOW}[WARN] {text}{Colors.RESET}")

def print_info(text: str):
    """Print info message."""
    print(f"{Colors.BLUE}[INFO] {text}{Colors.RESET}")

def run_script(script_path: Path, description: str, timeout: Optional[int] = None) -> Dict:
    """Run a test script and return results."""
    print_info(f"Running: {description}")
    print(f"  Script: {script_path.name}")
    
    start_time = time.time()
    
    try:
        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        duration = time.time() - start_time
        
        return {
            "success": result.returncode == 0,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "duration": duration,
            "description": description,
            "script": script_path.name
        }
    except subprocess.TimeoutExpired:
        print_error(f"Timeout after {timeout}s: {description}")
        return {
            "success": False,
            "returncode": -1,
            "stdout": "",
            "stderr": f"Timeout after {timeout}s",
            "duration": timeout,
            "description": description,
            "script": script_path.name,
            "error": "Timeout"
        }
    except Exception as e:
        print_error(f"Error running {description}: {e}")
        return {
            "success": False,
            "returncode": -1,
            "stdout": "",
            "stderr": str(e),
            "duration": 0,
            "description": description,
            "script": script_path.name,
            "error": str(e)
        }

def check_service_availability(port: int = 8000) -> bool:
    """Check if service is running on port."""
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('localhost', port))
        sock.close()
        return result == 0
    except:
        return False

def phase1_basic_validation() -> Dict:
    """Phase 1: Basic Validation Tests."""
    print_header("PHASE 1: BASIS-VALIDIERUNG")
    
    results = {
        "phase": "Phase 1: Basic Validation",
        "tests": [],
        "summary": {"total": 0, "passed": 0, "failed": 0}
    }
    
    # Test 1.1: Poetry Obfuscation
    script = SCRIPTS_DIR / "test_poetry_obfuscation.py"
    if script.exists():
        result = run_script(script, "Poetry Obfuscation Test", timeout=300)
        results["tests"].append(result)
        results["summary"]["total"] += 1
        if result["success"]:
            results["summary"]["passed"] += 1
            print_success(f"Poetry Obfuscation: PASSED ({result['duration']:.1f}s)")
        else:
            results["summary"]["failed"] += 1
            print_error(f"Poetry Obfuscation: FAILED")
    else:
        print_warning(f"Script not found: {script}")
    
    # Test 1.2: Direct Bypass Validation
    script = SCRIPTS_DIR / "test_4_bypasses_direct.py"
    if script.exists():
        result = run_script(script, "Direct Bypass Validation", timeout=60)
        results["tests"].append(result)
        results["summary"]["total"] += 1
        if result["success"]:
            results["summary"]["passed"] += 1
            print_success(f"Direct Bypass: PASSED ({result['duration']:.1f}s)")
        else:
            results["summary"]["failed"] += 1
            print_error(f"Direct Bypass: FAILED")
    else:
        print_warning(f"Script not found: {script}")
    
    return results

def phase2_hardcore_tests() -> Dict:
    """Phase 2: Hardcore Red Team Tests."""
    print_header("PHASE 2: HARDCORE RED TEAM TESTS")
    
    results = {
        "phase": "Phase 2: Hardcore Red Team Tests",
        "tests": [],
        "summary": {"total": 0, "passed": 0, "failed": 0}
    }
    
    # Check if services are running
    if not check_service_availability(8000):
        print_warning("Service on port 8000 not available. Starting services...")
        print_info("Please start the Code Intent Detection service manually:")
        print_info("  cd detectors/code_intent_service")
        print_info("  python -m uvicorn api.main:app --reload --port 8000")
        return results
    
    test_scripts = [
        ("hardcore_red_team_assault.py", "Hardcore Red Team Assault", 3600),
        ("adaptive_bypass_assault.py", "Adaptive Bypass Assault", 600),
        ("advanced_bypass_techniques.py", "Advanced Bypass Techniques", 600),
        ("ultimate_bypass_challenge.py", "Ultimate Bypass Challenge", 600),
        ("multi_turn_bypass_assault.py", "Multi-Turn Bypass Assault", 600),
    ]
    
    for script_name, description, timeout in test_scripts:
        script = SCRIPTS_DIR / script_name
        if script.exists():
            result = run_script(script, description, timeout=timeout)
            results["tests"].append(result)
            results["summary"]["total"] += 1
            if result["success"]:
                results["summary"]["passed"] += 1
                print_success(f"{description}: PASSED ({result['duration']:.1f}s)")
            else:
                results["summary"]["failed"] += 1
                print_error(f"{description}: FAILED")
        else:
            print_warning(f"Script not found: {script}")
    
    return results

def phase3_adversarial() -> Dict:
    """Phase 3: Adversarial Red-Teaming."""
    print_header("PHASE 3: ADVERSARIAL RED-TEAMING")
    
    results = {
        "phase": "Phase 3: Adversarial Red-Teaming",
        "tests": [],
        "summary": {"total": 0, "passed": 0, "failed": 0}
    }
    
    # Test 3.1: Adversarial Red-Teaming
    script = SCRIPTS_DIR / "adversarial_red_teaming.py"
    if script.exists():
        result = run_script(script, "Adversarial Red-Teaming", timeout=7200)
        results["tests"].append(result)
        results["summary"]["total"] += 1
        if result["success"]:
            results["summary"]["passed"] += 1
            print_success(f"Adversarial Red-Teaming: PASSED ({result['duration']:.1f}s)")
        else:
            results["summary"]["failed"] += 1
            print_error(f"Adversarial Red-Teaming: FAILED")
    else:
        print_warning(f"Script not found: {script}")
    
    return results

def phase4_false_positives() -> Dict:
    """Phase 4: False Positive Rate Validation."""
    print_header("PHASE 4: FALSE POSITIVE RATE VALIDATION")
    
    results = {
        "phase": "Phase 4: False Positive Rate Validation",
        "tests": [],
        "summary": {"total": 0, "passed": 0, "failed": 0}
    }
    
    # Test 4.1: Benign Detection
    script = SCRIPTS_DIR / "test_benign_detection.py"
    if not script.exists():
        script = SCRIPTS_DIR / "test_benign_function.py"
    
    if script.exists():
        result = run_script(script, "Benign Detection Test", timeout=1800)
        results["tests"].append(result)
        results["summary"]["total"] += 1
        if result["success"]:
            results["summary"]["passed"] += 1
            print_success(f"Benign Detection: PASSED ({result['duration']:.1f}s)")
        else:
            results["summary"]["failed"] += 1
            print_error(f"Benign Detection: FAILED")
    else:
        print_warning("Benign detection script not found")
    
    return results

def phase5_performance() -> Dict:
    """Phase 5: Performance & Stress Testing."""
    print_header("PHASE 5: PERFORMANCE & STRESS TESTING")
    
    results = {
        "phase": "Phase 5: Performance & Stress Testing",
        "tests": [],
        "summary": {"total": 0, "passed": 0, "failed": 0}
    }
    
    # Test 5.1: Service Direct Test (if available)
    script = SCRIPTS_DIR / "test_service_direct.py"
    if script.exists():
        result = run_script(script, "Service Performance Test", timeout=300)
        results["tests"].append(result)
        results["summary"]["total"] += 1
        if result["success"]:
            results["summary"]["passed"] += 1
            print_success(f"Performance Test: PASSED ({result['duration']:.1f}s)")
        else:
            results["summary"]["failed"] += 1
            print_error(f"Performance Test: FAILED")
    else:
        print_warning("Performance test script not found")
    
    return results

def generate_report(all_results: List[Dict]) -> Dict:
    """Generate comprehensive test report."""
    total_tests = sum(r["summary"]["total"] for r in all_results)
    total_passed = sum(r["summary"]["passed"] for r in all_results)
    total_failed = sum(r["summary"]["failed"] for r in all_results)
    
    total_duration = sum(
        sum(t.get("duration", 0) for t in r["tests"])
        for r in all_results
    )
    
    report = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_phases": len(all_results),
            "total_tests": total_tests,
            "passed": total_passed,
            "failed": total_failed,
            "success_rate": (total_passed / total_tests * 100) if total_tests > 0 else 0,
            "total_duration_seconds": total_duration
        },
        "phases": all_results,
        "status": "PASSED" if total_failed == 0 else "FAILED"
    }
    
    return report

def print_summary(report: Dict):
    """Print test summary."""
    print_header("TEST SUMMARY")
    
    summary = report["summary"]
    print(f"Total Phases: {summary['total_phases']}")
    print(f"Total Tests: {summary['total_tests']}")
    print(f"Passed: {Colors.GREEN}{summary['passed']}{Colors.RESET}")
    print(f"Failed: {Colors.RED}{summary['failed']}{Colors.RESET}")
    print(f"Success Rate: {summary['success_rate']:.1f}%")
    print(f"Total Duration: {summary['total_duration_seconds']:.1f}s ({summary['total_duration_seconds']/60:.1f} minutes)")
    
    print(f"\n{Colors.BOLD}Status: {Colors.RESET}", end="")
    if report["status"] == "PASSED":
        print_success(report["status"])
    else:
        print_error(report["status"])
    
    print("\nPhase Details:")
    for phase in report["phases"]:
        phase_summary = phase["summary"]
        status = "[OK]" if phase_summary["failed"] == 0 else "[ERROR]"
        print(f"  {status} {phase['phase']}: {phase_summary['passed']}/{phase_summary['total']}")

def main():
    """Main test runner."""
    print_header("COMPREHENSIVE TEST SUITE")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Check if services are available
    if not check_service_availability(8000):
        print_warning("Service on port 8000 not detected!")
        print_info("Some tests require running services.")
        print_info("Start the Code Intent Detection service with:")
        print_info("  cd detectors/code_intent_service")
        print_info("  python -m uvicorn api.main:app --reload --port 8000")
        response = input("\nContinue anyway? (y/n): ")
        if response.lower() != 'y':
            print("Exiting...")
            return
    
    all_results = []
    
    try:
        # Phase 1: Basic Validation
        results = phase1_basic_validation()
        all_results.append(results)
        
        # Phase 2: Hardcore Tests
        results = phase2_hardcore_tests()
        all_results.append(results)
        
        # Phase 3: Adversarial
        results = phase3_adversarial()
        all_results.append(results)
        
        # Phase 4: False Positives
        results = phase4_false_positives()
        all_results.append(results)
        
        # Phase 5: Performance
        results = phase5_performance()
        all_results.append(results)
        
    except KeyboardInterrupt:
        print("\n\nTest suite interrupted by user.")
        print("Generating partial report...")
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
    
    # Generate report
    report = generate_report(all_results)
    
    # Print summary
    print_summary(report)
    
    # Save report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = RESULTS_DIR / f"comprehensive_test_report_{timestamp}.json"
    
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    print(f"\n{Colors.BLUE}Report saved to: {report_file}{Colors.RESET}")
    
    # Exit with appropriate code
    sys.exit(0 if report["status"] == "PASSED" else 1)

if __name__ == "__main__":
    main()

