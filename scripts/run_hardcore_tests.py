#!/usr/bin/env python3
"""
Quick-Start Script für HARDCORE Tests
======================================

Führt beide Test-Suites nacheinander aus:
1. Hardcore Red Team Assault
2. Performance Stress Test

Usage:
    python scripts/run_hardcore_tests.py
"""

import sys
import subprocess
import time
from pathlib import Path

# Color codes
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'


def print_header(text: str):
    """Print a formatted header."""
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'=' * 80}{Colors.END}")
    print(f"{Colors.CYAN}{Colors.BOLD}{text:^80}{Colors.END}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'=' * 80}{Colors.END}\n")


def run_command(cmd: list, description: str):
    """Run a command and handle errors."""
    print(f"{Colors.YELLOW}▶ {description}...{Colors.END}")
    print(f"{Colors.BLUE}Command: {' '.join(cmd)}{Colors.END}\n")
    
    start_time = time.time()
    
    try:
        result = subprocess.run(
            cmd,
            check=False,
            capture_output=False,
            text=True,
        )
        
        elapsed = time.time() - start_time
        
        if result.returncode == 0:
            print(f"\n{Colors.GREEN}✅ {description} completed in {elapsed:.2f}s{Colors.END}\n")
            return True
        else:
            print(f"\n{Colors.RED}❌ {description} failed (exit code: {result.returncode}){Colors.END}\n")
            return False
            
    except Exception as e:
        print(f"\n{Colors.RED}❌ Error running {description}: {e}{Colors.END}\n")
        return False


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Run all Hardcore Tests")
    parser.add_argument("--workers", type=int, help="Number of parallel workers")
    parser.add_argument("--no-gpu", action="store_true", help="Disable GPU acceleration")
    parser.add_argument("--skip-assault", action="store_true", help="Skip Red Team Assault")
    parser.add_argument("--skip-stress", action="store_true", help="Skip Stress Test")
    
    args = parser.parse_args()
    
    # Script directory
    script_dir = Path(__file__).parent
    
    print_header("HARDCORE RED TEAM TESTS - ZERO MERCY EDITION")
    
    print(f"{Colors.CYAN}Starting comprehensive security testing...{Colors.END}\n")
    
    success_count = 0
    total_tests = 0
    
    # 1. Hardcore Red Team Assault
    if not args.skip_assault:
        total_tests += 1
        cmd = [sys.executable, str(script_dir / "hardcore_red_team_assault.py")]
        
        if args.workers:
            cmd.extend(["--workers", str(args.workers)])
        if args.no_gpu:
            cmd.append("--no-gpu")
        
        if run_command(cmd, "Hardcore Red Team Assault"):
            success_count += 1
        else:
            print(f"{Colors.YELLOW}⚠️  Continuing despite failure...{Colors.END}\n")
    
    # 2. Performance Stress Test
    if not args.skip_stress:
        total_tests += 1
        cmd = [sys.executable, str(script_dir / "performance_stress_test.py")]
        
        if args.workers:
            cmd.extend(["--workers", str(args.workers)])
        
        if run_command(cmd, "Performance Stress Test"):
            success_count += 1
        else:
            print(f"{Colors.YELLOW}⚠️  Continuing despite failure...{Colors.END}\n")
    
    # Final summary
    print_header("TEST SUMMARY")
    
    print(f"{Colors.CYAN}Tests Run: {total_tests}{Colors.END}")
    print(f"{Colors.GREEN if success_count == total_tests else Colors.YELLOW}Tests Passed: {success_count}{Colors.END}")
    
    if success_count == total_tests:
        print(f"\n{Colors.GREEN}{Colors.BOLD}✅ All tests completed successfully!{Colors.END}\n")
    else:
        print(f"\n{Colors.YELLOW}{Colors.BOLD}⚠️  Some tests failed. Check the output above.{Colors.END}\n")
    
    print(f"{Colors.CYAN}Check the output files for detailed results.{Colors.END}\n")


if __name__ == "__main__":
    main()

