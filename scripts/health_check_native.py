#!/usr/bin/env python3
"""
Native Health Check Script (NO DOCKER)
=======================================

Checks health of all services without Docker dependencies.

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-07
License: MIT
"""

import sys
import requests
import time
from pathlib import Path
from typing import Dict, List, Tuple

# Add project root to path
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))


class HealthChecker:
    """Health checker for native services."""
    
    def __init__(self):
        self.base_urls = {
            "firewall": "http://localhost:8080",
            "code_intent": "http://localhost:8001",
            "persuasion": "http://localhost:8002",
        }
        self.results: List[Tuple[str, bool, str]] = []
    
    def check_service(self, name: str, url: str, endpoint: str = "/health", timeout: int = 5) -> Tuple[bool, str]:
        """Check a single service."""
        try:
            full_url = f"{url}{endpoint}"
            response = requests.get(full_url, timeout=timeout)
            
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "healthy":
                    return True, "healthy"
                else:
                    return False, f"unhealthy: {data.get('status')}"
            else:
                return False, f"HTTP {response.status_code}"
        
        except requests.exceptions.ConnectionError:
            return False, "connection refused (service not running)"
        except requests.exceptions.Timeout:
            return False, "timeout"
        except Exception as e:
            return False, f"error: {str(e)}"
    
    def check_firewall(self) -> bool:
        """Check firewall service."""
        healthy, message = self.check_service("firewall", self.base_urls["firewall"])
        self.results.append(("Firewall", healthy, message))
        return healthy
    
    def check_code_intent(self) -> bool:
        """Check code intent detector."""
        healthy, message = self.check_service("code_intent", self.base_urls["code_intent"])
        self.results.append(("Code Intent Detector", healthy, message))
        return healthy
    
    def check_persuasion(self) -> bool:
        """Check persuasion detector."""
        healthy, message = self.check_service("persuasion", self.base_urls["persuasion"])
        self.results.append(("Persuasion Detector", healthy, message))
        return healthy
    
    def check_processes(self) -> bool:
        """Check if processes are running (via PID files)."""
        pid_dir = PROJECT_ROOT / "pids"
        if not pid_dir.exists():
            self.results.append(("Processes", False, "PID directory not found"))
            return False
        
        pid_files = list(pid_dir.glob("*.pid"))
        if not pid_files:
            self.results.append(("Processes", False, "No PID files found"))
            return False
        
        running = 0
        for pid_file in pid_files:
            try:
                pid = int(pid_file.read_text().strip())
                # Check if process is running (Unix only)
                import os
                try:
                    os.kill(pid, 0)  # Signal 0 just checks if process exists
                    running += 1
                except OSError:
                    pass
            except (ValueError, FileNotFoundError):
                pass
        
        if running > 0:
            self.results.append(("Processes", True, f"{running} processes running"))
            return True
        else:
            self.results.append(("Processes", False, "No processes running"))
            return False
    
    def run_all_checks(self) -> bool:
        """Run all health checks."""
        print("=" * 80)
        print("HEALTH CHECK - Native Services")
        print("=" * 80)
        print()
        
        all_healthy = True
        
        # Check processes (if available)
        try:
            self.check_processes()
        except Exception:
            pass  # Skip on Windows or if not available
        
        # Check services
        all_healthy &= self.check_firewall()
        all_healthy &= self.check_code_intent()
        all_healthy &= self.check_persuasion()
        
        # Print results
        print("Results:")
        print("-" * 80)
        for name, healthy, message in self.results:
            status = "✅" if healthy else "❌"
            print(f"{status} {name:30s} {message}")
        print("-" * 80)
        
        if all_healthy:
            print("\n✅ All services are healthy!")
        else:
            print("\n❌ Some services are unhealthy")
        
        return all_healthy


def main():
    checker = HealthChecker()
    success = checker.run_all_checks()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
