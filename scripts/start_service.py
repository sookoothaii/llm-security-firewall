#!/usr/bin/env python3
"""
Start Firewall Service
======================

Startet den Code Intent Detector Service für lokale Tests und CI/CD.

Creator: HAK_GAL Security Team
Date: 2025-12-10
"""

import subprocess
import sys
import os
from pathlib import Path

def main():
    """Start the firewall service."""
    # Change to service directory
    service_dir = Path(__file__).parent.parent / "detectors" / "code_intent_service"
    
    if not service_dir.exists():
        print(f"ERROR: Service directory not found: {service_dir}")
        return 1
    
    os.chdir(service_dir)
    
    print("=" * 80)
    print("STARTING FIREWALL SERVICE")
    print("=" * 80)
    print(f"Directory: {service_dir}")
    print(f"Port: 8001")
    print(f"Health Check: http://localhost:8001/health")
    print("=" * 80)
    print()
    
    # Start uvicorn
    try:
        subprocess.run([
            sys.executable, "-m", "uvicorn",
            "main:app",
            "--host", "0.0.0.0",
            "--port", "8001"
        ], check=True)
    except KeyboardInterrupt:
        print("\nService stopped")
        return 0
    except Exception as e:
        print(f"ERROR: Failed to start service: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())

