#!/usr/bin/env python3
"""
Fix NumPy Compatibility Issues
===============================

Downgrades NumPy to <2.0 to fix compatibility with scipy and sklearn.

Usage:
    python scripts/fix_numpy_compatibility.py
"""

import subprocess
import sys
from pathlib import Path

def run_command(cmd: list, description: str):
    """Run a command and handle errors."""
    print(f"▶ {description}...")
    try:
        result = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
        )
        print(f"✅ {description} completed")
        if result.stdout:
            print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed")
        print(f"Error: {e.stderr}")
        return False

def main():
    """Main entry point."""
    print("=" * 80)
    print("  NumPy Compatibility Fix")
    print("=" * 80)
    print()
    print("This script will downgrade NumPy to <2.0 to fix compatibility issues")
    print("with scipy and sklearn.")
    print()
    
    # Check current NumPy version
    try:
        import numpy
        current_version = numpy.__version__
        print(f"Current NumPy version: {current_version}")
        
        if current_version.startswith("2."):
            print("⚠️  NumPy 2.x detected - needs downgrade")
        else:
            print("✅ NumPy version is compatible")
            return
    except ImportError:
        print("⚠️  NumPy not installed")
    
    print()
    print("Downgrading NumPy to <2.0...")
    
    # Uninstall NumPy 2.x
    run_command(
        [sys.executable, "-m", "pip", "uninstall", "numpy", "-y"],
        "Uninstalling NumPy 2.x"
    )
    
    # Install NumPy <2.0
    run_command(
        [sys.executable, "-m", "pip", "install", "numpy<2.0", "--upgrade"],
        "Installing NumPy <2.0"
    )
    
    # Verify installation (reload module to get new version)
    import importlib
    if 'numpy' in sys.modules:
        importlib.reload(sys.modules['numpy'])
    
    try:
        import numpy
        new_version = numpy.__version__
        print(f"\n✅ NumPy downgraded to: {new_version}")
        
        # Parse version to check if < 2.0
        version_parts = new_version.split('.')
        major_version = int(version_parts[0])
        
        if major_version >= 2:
            print("⚠️  WARNING: NumPy 2.x still installed!")
            print("   Try: pip install 'numpy<2.0' --force-reinstall --no-cache-dir")
            return False
        else:
            print("✅ NumPy version is now compatible (<2.0)")
            return True
    except ImportError:
        print("❌ NumPy installation failed")
        return False
    except Exception as e:
        print(f"⚠️  Error verifying NumPy version: {e}")
        print("   But installation might have succeeded. Try restarting Python.")
        return False
    
    print()
    print("=" * 80)
    print("  Fix Complete!")
    print("=" * 80)
    print()
    print("You can now restart the service:")
    print("  python -m uvicorn detectors.code_intent_service.main:app --host 0.0.0.0 --port 8001")

if __name__ == "__main__":
    main()

