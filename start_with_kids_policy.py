#!/usr/bin/env python3
"""
Start Firewall Server with Kids Policy Engine Enabled

Usage:
    python start_with_kids_policy.py

This script starts the firewall server with policy_profile="kids",
which enables the Kids Policy Engine (TAG-3 + TAG-2).
"""

import sys
from pathlib import Path

# Add src to path
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

from firewall_engine import ProxyConfig, LLMProxyServer, run

if __name__ == "__main__":
    # Create config with Kids Policy enabled
    config = ProxyConfig(
        port=8081,
        policy_profile="kids",  # Enable Kids Policy Engine
        policy_engine_config={
            "enable_tag2": True,  # Enable TAG-2 Truth Preservation
        },
    )

    # Create and start server
    print("=" * 70)
    print("Starting Firewall Server with Kids Policy Engine")
    print("=" * 70)
    print(f"Port: {config.port}")
    print(f"Policy Profile: {config.policy_profile}")
    print("=" * 70)

    # Initialize server (this will load Kids Policy Engine)
    server = LLMProxyServer(config=config)

    # Start FastAPI server
    if hasattr(run, "__call__"):
        run()
    else:
        print("FastAPI not available. Install with: pip install fastapi uvicorn")
