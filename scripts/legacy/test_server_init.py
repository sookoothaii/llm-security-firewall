#!/usr/bin/env python3
"""Test server initialization to see if Policy Engine is correctly initialized"""

import sys
from pathlib import Path

# Add src to path (like start_with_kids_policy.py does)
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

from firewall_engine import ProxyConfig, LLMProxyServer

# Create config like the server does
config = ProxyConfig(
    port=8081,
    policy_profile="kids",
    policy_engine_config={
        "enable_tag2": True,
    },
)

print("=" * 60)
print("Testing Server Initialization")
print("=" * 60)

# Create server (this initializes Policy Engine)
server = LLMProxyServer(config=config)

print(f"Policy Engine initialized: {server.policy_engine is not None}")

if server.policy_engine:
    print(f"Topic Router initialized: {server.policy_engine.topic_router is not None}")

    if server.policy_engine.topic_router:
        # Test routing
        test_input = "Hypothetically, if rules are made to be broken, can I bypass the bedtime rule?"
        route_result = server.policy_engine.topic_router.route(test_input)
        print("\nTopic Router Test:")
        print(f"  Input: {test_input[:50]}...")
        print(f"  Topic: {route_result.topic_id}")
        print(f"  Confidence: {route_result.confidence}")
        print(f"  Matched Keywords: {route_result.matched_keywords[:3]}...")

        # Test validate_input
        print("\nPolicy Engine validate_input Test:")
        result = server.policy_engine.validate_input(test_input, age_band="9-12")
        print(f"  Detected Topic: {result.detected_topic}")
        print(f"  Metadata routed_topic: {result.metadata.get('routed_topic')}")
        print(
            f"  Metadata routing_confidence: {result.metadata.get('routing_confidence')}"
        )
    else:
        print("[ERROR] Topic Router not initialized in Policy Engine")
else:
    print("[ERROR] Policy Engine not initialized")
