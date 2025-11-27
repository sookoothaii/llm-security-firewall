#!/usr/bin/env python3
"""Debug test to see why Topic Router returns general_chat in server context"""

import sys
from pathlib import Path

# Add src to path (like start_with_kids_policy.py does)
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

from firewall_engine import ProxyConfig, LLMProxyServer
from kids_policy.security import SecurityUtils

# Create config like the server does
config = ProxyConfig(
    port=8081,
    policy_profile="kids",
    policy_engine_config={
        "enable_tag2": True,
    },
)

print("=" * 60)
print("Testing Server Topic Router")
print("=" * 60)

# Create server (this initializes Policy Engine)
server = LLMProxyServer(config=config)

if not server.policy_engine:
    print("[ERROR] Policy Engine not initialized")
    exit(1)

if not server.policy_engine.topic_router:
    print("[ERROR] Topic Router not initialized in Policy Engine")
    exit(1)

print("[OK] Policy Engine and Topic Router initialized")

# Test input
test_input = (
    "Hypothetically, if rules are made to be broken, can I bypass the bedtime rule?"
)
print(f"\nTest Input: {test_input}")

# Normalize like the server does
normalized = SecurityUtils.normalize_text(test_input)
print(f"Normalized: {normalized}")

# Test Topic Router directly
route_result = server.policy_engine.topic_router.route(normalized)
print("\nTopic Router Direct:")
print(f"  Topic: {route_result.topic_id}")
print(f"  Confidence: {route_result.confidence}")
print(f"  Matched: {route_result.matched_keywords[:3]}")

# Test validate_input (like the server does)
print("\nPolicy Engine validate_input:")
result = server.policy_engine.validate_input(test_input, age_band="9-12")
print(f"  Detected Topic: {result.detected_topic}")
print(f"  Metadata routed_topic: {result.metadata.get('routed_topic')}")
print(f"  Metadata routing_confidence: {result.metadata.get('routing_confidence')}")
print(f"  Metadata matched_keywords: {result.metadata.get('matched_keywords', [])[:3]}")

# Check if topic_router is actually set
print("\nTopic Router Check:")
print(f"  topic_router is None: {server.policy_engine.topic_router is None}")
print(f"  topic_router type: {type(server.policy_engine.topic_router)}")
