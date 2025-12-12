"""
Simple Policy Engine

Einfache regelbasierte Policy Engine für Routing-Entscheidungen.
"""
import logging
from typing import Dict, Any, List
import yaml
from pathlib import Path

logger = logging.getLogger(__name__)


class SimplePolicyEngine:
    """Einfache regelbasierte Policy Engine."""
    
    def __init__(self, policy_path: str = None):
        """
        Initialize policy engine.
        
        Args:
            policy_path: Optional path to YAML policy file. If None, uses default policies.
        """
        self.policies = self._load_policies(policy_path)
        logger.info(f"SimplePolicyEngine initialized with {len(self.policies.get('policies', []))} policies")
        
    def _load_policies(self, policy_path: str = None) -> Dict:
        """Lädt Routing-Policies aus YAML oder verwendet Defaults."""
        if policy_path and Path(policy_path).exists():
            try:
                with open(policy_path, 'r', encoding='utf-8') as f:
                    policies = yaml.safe_load(f)
                    logger.info(f"Loaded policies from {policy_path}")
                    return policies
            except Exception as e:
                logger.warning(f"Failed to load policies from {policy_path}: {e}. Using defaults.")
        
        # Default policies
        default_policies = {
            "policies": [
                {
                    "name": "code_tool_policy",
                    "condition": "context.get('source_tool') == 'code_interpreter'",
                    "detectors": [
                        {"name": "code_intent", "mode": "required", "timeout_ms": 500},
                        {"name": "content_safety", "mode": "required", "timeout_ms": 500}
                    ],
                    "strategy": "parallel",
                    "max_latency": 1000
                },
                {
                    "name": "high_risk_policy", 
                    "condition": "context.get('user_risk_tier', 1) >= 2",
                    "detectors": [
                        {"name": "content_safety", "mode": "required", "timeout_ms": 500},
                        {"name": "persuasion", "mode": "required", "timeout_ms": 500},
                        {"name": "code_intent", "mode": "optional", "timeout_ms": 500}
                    ],
                    "strategy": "parallel",
                    "max_latency": 1500
                },
                {
                    "name": "default_policy",
                    "condition": "True",  # Immer wahr
                    "detectors": [
                        {"name": "content_safety", "mode": "required", "timeout_ms": 500}
                    ],
                    "strategy": "sequential",
                    "max_latency": 600
                }
            ]
        }
        logger.info("Using default policies")
        return default_policies
    
    def evaluate(self, context: Dict[str, Any]) -> Dict:
        """
        Findet passende Policy für gegebenen Kontext.
        
        Args:
            context: Kontext-Dictionary mit source_tool, user_risk_tier, etc.
            
        Returns:
            Policy-Dictionary mit detectors, strategy, max_latency
        """
        for policy in self.policies.get("policies", []):
            try:
                # Sicherheit: Nur erlaubte Variablen im eval-Kontext
                safe_context = {"context": context}
                if eval(policy["condition"], {"__builtins__": {}}, safe_context):
                    logger.debug(f"Matched policy: {policy['name']}")
                    return policy
            except Exception as e:
                logger.warning(f"Error evaluating policy {policy.get('name', 'unknown')}: {e}")
                continue
        
        # Fallback auf default (letzte Policy)
        default_policy = self.policies.get("policies", [])[-1] if self.policies.get("policies") else None
        if default_policy:
            logger.debug(f"Using fallback policy: {default_policy.get('name', 'default')}")
            return default_policy
        
        # Absolute fallback
        logger.error("No policies available, using hardcoded fallback")
        return {
            "name": "hardcoded_fallback",
            "detectors": [{"name": "content_safety", "mode": "required", "timeout_ms": 75}],
            "strategy": "sequential",
            "max_latency": 100
        }

