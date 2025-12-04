"""
Policy Provider: Per-Tenant/Per-Route AnswerPolicy Selection
===========================================================

Provides AnswerPolicy instances based on tenant, route, or context.
Supports YAML configuration and programmatic policy selection.

Author: Joerg Bollwahn
Date: 2025-12-02
License: MIT
"""

import logging
from pathlib import Path
from typing import Dict, Any, Optional

try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False

from .decision_policy import AnswerPolicy, get_policy, POLICIES

logger = logging.getLogger(__name__)


class PolicyProvider:
    """
    Provides AnswerPolicy instances based on tenant, route, or context.

    Supports:
    - Predefined policies (default, kids, strict, etc.)
    - YAML configuration file
    - Per-tenant policy mapping
    - Per-route policy mapping
    - Fallback to default policy
    """

    def __init__(
        self,
        config_path: Optional[Path] = None,
        tenant_policy_map: Optional[Dict[str, str]] = None,
        route_policy_map: Optional[Dict[str, str]] = None,
    ):
        """
        Initialize PolicyProvider.

        Args:
            config_path: Optional path to YAML configuration file
            tenant_policy_map: Optional mapping of tenant_id -> policy_name
            route_policy_map: Optional mapping of route/endpoint -> policy_name
        """
        self.tenant_policy_map = tenant_policy_map or {}
        self.route_policy_map = route_policy_map or {}
        self._policies: Dict[str, AnswerPolicy] = {}

        # Load policies from YAML if provided
        if config_path and config_path.exists() and HAS_YAML:
            self._load_from_yaml(config_path)
        else:
            # Use predefined policies
            self._policies = POLICIES.copy()

        # Ensure default policy exists
        if "default" not in self._policies:
            self._policies["default"] = get_policy("default")

    def _load_from_yaml(self, config_path: Path) -> None:
        """Load policies from YAML configuration file."""
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f)

            for policy_name, policy_config in config.items():
                if policy_name == "description":
                    continue  # Skip top-level description if present

                try:
                    policy = AnswerPolicy(
                        benefit_correct=float(
                            policy_config.get("benefit_correct", 1.0)
                        ),
                        cost_wrong=float(policy_config.get("cost_wrong", 9.0)),
                        cost_silence=float(policy_config.get("cost_silence", 0.0)),
                        policy_name=policy_name,
                    )
                    self._policies[policy_name] = policy
                    logger.debug(f"Loaded policy '{policy_name}' from YAML")
                except (ValueError, TypeError) as e:
                    logger.warning(
                        f"Failed to load policy '{policy_name}' from YAML: {e}. Using default."
                    )
                    self._policies[policy_name] = get_policy("default")

        except Exception as e:
            logger.warning(
                f"Failed to load YAML config from {config_path}: {e}. Using defaults."
            )
            self._policies = POLICIES.copy()

    def for_tenant(
        self,
        tenant_id: str,
        route: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> AnswerPolicy:
        """
        Get AnswerPolicy for given tenant, route, and context.

        Selection order:
        1. Route-specific policy (if route_policy_map provided)
        2. Tenant-specific policy (if tenant_policy_map provided)
        3. Context-based policy (if "policy" key in context)
        4. Default policy

        Args:
            tenant_id: Tenant identifier
            route: Optional route/endpoint identifier
            context: Optional context dictionary (may contain "policy" key)

        Returns:
            AnswerPolicy instance
        """
        # 1. Check route-specific policy
        if route and route in self.route_policy_map:
            policy_name = self.route_policy_map[route]
            if policy_name in self._policies:
                logger.debug(
                    f"Using route-specific policy '{policy_name}' for route '{route}'"
                )
                return self._policies[policy_name]

        # 2. Check tenant-specific policy
        if tenant_id in self.tenant_policy_map:
            policy_name = self.tenant_policy_map[tenant_id]
            if policy_name in self._policies:
                logger.debug(
                    f"Using tenant-specific policy '{policy_name}' for tenant '{tenant_id}'"
                )
                return self._policies[policy_name]

        # 3. Check context-based policy
        if context and "policy" in context:
            policy_name = context["policy"]
            if isinstance(policy_name, str) and policy_name in self._policies:
                logger.debug(f"Using context-based policy '{policy_name}'")
                return self._policies[policy_name]

        # 4. Fallback to default
        logger.debug(f"Using default policy for tenant '{tenant_id}'")
        return self._policies["default"]

    def get_policy(self, policy_name: str) -> AnswerPolicy:
        """
        Get policy by name.

        Args:
            policy_name: Name of policy

        Returns:
            AnswerPolicy instance

        Raises:
            KeyError: If policy not found
        """
        if policy_name not in self._policies:
            raise KeyError(
                f"Policy '{policy_name}' not found. Available: {list(self._policies.keys())}"
            )
        return self._policies[policy_name]

    def add_policy(self, policy: AnswerPolicy) -> None:
        """
        Add or update a policy.

        Args:
            policy: AnswerPolicy instance (must have policy_name set)
        """
        if not policy.policy_name:
            raise ValueError("Policy must have policy_name set")
        self._policies[policy.policy_name] = policy
        logger.debug(f"Added/updated policy '{policy.policy_name}'")


# Default global provider (can be overridden per FirewallEngine instance)
_default_provider: Optional[PolicyProvider] = None


def get_default_provider() -> PolicyProvider:
    """Get or create default global PolicyProvider."""
    global _default_provider
    if _default_provider is None:
        # Try to load from default config path
        config_path = (
            Path(__file__).parent.parent.parent / "config" / "answer_policy.yaml"
        )
        _default_provider = PolicyProvider(
            config_path=config_path if config_path.exists() else None
        )
    return _default_provider
