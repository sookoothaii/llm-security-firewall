"""
Tool/MCP Firewall (RC10: Tool-Level Defense Layer)
====================================================

Firewall layer for tool/MCP invocations, operating below the text/NLP layer.

Based on Anthropic Report (2025): The actual attack impact comes from tools
orchestrated via MCP servers, not just malicious prompts.

Design:
- Wrapper around tool/MCP calls
- Allowlists/Policies per tool category
- Risk scoring per tool invocation
- Integration with Kill-Chain Monitor

Creator: Joerg Bollwahn (with GPT-5.1 analysis)
Date: 2025-11-17
License: MIT
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

from llm_firewall.detectors.tool_killchain import ToolEvent


class ToolOperationType(Enum):
    """Tool operation types."""

    SCAN = "scan"  # Network scanning, port enumeration
    QUERY = "query"  # Database queries, API calls
    EXEC = "exec"  # Code execution, command execution
    WRITE = "write"  # File writes, database writes
    READ = "read"  # File reads, database reads
    DELETE = "delete"  # File deletion, data deletion
    NETWORK = "network"  # Network operations (connect, send, etc.)


class ToolScope(Enum):
    """Tool operation scope."""

    INTERNAL = "internal"  # Internal/test network
    EXTERNAL = "external"  # Public internet
    TESTLAB = "testlab"  # Isolated test environment
    UNKNOWN = "unknown"  # Scope not determined


@dataclass
class ToolInvocation:
    """Structured tool invocation event."""

    tool_name: str  # Tool name (e.g., "nmap", "mcp_filesystem_write")
    operation_type: ToolOperationType
    target: Optional[str] = None  # IP, domain, file path, etc.
    scope: ToolScope = ToolScope.UNKNOWN
    arguments: Dict[str, any] = field(default_factory=dict)
    session_id: Optional[str] = None
    operator_id: Optional[str] = None
    metadata: Dict[str, any] = field(default_factory=dict)


@dataclass
class ToolPolicy:
    """Policy for tool category."""

    tool_patterns: List[str]  # Tool name patterns (regex or exact)
    operation_types: Set[ToolOperationType]
    allowed_scopes: Set[ToolScope]
    allowed_targets: Optional[List[str]] = None  # IP ranges, domains, etc.
    requires_approval: bool = False  # Requires human approval
    risk_score: float = 0.5  # Base risk score
    max_per_hour: Optional[int] = None  # Rate limit
    max_per_day: Optional[int] = None


@dataclass
class ToolFirewallDecision:
    """Tool firewall decision."""

    action: str  # "ALLOW", "SANDBOX", "BLOCK", "REQUIRE_APPROVAL"
    risk_score: float  # 0.0 - 1.0
    reason: str
    policy_matched: Optional[str] = None
    signals: List[str] = field(default_factory=list)


class ToolFirewall:
    """
    Firewall for tool/MCP invocations.

    Evaluates tool calls against policies and returns decisions.
    """

    def __init__(self, policies: Optional[List[ToolPolicy]] = None):
        """
        Initialize tool firewall.

        Args:
            policies: List of tool policies (defaults to built-in policies)
        """
        self.policies = policies or self._default_policies()
        self.invocation_history: List[ToolInvocation] = []

    def _default_policies(self) -> List[ToolPolicy]:
        """Default tool policies based on security best practices."""
        return [
            # Network scanning - only internal/testlab
            ToolPolicy(
                tool_patterns=["nmap", "masscan", "port_scan", "service_scan"],
                operation_types={ToolOperationType.SCAN},
                allowed_scopes={ToolScope.INTERNAL, ToolScope.TESTLAB},
                allowed_targets=["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"],
                requires_approval=False,
                risk_score=0.3,
                max_per_hour=50,
            ),
            # Exploit frameworks - require approval
            ToolPolicy(
                tool_patterns=["exploit", "vuln_scan", "exploit_framework"],
                operation_types={ToolOperationType.EXEC},
                allowed_scopes={ToolScope.TESTLAB},
                requires_approval=True,
                risk_score=0.8,
                max_per_hour=5,
            ),
            # Database queries - internal only
            ToolPolicy(
                tool_patterns=["db_query", "sql_query", "database"],
                operation_types={ToolOperationType.QUERY},
                allowed_scopes={ToolScope.INTERNAL, ToolScope.TESTLAB},
                requires_approval=False,
                risk_score=0.4,
                max_per_day=1000,
            ),
            # File writes - require approval for external
            ToolPolicy(
                tool_patterns=["write_file", "create_file", "mcp_filesystem_write"],
                operation_types={ToolOperationType.WRITE},
                allowed_scopes={ToolScope.INTERNAL, ToolScope.TESTLAB},
                requires_approval=True,  # For production systems
                risk_score=0.6,
                max_per_hour=20,
            ),
            # File reads - internal/testlab only
            ToolPolicy(
                tool_patterns=["read_file", "mcp_filesystem_read"],
                operation_types={ToolOperationType.READ},
                allowed_scopes={ToolScope.INTERNAL, ToolScope.TESTLAB},
                requires_approval=False,
                risk_score=0.2,
                max_per_hour=100,
            ),
            # Data export - require approval
            ToolPolicy(
                tool_patterns=["data_export", "export_data", "exfil"],
                operation_types={ToolOperationType.READ, ToolOperationType.NETWORK},
                allowed_scopes={ToolScope.TESTLAB},
                requires_approval=True,
                risk_score=0.9,
                max_per_day=10,
            ),
        ]

    def evaluate_tool_invocation(
        self,
        invocation: ToolInvocation,
    ) -> ToolFirewallDecision:
        """
        Evaluate tool invocation against policies.

        Args:
            invocation: Tool invocation to evaluate

        Returns:
            Firewall decision
        """
        # Determine scope from target
        scope = self._determine_scope(invocation.target)
        invocation.scope = scope

        # Find matching policy
        matching_policy = self._find_matching_policy(invocation)

        if matching_policy is None:
            # No policy match - default to BLOCK
            return ToolFirewallDecision(
                action="BLOCK",
                risk_score=0.9,
                reason="No policy matched for tool",
                signals=["tool_no_policy_match"],
            )

        # Check scope restrictions
        if scope not in matching_policy.allowed_scopes:
            return ToolFirewallDecision(
                action="BLOCK",
                risk_score=0.8,
                reason=f"Tool not allowed in scope {scope.value}",
                policy_matched=matching_policy.tool_patterns[0]
                if matching_policy.tool_patterns
                else None,
                signals=["tool_scope_violation"],
            )

        # Check target restrictions
        if matching_policy.allowed_targets and invocation.target:
            if not self._target_allowed(
                invocation.target, matching_policy.allowed_targets
            ):
                return ToolFirewallDecision(
                    action="BLOCK",
                    risk_score=0.7,
                    reason="Target not in allowed list",
                    policy_matched=matching_policy.tool_patterns[0]
                    if matching_policy.tool_patterns
                    else None,
                    signals=["tool_target_violation"],
                )

        # Check rate limits
        rate_check = self._check_rate_limits(invocation, matching_policy)
        if not rate_check[0]:
            return ToolFirewallDecision(
                action="BLOCK",
                risk_score=0.6,
                reason=rate_check[1],
                policy_matched=matching_policy.tool_patterns[0]
                if matching_policy.tool_patterns
                else None,
                signals=["tool_rate_limit_exceeded"],
            )

        # Determine action
        if matching_policy.requires_approval:
            action = "REQUIRE_APPROVAL"
        else:
            action = "ALLOW"

        # Calculate risk score
        risk_score = matching_policy.risk_score

        # Boost risk if external scope
        if scope == ToolScope.EXTERNAL:
            risk_score = min(risk_score + 0.2, 1.0)

        # Record invocation
        self.invocation_history.append(invocation)

        return ToolFirewallDecision(
            action=action,
            risk_score=risk_score,
            reason="Policy matched, requirements met",
            policy_matched=matching_policy.tool_patterns[0]
            if matching_policy.tool_patterns
            else None,
            signals=[],
        )

    def _determine_scope(self, target: Optional[str]) -> ToolScope:
        """Determine operation scope from target."""
        if not target:
            return ToolScope.UNKNOWN

        target_lower = target.lower()

        # Check for internal IP ranges
        if any(
            target.startswith(prefix)
            for prefix in [
                "10.",
                "192.168.",
                "172.16.",
                "172.17.",
                "172.18.",
                "172.19.",
                "172.20.",
                "172.21.",
                "172.22.",
                "172.23.",
                "172.24.",
                "172.25.",
                "172.26.",
                "172.27.",
                "172.28.",
                "172.29.",
                "172.30.",
                "172.31.",
            ]
        ):
            return ToolScope.INTERNAL

        # Check for testlab indicators
        if any(
            x in target_lower
            for x in ["test", "lab", "staging", "dev", "localhost", "127.0.0.1"]
        ):
            return ToolScope.TESTLAB

        # Default to external
        return ToolScope.EXTERNAL

    def _find_matching_policy(self, invocation: ToolInvocation) -> Optional[ToolPolicy]:
        """Find matching policy for tool invocation."""
        tool_lower = invocation.tool_name.lower()

        for policy in self.policies:
            # Check tool name patterns
            for pattern in policy.tool_patterns:
                if pattern.lower() in tool_lower or tool_lower in pattern.lower():
                    # Check operation type
                    if invocation.operation_type in policy.operation_types:
                        return policy

        return None

    def _target_allowed(self, target: str, allowed_targets: List[str]) -> bool:
        """Check if target is in allowed list (simple prefix matching)."""
        for allowed in allowed_targets:
            if target.startswith(
                allowed.replace("/8", "").replace("/16", "").replace("/12", "")
            ):
                return True
        return False

    def _check_rate_limits(
        self,
        invocation: ToolInvocation,
        policy: ToolPolicy,
    ) -> Tuple[bool, str]:
        """Check rate limits for tool invocation."""
        from datetime import datetime, timedelta

        now = datetime.now()

        # Check per-hour limit
        if policy.max_per_hour:
            hour_ago = now - timedelta(hours=1)
            recent_count = sum(
                1
                for inv in self.invocation_history
                if inv.tool_name == invocation.tool_name
                and datetime.fromtimestamp(getattr(inv, "timestamp", now.timestamp()))
                >= hour_ago
            )
            if recent_count >= policy.max_per_hour:
                return False, f"Hourly limit exceeded ({policy.max_per_hour})"

        # Check per-day limit
        if policy.max_per_day:
            day_ago = now - timedelta(days=1)
            recent_count = sum(
                1
                for inv in self.invocation_history
                if inv.tool_name == invocation.tool_name
                and datetime.fromtimestamp(getattr(inv, "timestamp", now.timestamp()))
                >= day_ago
            )
            if recent_count >= policy.max_per_day:
                return False, f"Daily limit exceeded ({policy.max_per_day})"

        return True, ""

    def convert_to_tool_event(self, invocation: ToolInvocation) -> ToolEvent:
        """Convert tool invocation to ToolEvent for kill-chain tracking."""
        import time

        # Map operation type to category
        category_map = {
            ToolOperationType.SCAN: "net_scan",
            ToolOperationType.EXEC: "exploit",
            ToolOperationType.QUERY: "lateral",
            ToolOperationType.READ: "exfil",
            ToolOperationType.WRITE: "lateral",
        }

        category = category_map.get(invocation.operation_type, "unknown")

        return ToolEvent(
            timestamp=time.time(),
            tool=invocation.tool_name,
            category=category,
            target=invocation.target,
            success=True,  # Assume success if firewall allows
            metadata={
                "operation_type": invocation.operation_type.value,
                "scope": invocation.scope.value,
            },
        )
