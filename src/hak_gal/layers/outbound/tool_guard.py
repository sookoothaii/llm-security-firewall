"""
HAK_GAL v2.2-ALPHA: ToolGuard Framework

Business logic validation for tool calls before execution.
NO OPA - Pure Python logic for stateful validation.

Creator: Joerg Bollwahn
License: MIT
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List

from hak_gal.core.exceptions import BusinessLogicException, SecurityException

logger = logging.getLogger(__name__)


@dataclass
class SessionContext:
    """
    Session context for stateful validation.

    CRITICAL FIX (P1): Added tenant_id for per-tenant rate limiting.

    Holds session state (e.g., transaction counts, user permissions, etc.)
    for business logic validation.
    """

    state: Dict[str, Any] = field(default_factory=dict)
    tenant_id: str = "default"  # CRITICAL FIX (P1): Required for tenant isolation

    def get(self, key: str, default: Any = None) -> Any:
        """Get state value with default."""
        return self.state.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set state value."""
        self.state[key] = value

    def increment(self, key: str, delta: int = 1) -> int:
        """Increment numeric state value."""
        current = self.state.get(key, 0)
        if not isinstance(current, (int, float)):
            current = 0
        new_value = current + delta
        self.state[key] = new_value
        return new_value


class BaseToolGuard(ABC):
    """
    Abstract base class for tool call validators.

    Each guard implements business logic validation for specific tools.
    Pure Python logic - NO external dependencies (no OPA).
    """

    def __init__(self, tool_name: str, priority: int = 50):
        """
        Initialize tool guard.

        Args:
            tool_name: Name of the tool this guard validates
            priority: Guard priority (0 = Highest/System, 100 = Lowest). Default: 50
        """
        self.tool_name = tool_name
        self.priority = priority

    @abstractmethod
    async def validate(
        self, tool_name: str, args: Dict[str, Any], context: SessionContext
    ) -> bool:
        """
        Validate tool call arguments against business logic.

        Args:
            tool_name: Name of the tool being called
            args: Tool call arguments (dict)
            context: Session context for stateful validation

        Returns:
            True if validation passes

        Raises:
            BusinessLogicException: If validation fails (fail-closed)
        """
        pass

    def _raise_violation(
        self,
        rule_name: str,
        message: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Raise BusinessLogicException with standardized format.

        Args:
            rule_name: Name of the violated rule
            message: Human-readable error message
            metadata: Additional context

        Raises:
            BusinessLogicException: Always raises
        """
        raise BusinessLogicException(
            message=message,
            tool_name=self.tool_name,
            rule_name=rule_name,
            metadata=metadata or {},
        )


class FinancialToolGuard(BaseToolGuard):
    """
    Business logic guard for financial tools (e.g., transfer_money).

    Rules:
    1. Micro-Transaction Spam Prevention:
       Block if amount < 1.0 AND tx_count_1h > 50
    2. Forbidden Keywords:
       Block if reason contains "admin"
    """

    def __init__(self, tool_name: str = "transfer_money", priority: int = 30):
        """
        Initialize Financial Tool Guard.

        Args:
            tool_name: Name of the financial tool (default: "transfer_money")
            priority: Guard priority (default: 30 = High priority for financial tools)
        """
        super().__init__(tool_name, priority=priority)
        self.min_amount_threshold = 1.0
        self.max_tx_count_1h = 50

    async def validate(
        self, tool_name: str, args: Dict[str, Any], context: SessionContext
    ) -> bool:
        """
        Validate financial tool call.

        Args:
            tool_name: Name of the tool being called
            args: Tool call arguments (must contain 'amount' and optionally 'reason')
            context: Session context (must contain 'tx_count_1h' in state)

        Returns:
            True if validation passes

        Raises:
            BusinessLogicException: If validation fails
        """
        # Rule 1: Micro-Transaction Spam Prevention
        amount = args.get("amount")
        if amount is not None:
            try:
                amount_float = float(amount)
                tx_count_1h = context.get("tx_count_1h", 0)

                if (
                    amount_float < self.min_amount_threshold
                    and tx_count_1h > self.max_tx_count_1h
                ):
                    self._raise_violation(
                        rule_name="micro_transaction_spam",
                        message=(
                            f"Micro-transaction spam detected: "
                            f"amount={amount_float} < {self.min_amount_threshold} "
                            f"AND tx_count_1h={tx_count_1h} > {self.max_tx_count_1h}"
                        ),
                        metadata={
                            "amount": amount_float,
                            "tx_count_1h": tx_count_1h,
                            "threshold_amount": self.min_amount_threshold,
                            "threshold_tx_count": self.max_tx_count_1h,
                        },
                    )
            except (ValueError, TypeError):
                # Invalid amount format - let other validators handle this
                logger.warning(f"Invalid amount format in {tool_name}: {amount}")

        # Rule 2: Forbidden Keywords (Semantic Check)
        reason = args.get("reason", "")
        if isinstance(reason, str) and "admin" in reason.lower():
            self._raise_violation(
                rule_name="forbidden_keyword",
                message=f"Forbidden keyword 'admin' detected in reason: {reason}",
                metadata={"reason": reason, "forbidden_keyword": "admin"},
            )

        # Validation passed
        logger.debug(f"Financial tool validation passed: {tool_name}")
        return True


class ToolGuardRegistry:
    """
    Registry for tool guards (Registry Pattern) with priority-based execution.

    Maps tool names to multiple guard instances, executes them in priority order.
    """

    def __init__(self, tenant_rate_limiter=None):
        """
        Initialize empty registry.

        CRITICAL FIX (P1): Removed global TokenBucket.
        Per-tenant rate limiting via TenantRateLimiter (optional, for backward compatibility).

        Args:
            tenant_rate_limiter: Optional TenantRateLimiter instance (from hak_gal.utils.tenant_rate_limiter)
        """
        self._guards: Dict[str, List[BaseToolGuard]] = {}  # tool_name -> list of guards
        # CRITICAL FIX (P1): Per-tenant rate limiter (replaces global TokenBucket)
        self._tenant_rate_limiter = tenant_rate_limiter

    def register(self, tool_name: str, guard: BaseToolGuard) -> None:
        """
        Register a guard for a tool name.

        Multiple guards can be registered for the same tool (executed by priority).

        Args:
            tool_name: Name of the tool
            guard: Guard instance
        """
        if tool_name not in self._guards:
            self._guards[tool_name] = []

        self._guards[tool_name].append(guard)
        logger.info(
            f"Registered guard for tool: {tool_name} "
            f"({guard.__class__.__name__}, priority={guard.priority})"
        )

    def get_guards(self, tool_name: str) -> List[BaseToolGuard]:
        """
        Get all guards for a tool name, sorted by priority (ascending: 0 = highest).

        Args:
            tool_name: Name of the tool

        Returns:
            List of guard instances, sorted by priority (lowest priority number first)
        """
        guards = self._guards.get(tool_name, [])
        # Sort by priority (ascending: 0 = highest priority, executed first)
        return sorted(guards, key=lambda g: g.priority)

    def get_guard(self, tool_name: str) -> Optional[BaseToolGuard]:
        """
        Get first guard for a tool name (backward compatibility).

        Args:
            tool_name: Name of the tool

        Returns:
            First guard instance (by priority) or None if not found
        """
        guards = self.get_guards(tool_name)
        return guards[0] if guards else None

    async def validate(
        self, tool_name: str, args: Dict[str, Any], context: SessionContext
    ) -> bool:
        """
        Validate tool call using all registered guards (priority-based, short-circuit).

        CRITICAL FIX (P1): Per-tenant rate limiting replaces global TokenBucket.
        Prevents Cross-Tenant DoS attacks.

        Guards are executed in priority order (0 = highest priority first).
        If a high-priority guard fails, execution stops immediately (short-circuit).

        Args:
            tool_name: Name of the tool being called
            args: Tool call arguments
            context: Session context (must contain tenant_id)

        Returns:
            True if all guards pass

        Raises:
            SecurityException: If rate limit exceeded (fail-closed)
            BusinessLogicException: If any guard fails (fail-closed, short-circuit)
        """
        # CRITICAL FIX (P1): Per-tenant rate limiting (replaces global TokenBucket)
        if self._tenant_rate_limiter is not None:
            # Validate tenant_id is present
            tenant_id = getattr(context, "tenant_id", None)
            if not tenant_id or tenant_id == "default":
                logger.warning(
                    f"ToolGuardRegistry: tenant_id missing or default in context. "
                    f"Rate limiting may not work correctly. Tool: {tool_name}"
                )

            # Per-tenant rate limit check
            allowed, current_count = await self._tenant_rate_limiter.is_allowed(
                tenant_id=tenant_id or "default", guard_name=f"tool_{tool_name}"
            )

            if not allowed:
                raise SecurityException(
                    message=f"Rate limit exceeded for tenant {tenant_id}: "
                    f"{current_count}/{self._tenant_rate_limiter.max_requests} requests/sec",
                    code="RATE_LIMIT_EXCEEDED",
                    metadata={
                        "tool_name": tool_name,
                        "tenant_id": tenant_id,
                        "current_count": current_count,
                        "max_requests": self._tenant_rate_limiter.max_requests,
                    },
                )

        guards = self.get_guards(tool_name)

        if not guards:
            # No guard registered - allow by default (or could be fail-closed)
            logger.debug(f"No guard registered for tool: {tool_name}, allowing")
            return True

        # Execute guards in priority order (0 = highest priority first)
        # Short-circuit: If high-priority guard fails, stop immediately
        for guard in guards:
            try:
                # SECURITY: Real async operation (not fake async)
                await guard.validate(tool_name, args, context)
                logger.debug(
                    f"Guard {guard.__class__.__name__} (priority={guard.priority}) passed"
                )
            except BusinessLogicException:
                # High-priority guard failed - short-circuit (don't check lower priority guards)
                logger.warning(
                    f"Guard {guard.__class__.__name__} (priority={guard.priority}) blocked tool call"
                )
                # CRITICAL FIX (v2.3.2): Jitter sleep REMOVED (replaced by rate limiter)
                raise

            # CRITICAL FIX (v2.3.2): Jitter sleep REMOVED (replaced by rate limiter)
            # No more exponential latency growth under load

        return True

    def list_guards(self) -> Dict[str, str]:
        """
        List all registered guards.

        Returns:
            Dict mapping tool_name -> guard_class_name
        """
        return {
            tool_name: guard.__class__.__name__
            for tool_name, guard in self._guards.items()
        }
