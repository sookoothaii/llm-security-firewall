"""
HAK_GAL v2.2-ALPHA: Custom Exception Hierarchy

Custom exceptions for security policy violations and system errors.
All exceptions inherit from SecurityException for unified error handling.

Creator: Joerg Bollwahn
License: MIT
"""

from typing import Optional, Dict, Any

__all__ = [
    "SecurityException",
    "PolicyViolation",
    "SystemError",
    "BusinessLogicException",
]


class SecurityException(Exception):
    """
    Base exception for all security-related errors.

    Attributes:
        message: Human-readable error message
        code: Error code for programmatic handling
        metadata: Additional context (threats, risk_score, etc.)
    """

    def __init__(
        self,
        message: str,
        code: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.code = code or "SECURITY_ERROR"
        self.metadata = metadata or {}


class PolicyViolation(SecurityException):
    """
    Raised when a security policy is violated.

    Examples:
        - Semantic drift detected (SessionTrajectory)
        - Tool call blocked by ToolGuard
        - Regex pattern match (inbound pipeline)
    """

    def __init__(
        self,
        message: str,
        policy_name: str,
        risk_score: float = 1.0,
        detected_threats: Optional[list] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, code="POLICY_VIOLATION", metadata=metadata)
        self.policy_name = policy_name
        self.risk_score = risk_score
        self.detected_threats = detected_threats or []


class SystemError(SecurityException):
    """
    Raised when a system component fails (fail-closed behavior).

    Examples:
        - Embedding model timeout
        - HMAC computation failure
        - Database connection error
    """

    def __init__(
        self,
        message: str,
        component: str,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, code="SYSTEM_ERROR", metadata=metadata)
        self.component = component


class BusinessLogicException(SecurityException):
    """
    Raised when business logic validation fails.

    Examples:
        - Transaction limit exceeded
        - Forbidden keyword in arguments
        - Invalid state transition
    """

    def __init__(
        self,
        message: str,
        tool_name: str,
        rule_name: str,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            message,
            code="BUSINESS_LOGIC_VIOLATION",
            metadata=metadata or {},
        )
        self.tool_name = tool_name
        self.rule_name = rule_name
