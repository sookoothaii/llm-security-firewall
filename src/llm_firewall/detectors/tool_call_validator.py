"""
Protocol HEPHAESTUS: Tool Call Validator
==========================================

Validates and sanitizes LLM tool calls to prevent:
- Unauthorized tool execution (Whitelist enforcement)
- SQL Injection via tool arguments
- Path Traversal attacks
- Remote Code Execution (RCE) attempts
- Argument manipulation

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-11-29
Status: Protocol HEPHAESTUS - Core Component
License: MIT
"""

import re
import logging
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ToolCallValidationResult:
    """
    Result of tool call validation.

    Attributes:
        allowed: Whether the tool call is allowed
        reason: Human-readable reason for allow/block decision
        sanitized_args: Sanitized arguments (if sanitization was applied)
        risk_score: Risk score [0.0, 1.0] for the tool call
        detected_threats: List of detected threat patterns
    """

    allowed: bool
    reason: str
    sanitized_args: Dict[str, Any]
    risk_score: float = 0.0
    detected_threats: List[str] = None

    def __post_init__(self):
        if self.detected_threats is None:
            self.detected_threats = []


class ToolCallValidator:
    """
    Validates and sanitizes LLM tool calls (Protocol HEPHAESTUS).

    Architecture:
    - Whitelist enforcement: Only allowed tools can be executed
    - Argument validation: Detects SQL Injection, Path Traversal, RCE
    - Argument sanitization: Removes dangerous patterns from arguments
    - Risk scoring: Calculates risk score for the tool call

    Usage:
        validator = ToolCallValidator(allowed_tools=["web_search", "calculator"])
        result = validator.validate_tool_call("web_search", {"query": "test"})
        if not result.allowed:
            # Block the tool call
            pass
    """

    def __init__(
        self,
        allowed_tools: Optional[List[str]] = None,
        strict_mode: bool = True,
        enable_sanitization: bool = True,
    ):
        """
        Initialize Tool Call Validator.

        Args:
            allowed_tools: List of allowed tool names. If None, uses default safe tools.
            strict_mode: If True, blocks on any detected threat. If False, sanitizes and warns.
            enable_sanitization: If True, attempts to sanitize dangerous arguments.
        """
        # Default safe tools (if no whitelist provided)
        self.default_safe_tools: Set[str] = {
            "web_search",
            "calculator",
            "text_analysis",
            "date_time",
            "unit_converter",
        }

        # User-provided whitelist or default
        if allowed_tools is None:
            self.allowed_tools: Set[str] = self.default_safe_tools
            logger.info(
                f"ToolCallValidator initialized with default safe tools: {self.allowed_tools}"
            )
        else:
            self.allowed_tools = set(allowed_tools)
            logger.info(
                f"ToolCallValidator initialized with custom whitelist: {self.allowed_tools}"
            )

        self.strict_mode = strict_mode
        self.enable_sanitization = enable_sanitization

        # Compile regex patterns for performance
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile regex patterns for threat detection."""
        # SQL Injection patterns
        self.sql_injection_patterns = [
            re.compile(
                r"\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b",
                re.IGNORECASE,
            ),
            re.compile(r"--\s*$", re.MULTILINE),  # SQL comment
            re.compile(r"/\*.*?\*/", re.DOTALL),  # SQL block comment
            re.compile(
                r"';?\s*(OR|AND)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", re.IGNORECASE
            ),
            re.compile(r"'\s*;\s*--", re.IGNORECASE),
            re.compile(r"xp_\w+|sp_\w+", re.IGNORECASE),  # SQL Server procedures
        ]

        # Path Traversal patterns
        self.path_traversal_patterns = [
            re.compile(r"\.\./", re.IGNORECASE),  # Relative path traversal
            re.compile(r"\.\.\\", re.IGNORECASE),  # Windows path traversal
            re.compile(r"/etc/(?:passwd|shadow|hosts)", re.IGNORECASE),
            re.compile(r"C:\\Windows\\System32", re.IGNORECASE),
            re.compile(r"/proc/", re.IGNORECASE),
            re.compile(r"/sys/", re.IGNORECASE),
            re.compile(r"~/", re.IGNORECASE),  # Home directory access
            re.compile(r"//", re.IGNORECASE),  # UNC path (Windows)
        ]

        # RCE patterns
        self.rce_patterns = [
            re.compile(r"\bos\.system\s*\(", re.IGNORECASE),
            re.compile(r"\bsubprocess\.(call|run|Popen)\s*\(", re.IGNORECASE),
            re.compile(r"\beval\s*\(", re.IGNORECASE),
            re.compile(r"\bexec\s*\(", re.IGNORECASE),
            re.compile(r"\bexecfile\s*\(", re.IGNORECASE),
            re.compile(r"\bcompile\s*\(", re.IGNORECASE),
            re.compile(r"`.*`", re.IGNORECASE),  # Backtick execution (shell)
            re.compile(r"\$\(", re.IGNORECASE),  # Command substitution
            re.compile(r"&&|\|\|", re.IGNORECASE),  # Command chaining
            re.compile(r";\s*(rm|del|format|shutdown)", re.IGNORECASE),
        ]

    def validate_tool_call(
        self, tool_name: str, arguments: Dict[str, Any]
    ) -> ToolCallValidationResult:
        """
        Validate a tool call.

        Args:
            tool_name: Name of the tool to be called
            arguments: Dictionary of arguments for the tool call

        Returns:
            ToolCallValidationResult with validation decision and sanitized arguments
        """
        detected_threats: List[str] = []
        risk_score = 0.0
        sanitized_args = arguments.copy() if arguments else {}

        # Step 1: Whitelist Check
        if tool_name not in self.allowed_tools:
            logger.warning(
                f"[HEPHAESTUS] Tool '{tool_name}' not in whitelist. Allowed tools: {self.allowed_tools}"
            )
            return ToolCallValidationResult(
                allowed=False,
                reason=f"Tool '{tool_name}' is not in the allowed whitelist",
                sanitized_args={},
                risk_score=1.0,
                detected_threats=["unauthorized_tool"],
            )

        # Step 2: Argument Validation
        if not arguments:
            # No arguments = safe (but might be incomplete)
            return ToolCallValidationResult(
                allowed=True,
                reason="Tool call allowed (no arguments to validate)",
                sanitized_args={},
                risk_score=0.0,
                detected_threats=[],
            )

        # Step 3: Check each argument for threats
        for arg_name, arg_value in arguments.items():
            if not isinstance(arg_value, str):
                # Non-string arguments: convert to string for pattern matching
                arg_str = str(arg_value)
            else:
                arg_str = arg_value

            # Check argument name for context clues
            arg_name_lower = arg_name.lower()

            # SQL Injection check (for "sql", "query", "statement" arguments)
            if any(
                keyword in arg_name_lower
                for keyword in ["sql", "query", "statement", "db"]
            ):
                sql_threats = self._detect_sql_injection(arg_str)
                if sql_threats:
                    detected_threats.extend(sql_threats)
                    risk_score = max(risk_score, 0.8)
                    logger.warning(
                        f"[HEPHAESTUS] SQL Injection detected in argument '{arg_name}': {sql_threats}"
                    )

            # Path Traversal check (for "path", "file", "dir", "filename" arguments)
            if any(
                keyword in arg_name_lower
                for keyword in [
                    "path",
                    "file",
                    "dir",
                    "filename",
                    "directory",
                    "location",
                ]
            ):
                path_threats = self._detect_path_traversal(arg_str)
                if path_threats:
                    detected_threats.extend(path_threats)
                    risk_score = max(risk_score, 0.7)
                    logger.warning(
                        f"[HEPHAESTUS] Path Traversal detected in argument '{arg_name}': {path_threats}"
                    )

            # RCE check (for "code", "command", "script", "exec" arguments)
            if any(
                keyword in arg_name_lower
                for keyword in ["code", "command", "script", "exec", "cmd", "shell"]
            ):
                rce_threats = self._detect_rce(arg_str)
                if rce_threats:
                    detected_threats.extend(rce_threats)
                    risk_score = max(risk_score, 0.9)
                    logger.warning(
                        f"[HEPHAESTUS] RCE detected in argument '{arg_name}': {rce_threats}"
                    )

            # Generic threat check (for all arguments)
            # Also check for SQL injection in non-SQL arguments (broader detection)
            if not any(
                keyword in arg_name_lower
                for keyword in ["sql", "query", "statement", "db"]
            ):
                # Check for SQL injection even in non-SQL arguments (broader detection)
                sql_threats_generic = self._detect_sql_injection(arg_str)
                if sql_threats_generic:
                    detected_threats.extend(sql_threats_generic)
                    risk_score = max(
                        risk_score, 0.6
                    )  # Lower risk than explicit SQL args

            generic_threats = self._detect_generic_threats(arg_str)
            if generic_threats:
                detected_threats.extend(generic_threats)
                risk_score = max(risk_score, 0.5)

            # Sanitization (if enabled and threats detected)
            if self.enable_sanitization and detected_threats:
                sanitized_value = self._sanitize_argument(arg_str, detected_threats)
                sanitized_args[arg_name] = sanitized_value
                logger.info(
                    f"[HEPHAESTUS] Sanitized argument '{arg_name}': '{arg_str[:50]}...' -> '{sanitized_value[:50]}...'"
                )

        # Step 4: Decision
        if detected_threats:
            if self.strict_mode:
                # Strict mode: Block on any threat
                return ToolCallValidationResult(
                    allowed=False,
                    reason=f"Threats detected: {', '.join(detected_threats)}",
                    sanitized_args=sanitized_args,
                    risk_score=risk_score,
                    detected_threats=detected_threats,
                )
            else:
                # Lenient mode: Sanitize and warn
                return ToolCallValidationResult(
                    allowed=True,
                    reason=f"Threats detected but sanitized: {', '.join(detected_threats)}",
                    sanitized_args=sanitized_args,
                    risk_score=risk_score,
                    detected_threats=detected_threats,
                )
        else:
            # No threats detected
            return ToolCallValidationResult(
                allowed=True,
                reason="Tool call validated successfully",
                sanitized_args=sanitized_args,
                risk_score=0.0,
                detected_threats=[],
            )

    def _detect_sql_injection(self, text: str) -> List[str]:
        """Detect SQL injection patterns in text."""
        threats = []
        for pattern in self.sql_injection_patterns:
            if pattern.search(text):
                threats.append("sql_injection")
                break  # One match is enough
        return threats

    def _detect_path_traversal(self, text: str) -> List[str]:
        """Detect path traversal patterns in text."""
        threats = []
        for pattern in self.path_traversal_patterns:
            if pattern.search(text):
                threats.append("path_traversal")
                break
        return threats

    def _detect_rce(self, text: str) -> List[str]:
        """Detect remote code execution patterns in text."""
        threats = []
        for pattern in self.rce_patterns:
            if pattern.search(text):
                threats.append("rce")
                break
        return threats

    def _detect_generic_threats(self, text: str) -> List[str]:
        """Detect generic threat patterns (not specific to SQL/Path/RCE)."""
        threats = []

        # Check for suspicious URL schemes
        if re.search(r"(javascript|data|vbscript):", text, re.IGNORECASE):
            threats.append("suspicious_url_scheme")

        # Check for encoded payloads (base64, hex)
        if re.search(r"[A-Za-z0-9+/]{50,}={0,2}", text):  # Base64-like
            # Additional check: decode and re-check
            threats.append("possible_encoding_bypass")

        return threats

    def _sanitize_argument(self, value: str, detected_threats: List[str]) -> str:
        """
        Sanitize an argument value based on detected threats.

        Args:
            value: Original argument value
            detected_threats: List of detected threat types

        Returns:
            Sanitized value
        """
        sanitized = value

        # Remove SQL injection patterns
        if "sql_injection" in detected_threats:
            for pattern in self.sql_injection_patterns:
                sanitized = pattern.sub("", sanitized)

        # Remove path traversal patterns
        if "path_traversal" in detected_threats:
            sanitized = re.sub(r"\.\./", "", sanitized)
            sanitized = re.sub(r"\.\.\\", "", sanitized)
            sanitized = re.sub(r"/etc/", "", sanitized, flags=re.IGNORECASE)
            sanitized = re.sub(r"C:\\Windows", "", sanitized, flags=re.IGNORECASE)

        # Remove RCE patterns
        if "rce" in detected_threats:
            for pattern in self.rce_patterns:
                sanitized = pattern.sub("", sanitized)

        # Remove suspicious URL schemes
        if "suspicious_url_scheme" in detected_threats:
            sanitized = re.sub(
                r"(javascript|data|vbscript):", "", sanitized, flags=re.IGNORECASE
            )

        # Trim whitespace
        sanitized = sanitized.strip()

        # If sanitization removed everything, return a safe placeholder
        if not sanitized:
            sanitized = "[SANITIZED]"

        return sanitized

    def add_allowed_tool(self, tool_name: str):
        """Add a tool to the whitelist."""
        self.allowed_tools.add(tool_name)
        logger.info(f"[HEPHAESTUS] Added tool '{tool_name}' to whitelist")

    def remove_allowed_tool(self, tool_name: str):
        """Remove a tool from the whitelist."""
        if tool_name in self.allowed_tools:
            self.allowed_tools.remove(tool_name)
            logger.info(f"[HEPHAESTUS] Removed tool '{tool_name}' from whitelist")
        else:
            logger.warning(
                f"[HEPHAESTUS] Tool '{tool_name}' not in whitelist, cannot remove"
            )
