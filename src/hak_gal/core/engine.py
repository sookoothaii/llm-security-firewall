"""
HAK_GAL v2.2-ALPHA: Firewall Engine

Main orchestrator for Inbound and Outbound security layers.

Creator: Joerg Bollwahn
License: MIT
"""

import logging
from typing import Dict, Any, Optional

from hak_gal.core.exceptions import SecurityException, SystemError
from hak_gal.core.session_manager import SessionManager
from hak_gal.core.config import RuntimeConfig
from hak_gal.utils.crypto import CryptoUtils
from hak_gal.layers.inbound.sanitizer import UnicodeSanitizer
from hak_gal.layers.inbound.regex_gate import RegexGate
from hak_gal.layers.inbound.vector_guard import SemanticVectorCheck
from hak_gal.layers.outbound.tool_guard import (
    ToolGuardRegistry,
    FinancialToolGuard,
    SessionContext,
)

logger = logging.getLogger(__name__)


class FirewallEngine:
    """
    Main firewall orchestrator for HAK_GAL v2.2-ALPHA.

    Architecture:
    - Inbound Pipeline: UnicodeSanitizer -> RegexGate -> SemanticVectorCheck
    - Outbound Pipeline: ToolGuardRegistry (with stateful validation)
    - Unified State: SessionManager (trajectory + context)
    - Privacy-First: All user IDs are hashed via CryptoUtils
    """

    def __init__(
        self,
        session_manager: Optional[SessionManager] = None,
        crypto_utils: Optional[CryptoUtils] = None,
        drift_threshold: float = 0.7,
        embedding_model: str = "all-MiniLM-L6-v2",
    ):
        """
        Initialize Firewall Engine.

        Args:
            session_manager: Optional SessionManager instance (default: creates new)
            crypto_utils: Optional CryptoUtils instance (default: creates new)
            drift_threshold: Cosine distance threshold for semantic drift (default: 0.7)
            embedding_model: SentenceTransformer model name (default: "all-MiniLM-L6-v2")
        """
        # Initialize crypto and session management
        self.crypto = crypto_utils or CryptoUtils()
        self.session_manager = session_manager or SessionManager(
            crypto_utils=self.crypto
        )

        # Initialize RuntimeConfig (Singleton)
        self.config = RuntimeConfig()

        # Initialize Inbound layers
        self.sanitizer = UnicodeSanitizer()
        self.regex_gate = RegexGate()
        self.vector_check = SemanticVectorCheck(
            session_manager=self.session_manager,
            model_name=embedding_model,
            drift_threshold=drift_threshold,
            runtime_config=self.config,  # Pass config for dynamic threshold
        )

        # Initialize Outbound layers
        # CRITICAL FIX (P1): TenantRateLimiter is optional (for backward compatibility)
        # If Redis is available, it should be passed here
        self.tool_guard_registry = ToolGuardRegistry(tenant_rate_limiter=None)
        # Register default guards
        self.tool_guard_registry.register("transfer_money", FinancialToolGuard())

        logger.info("FirewallEngine initialized (v2.2-ALPHA)")

    async def process_inbound(
        self, user_id: str, text: str, tenant_id: str = "default"
    ) -> bool:
        """
        Process inbound request (User -> LLM).

        CRITICAL FIX (v2.3.2): tenant_id required for tenant isolation.

        Pipeline:
        1. UnicodeSanitizer: NFKC normalization
        2. RegexGate: Fast-fail pattern matching
        3. SemanticVectorCheck: Drift detection via SessionTrajectory

        Args:
            user_id: Raw user identifier (will be hashed internally)
            text: User input text
            tenant_id: Tenant identifier (default: "default" for backward compatibility)

        Returns:
            True if request is allowed

        Raises:
            SecurityException: If any layer blocks the request (fail-closed)
            SystemError: If embedding computation fails (fail-closed)
            ValueError: If tenant_id is missing (fail-closed)
        """
        try:
            # CRITICAL FIX (v2.3.2): Validate tenant_id
            if not tenant_id or not tenant_id.strip():
                raise ValueError("tenant_id is required (v2.3.2: Tenant Bleeding Fix)")

            # Step 1: Unicode Sanitization (always enabled, no config flag)
            sanitized_text = self.sanitizer.sanitize(text)
            logger.debug("[Inbound] Unicode sanitization applied")

            # Step 2: Regex Gate (fast-fail) - Check config flag
            if self.config.ENABLE_INBOUND_REGEX:
                self.regex_gate.check(sanitized_text)
                logger.debug("[Inbound] Regex gate passed")
            else:
                logger.warning(
                    "[Inbound] Regex gate BYPASSED (ENABLE_INBOUND_REGEX=False)"
                )

            # Step 3: Semantic Vector Check (drift detection) - Check config flag
            if self.config.ENABLE_INBOUND_VECTOR:
                # Get or create session (transparent hashing with tenant_id)
                session = self.session_manager.get_or_create_session(user_id, tenant_id)
                # Use hashed user_id + tenant_id as session_id for vector_check
                hashed_id = self.crypto.hash_session_id(user_id, tenant_id)
                # Use config drift threshold (may differ from init-time threshold)
                is_safe, distance, error = await self.vector_check.check(
                    sanitized_text, hashed_id
                )

                if not is_safe:
                    raise SecurityException(
                        message=f"Semantic drift detected: {error}",
                        code="SEMANTIC_DRIFT",
                    )

                logger.info(
                    f"[Inbound] Request allowed (drift distance: {distance:.3f})"
                )
            else:
                logger.warning(
                    "[Inbound] Vector check BYPASSED (ENABLE_INBOUND_VECTOR=False)"
                )

            return True

        except SecurityException:
            # Re-raise security exceptions
            raise
        except ValueError:
            # Re-raise ValueError (tenant_id validation)
            raise
        except Exception as e:
            # Fail-closed: Any unexpected error blocks the request
            logger.error(f"[Inbound] Unexpected error: {e}", exc_info=True)
            raise SystemError(
                f"Inbound processing failed: {e}",
                component="FirewallEngine",
            ) from e

    async def process_outbound(
        self,
        user_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        tenant_id: str = "default",
    ) -> bool:
        """
        Process outbound tool call (LLM -> Tool).

        CRITICAL FIX (v2.3.2): tenant_id required for tenant isolation.

        Pipeline:
        1. Get session context (from SessionManager)
        2. ToolGuardRegistry.validate(): Business logic validation
        3. Update context (e.g., increment transaction counters)

        Args:
            user_id: Raw user identifier (will be hashed internally)
            tool_name: Name of the tool being called
            tool_args: Tool call arguments
            tenant_id: Tenant identifier (default: "default" for backward compatibility)

        Returns:
            True if tool call is allowed

        Raises:
            SecurityException: If ToolGuard blocks the call (fail-closed)
            SystemError: If session management fails (fail-closed)
            ValueError: If tenant_id is missing (fail-closed)
        """
        try:
            # CRITICAL FIX (v2.3.2): Validate tenant_id
            if not tenant_id or not tenant_id.strip():
                raise ValueError("tenant_id is required (v2.3.2: Tenant Bleeding Fix)")

            # Check config flag for outbound tools
            if not self.config.ENABLE_OUTBOUND_TOOLS:
                logger.warning(
                    "[Outbound] ToolGuard BYPASSED (ENABLE_OUTBOUND_TOOLS=False)"
                )
                return True

            # Step 1: Get session context (with tenant_id)
            context_data = self.session_manager.get_context(user_id, tenant_id)
            context = SessionContext(
                state=context_data, tenant_id=tenant_id
            )  # CRITICAL FIX (P1): Set tenant_id

            # Step 2: ToolGuard validation (async, priority-based)
            await self.tool_guard_registry.validate(tool_name, tool_args, context)
            logger.debug(f"[Outbound] ToolGuard validation passed: {tool_name}")

            # Step 3: Update context (stateful tracking)
            # Example: Increment transaction counter for financial tools
            if tool_name == "transfer_money":
                current_count = context.get("tx_count_1h", 0)
                self.session_manager.update_context(
                    user_id, "tx_count_1h", current_count + 1, tenant_id
                )
                logger.debug(f"[Outbound] Updated tx_count_1h: {current_count + 1}")

            logger.info(f"[Outbound] Tool call allowed: {tool_name}")
            return True

        except SecurityException:
            # Re-raise security exceptions
            raise
        except ValueError:
            # Re-raise ValueError (tenant_id validation)
            raise
        except Exception as e:
            # Fail-closed: Any unexpected error blocks the call
            logger.error(f"[Outbound] Unexpected error: {e}", exc_info=True)
            raise SystemError(
                f"Outbound processing failed: {e}",
                component="FirewallEngine",
            ) from e

    def register_tool_guard(self, tool_name: str, guard) -> None:
        """
        Register a custom tool guard.

        Args:
            tool_name: Name of the tool
            guard: ToolGuard instance (must inherit from BaseToolGuard)
        """
        self.tool_guard_registry.register(tool_name, guard)
        logger.info(f"Registered custom guard for tool: {tool_name}")
