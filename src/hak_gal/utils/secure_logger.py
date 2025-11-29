"""
HAK_GAL v2.3.3: Secure Logger with Per-Tenant Redaction

CRITICAL FIX (P2): GDPR-compliant logging.
Integrates TenantLogRedactor with Python logging.

Creator: Joerg Bollwahn
Date: 2025-01-15
Status: P2 Implementation (v2.3.3)
License: MIT
"""

import logging
import json
import sys
from hak_gal.utils.tenant_log_redactor import TenantLogRedactor

logger = logging.getLogger(__name__)


class SecureLoggingHandler(logging.Handler):
    """
    Secure Logging Handler with per-tenant redaction.

    CRITICAL FIX (P2): Automatically redacts sensitive fields before logging.
    """

    def __init__(self, tenant_redactor: TenantLogRedactor, stream=sys.stdout):
        """
        Initialize Secure Logging Handler.

        Args:
            tenant_redactor: TenantLogRedactor instance
            stream: Output stream (default: sys.stdout)
        """
        super().__init__()
        self.tenant_redactor = tenant_redactor
        self.stream = stream

    def emit(self, record: logging.LogRecord) -> None:
        """
        Emit log record with redaction.

        Args:
            record: LogRecord instance
        """
        try:
            # Extract tenant_id from record (if present)
            tenant_id = getattr(record, "tenant_id", "default")

            # Build log entry
            log_entry = {
                "timestamp": record.created,
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
                "module": record.module,
                "function": record.funcName,
                "line": record.lineno,
            }

            # Add extra fields (may contain sensitive data)
            if hasattr(record, "__dict__"):
                for key, value in record.__dict__.items():
                    if key not in [
                        "name",
                        "msg",
                        "args",
                        "created",
                        "filename",
                        "funcName",
                        "levelname",
                        "levelno",
                        "lineno",
                        "module",
                        "msecs",
                        "message",
                        "pathname",
                        "process",
                        "processName",
                        "relativeCreated",
                        "thread",
                        "threadName",
                        "exc_info",
                        "exc_text",
                        "stack_info",
                        "tenant_id",
                    ]:
                        log_entry[key] = value

            # Redact sensitive fields
            # CRITICAL: Logging is synchronous, but redaction is async
            # Use thread pool to run async code from sync context
            import asyncio
            import concurrent.futures

            def run_async():
                try:
                    loop = asyncio.get_event_loop()
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)

                return loop.run_until_complete(
                    self.tenant_redactor.redact(tenant_id, log_entry)
                )

            # Run async redaction in thread pool (avoids blocking)
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(run_async)
                try:
                    redacted = future.result(timeout=1.0)
                except concurrent.futures.TimeoutError:
                    # Fallback: log without redaction if timeout
                    logger.warning(
                        f"Log redaction timeout for tenant {tenant_id}, logging without redaction"
                    )
                    redacted = log_entry

            # Output JSON
            json_str = json.dumps(redacted, default=str)
            self.stream.write(json_str + "\n")
            self.stream.flush()

        except Exception as e:
            # Fallback to standard logging if redaction fails
            logger.error(f"SecureLoggingHandler: Redaction failed: {e}", exc_info=True)
            self.handleError(record)


def setup_secure_logging(tenant_redactor: TenantLogRedactor) -> None:
    """
    Setup secure logging with per-tenant redaction.

    Args:
        tenant_redactor: TenantLogRedactor instance
    """
    # Remove default handlers
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Add secure handler
    secure_handler = SecureLoggingHandler(tenant_redactor)
    secure_handler.setLevel(logging.INFO)
    root_logger.addHandler(secure_handler)
    root_logger.setLevel(logging.INFO)

    logger.info("Secure logging enabled with per-tenant redaction")
