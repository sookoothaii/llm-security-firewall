"""
Shared API Middleware

Common middleware for detector services.
"""

from .logging_middleware import LoggingMiddleware
from .error_handler import ErrorHandlerMiddleware

__all__ = ["LoggingMiddleware", "ErrorHandlerMiddleware"]

