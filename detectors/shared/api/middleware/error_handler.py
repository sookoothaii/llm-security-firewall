"""
Error Handler Middleware

Common error handling middleware for detector services.
"""
import logging
from typing import Callable
from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

logger = logging.getLogger(__name__)


class ErrorHandlerMiddleware:
    """
    Error handling middleware for FastAPI applications.
    
    Provides consistent error responses across all detector services.
    """
    
    @staticmethod
    async def validation_exception_handler(
        request: Request,
        exc: RequestValidationError
    ) -> JSONResponse:
        """
        Handle validation errors.
        
        Returns consistent error response format.
        """
        logger.warning(f"Validation error: {exc.errors()}")
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "success": False,
                "data": None,
                "error": f"Validation error: {exc.errors()}"
            }
        )
    
    @staticmethod
    async def general_exception_handler(
        request: Request,
        exc: Exception
    ) -> JSONResponse:
        """
        Handle general exceptions.
        
        Returns consistent error response format.
        """
        logger.error(f"Unhandled exception: {exc}", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "success": False,
                "data": None,
                "error": "Internal server error"
            }
        )

