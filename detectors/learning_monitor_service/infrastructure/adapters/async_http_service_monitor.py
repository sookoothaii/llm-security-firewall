"""
Async HTTP Service Monitor Adapter

Implements ServiceMonitorPort using async HTTP calls.
"""
import logging
from typing import Optional
from datetime import datetime

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False
    # Fallback to requests (synchronous)
    try:
        import requests
        HAS_REQUESTS = True
    except ImportError:
        HAS_REQUESTS = False

from domain.ports import ServiceMonitorPort
from domain.value_objects import ServiceStatus

logger = logging.getLogger(__name__)


class AsyncHttpServiceMonitorAdapter(ServiceMonitorPort):
    """
    Async HTTP adapter for monitoring services.
    
    Uses httpx for async HTTP calls, falls back to requests if not available.
    """
    
    def __init__(self, timeout: float = 2.0):
        """
        Initialize async HTTP service monitor.
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        if HAS_HTTPX:
            self.client = httpx.AsyncClient(timeout=timeout)
            logger.info("AsyncHttpServiceMonitorAdapter initialized with httpx")
        elif HAS_REQUESTS:
            logger.warning("httpx not available, using synchronous requests (slower)")
            self.client = None
        else:
            raise ImportError("Neither httpx nor requests available")
    
    async def check_service_health(
        self,
        service_id: str,
        service_url: str
    ) -> Optional[ServiceStatus]:
        """
        Check the health and status of a service.
        
        Args:
            service_id: Identifier for the service
            service_url: Base URL of the service
            
        Returns:
            ServiceStatus if service is reachable, None otherwise
        """
        start_time = datetime.now()
        
        try:
            if HAS_HTTPX and self.client:
                # Async HTTP call with httpx
                # Try /api/v1/health first (Code Intent), fallback to /health
                health_response = None
                for health_path in ["/api/v1/health", "/health"]:
                    try:
                        health_response = await self.client.get(f"{service_url}{health_path}", timeout=self.timeout)
                        if health_response.status_code == 200:
                            break
                    except:
                        continue
                
                if not health_response or health_response.status_code != 200:
                    latency_ms = (datetime.now() - start_time).total_seconds() * 1000
                    return ServiceStatus(
                        service_id=service_id,
                        service_name=service_id,
                        is_healthy=False,
                        feedback_enabled=False,
                        latency_ms=latency_ms,
                        error=f"Health check failed: {health_response.status_code if health_response else 'No response'}",
                        last_checked=datetime.now()
                    )
                
                # Try to get feedback stats
                # Orchestrator: /api/v1/learning/metrics
                # Code Intent: /api/v1/feedback/stats
                # Fallback: /feedback/stats
                try:
                    stats_response = None
                    for stats_path in [
                        "/api/v1/learning/metrics",  # Orchestrator Learning Metrics
                        "/api/v1/feedback/stats",    # Code Intent Feedback Stats
                        "/feedback/stats"             # Fallback
                    ]:
                        try:
                            stats_response = await self.client.get(f"{service_url}{stats_path}", timeout=self.timeout)
                            if stats_response.status_code == 200:
                                break
                        except:
                            continue
                    
                    if stats_response and stats_response.status_code == 200:
                        stats = stats_response.json()
                        latency_ms = (datetime.now() - start_time).total_seconds() * 1000
                        # Handle different feedback stats structures
                        # Code Intent uses: total_samples, blocked_samples, etc.
                        # Old format uses: enabled, buffer_size, max_size
                        feedback_enabled = stats.get("enabled", True)  # Default True if stats exist
                        buffer_size = stats.get("buffer_size", stats.get("total_samples", 0))
                        max_size = stats.get("max_size", 0)
                        online_learning = stats.get("online_learning", {})
                        statistics = stats.get("statistics", stats)  # Use full stats if no statistics key
                        
                        return ServiceStatus(
                            service_id=service_id,
                            service_name=service_id,
                            is_healthy=True,
                            feedback_enabled=feedback_enabled,
                            buffer_size=buffer_size,
                            max_size=max_size,
                            online_learning=online_learning,
                            statistics=statistics,
                            latency_ms=latency_ms,
                            last_checked=datetime.now()
                        )
                except Exception:
                    pass  # Feedback API not available
                
                # Service healthy but no feedback API
                latency_ms = (datetime.now() - start_time).total_seconds() * 1000
                return ServiceStatus(
                    service_id=service_id,
                    service_name=service_id,
                    is_healthy=True,
                    feedback_enabled=False,
                    latency_ms=latency_ms,
                    last_checked=datetime.now()
                )
            
            elif HAS_REQUESTS:
                # Synchronous fallback (wrapped in async)
                import asyncio
                loop = asyncio.get_event_loop()
                
                # Try /api/v1/health first (Code Intent), fallback to /health
                health_response = None
                for health_path in ["/api/v1/health", "/health"]:
                    try:
                        health_response = await loop.run_in_executor(
                            None,
                            lambda path=health_path: requests.get(f"{service_url}{path}", timeout=self.timeout)
                        )
                        if health_response.status_code == 200:
                            break
                    except:
                        continue
                
                if not health_response or health_response.status_code != 200:
                    latency_ms = (datetime.now() - start_time).total_seconds() * 1000
                    return ServiceStatus(
                        service_id=service_id,
                        service_name=service_id,
                        is_healthy=False,
                        feedback_enabled=False,
                        latency_ms=latency_ms,
                        error=f"Health check failed: {health_response.status_code if health_response else 'No response'}",
                        last_checked=datetime.now()
                    )
                
                # Try feedback stats
                # Orchestrator: /api/v1/learning/metrics
                # Code Intent: /api/v1/feedback/stats
                # Fallback: /feedback/stats
                try:
                    stats_response = None
                    for stats_path in [
                        "/api/v1/learning/metrics",  # Orchestrator Learning Metrics
                        "/api/v1/feedback/stats",    # Code Intent Feedback Stats
                        "/feedback/stats"             # Fallback
                    ]:
                        try:
                            stats_response = await loop.run_in_executor(
                                None,
                                lambda path=stats_path: requests.get(f"{service_url}{path}", timeout=self.timeout)
                            )
                            if stats_response.status_code == 200:
                                break
                        except:
                            continue
                    
                    if stats_response and stats_response.status_code == 200:
                        stats = stats_response.json()
                        latency_ms = (datetime.now() - start_time).total_seconds() * 1000
                        
                        # Handle different feedback stats structures
                        # Orchestrator Learning Metrics: feedback_last_24h, detector_performance
                        # Code Intent Feedback Stats: total_samples, blocked_samples, etc.
                        # Old format: enabled, buffer_size, max_size
                        
                        # Check if it's Orchestrator Learning Metrics format
                        if "feedback_last_24h" in stats or "detector_performance" in stats:
                            # Orchestrator format
                            feedback_24h = stats.get("feedback_last_24h", {})
                            false_negatives = feedback_24h.get("false_negative", 0)
                            false_positives = stats.get("total_false_positives", 0)
                            feedback_enabled = (false_negatives > 0 or false_positives > 0) or stats.get("auto_optimization_enabled", False)
                            buffer_size = false_negatives + false_positives
                            max_size = 0  # Not applicable for Orchestrator
                            online_learning = {"running": stats.get("auto_optimization_enabled", False)}
                            statistics = {
                                "false_negatives_24h": false_negatives,
                                "false_positives_total": false_positives,
                                "auto_optimization": stats.get("auto_optimization_enabled", False),
                                "last_optimization": stats.get("last_auto_optimization"),
                                "detector_performance": stats.get("detector_performance", {})
                            }
                        else:
                            # Code Intent or old format
                            feedback_enabled = stats.get("enabled", True)  # Default True if stats exist
                            buffer_size = stats.get("buffer_size", stats.get("total_samples", 0))
                            max_size = stats.get("max_size", 0)
                            online_learning = stats.get("online_learning", {})
                            statistics = stats.get("statistics", stats)  # Use full stats if no statistics key
                        
                        return ServiceStatus(
                            service_id=service_id,
                            service_name=service_id,
                            is_healthy=True,
                            feedback_enabled=feedback_enabled,
                            buffer_size=buffer_size,
                            max_size=max_size,
                            online_learning=online_learning,
                            statistics=statistics,
                            latency_ms=latency_ms,
                            last_checked=datetime.now()
                        )
                except Exception:
                    pass
                
                latency_ms = (datetime.now() - start_time).total_seconds() * 1000
                return ServiceStatus(
                    service_id=service_id,
                    service_name=service_id,
                    is_healthy=True,
                    feedback_enabled=False,
                    latency_ms=latency_ms,
                    last_checked=datetime.now()
                )
        
        except Exception as e:
            logger.error(f"Error checking service {service_id}: {e}")
            latency_ms = (datetime.now() - start_time).total_seconds() * 1000
            return ServiceStatus(
                service_id=service_id,
                service_name=service_id,
                is_healthy=False,
                feedback_enabled=False,
                latency_ms=latency_ms,
                error=str(e),
                last_checked=datetime.now()
            )
        
        return None
    
    async def close(self):
        """Close HTTP client"""
        if HAS_HTTPX and self.client:
            await self.client.aclose()

