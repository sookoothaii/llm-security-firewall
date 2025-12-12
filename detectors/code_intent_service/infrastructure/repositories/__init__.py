"""
Infrastructure Repositories

Repository implementations for feedback storage.
"""

from .feedback_buffer_repository import FeedbackBufferRepository, NullFeedbackRepository

# Optional imports (may fail if dependencies not installed)
try:
    from .redis_feedback_repository import RedisFeedbackRepository
    __all__ = ["FeedbackBufferRepository", "NullFeedbackRepository", "RedisFeedbackRepository"]
except ImportError:
    __all__ = ["FeedbackBufferRepository", "NullFeedbackRepository"]

try:
    from .postgres_feedback_repository import PostgresFeedbackRepository
    if "PostgresFeedbackRepository" not in __all__:
        __all__.append("PostgresFeedbackRepository")
except ImportError:
    pass

try:
    from .hybrid_feedback_repository import HybridFeedbackRepository
    if "HybridFeedbackRepository" not in __all__:
        __all__.append("HybridFeedbackRepository")
except ImportError:
    pass

