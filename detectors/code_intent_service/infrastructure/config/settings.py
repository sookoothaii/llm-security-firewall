"""
Configuration Settings - Pydantic-based Configuration

Replaces global flags and environment variables with type-safe configuration.
"""
from typing import Optional
from pathlib import Path
import os

# Load .env file if python-dotenv is available
try:
    from dotenv import load_dotenv
    # Load .env from service directory
    service_dir = Path(__file__).parent.parent.parent
    env_file = service_dir / ".env"
    if env_file.exists():
        load_dotenv(env_file)
        HAS_DOTENV = True
    else:
        HAS_DOTENV = False
except ImportError:
    HAS_DOTENV = False

# Try to import pydantic_settings, fallback to simple class
try:
    from pydantic_settings import BaseSettings
    HAS_PYDANTIC_SETTINGS = True
except ImportError:
    # Fallback: Simple class without pydantic
    class BaseSettings:
        def __init__(self, **kwargs):
            # Set attributes from kwargs
            for key, value in kwargs.items():
                setattr(self, key, value)
        
        class Config:
            env_prefix = ""
            env_file = None
            case_sensitive = False
    HAS_PYDANTIC_SETTINGS = False


class DetectionSettings(BaseSettings):
    """Settings for Code Intent Detection Service"""
    
    # ML Model Configuration
    use_quantum_model: bool = True
    quantum_model_path: Optional[Path] = None
    shadow_mode: bool = False
    hybrid_mode: bool = True
    quantum_threshold: float = 0.60
    
    # CodeBERT Configuration
    use_codebert: bool = True
    codebert_model_name: str = "microsoft/codebert-base"
    
    # V2.1 Hotfix Configuration (Production Ready - Recommended)
    use_v21_hotfix: bool = False  # Enable V2.1 Hotfix (set to True for production)
    v1_model_path: Optional[Path] = None  # Default: models/code_intent_adversarial_v1/best_model.pt
    v2_model_path: Optional[Path] = None  # Default: models/code_intent_adversarial_v2/best_model.pt
    v21_threshold: float = 0.95  # V2 threshold (only block at high confidence)
    v21_fallback_threshold: float = 0.7  # V1 fallback threshold
    v21_whitelist_enabled: bool = True  # Enable technical questions whitelist
    
    # Rule Engine Configuration
    enable_rule_engine: bool = True
    rule_engine_threshold: float = 0.5
    
    # Feedback Collection
    enable_feedback_collection: bool = True
    feedback_buffer_size: int = 10000
    
    # Online Learning Configuration
    enable_online_learning: bool = False  # Requires model and tokenizer
    online_learning_batch_size: int = 32
    online_learning_update_interval: int = 100  # Update every N new samples
    online_learning_min_samples: int = 10  # Minimum samples for training
    online_learning_rate: float = 1e-5
    
    # Feedback Repository Configuration
    feedback_repository_type: str = "hybrid"  # "memory", "redis", "postgres", "hybrid"
    
    # Redis Configuration (for Redis Feedback Repository)
    redis_host: Optional[str] = None
    redis_port: Optional[int] = None
    redis_password: Optional[str] = None
    redis_username: Optional[str] = None
    redis_ssl: bool = True
    redis_ttl_hours: int = 720  # 30 days
    
    # PostgreSQL Configuration (for PostgreSQL Feedback Repository)
    postgres_connection_string: Optional[str] = None
    
    # Performance
    request_timeout_seconds: float = 15.0
    max_concurrent_requests: int = 100
    
    # Logging
    log_level: str = "INFO"
    enable_structured_logging: bool = True
    
    # Prometheus Metrics
    enable_metrics: bool = True
    
    class Config:
        env_prefix = "DETECTION_"
        env_file = ".env"
        case_sensitive = False
        
    def __init__(self, **kwargs):
        # Load from environment if pydantic_settings available
        if HAS_PYDANTIC_SETTINGS:
            super().__init__(**kwargs)
        else:
            # Fallback: Set defaults and override with kwargs
            # Set all defaults first
            self.use_quantum_model = True
            self.quantum_model_path = None
            self.shadow_mode = False
            self.hybrid_mode = True
            self.quantum_threshold = 0.60
            self.use_codebert = True
            self.codebert_model_name = "microsoft/codebert-base"
            self.use_v21_hotfix = False
            self.v1_model_path = None
            self.v2_model_path = None
            self.v21_threshold = 0.95
            self.v21_fallback_threshold = 0.7
            self.v21_whitelist_enabled = True
            self.enable_rule_engine = True
            self.rule_engine_threshold = 0.5
            self.enable_feedback_collection = True
            self.feedback_buffer_size = 10000
            self.enable_online_learning = False
            self.online_learning_batch_size = 32
            self.online_learning_update_interval = 100
            self.online_learning_min_samples = 10
            self.online_learning_rate = 1e-5
            self.feedback_repository_type = "hybrid"
            self.redis_host = None
            self.redis_port = None
            self.redis_password = None
            self.redis_username = None
            self.redis_ssl = True
            self.redis_ttl_hours = 720
            self.postgres_connection_string = None
            self.request_timeout_seconds = 15.0
            self.max_concurrent_requests = 100
            self.log_level = "INFO"
            self.enable_structured_logging = True
            self.enable_metrics = True
            
            # Override with kwargs
            for key, value in kwargs.items():
                setattr(self, key, value)
            
            # Load from environment variables (simple fallback)
            import os
            if not self.redis_host:
                self.redis_host = os.getenv("REDIS_CLOUD_HOST") or os.getenv("REDIS_HOST")
            if not self.redis_port:
                port_str = os.getenv("REDIS_CLOUD_PORT") or os.getenv("REDIS_PORT")
                self.redis_port = int(port_str) if port_str else None
            if not self.redis_password:
                self.redis_password = os.getenv("REDIS_CLOUD_PASSWORD") or os.getenv("REDIS_PASSWORD")
            if not self.redis_username:
                self.redis_username = os.getenv("REDIS_CLOUD_USERNAME") or os.getenv("REDIS_USERNAME")
            if not self.postgres_connection_string:
                self.postgres_connection_string = os.getenv("POSTGRES_CONNECTION_STRING") or os.getenv("DATABASE_URL")
        
        # Set default quantum_model_path if not provided
        if self.quantum_model_path is None:
            # Default path: models/quantum_cnn_trained/best_model.pt (wie in main.py)
            service_dir = Path(__file__).parent.parent.parent
            project_root = service_dir.parent.parent
            default_path = project_root / "models" / "quantum_cnn_trained" / "best_model.pt"
            self.quantum_model_path = default_path

