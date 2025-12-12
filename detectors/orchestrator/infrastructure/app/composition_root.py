"""
Orchestrator Composition Root

Central place where all adapters are composed and injected into the domain layer.
Extends BaseCompositionRoot from shared components.

Phase 5.2: Supports both BasicRouterService (Phase 5.1) and IntelligentRouterService (Phase 5.2).
"""
import logging
import sys
import os
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# Add detectors directory to path for shared imports
service_dir = Path(__file__).parent.parent.parent
detectors_dir = service_dir.parent
if str(detectors_dir) not in sys.path:
    sys.path.insert(0, str(detectors_dir))

# Import Base Composition Root
from shared.infrastructure.composition import BaseCompositionRoot

# Import infrastructure components (Phase 5.1 and 5.2)
from infrastructure.simple_policy_engine import SimplePolicyEngine
from infrastructure.dynamic_policy_engine import DynamicPolicyEngine

# Import application services
from application.router_service import BasicRouterService
from application.intelligent_router_service import IntelligentRouterService
from application.learning_router_service import LearningRouterService
from application.monitored_router_service import MonitoredRouterService

# Import learning components (Phase 5.3)
from domain.learning.feedback_collector import FeedbackCollector
from domain.learning.policy_optimizer import AdaptivePolicyOptimizer


class OrchestratorCompositionRoot(BaseCompositionRoot):
    """
    Composition root for assembling the orchestrator service.
    
    Extends BaseCompositionRoot to inherit common functionality (cache, decoder).
    Adds orchestrator-specific components (policy engine, router service).
    
    Usage:
        root = OrchestratorCompositionRoot()
        router_service = root.create_router_service()
        decision = router_service.analyze_and_route("text", context)
    """
    
    def __init__(
        self,
        enable_cache: bool = True,
        enable_normalization: bool = True,
        policy_path: str = None,
        detector_endpoints: Dict[str, str] = None,
        use_intelligent_router: bool = True,
        enable_adaptive_learning: bool = False,
        enable_monitoring: bool = False,
        settings: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize composition root.
        
        Args:
            enable_cache: If True, use cache adapter (from BaseCompositionRoot).
            enable_normalization: If True, use normalization (from BaseCompositionRoot).
            policy_path: Optional path to YAML policy file.
            detector_endpoints: Optional dictionary mapping detector names to URLs.
                              If None, uses defaults from environment or localhost.
            use_intelligent_router: If True, use IntelligentRouterService (Phase 5.2),
                                   else use BasicRouterService (Phase 5.1).
            enable_adaptive_learning: If True, enable adaptive learning (Phase 5.3).
            enable_monitoring: If True, enable monitoring (Phase 5.4).
            settings: Optional settings dictionary.
        """
        # Initialize base composition root
        super().__init__(enable_cache=enable_cache, enable_normalization=enable_normalization)
        
        # Merge settings with environment variables (env vars take precedence)
        self.settings = settings or {}
        # Read from environment variables if not in settings
        if "FEEDBACK_REPOSITORY_TYPE" not in self.settings:
            self.settings["FEEDBACK_REPOSITORY_TYPE"] = os.getenv("FEEDBACK_REPOSITORY_TYPE", "hybrid")
        if "POSTGRES_CONNECTION_STRING" not in self.settings:
            self.settings["POSTGRES_CONNECTION_STRING"] = os.getenv("POSTGRES_CONNECTION_STRING")
        if "ENABLE_ADAPTIVE_LEARNING" not in self.settings:
            self.settings["ENABLE_ADAPTIVE_LEARNING"] = os.getenv("ENABLE_ADAPTIVE_LEARNING", "false").lower() == "true"
        self.policy_path = policy_path or self.settings.get("POLICY_CONFIG_PATH")
        self.detector_endpoints = detector_endpoints or self._get_default_endpoints()
        self.use_intelligent_router = use_intelligent_router
        self.enable_adaptive_learning = enable_adaptive_learning
        self.enable_monitoring = enable_monitoring or self.settings.get("ENABLE_MONITORING", False)
        
        # Lazy initialization
        self._router_service = None
        self._policy_engine = None
        self._simple_policy_engine = None
        self._feedback_collector = None
        self._policy_optimizer = None
        self._feedback_repository = None
        self._monitored_service = None
        
        logger.info(
            f"OrchestratorCompositionRoot initialized "
            f"(extends BaseCompositionRoot, {len(self.detector_endpoints)} detector endpoints, "
            f"intelligent_router={use_intelligent_router})"
        )
    
    def _get_default_endpoints(self) -> Dict[str, str]:
        """Get default detector endpoints from environment or use localhost defaults."""
        return {
            "code_intent": os.getenv("CODE_INTENT_URL", "http://localhost:8000"),
            "persuasion": os.getenv("PERSUASION_URL", "http://localhost:8002"),
            "content_safety": os.getenv("CONTENT_SAFETY_URL", "http://localhost:8003"),
        }
    
    def create_simple_policy_engine(self) -> SimplePolicyEngine:
        """
        Create simple policy engine (Phase 5.1).
        
        Returns:
            SimplePolicyEngine instance
        """
        if self._simple_policy_engine is None:
            self._simple_policy_engine = SimplePolicyEngine(policy_path=self.policy_path)
        return self._simple_policy_engine
    
    def create_policy_engine(self) -> DynamicPolicyEngine:
        """
        Create dynamic policy engine (Phase 5.2).
        
        Returns:
            DynamicPolicyEngine instance
        """
        if self._policy_engine is None:
            # Pfad zur Policy-Konfiguration
            if self.policy_path:
                config_path = Path(self.policy_path)
            else:
                config_dir = service_dir / "config"
                config_path = config_dir / "advanced_policies.yaml"
            
            # Stelle sicher, dass die Datei existiert
            if not config_path.exists():
                self._create_default_policy_config(config_path)
            
            watch_for_changes = self.settings.get("POLICY_HOT_RELOAD", True)
            
            self._policy_engine = DynamicPolicyEngine(
                config_path=str(config_path),
                watch_for_changes=watch_for_changes
            )
        
        return self._policy_engine
    
    def create_feedback_repository(self):
        """
        Create feedback repository (Redis/PostgreSQL/Hybrid).
        
        Returns:
            FeedbackRepositoryPort implementation
        """
        if self._feedback_repository is None:
            repo_type = self.settings.get("FEEDBACK_REPOSITORY_TYPE", "hybrid").lower()
            
            # Hybrid Repository (Redis + PostgreSQL) - Recommended
            if repo_type == "hybrid":
                try:
                    redis_repo = None
                    postgres_repo = None
                    
                    # Try Redis
                    try:
                        from infrastructure.repositories.code_intent_repository_loader import load_redis_repository
                        redis_repo = load_redis_repository(
                            host=self.settings.get("REDIS_HOST") or os.getenv("REDIS_CLOUD_HOST"),
                            port=int(self.settings.get("REDIS_PORT") or os.getenv("REDIS_CLOUD_PORT", "6379")),
                            password=self.settings.get("REDIS_PASSWORD") or os.getenv("REDIS_CLOUD_PASSWORD"),
                            username=self.settings.get("REDIS_USERNAME") or os.getenv("REDIS_CLOUD_USERNAME"),
                            ttl_hours=int(self.settings.get("REDIS_TTL_HOURS", "720")),
                            ssl=bool(self.settings.get("REDIS_SSL", False))
                        )
                        if redis_repo:
                            logger.info("Redis Feedback Repository created")
                    except Exception as e:
                        logger.warning(f"Redis repository creation failed: {e}", exc_info=True)
                        redis_repo = None
                    
                    # Try PostgreSQL (direkte Implementierung im Orchestrator)
                    try:
                        from infrastructure.repositories.postgres_feedback_repository import PostgresFeedbackRepository
                        postgres_repo = PostgresFeedbackRepository(
                            connection_string=self.settings.get("POSTGRES_CONNECTION_STRING") or os.getenv("POSTGRES_CONNECTION_STRING")
                        )
                        logger.info("PostgreSQL Feedback Repository created")
                    except Exception as e:
                        logger.warning(f"PostgreSQL repository creation failed: {e}", exc_info=True)
                        postgres_repo = None
                    
                    # Create Hybrid (wenn Redis oder PostgreSQL verfügbar)
                    if redis_repo or postgres_repo:
                        try:
                            from infrastructure.repositories.code_intent_repository_loader import load_hybrid_repository
                            hybrid_repo = load_hybrid_repository(
                                redis_repo=redis_repo,
                                postgres_repo=postgres_repo
                            )
                            if hybrid_repo:
                                self._feedback_repository = hybrid_repo
                                logger.info("Hybrid Feedback Repository created")
                            else:
                                raise ImportError("Hybrid repository loader returned None")
                        except Exception as e:
                            logger.warning(f"Hybrid repository creation failed: {e}")
                            # Fallback: Use PostgreSQL directly if available, otherwise Redis, otherwise Memory
                            if postgres_repo:
                                self._feedback_repository = postgres_repo
                                logger.info("Using PostgreSQL Feedback Repository directly (hybrid failed)")
                            elif redis_repo:
                                self._feedback_repository = redis_repo
                                logger.info("Using Redis Feedback Repository directly (hybrid failed)")
                            else:
                                from infrastructure.repositories.memory_feedback_repository import MemoryFeedbackRepository
                                self._feedback_repository = MemoryFeedbackRepository(max_size=10000)
                                logger.info("Memory Feedback Repository created (fallback)")
                    else:
                        # Fallback to memory
                        from infrastructure.repositories.memory_feedback_repository import MemoryFeedbackRepository
                        self._feedback_repository = MemoryFeedbackRepository(max_size=10000)
                        logger.info("Memory Feedback Repository created (fallback)")
                
                except Exception as e:
                    logger.warning(f"Hybrid repository creation failed: {e}, using memory")
                    from code_intent_service.infrastructure.repositories.feedback_buffer_repository import FeedbackBufferRepository
                    self._feedback_repository = FeedbackBufferRepository(max_size=10000)
            
            # Redis-only
            elif repo_type == "redis":
                try:
                    from code_intent_service.infrastructure.repositories.redis_feedback_repository import RedisFeedbackRepository
                    self._feedback_repository = RedisFeedbackRepository(
                        host=self.settings.get("REDIS_HOST") or os.getenv("REDIS_CLOUD_HOST"),
                        port=int(self.settings.get("REDIS_PORT") or os.getenv("REDIS_CLOUD_PORT", "6379")),
                        password=self.settings.get("REDIS_PASSWORD") or os.getenv("REDIS_CLOUD_PASSWORD"),
                        username=self.settings.get("REDIS_USERNAME") or os.getenv("REDIS_CLOUD_USERNAME"),
                        ttl_hours=int(self.settings.get("REDIS_TTL_HOURS", "720")),
                        ssl=bool(self.settings.get("REDIS_SSL", False))
                    )
                    logger.info("Redis Feedback Repository created")
                except Exception as e:
                    logger.warning(f"Redis repository creation failed: {e}, using memory")
                    from infrastructure.repositories.memory_feedback_repository import MemoryFeedbackRepository
                    self._feedback_repository = MemoryFeedbackRepository(max_size=10000)
            
            # PostgreSQL-only
            elif repo_type == "postgres":
                try:
                    # Use local PostgreSQL repository implementation (not code_intent_service)
                    from infrastructure.repositories.postgres_feedback_repository import PostgresFeedbackRepository
                    self._feedback_repository = PostgresFeedbackRepository(
                        connection_string=self.settings.get("POSTGRES_CONNECTION_STRING") or os.getenv("POSTGRES_CONNECTION_STRING")
                    )
                    logger.info("PostgreSQL Feedback Repository created (Orchestrator)")
                except Exception as e:
                    logger.warning(f"PostgreSQL repository creation failed: {e}, using memory", exc_info=True)
                    from infrastructure.repositories.memory_feedback_repository import MemoryFeedbackRepository
                    self._feedback_repository = MemoryFeedbackRepository(max_size=10000)
            
            # Memory (default)
            else:
                from infrastructure.repositories.memory_feedback_repository import MemoryFeedbackRepository
                self._feedback_repository = MemoryFeedbackRepository(max_size=10000)
                logger.info("Memory Feedback Repository created")
        
        return self._feedback_repository
    
    def create_feedback_collector(self) -> FeedbackCollector:
        """Create feedback collector with repository."""
        if self._feedback_collector is None:
            feedback_repo = self.create_feedback_repository()
            self._feedback_collector = FeedbackCollector(feedback_repository=feedback_repo)
            # Start async processing - nur wenn Event Loop läuft
            # Ansonsten wird start() später aufgerufen, wenn der Service verwendet wird
            import asyncio
            try:
                loop = asyncio.get_running_loop()
                # Event Loop läuft, erstelle Task
                asyncio.create_task(self._feedback_collector.start())
                logger.debug("FeedbackCollector start task created in running event loop")
            except RuntimeError:
                # Kein laufender Event Loop - start() wird später aufgerufen
                logger.debug("No running event loop, FeedbackCollector will start later")
            logger.info("FeedbackCollector created")
        return self._feedback_collector
    
    def create_policy_optimizer(self) -> AdaptivePolicyOptimizer:
        """Create policy optimizer."""
        if self._policy_optimizer is None:
            policy_engine = self.create_policy_engine()
            feedback_collector = self.create_feedback_collector()
            
            # Get policy config path
            if self.policy_path:
                config_path = Path(self.policy_path)
            else:
                config_dir = service_dir / "config"
                config_path = config_dir / "advanced_policies.yaml"
            
            self._policy_optimizer = AdaptivePolicyOptimizer(
                policy_engine=policy_engine,
                feedback_collector=feedback_collector,
                config_path=str(config_path)
            )
            logger.info("AdaptivePolicyOptimizer created")
        return self._policy_optimizer
    
    def create_router_service(self):
        """
        Create router service with all dependencies.
        
        Returns:
            BasicRouterService (Phase 5.1), IntelligentRouterService (Phase 5.2),
            or LearningRouterService (Phase 5.3)
        """
        if self._router_service is None:
            if self.enable_adaptive_learning and self.use_intelligent_router:
                # Phase 5.3: Learning Router
                policy_engine = self.create_policy_engine()
                feedback_collector = self.create_feedback_collector()
                policy_optimizer = self.create_policy_optimizer()
                
                self._router_service = LearningRouterService(
                    policy_engine=policy_engine,
                    detector_endpoints=self.detector_endpoints,
                    enable_adaptive_learning=True,
                    feedback_collector=feedback_collector,
                    policy_optimizer=policy_optimizer
                )
                
                logger.info("LearningRouterService created with all dependencies")
            elif self.use_intelligent_router:
                # Phase 5.2: Intelligent Router
                policy_engine = self.create_policy_engine()
                
                self._router_service = IntelligentRouterService(
                    policy_engine=policy_engine,
                    detector_endpoints=self.detector_endpoints,
                    enable_adaptive_learning=False
                )
                
                logger.info("IntelligentRouterService created with all dependencies")
            else:
                # Phase 5.1: Basic Router
                policy_engine = self.create_simple_policy_engine()
                
                self._router_service = BasicRouterService(
                    policy_engine=policy_engine,
                    detector_endpoints=self.detector_endpoints
                )
                
                logger.info("BasicRouterService created with all dependencies")
        
        return self._router_service
    
    def create_monitored_router_service(self) -> MonitoredRouterService:
        """Create monitored router service with full observability."""
        if self._monitored_service is None:
            try:
                # Erstelle direkt mit allen benötigten Komponenten
                policy_engine = self.create_policy_engine()
                
                # Nur Learning-Komponenten erstellen, wenn aktiviert
                feedback_collector = None
                policy_optimizer = None
                
                if self.enable_adaptive_learning:
                    # Erstelle Feedback Collector zuerst
                    feedback_collector = self.create_feedback_collector()
                    
                    # Erstelle Policy Optimizer (ruft intern create_feedback_collector auf,
                    # aber das ist OK wegen lazy initialization)
                    policy_optimizer = self.create_policy_optimizer()
                
                self._monitored_service = MonitoredRouterService(
                    policy_engine=policy_engine,
                    detector_endpoints=self.detector_endpoints,
                    enable_adaptive_learning=self.enable_adaptive_learning,
                    feedback_collector=feedback_collector,
                    policy_optimizer=policy_optimizer
                )
                
                logger.info(
                    f"MonitoredRouterService created with full observability "
                    f"(adaptive_learning={self.enable_adaptive_learning})"
                )
            except Exception as e:
                logger.error(f"Failed to create MonitoredRouterService: {e}", exc_info=True)
                raise
        
        return self._monitored_service
    
    def _create_default_policy_config(self, policy_path: Path):
        """Erstellt eine Standard-Policy-Konfiguration."""
        default_config = """version: "2.0.0"
description: "Default advanced routing policies"

policies:
  - name: "code_interpreter_workflow"
    priority: 100
    enabled: true
    activation_threshold: 0.7
    conditions:
      - type: "simple"
        expression: "context.get('source_tool') == 'code_interpreter'"
        description: "Code interpreter tool"
        weight: 1.0
    detectors:
      - name: "code_intent"
        mode: "required"
        timeout_ms: 500
        priority: 1
      - name: "content_safety"
        mode: "required"
        timeout_ms: 500
        priority: 2
    strategy: "parallel"
    max_latency: 1000

  - name: "default"
    priority: 10
    enabled: true
    activation_threshold: 0.3
    conditions:
      - type: "simple"
        expression: "True"
        description: "Default fallback"
        weight: 1.0
    detectors:
      - name: "content_safety"
        mode: "required"
        timeout_ms: 500
    strategy: "sequential"
    max_latency: 600
"""
        
        # Stelle sicher, dass das Verzeichnis existiert
        policy_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Schreibe Konfiguration
        with open(policy_path, 'w', encoding='utf-8') as f:
            f.write(default_config)
        
        logger.info(f"Created default policy config at {policy_path}")

