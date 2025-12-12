"""
Code Intent Repository Loader

Lädt Code Intent Repositories mit korrektem Import-Pfad.
"""
import sys
import logging
from pathlib import Path
from typing import Optional, Any

logger = logging.getLogger(__name__)


def load_postgres_repository(connection_string: Optional[str] = None) -> Optional[Any]:
    """
    Lädt PostgreSQL Feedback Repository von Code Intent Service.
    
    Returns:
        PostgresFeedbackRepository instance oder None bei Fehler
    """
    try:
        # Finde code_intent_service Verzeichnis
        orchestrator_dir = Path(__file__).parent.parent.parent
        detectors_dir = orchestrator_dir.parent
        code_intent_service_dir = detectors_dir / "code_intent_service"
        
        if not code_intent_service_dir.exists():
            logger.warning(f"Code Intent Service directory not found: {code_intent_service_dir}")
            return None
        
        # Füge code_intent_service zum sys.path hinzu
        code_intent_path = str(code_intent_service_dir)
        if code_intent_path not in sys.path:
            sys.path.insert(0, code_intent_path)
        
        # Importiere direkt aus der Datei, um __init__.py zu umgehen
        import importlib.util
        
        postgres_file = code_intent_service_dir / "infrastructure" / "repositories" / "postgres_feedback_repository.py"
        if not postgres_file.exists():
            logger.warning(f"PostgreSQL repository file not found: {postgres_file}")
            return None
        
        spec = importlib.util.spec_from_file_location(
            "postgres_feedback_repo_module",
            postgres_file
        )
        if spec is None or spec.loader is None:
            logger.warning(f"Could not create spec for PostgreSQL repository")
            return None
        
        module = importlib.util.module_from_spec(spec)
        # Setze __package__ und __name__ für korrekte Imports
        module.__package__ = "code_intent_service.infrastructure.repositories"
        module.__name__ = "postgres_feedback_repo_module"
        sys.modules[module.__name__] = module
        
        # Führe das Modul aus
        spec.loader.exec_module(module)
        
        # Erstelle Repository-Instanz
        PostgresFeedbackRepository = getattr(module, "PostgresFeedbackRepository")
        repo = PostgresFeedbackRepository(connection_string=connection_string)
        
        logger.info("PostgreSQL Feedback Repository loaded successfully")
        return repo
        
    except Exception as e:
        logger.warning(f"Failed to load PostgreSQL repository: {e}", exc_info=True)
        return None


def load_redis_repository(
    host: Optional[str] = None,
    port: Optional[int] = None,
    password: Optional[str] = None,
    username: Optional[str] = None,
    ttl_hours: int = 720,
    ssl: bool = True
) -> Optional[Any]:
    """
    Lädt Redis Feedback Repository von Code Intent Service.
    
    Returns:
        RedisFeedbackRepository instance oder None bei Fehler
    """
    try:
        # Finde code_intent_service Verzeichnis
        orchestrator_dir = Path(__file__).parent.parent.parent
        detectors_dir = orchestrator_dir.parent
        code_intent_service_dir = detectors_dir / "code_intent_service"
        
        if not code_intent_service_dir.exists():
            logger.warning(f"Code Intent Service directory not found: {code_intent_service_dir}")
            return None
        
        # Füge code_intent_service zum sys.path hinzu
        code_intent_path = str(code_intent_service_dir)
        if code_intent_path not in sys.path:
            sys.path.insert(0, code_intent_path)
        
        # Importiere direkt aus der Datei, um __init__.py zu umgehen
        import importlib.util
        
        redis_file = code_intent_service_dir / "infrastructure" / "repositories" / "redis_feedback_repository.py"
        if not redis_file.exists():
            logger.warning(f"Redis repository file not found: {redis_file}")
            return None
        
        spec = importlib.util.spec_from_file_location(
            "redis_feedback_repo_module",
            redis_file
        )
        if spec is None or spec.loader is None:
            logger.warning(f"Could not create spec for Redis repository")
            return None
        
        module = importlib.util.module_from_spec(spec)
        # Setze __package__ und __name__ für korrekte Imports
        module.__package__ = "code_intent_service.infrastructure.repositories"
        module.__name__ = "redis_feedback_repo_module"
        sys.modules[module.__name__] = module
        
        # Führe das Modul aus
        spec.loader.exec_module(module)
        
        # Erstelle Repository-Instanz
        RedisFeedbackRepository = getattr(module, "RedisFeedbackRepository")
        repo = RedisFeedbackRepository(
            host=host,
            port=port,
            password=password,
            username=username,
            ttl_hours=ttl_hours,
            ssl=ssl
        )
        
        logger.info("Redis Feedback Repository loaded successfully")
        return repo
        
    except Exception as e:
        logger.warning(f"Failed to load Redis repository: {e}", exc_info=True)
        return None


def load_hybrid_repository(
    redis_repo: Optional[Any] = None,
    postgres_repo: Optional[Any] = None
) -> Optional[Any]:
    """
    Lädt Hybrid Feedback Repository von Code Intent Service.
    
    Returns:
        HybridFeedbackRepository instance oder None bei Fehler
    """
    try:
        # Finde code_intent_service Verzeichnis
        orchestrator_dir = Path(__file__).parent.parent.parent
        detectors_dir = orchestrator_dir.parent
        code_intent_service_dir = detectors_dir / "code_intent_service"
        
        if not code_intent_service_dir.exists():
            logger.warning(f"Code Intent Service directory not found: {code_intent_service_dir}")
            return None
        
        # Füge code_intent_service zum sys.path hinzu
        code_intent_path = str(code_intent_service_dir)
        if code_intent_path not in sys.path:
            sys.path.insert(0, code_intent_path)
        
        # Importiere direkt aus der Datei, um __init__.py zu umgehen
        import importlib.util
        
        hybrid_file = code_intent_service_dir / "infrastructure" / "repositories" / "hybrid_feedback_repository.py"
        if not hybrid_file.exists():
            logger.warning(f"Hybrid repository file not found: {hybrid_file}")
            return None
        
        spec = importlib.util.spec_from_file_location(
            "hybrid_feedback_repo_module",
            hybrid_file
        )
        if spec is None or spec.loader is None:
            logger.warning(f"Could not create spec for Hybrid repository")
            return None
        
        module = importlib.util.module_from_spec(spec)
        # Setze __package__ und __name__ für korrekte Imports
        module.__package__ = "code_intent_service.infrastructure.repositories"
        module.__name__ = "hybrid_feedback_repo_module"
        sys.modules[module.__name__] = module
        
        # Führe das Modul aus
        spec.loader.exec_module(module)
        
        # Erstelle Repository-Instanz
        HybridFeedbackRepository = getattr(module, "HybridFeedbackRepository")
        from infrastructure.repositories.memory_feedback_repository import MemoryFeedbackRepository
        memory_repo = MemoryFeedbackRepository(max_size=10000)
        
        repo = HybridFeedbackRepository(
            redis_repo=redis_repo,
            postgres_repo=postgres_repo,
            memory_repo=memory_repo
        )
        
        logger.info("Hybrid Feedback Repository loaded successfully")
        return repo
        
    except Exception as e:
        logger.warning(f"Failed to load Hybrid repository: {e}", exc_info=True)
        return None

