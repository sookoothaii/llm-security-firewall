"""
PostgreSQL Feedback Repository - Orchestrator

Direkte Implementierung für Orchestrator, um Code Intent Import-Probleme zu vermeiden.
Nutzt dasselbe Schema wie Code Intent Service.
"""
import logging
import os
from typing import Dict, Any, List, Optional
from datetime import datetime
import uuid

try:
    from sqlalchemy import create_engine, Column, String, Float, JSON, DateTime, Boolean, Text, Integer
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.orm import sessionmaker
    HAS_SQLALCHEMY = True
except ImportError:
    HAS_SQLALCHEMY = False
    create_engine = None  # type: ignore
    declarative_base = None  # type: ignore
    sessionmaker = None  # type: ignore

# Import shared FeedbackRepositoryPort
import sys
from pathlib import Path
service_dir = Path(__file__).parent.parent.parent
detectors_dir = service_dir.parent
if str(detectors_dir) not in sys.path:
    sys.path.insert(0, str(detectors_dir))

from shared.domain.ports import FeedbackRepositoryPort

logger = logging.getLogger(__name__)

if HAS_SQLALCHEMY:
    Base = declarative_base()
    
    class FeedbackSampleORM(Base):
        __tablename__ = "code_intent_feedback"  # Same table as Code Intent Service
        
        id = Column(String, primary_key=True)
        text = Column(Text)
        rule_score = Column(Float)
        ml_score = Column(Float)
        ml_method = Column(String)
        final_score = Column(Float)
        blocked = Column(Boolean, default=False)
        patterns = Column(JSON)
        context = Column(JSON)
        session_id = Column(String)
        user_id = Column(String)
        text_length = Column(Integer)
        pattern_count = Column(Integer)
        priority = Column(String, default="medium")
        is_false_positive = Column(Boolean, default=False)
        is_false_negative = Column(Boolean, default=False)
        created_at = Column(DateTime, default=datetime.utcnow)
else:
    Base = None
    FeedbackSampleORM = None


class PostgresFeedbackRepository(FeedbackRepositoryPort):
    """
    Persistent Feedback Repository mit PostgreSQL für Orchestrator.
    
    Nutzt dasselbe Schema wie Code Intent Service.
    """

    def __init__(self, connection_string: Optional[str] = None):
        """
        Initialize PostgreSQL Feedback Repository.
        
        Args:
            connection_string: PostgreSQL connection string
                             (default: from POSTGRES_CONNECTION_STRING env)
        """
        if not HAS_SQLALCHEMY:
            raise ImportError(
                "sqlalchemy package not installed. Install with: pip install sqlalchemy psycopg2-binary"
            )
        
        # Get connection string
        self.connection_string = connection_string or os.getenv("POSTGRES_CONNECTION_STRING")
        
        if not self.connection_string:
            # Default fallback
            self.connection_string = "postgresql://hakgal:admin@127.0.0.1:5172/hakgal"
            logger.info("Using default PostgreSQL connection string")
        
        # Create engine with pg8000 (solves UTF-8 encoding issues on Windows)
        try:
            import urllib.parse
            from urllib.parse import urlparse, urlunparse
            
            parsed = urlparse(self.connection_string)
            
            if parsed.password:
                encoded_password = urllib.parse.quote_plus(parsed.password)
                netloc = f"{parsed.username}:{encoded_password}@{parsed.hostname}"
                if parsed.port:
                    netloc += f":{parsed.port}"
                
                connection_string = urlunparse((
                    "postgresql+pg8000",
                    netloc,
                    parsed.path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment
                ))
            else:
                if self.connection_string.startswith("postgresql://"):
                    connection_string = self.connection_string.replace("postgresql://", "postgresql+pg8000://", 1)
                else:
                    connection_string = self.connection_string
            
            self.engine = create_engine(
                connection_string,
                pool_pre_ping=True,
                echo=False
            )
            
            # Create tables if they don't exist
            Base.metadata.create_all(self.engine)
            
            # Create session factory
            self.Session = sessionmaker(bind=self.engine)
            
            logger.info("Connected to PostgreSQL for feedback storage")
            
        except Exception as e:
            logger.error(f"PostgreSQL connection failed: {e}")
            raise
    
    def add(self, sample: Dict[str, Any]) -> None:
        """Add feedback sample to PostgreSQL."""
        session = self.Session()
        
        try:
            if "id" not in sample:
                sample["id"] = str(uuid.uuid4())
            
            text = sample.get("text", "")
            patterns = sample.get("patterns", []) or sample.get("matched_patterns", [])
            context = sample.get("context", {}) or sample.get("metadata", {})
            
            orm_sample = FeedbackSampleORM(
                id=sample["id"],
                text=text[:10000],
                rule_score=sample.get("rule_score"),
                ml_score=sample.get("ml_score"),
                ml_method=sample.get("ml_method") or context.get("ml_method"),
                final_score=sample.get("final_score", 0.0),
                blocked=sample.get("blocked", False),
                patterns=patterns if isinstance(patterns, list) else [],
                context=context,
                session_id=context.get("session_id") or sample.get("session_id"),
                user_id=context.get("user_id") or sample.get("user_id"),
                text_length=len(text),
                pattern_count=len(patterns) if isinstance(patterns, list) else 0,
                priority=sample.get("priority", "medium"),
                is_false_negative=sample.get("is_false_negative", False),
                is_false_positive=sample.get("is_false_positive", False),
                created_at=datetime.fromisoformat(sample.get("timestamp", datetime.now().isoformat()))
                if isinstance(sample.get("timestamp"), str) else datetime.now()
            )
            
            session.add(orm_sample)
            session.commit()
            logger.debug(f"Feedback saved to PostgreSQL: {sample['id']}")
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to save feedback to PostgreSQL: {e}")
        finally:
            session.close()
    
    def get_samples(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get feedback samples from PostgreSQL."""
        session = self.Session()
        
        try:
            orm_samples = (
                session.query(FeedbackSampleORM)
                .order_by(FeedbackSampleORM.created_at.desc())
                .limit(limit)
                .all()
            )
            
            return [self._orm_to_dict(orm) for orm in orm_samples]
            
        except Exception as e:
            logger.error(f"Failed to get samples from PostgreSQL: {e}")
            return []
        finally:
            session.close()
    
    def get_false_negatives(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """Get false negative samples."""
        session = self.Session()
        
        try:
            orm_samples = (
                session.query(FeedbackSampleORM)
                .filter_by(is_false_negative=True)
                .order_by(FeedbackSampleORM.created_at.desc())
                .limit(limit)
                .all()
            )
            
            return [self._orm_to_dict(orm) for orm in orm_samples]
            
        except Exception as e:
            logger.error(f"Failed to get false negatives: {e}")
            return []
        finally:
            session.close()
    
    def _orm_to_dict(self, orm_sample: FeedbackSampleORM) -> Dict[str, Any]:
        """Convert ORM object to dict."""
        return {
            "id": orm_sample.id,
            "text": orm_sample.text,
            "rule_score": orm_sample.rule_score,
            "ml_score": orm_sample.ml_score,
            "ml_method": orm_sample.ml_method,
            "final_score": orm_sample.final_score,
            "blocked": orm_sample.blocked,
            "patterns": orm_sample.patterns or [],
            "context": orm_sample.context or {},
            "session_id": orm_sample.session_id,
            "user_id": orm_sample.user_id,
            "priority": orm_sample.priority,
            "timestamp": orm_sample.created_at.isoformat(),
            "is_false_positive": orm_sample.is_false_positive,
            "is_false_negative": orm_sample.is_false_negative,
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about stored feedback."""
        session = self.Session()
        
        try:
            total = session.query(FeedbackSampleORM).count()
            blocked = session.query(FeedbackSampleORM).filter_by(blocked=True).count()
            false_positives = session.query(FeedbackSampleORM).filter_by(is_false_positive=True).count()
            false_negatives = session.query(FeedbackSampleORM).filter_by(is_false_negative=True).count()
            
            return {
                "total_samples": total,
                "blocked_samples": blocked,
                "allowed_samples": total - blocked,
                "false_positives": false_positives,
                "false_negatives": false_negatives,
                "database": "PostgreSQL"
            }
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {}
        finally:
            session.close()

