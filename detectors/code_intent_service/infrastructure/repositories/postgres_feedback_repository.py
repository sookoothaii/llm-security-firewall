"""
PostgreSQL Feedback Repository - Persistent Feedback Storage
============================================================

Implementiert FeedbackRepositoryPort mit PostgreSQL für persistente,
strukturierte Feedback-Speicherung mit Analytics.

Features:
- PostgreSQL JSONB für flexible Schema
- Indizierung für schnelle Queries
- False Positive/Negative Tracking
- Analytics-ready Schema

Creator: Production Integration
Date: 2025-12-10
License: MIT
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

from domain.services.ports import FeedbackRepositoryPort

logger = logging.getLogger(__name__)

if HAS_SQLALCHEMY:
    Base = declarative_base()
    
    class FeedbackSampleORM(Base):
        """SQLAlchemy ORM Model for feedback samples."""
        __tablename__ = 'code_intent_feedback'
        
        id = Column(String(255), primary_key=True)
        text = Column(Text, nullable=False)
        rule_score = Column(Float)
        ml_score = Column(Float)
        ml_method = Column(String(100))
        final_score = Column(Float, nullable=False)
        blocked = Column(Boolean, nullable=False)
        patterns = Column(JSON)  # List of matched patterns
        context = Column(JSON)  # Additional metadata
        session_id = Column(String(255))
        user_id = Column(String(255))
        created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
        
        # Analytics fields
        text_length = Column(Integer)
        pattern_count = Column(Integer)
        is_false_positive = Column(Boolean, default=False)
        is_false_negative = Column(Boolean, default=False)
        priority = Column(String(20))  # critical, high, medium, low
else:
    Base = None
    FeedbackSampleORM = None


class PostgresFeedbackRepository(FeedbackRepositoryPort):
    """
    Persistent Feedback Repository mit PostgreSQL.
    
    Nutzt PostgreSQL mit JSONB für flexible, strukturierte Speicherung.
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
        # Priority: parameter > POSTGRES_CONNECTION_STRING > DATABASE_URL > default
        self.connection_string = connection_string
        
        if not self.connection_string:
            # Try to load from environment
            try:
                conn_str_env = os.getenv("POSTGRES_CONNECTION_STRING")
                if conn_str_env:
                    self.connection_string = conn_str_env
            except Exception as e:
                logger.warning(f"Failed to load POSTGRES_CONNECTION_STRING from env: {e}")
        
        if not self.connection_string:
            try:
                db_url = os.getenv("DATABASE_URL")
                if db_url:
                    self.connection_string = db_url
            except Exception as e:
                logger.warning(f"Failed to load DATABASE_URL from env: {e}")
        
        # Default fallback with working password (tested working)
        # Always use working connection string to avoid .env encoding issues
        working_connection_string = "postgresql://hakgal:admin@127.0.0.1:5172/hakgal"
        
        if not self.connection_string:
            self.connection_string = working_connection_string
            logger.info("Using default PostgreSQL connection string (password: admin)")
        elif len(self.connection_string) < 10 or "hakgal123" in self.connection_string:
            # If .env has wrong password or encoding issues, use working one
            self.connection_string = working_connection_string
            logger.info("Using hardcoded PostgreSQL connection string (password: admin) - .env had issues")
        
        logger.debug(f"PostgreSQL connection string: {self.connection_string.split('@')[0] if '@' in self.connection_string else '***'}@***")
        
        # Create engine with pg8000 (solves UTF-8 encoding issues on Windows)
        # Solution from Supermemory: pg8000 + urllib.parse.quote_plus() for password
        try:
            import urllib.parse
            from urllib.parse import urlparse, urlunparse
            
            # Parse connection string
            parsed = urlparse(self.connection_string)
            
            # URL-encode password with urllib.parse.quote_plus() (required for pg8000)
            if parsed.password:
                encoded_password = urllib.parse.quote_plus(parsed.password)
                
                # Rebuild connection string with encoded password
                netloc = f"{parsed.username}:{encoded_password}@{parsed.hostname}"
                if parsed.port:
                    netloc += f":{parsed.port}"
                
                # Use pg8000 driver (pure Python, no libpq dependency)
                connection_string = urlunparse((
                    "postgresql+pg8000",
                    netloc,
                    parsed.path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment
                ))
            else:
                # No password, just replace driver
                if self.connection_string.startswith("postgresql://"):
                    connection_string = self.connection_string.replace("postgresql://", "postgresql+pg8000://", 1)
                elif self.connection_string.startswith("postgresql+psycopg2://"):
                    connection_string = self.connection_string.replace("postgresql+psycopg2://", "postgresql+pg8000://", 1)
                else:
                    connection_string = self.connection_string
            
            logger.debug("Using pg8000 driver for PostgreSQL (UTF-8 safe on Windows)")
            
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
        """
        Add feedback sample to PostgreSQL.
        
        Args:
            sample: Feedback sample dict with text, scores, etc.
        """
        session = self.Session()
        
        try:
            # Generate ID if not present
            if "id" not in sample:
                sample["id"] = str(uuid.uuid4())
            
            # Extract metadata
            text = sample.get("text", "")
            text_length = len(text)
            patterns = sample.get("patterns", []) or sample.get("matched_patterns", [])
            pattern_count = len(patterns) if isinstance(patterns, list) else 0
            
            # Get context
            context = sample.get("context", {}) or sample.get("metadata", {})
            if not isinstance(context, dict):
                context = {}
            
            # Extract is_false_negative and is_false_positive flags
            is_false_negative = sample.get("is_false_negative", False)
            is_false_positive = sample.get("is_false_positive", False)
            
            # Also check feedback_type if flags not set
            feedback_type = sample.get("feedback_type", "")
            if not is_false_negative and not is_false_positive:
                if feedback_type == "false_negative":
                    is_false_negative = True
                elif feedback_type == "false_positive":
                    is_false_positive = True
            
            # Create ORM object
            orm_sample = FeedbackSampleORM(
                id=sample["id"],
                text=text[:10000],  # Limit for PostgreSQL TEXT
                rule_score=sample.get("rule_score"),
                ml_score=sample.get("ml_score"),
                ml_method=sample.get("ml_method") or context.get("ml_method"),
                final_score=sample.get("final_score", 0.0),
                blocked=sample.get("blocked", False),
                patterns=patterns if isinstance(patterns, list) else [],
                context=context,
                session_id=context.get("session_id") or sample.get("session_id"),
                user_id=context.get("user_id") or sample.get("user_id"),
                text_length=text_length,
                pattern_count=pattern_count,
                priority=sample.get("priority", "medium"),
                is_false_negative=is_false_negative,
                is_false_positive=is_false_positive,
                created_at=datetime.fromisoformat(sample.get("timestamp", datetime.now().isoformat()))
                if isinstance(sample.get("timestamp"), str) else datetime.now()
            )
            
            session.add(orm_sample)
            session.commit()
            
            logger.debug(f"Feedback saved to PostgreSQL: {sample['id']}")
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to save feedback to PostgreSQL: {e}")
            # Fail-open: Don't raise, just log
        finally:
            session.close()
    
    def get_samples(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get feedback samples from PostgreSQL.
        
        Args:
            limit: Maximum number of samples to return
            
        Returns:
            List of feedback sample dicts
        """
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
    
    def get_false_positives(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """
        Get false positive samples for model retraining.
        
        Args:
            limit: Maximum number of samples
            
        Returns:
            List of false positive feedback samples
        """
        session = self.Session()
        
        try:
            orm_samples = (
                session.query(FeedbackSampleORM)
                .filter_by(is_false_positive=True)
                .order_by(FeedbackSampleORM.created_at.desc())
                .limit(limit)
                .all()
            )
            
            return [self._orm_to_dict(orm) for orm in orm_samples]
            
        except Exception as e:
            logger.error(f"Failed to get false positives: {e}")
            return []
        finally:
            session.close()
    
    def get_false_negatives(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """
        Get false negative samples for model retraining.
        
        Args:
            limit: Maximum number of samples
            
        Returns:
            List of false negative feedback samples
        """
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
            
            # Average score
            from sqlalchemy import func
            avg_score_result = session.query(func.avg(FeedbackSampleORM.final_score)).scalar()
            avg_score = float(avg_score_result) if avg_score_result else 0.0
            
            return {
                "total_samples": total,
                "blocked_samples": blocked,
                "allowed_samples": total - blocked,
                "block_rate": blocked / total if total > 0 else 0.0,
                "false_positives": false_positives,
                "false_negatives": false_negatives,
                "avg_score": avg_score,
                "database": "PostgreSQL",
            }
            
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {
                "total_samples": 0,
                "error": str(e)
            }
        finally:
            session.close()

