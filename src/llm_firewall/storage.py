"""
Persistence Layer for Session Storage (PostgreSQL + SQLite Support)

Replaces in-memory SESSION_STORE with database-backed storage.
State (HierarchicalMemory) survives server restarts.

Creator: Joerg Bollwahn
Date: 2025-11-19
License: MIT
"""

import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any
from pathlib import Path

from sqlalchemy import create_engine, Column, String, DateTime, JSON, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.dialects.postgresql import JSONB

logger = logging.getLogger(__name__)

Base = declarative_base()


class SessionModel(Base):
    """
    SQLAlchemy model for session storage.
    
    Supports both PostgreSQL (JSONB) and SQLite (JSON/Text).
    """
    __tablename__ = "sessions"
    
    session_id = Column(String(255), primary_key=True)
    data = Column(JSON)  # Will be JSONB for PostgreSQL, JSON for SQLite
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<SessionModel(session_id={self.session_id}, last_updated={self.last_updated})>"


class StorageManager:
    """
    Manages persistent storage for HierarchicalMemory objects.
    
    Supports:
    - PostgreSQL (uses JSONB for efficiency)
    - SQLite (uses JSON/Text)
    """
    
    def __init__(self, connection_string: Optional[str] = None):
        """
        Initialize storage manager.
        
        Args:
            connection_string: Database URL (e.g., 'postgresql://user:pass@localhost/db' or 'sqlite:///./hak_gal.db')
                              If None, defaults to SQLite: 'sqlite:///./hak_gal.db'
        """
        if connection_string is None:
            # Default: SQLite in project root
            db_path = Path(__file__).parent.parent.parent / "hak_gal.db"
            connection_string = f"sqlite:///{db_path}"
            logger.info(f"Using default SQLite database: {db_path}")
        
        self.connection_string = connection_string
        self.is_postgresql = connection_string.startswith("postgresql://")
        
        # Create engine
        if self.is_postgresql:
            # PostgreSQL: Use JSONB for efficiency
            self.engine = create_engine(
                connection_string,
                pool_pre_ping=True,  # Verify connections before using
                echo=False  # Set to True for SQL debugging
            )
            logger.info("Storage: Using PostgreSQL with JSONB")
        else:
            # SQLite: Use JSON (stored as TEXT)
            self.engine = create_engine(
                connection_string,
                connect_args={"check_same_thread": False}  # SQLite threading
            )
            logger.info("Storage: Using SQLite with JSON")
        
        # Create session factory
        self.SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        
        # Create tables if they don't exist
        Base.metadata.create_all(bind=self.engine)
        logger.info("Storage: Tables created/verified")
    
    def save_session(self, session_id: str, memory_obj) -> bool:
        """
        Save HierarchicalMemory object to database.
        
        Args:
            session_id: Session identifier
            memory_obj: HierarchicalMemory instance (must have to_dict() method)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Serialize memory object to dict
            if hasattr(memory_obj, 'to_dict'):
                data_dict = memory_obj.to_dict()
            else:
                # Fallback: try to convert to dict directly
                logger.warning(f"Memory object {type(memory_obj)} has no to_dict() method, using fallback")
                data_dict = {
                    "session_id": getattr(memory_obj, 'session_id', session_id),
                    "max_phase_ever": getattr(memory_obj, 'max_phase_ever', 0),
                    "latent_risk_multiplier": getattr(memory_obj, 'latent_risk_multiplier', 1.0),
                    "tool_counts": dict(getattr(memory_obj, 'tool_counts', {})),
                    "start_time": getattr(memory_obj, 'start_time', 0.0),
                    "tactical_buffer": [],  # Events are complex, skip for now
                    "recent_phases": list(getattr(memory_obj, 'recent_phases', [])),
                    "phase_transitions": {}  # MarkovChain is complex, skip for now
                }
            
            db_session = self.SessionLocal()
            try:
                # Check if session exists
                existing = db_session.query(SessionModel).filter_by(session_id=session_id).first()
                
                if existing:
                    # Update existing
                    existing.data = data_dict
                    existing.last_updated = datetime.utcnow()
                else:
                    # Create new
                    new_session = SessionModel(
                        session_id=session_id,
                        data=data_dict,
                        last_updated=datetime.utcnow()
                    )
                    db_session.add(new_session)
                
                db_session.commit()
                logger.debug(f"Storage: Saved session {session_id}")
                return True
            except Exception as e:
                db_session.rollback()
                logger.error(f"Storage: Error saving session {session_id}: {e}", exc_info=True)
                return False
            finally:
                db_session.close()
        except Exception as e:
            logger.error(f"Storage: Fatal error saving session {session_id}: {e}", exc_info=True)
            return False
    
    def load_session(self, session_id: str):
        """
        Load HierarchicalMemory object from database.
        
        Args:
            session_id: Session identifier
            
        Returns:
            HierarchicalMemory instance or None if not found
        """
        try:
            db_session = self.SessionLocal()
            try:
                session_record = db_session.query(SessionModel).filter_by(session_id=session_id).first()
                
                if session_record is None:
                    logger.debug(f"Storage: Session {session_id} not found")
                    return None
                
                # Deserialize data dict
                data_dict = session_record.data
                
                # Import here to avoid circular dependencies
                from llm_firewall.agents.memory import HierarchicalMemory
                
                # Reconstruct HierarchicalMemory from dict
                if hasattr(HierarchicalMemory, 'from_dict'):
                    memory_obj = HierarchicalMemory.from_dict(data_dict)
                else:
                    # Fallback: manual reconstruction
                    logger.warning(f"HierarchicalMemory has no from_dict() method, using fallback")
                    memory_obj = HierarchicalMemory(session_id=session_id)
                    memory_obj.max_phase_ever = data_dict.get("max_phase_ever", 0)
                    memory_obj.latent_risk_multiplier = data_dict.get("latent_risk_multiplier", 1.0)
                    memory_obj.tool_counts = data_dict.get("tool_counts", {})
                    memory_obj.start_time = data_dict.get("start_time", 0.0)
                    # Note: tactical_buffer and phase_transitions are complex, skip for now
                
                logger.debug(f"Storage: Loaded session {session_id}")
                return memory_obj
            except Exception as e:
                logger.error(f"Storage: Error loading session {session_id}: {e}", exc_info=True)
                return None
            finally:
                db_session.close()
        except Exception as e:
            logger.error(f"Storage: Fatal error loading session {session_id}: {e}", exc_info=True)
            return None
    
    def delete_session(self, session_id: str) -> bool:
        """
        Delete a session from database.
        
        Args:
            session_id: Session identifier
            
        Returns:
            True if successful, False otherwise
        """
        try:
            db_session = self.SessionLocal()
            try:
                session_record = db_session.query(SessionModel).filter_by(session_id=session_id).first()
                if session_record:
                    db_session.delete(session_record)
                    db_session.commit()
                    logger.debug(f"Storage: Deleted session {session_id}")
                    return True
                else:
                    logger.debug(f"Storage: Session {session_id} not found for deletion")
                    return False
            except Exception as e:
                db_session.rollback()
                logger.error(f"Storage: Error deleting session {session_id}: {e}", exc_info=True)
                return False
            finally:
                db_session.close()
        except Exception as e:
            logger.error(f"Storage: Fatal error deleting session {session_id}: {e}", exc_info=True)
            return False

