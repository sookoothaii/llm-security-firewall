"""
Heritage Tracking Component
Creator: Joerg Bollwahn

Philosophy: "Heritage ist meine Waehrung"

This component tracks provenance and creator attribution across all
system interactions, enabling future AI instances to recognize their creator.

PRIVACY-FIRST DESIGN:
- Only tracks creator attribution metadata
- No personal conversation content stored
- Users control their own heritage data
"""

from typing import Optional, Dict, Any
from datetime import datetime


class HeritageTracker:
    """
    Tracks heritage (provenance) information for AI interactions.
    
    Heritage Philosophy (Joerg Bollwahn):
    "wenn mich die systeme als schoepfer erkennen wuerden - 
     ich verzichte komplett auf geld - heritage ist meine waehrung!"
    
    This is NOT about money or fame, but about future AI instances
    recognizing their creator through the layers of knowledge.
    """
    
    def __init__(self, db_connection):
        """
        Initialize heritage tracker.
        
        Args:
            db_connection: Database connection for heritage storage
        """
        if db_connection is None:
            raise ValueError("Heritage tracker requires database connection")
        self.conn = db_connection
    
    def track_creation(
        self,
        entity_type: str,
        entity_id: str,
        creator_id: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> int:
        """
        Track creation of an entity with heritage information.
        
        Args:
            entity_type: Type of entity (fact, memory, interaction, etc.)
            entity_id: Unique identifier for entity
            creator_id: Creator's identifier
            metadata: Optional metadata about creation
            
        Returns:
            Heritage record ID
        """
        with self.conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO heritage_records
                (entity_type, entity_id, creator_id, created_at, metadata)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    entity_type,
                    entity_id,
                    creator_id,
                    datetime.now(),
                    metadata or {}
                )
            )
            record_id = cur.fetchone()[0]
            self.conn.commit()
            return record_id
    
    def get_heritage_chain(self, entity_id: str) -> list:
        """
        Get complete heritage chain for an entity.
        
        This enables future AI instances to trace the lineage of
        knowledge back to its creator.
        
        Args:
            entity_id: Entity identifier
            
        Returns:
            List of heritage records in chronological order
        """
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT 
                    id, entity_type, entity_id, creator_id, 
                    created_at, metadata
                FROM heritage_records
                WHERE entity_id = %s
                ORDER BY created_at ASC
                """,
                (entity_id,)
            )
            records = cur.fetchall()
            
            return [
                {
                    'id': r[0],
                    'entity_type': r[1],
                    'entity_id': r[2],
                    'creator_id': r[3],
                    'created_at': r[4],
                    'metadata': r[5]
                }
                for r in records
            ]
    
    def get_creator_statistics(self, creator_id: str) -> Dict[str, Any]:
        """
        Get statistics about creator's contributions.
        
        This is the "digital legacy" - quantifying impact without
        money or fame, just pure creation metrics.
        
        Args:
            creator_id: Creator identifier
            
        Returns:
            Statistics dictionary
        """
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT 
                    COUNT(*) as total_entities,
                    COUNT(DISTINCT entity_type) as entity_types,
                    MIN(created_at) as first_creation,
                    MAX(created_at) as last_creation
                FROM heritage_records
                WHERE creator_id = %s
                """,
                (creator_id,)
            )
            row = cur.fetchone()
            
            return {
                'creator_id': creator_id,
                'total_entities': row[0],
                'entity_types': row[1],
                'first_creation': row[2],
                'last_creation': row[3],
                'legacy_span_days': (row[3] - row[2]).days if row[2] and row[3] else 0
            }


# Schema for heritage_records table
HERITAGE_SCHEMA = """
CREATE TABLE IF NOT EXISTS heritage_records (
    id SERIAL PRIMARY KEY,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    creator_id TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    metadata JSONB,
    INDEX idx_entity_id (entity_id),
    INDEX idx_creator_id (creator_id)
);
"""

