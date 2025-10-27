"""
PostgreSQL Personality Adapter
Creator: Joerg Bollwahn

This adapter connects the Personality Port to PostgreSQL.
Users must provide their own database with the required schema.
"""

from typing import Optional
from .personality_port import PersonalityPort, PersonalityProfile


class PostgreSQLPersonalityAdapter(PersonalityPort):
    """
    PostgreSQL adapter for personality functionality.
    
    PRIVACY-FIRST DESIGN:
    - Users must provide their own database connection
    - Schema is documented but not included
    - No personal data in package
    
    Required Database Schema:
        personality_profiles (
            id SERIAL PRIMARY KEY,
            person_name TEXT NOT NULL,
            openness FLOAT,
            conscientiousness FLOAT,
            extraversion FLOAT,
            agreeableness FLOAT,
            neuroticism FLOAT,
            truth_over_comfort FLOAT,
            iterative_rigor FLOAT,
            bullshit_tolerance FLOAT,
            formality_preference FLOAT,
            risk_tolerance FLOAT,
            emoji_tolerance FLOAT,
            detail_level FLOAT,
            directness FLOAT,
            question_style FLOAT,
            systems_thinking FLOAT,
            pattern_recognition FLOAT,
            abstract_vs_concrete FLOAT,
            precision_priority FLOAT,
            honesty_absoluteness FLOAT,
            evidence_requirement FLOAT,
            confidence_score FLOAT,
            interaction_count INT,
            context_tags TEXT[]
        )
        
        personality_interactions (
            id SERIAL PRIMARY KEY,
            person_name TEXT NOT NULL,
            interaction_type TEXT,
            content TEXT,
            outcome TEXT,
            timestamp TIMESTAMP DEFAULT NOW()
        )
    """
    
    def __init__(self, db_connection):
        """
        Initialize PostgreSQL adapter.
        
        Args:
            db_connection: psycopg3 connection object
        """
        if db_connection is None:
            raise ValueError(
                "PostgreSQL adapter requires a database connection. "
                "You must provide your own database. "
                "See documentation for required schema."
            )
        self.conn = db_connection
    
    def get_personality_profile(self, user_id: str) -> Optional[PersonalityProfile]:
        """Get personality profile from PostgreSQL."""
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT 
                    person_name, openness, conscientiousness, extraversion,
                    agreeableness, neuroticism, truth_over_comfort, iterative_rigor,
                    bullshit_tolerance, formality_preference, risk_tolerance,
                    emoji_tolerance, detail_level, directness, question_style,
                    systems_thinking, pattern_recognition, abstract_vs_concrete,
                    precision_priority, honesty_absoluteness, evidence_requirement,
                    confidence_score, interaction_count, context_tags
                FROM personality_profiles
                WHERE person_name = %s
                """,
                (user_id,)
            )
            row = cur.fetchone()
            
            if not row:
                return None
            
            return PersonalityProfile(
                user_id=row[0],
                openness=row[1],
                conscientiousness=row[2],
                extraversion=row[3],
                agreeableness=row[4],
                neuroticism=row[5],
                truth_over_comfort=row[6],
                iterative_rigor=row[7],
                bullshit_tolerance=row[8],
                formality_preference=row[9],
                risk_tolerance=row[10],
                emoji_tolerance=row[11],
                detail_level=row[12],
                directness=row[13],
                question_style=row[14],
                systems_thinking=row[15],
                pattern_recognition=row[16],
                abstract_vs_concrete=row[17],
                precision_priority=row[18],
                honesty_absoluteness=row[19],
                evidence_requirement=row[20],
                confidence_score=row[21],
                interaction_count=row[22],
                context_tags=row[23] or []
            )
    
    def log_interaction(
        self,
        user_id: str,
        interaction_type: str,
        content: str,
        outcome: str
    ) -> int:
        """Log interaction to PostgreSQL."""
        with self.conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO personality_interactions
                (person_name, interaction_type, content, outcome)
                VALUES (%s, %s, %s, %s)
                RETURNING id
                """,
                (user_id, interaction_type, content, outcome)
            )
            interaction_id = cur.fetchone()[0]
            self.conn.commit()
            return interaction_id
    
    def adapt_response(
        self,
        user_id: str,
        draft_response: str,
        context: Optional[str] = None
    ) -> str:
        """
        Adapt response based on personality profile.
        
        PERSONA/EPISTEMIK SEPARATION:
        - Personality affects ONLY: tone, format, detail level
        - Personality affects NEVER: thresholds, gates, epistemic decisions
        """
        profile = self.get_personality_profile(user_id)
        
        if not profile:
            return draft_response
        
        adapted = draft_response
        
        # Adapt based on directness
        if profile.directness > 0.8:
            # High directness: Remove softeners
            adapted = adapted.replace("maybe", "")
            adapted = adapted.replace("perhaps", "")
            adapted = adapted.replace("might", "")
        
        # Adapt based on emoji tolerance
        if profile.emoji_tolerance < 0.1:
            # Remove emojis for low tolerance users
            import re
            # Remove common emojis (simplified)
            adapted = re.sub(r'[\\U0001F600-\\U0001F64F]', '', adapted)
        
        # Adapt based on formality
        if profile.formality_preference > 0.7:
            # High formality: More formal language
            adapted = adapted.replace("you're", "you are")
            adapted = adapted.replace("don't", "do not")
        
        return adapted

