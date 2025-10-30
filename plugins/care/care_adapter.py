"""
PostgreSQL CARE Adapter
Creator: Joerg Bollwahn

This adapter connects the CARE Port to PostgreSQL.
Users must provide their own database with the required schema.
"""

from datetime import datetime
from typing import Dict, Optional

from .care_port import CAREPort, ReadinessScore


class PostgreSQLCAREAdapter(CAREPort):
    """
    PostgreSQL adapter for CARE functionality.
    
    PRIVACY-FIRST DESIGN:
    - Users must provide their own database connection
    - Schema is documented but not included
    - No personal data in package
    
    Required Database Schema:
        care_sessions (
            id SERIAL PRIMARY KEY,
            session_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT NOW(),
            facts_attempted INT,
            facts_supported INT,
            success_rate FLOAT,
            
            -- Cognitive State Features
            hyperfocus FLOAT,
            satisfaction FLOAT,
            arousal FLOAT,
            engagement FLOAT,
            
            -- Metadata
            duration_minutes INT,
            session_type TEXT
        )
        
        care_readiness_model (
            id SERIAL PRIMARY KEY,
            user_id TEXT NOT NULL,
            model_version TEXT,
            trained_on_n_sessions INT,
            last_training TIMESTAMP,
            model_parameters JSONB
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

    def get_readiness(self, user_id: str) -> ReadinessScore:
        """Get cognitive readiness score for user."""
        with self.conn.cursor() as cur:
            # Check if model exists
            cur.execute(
                "SELECT trained_on_n_sessions FROM care_readiness_model WHERE user_id = %s",
                (user_id,)
            )
            row = cur.fetchone()

            if not row or row[0] < 10:
                # Not enough data yet
                return ReadinessScore(
                    user_id=user_id,
                    readiness_score=0.5,
                    recommendation="MARGINAL",
                    factors={"insufficient_data": True},
                    timestamp=datetime.now(),
                    model_confidence=0.0
                )

            # Calculate readiness based on recent patterns
            cur.execute(
                """
                SELECT 
                    AVG(success_rate) as avg_success,
                    COUNT(*) as recent_sessions
                FROM care_sessions
                WHERE user_id = %s
                AND timestamp > NOW() - INTERVAL '7 days'
                """,
                (user_id,)
            )
            row = cur.fetchone()

            avg_success = row[0] if row[0] else 0.5
            recent_sessions = row[1]

            # Simple readiness calculation
            # Production would use trained ML model
            readiness_score = avg_success

            if readiness_score >= 0.6:
                recommendation = "READY"
            elif readiness_score >= 0.4:
                recommendation = "MARGINAL"
            else:
                recommendation = "NOT_READY"

            return ReadinessScore(
                user_id=user_id,
                readiness_score=readiness_score,
                recommendation=recommendation,
                factors={
                    "avg_success_7d": avg_success,
                    "recent_sessions": recent_sessions
                },
                timestamp=datetime.now(),
                model_confidence=0.7
            )

    def log_session(
        self,
        session_id: str,
        user_id: str,
        facts_attempted: int,
        facts_supported: int,
        cognitive_state: Optional[Dict] = None
    ) -> int:
        """Log research session to PostgreSQL."""
        success_rate = facts_supported / max(facts_attempted, 1)

        cognitive_state = cognitive_state or {}

        with self.conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO care_sessions
                (session_id, user_id, facts_attempted, facts_supported, success_rate,
                 hyperfocus, satisfaction, arousal, engagement)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    session_id, user_id, facts_attempted, facts_supported, success_rate,
                    cognitive_state.get('hyperfocus', 0.5),
                    cognitive_state.get('satisfaction', 0.5),
                    cognitive_state.get('arousal', 0.5),
                    cognitive_state.get('engagement', 0.5)
                )
            )
            session_log_id = cur.fetchone()[0]
            self.conn.commit()

            # Check if model needs retraining
            cur.execute(
                "SELECT COUNT(*) FROM care_sessions WHERE user_id = %s",
                (user_id,)
            )
            n_sessions = cur.fetchone()[0]

            # Retrain at milestones
            if n_sessions in [10, 25, 50, 100]:
                self._retrain_model(user_id, n_sessions)

            return session_log_id

    def _retrain_model(self, user_id: str, n_sessions: int):
        """Retrain readiness model (simplified)."""
        with self.conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO care_readiness_model
                (user_id, model_version, trained_on_n_sessions, last_training)
                VALUES (%s, %s, %s, NOW())
                ON CONFLICT (user_id) DO UPDATE SET
                    trained_on_n_sessions = %s,
                    last_training = NOW()
                """,
                (user_id, "v1.0", n_sessions, n_sessions)
            )
            self.conn.commit()

    def suggest_optimal_time(self, user_id: str) -> Dict:
        """Suggest optimal time for next session."""
        with self.conn.cursor() as cur:
            # Find best performing time windows
            cur.execute(
                """
                SELECT 
                    EXTRACT(HOUR FROM timestamp) as hour,
                    AVG(success_rate) as avg_success,
                    COUNT(*) as n_sessions
                FROM care_sessions
                WHERE user_id = %s
                GROUP BY EXTRACT(HOUR FROM timestamp)
                ORDER BY avg_success DESC
                LIMIT 1
                """,
                (user_id,)
            )
            row = cur.fetchone()

            if not row:
                return {
                    'suggestion': 'insufficient_data',
                    'rationale': 'Not enough sessions to suggest optimal time'
                }

            optimal_hour = int(row[0])
            avg_success = row[1]
            n_sessions = row[2]

            return {
                'suggestion': f"{optimal_hour:02d}:00",
                'avg_success': avg_success,
                'n_sessions': n_sessions,
                'rationale': f"Pattern shows {avg_success:.0%} success at {optimal_hour:02d}:00 (based on {n_sessions} sessions)"
            }

    def get_stats(self) -> Dict:
        """Get CARE system statistics."""
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT 
                    COUNT(*) as total_sessions,
                    AVG(success_rate) as avg_success_rate,
                    COUNT(DISTINCT user_id) as total_users
                FROM care_sessions
                """
            )
            row = cur.fetchone()

            cur.execute(
                "SELECT COUNT(*) FROM care_readiness_model"
            )
            models_trained = cur.fetchone()[0]

            return {
                'total_sessions': row[0],
                'success_rate': row[1] if row[1] else 0.0,
                'total_users': row[2],
                'models_trained': models_trained,
                'model_ready': models_trained > 0
            }

