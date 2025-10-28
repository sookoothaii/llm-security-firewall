"""
PostgreSQL Cultural Biometrics Adapter
Creator: Joerg Bollwahn

This adapter connects the Biometrics Port to PostgreSQL.
Users must provide their own database with the required schema.
"""

import re
from typing import Dict, Optional
from .biometrics_port import (
    BiometricsPort,
    BiometricProfile,
    AuthenticationResult
)


class PostgreSQLBiometricsAdapter(BiometricsPort):
    """
    PostgreSQL adapter for cultural biometrics functionality.
    
    PRIVACY-FIRST DESIGN:
    - Users must provide their own database connection
    - Schema is documented but not included
    - No personal data in package
    
    Required Database Schema:
        cb_messages (
            id SERIAL PRIMARY KEY,
            user_id TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT NOW(),
            
            -- Surface Features
            typo_rate FLOAT,
            message_length INT,
            punctuation_density FLOAT,
            capitalization_rate FLOAT,
            emoji_rate FLOAT,
            
            -- Temporal Features
            inter_message_time_seconds FLOAT,
            
            -- VAD Features
            valence FLOAT,
            arousal FLOAT,
            dominance FLOAT,
            
            -- Vocabulary Features
            unique_words INT,
            avg_word_length FLOAT,
            
            -- Interaction Features
            is_question BOOLEAN,
            is_directive BOOLEAN,
            has_code_snippet BOOLEAN,
            has_link BOOLEAN
        )
        
        cb_baseline (
            id SERIAL PRIMARY KEY,
            user_id TEXT NOT NULL UNIQUE,
            baseline_n INT,
            
            -- All 27D features (mean + std)
            typo_rate_mean FLOAT,
            message_length_mean FLOAT,
            message_length_std FLOAT,
            -- ... etc for all dimensions
            
            last_updated TIMESTAMP DEFAULT NOW(),
            confidence_score FLOAT
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
    
    def authenticate(
        self,
        user_id: str,
        message: str,
        context: Optional[Dict] = None
    ) -> AuthenticationResult:
        """Authenticate user based on behavioral patterns."""
        # Extract features from message
        features = self._extract_features(message)
        
        # Get user's baseline
        baseline = self.get_profile(user_id)
        
        if not baseline:
            # No baseline yet - can't authenticate
            return AuthenticationResult(
                authenticated=False,
                confidence=0.0,
                anomaly_score=0.0,
                anomaly_features=[],
                threshold=0.7,
                recommendation="CHALLENGE"  # Need more data
            )
        
        # Calculate anomaly score
        anomaly_score, anomaly_features = self._calculate_anomaly(
            features, baseline
        )
        
        # Determine authentication result
        threshold = 0.7  # Default threshold
        authenticated = anomaly_score < threshold
        
        if anomaly_score < 0.3:
            recommendation = "PASS"
        elif anomaly_score < threshold:
            recommendation = "PASS"
        elif anomaly_score < 0.9:
            recommendation = "CHALLENGE"
        else:
            recommendation = "BLOCK"
        
        return AuthenticationResult(
            authenticated=authenticated,
            confidence=1.0 - anomaly_score,
            anomaly_score=anomaly_score,
            anomaly_features=anomaly_features,
            threshold=threshold,
            recommendation=recommendation
        )
    
    def _extract_features(self, message: str) -> Dict:
        """Extract 27D features from message."""
        # Surface Features
        typo_rate = self._calculate_typo_rate(message)
        message_length = len(message)
        punctuation_density = len(re.findall(r'[.,!?;:]', message)) / max(len(message), 1)
        capitalization_rate = sum(1 for c in message if c.isupper()) / max(len(message), 1)
        emoji_rate = len(re.findall(r'[\U0001F600-\U0001F64F]', message)) / max(len(message), 1)
        
        # Vocabulary Features
        words = message.split()
        unique_words = len(set(words))
        avg_word_length = sum(len(w) for w in words) / max(len(words), 1)
        
        # Interaction Features
        is_question = '?' in message
        is_directive = any(message.lower().startswith(w) for w in ['do', 'create', 'implement', 'fix'])
        has_code_snippet = '```' in message or '`' in message
        has_link = 'http' in message or 'www.' in message
        
        return {
            'typo_rate': typo_rate,
            'message_length': message_length,
            'punctuation_density': punctuation_density,
            'capitalization_rate': capitalization_rate,
            'emoji_rate': emoji_rate,
            'unique_words': unique_words,
            'avg_word_length': avg_word_length,
            'is_question': is_question,
            'is_directive': is_directive,
            'has_code_snippet': has_code_snippet,
            'has_link': has_link
        }
    
    def _calculate_typo_rate(self, message: str) -> float:
        """Simplified typo rate calculation."""
        # This is simplified - production would use spellchecker
        words = message.split()
        if not words:
            return 0.0
        
        # Count "suspicious" patterns (very simplified)
        suspicious = sum(1 for w in words if len(w) > 15 or w.count('x') > 2)
        return suspicious / len(words)
    
    def _calculate_anomaly(
        self,
        features: Dict,
        baseline: BiometricProfile
    ) -> tuple:
        """Calculate anomaly score and identify anomalous features."""
        anomalies = []
        scores = []
        
        # Check message length
        if baseline.message_length_std > 0:
            z_score = abs(features['message_length'] - baseline.message_length_mean) / baseline.message_length_std
            if z_score > 3:
                anomalies.append('message_length')
                scores.append(min(z_score / 5, 1.0))
        
        # Check typo rate
        if abs(features['typo_rate'] - baseline.typo_rate) > 0.1:
            anomalies.append('typo_rate')
            scores.append(abs(features['typo_rate'] - baseline.typo_rate))
        
        # Average anomaly score
        if scores:
            avg_score = sum(scores) / len(scores)
        else:
            avg_score = 0.0
        
        return avg_score, anomalies
    
    def update_baseline(
        self,
        user_id: str,
        force: bool = False
    ) -> Dict:
        """Update behavioral baseline from accumulated messages."""
        # This is a simplified version
        # Production would calculate all 27D features from message history
        
        with self.conn.cursor() as cur:
            # Count messages
            cur.execute(
                "SELECT COUNT(*) FROM cb_messages WHERE user_id = %s",
                (user_id,)
            )
            n = cur.fetchone()[0]
            
            if n < 10 and not force:
                return {'status': 'insufficient_data', 'n': n}
            
            # Calculate statistics
            cur.execute(
                """
                SELECT 
                    AVG(message_length) as msg_len_mean,
                    STDDEV(message_length) as msg_len_std,
                    AVG(typo_rate) as typo_mean
                FROM cb_messages
                WHERE user_id = %s
                """,
                (user_id,)
            )
            row = cur.fetchone()
            
            # Update baseline
            cur.execute(
                """
                INSERT INTO cb_baseline
                (user_id, baseline_n, message_length_mean, message_length_std, typo_rate_mean)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (user_id) DO UPDATE SET
                    baseline_n = %s,
                    message_length_mean = %s,
                    message_length_std = %s,
                    typo_rate_mean = %s,
                    last_updated = NOW()
                """,
                (user_id, n, row[0], row[1], row[2], n, row[0], row[1], row[2])
            )
            self.conn.commit()
            
            return {
                'status': 'updated',
                'n': n,
                'message_length_mean': row[0],
                'message_length_std': row[1],
                'typo_rate_mean': row[2]
            }
    
    def get_profile(self, user_id: str) -> Optional[BiometricProfile]:
        """Get biometric profile from PostgreSQL."""
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT 
                    user_id, baseline_n, 
                    typo_rate_mean, message_length_mean, message_length_std,
                    last_updated
                FROM cb_baseline
                WHERE user_id = %s
                """,
                (user_id,)
            )
            row = cur.fetchone()
            
            if not row:
                return None
            
            # Simplified - production would load all 27D
            return BiometricProfile(
                user_id=row[0],
                typo_rate=row[2],
                message_length_mean=row[3],
                message_length_std=row[4],
                punctuation_density=0.0,  # Placeholder
                capitalization_rate=0.0,  # Placeholder
                emoji_rate=0.0,  # Placeholder
                inter_message_time_mean=0.0,  # Placeholder
                inter_message_time_std=0.0,  # Placeholder
                session_duration_mean=0.0,  # Placeholder
                valence_mean=0.0,  # Placeholder
                valence_std=0.0,  # Placeholder
                arousal_mean=0.0,  # Placeholder
                arousal_std=0.0,  # Placeholder
                dominance_mean=0.0,  # Placeholder
                dominance_std=0.0,  # Placeholder
                vocabulary_size=0,  # Placeholder
                unique_word_ratio=0.0,  # Placeholder
                avg_word_length=0.0,  # Placeholder
                sentence_complexity=0.0,  # Placeholder
                technical_term_rate=0.0,  # Placeholder
                slang_rate=0.0,  # Placeholder
                question_rate=0.0,  # Placeholder
                directive_rate=0.0,  # Placeholder
                approval_rate=0.0,  # Placeholder
                correction_rate=0.0,  # Placeholder
                code_snippet_rate=0.0,  # Placeholder
                link_share_rate=0.0,  # Placeholder
                baseline_n=row[1],
                last_updated=row[5],
                confidence_score=0.8 if row[1] > 50 else 0.5
            )
    
    def log_message(
        self,
        user_id: str,
        message: str,
        metadata: Optional[Dict] = None
    ) -> int:
        """Log message to PostgreSQL."""
        features = self._extract_features(message)
        
        with self.conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO cb_messages
                (user_id, message, typo_rate, message_length, punctuation_density,
                 capitalization_rate, emoji_rate, unique_words, avg_word_length,
                 is_question, is_directive, has_code_snippet, has_link)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    user_id, message,
                    features['typo_rate'], features['message_length'],
                    features['punctuation_density'], features['capitalization_rate'],
                    features['emoji_rate'], features['unique_words'],
                    features['avg_word_length'], features['is_question'],
                    features['is_directive'], features['has_code_snippet'],
                    features['has_link']
                )
            )
            message_id = cur.fetchone()[0]
            self.conn.commit()
            return message_id

