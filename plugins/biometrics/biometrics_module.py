"""
Cultural Biometrics Module Implementation
Creator: Joerg Bollwahn

WORLD-FIRST: 27D behavioral authentication for Human/LLM interfaces.

PRIVACY-FIRST DESIGN:
- Users must provide their own database connection
- No personal behavioral data stored in package
- Framework only, not trained baselines
"""

from typing import Dict, Optional
from .biometrics_port import BiometricsPort, BiometricProfile, AuthenticationResult


class BiometricsModule:
    """
    Cultural Biometrics authentication module.
    
    WORLD-FIRST INNOVATION:
    This is the first behavioral authentication system specifically
    designed for Human/LLM interaction patterns.
    
    Traditional biometrics (fingerprint, face) don't work for text.
    This system uses 27 behavioral dimensions to detect:
    - Impersonation attempts
    - Account takeover
    - Anomalous behavior patterns
    
    IMPORTANT: This module requires user's own database.
    No personal data is included with this package.
    
    Example:
        import psycopg3
        
        conn = psycopg3.connect("postgresql://...")
        adapter = PostgreSQLBiometricsAdapter(conn)
        biometrics = BiometricsModule(adapter)
        
        result = biometrics.authenticate("user123", "Hello world")
        
        if result.authenticated:
            # Proceed with request
            pass
        elif result.recommendation == "CHALLENGE":
            # Request additional verification
            pass
        else:
            # Block suspicious request
            pass
    """
    
    def __init__(self, adapter: BiometricsPort):
        """
        Initialize cultural biometrics module.
        
        Args:
            adapter: Biometrics adapter (must implement BiometricsPort)
        
        Raises:
            ValueError: If adapter is None
        """
        if adapter is None:
            raise ValueError(
                "Biometrics module requires a BiometricsPort adapter. "
                "You must provide your own database connection. "
                "No personal data is included with this package."
            )
        self.adapter = adapter
    
    def authenticate(
        self,
        user_id: str,
        message: str,
        context: Optional[Dict] = None
    ) -> AuthenticationResult:
        """
        Authenticate user based on behavioral patterns.
        
        Args:
            user_id: User identifier
            message: Message to analyze
            context: Optional context (timestamp, session_id, etc.)
            
        Returns:
            AuthenticationResult with recommendation
        """
        return self.adapter.authenticate(user_id, message, context)
    
    def update_baseline(
        self,
        user_id: str,
        force: bool = False
    ) -> Dict:
        """
        Update behavioral baseline.
        
        Baselines should be updated periodically:
        - After 10 messages (initial)
        - After 50 messages
        - After 100 messages
        - After 500 messages
        - After 1000 messages
        
        Args:
            user_id: User identifier
            force: Force update regardless of message count
            
        Returns:
            Update statistics
        """
        return self.adapter.update_baseline(user_id, force)
    
    def get_profile(self, user_id: str) -> Optional[BiometricProfile]:
        """
        Get biometric profile for user.
        
        Args:
            user_id: User identifier
            
        Returns:
            BiometricProfile or None if not found
        """
        return self.adapter.get_profile(user_id)
    
    def log_message(
        self,
        user_id: str,
        message: str,
        metadata: Optional[Dict] = None
    ) -> int:
        """
        Log message for behavioral analysis.
        
        Args:
            user_id: User identifier
            message: Message content
            metadata: Optional metadata (timestamp, session_id, etc.)
            
        Returns:
            Message ID
        """
        return self.adapter.log_message(user_id, message, metadata)

