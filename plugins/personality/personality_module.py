"""
Personality Module Implementation
Creator: Joerg Bollwahn

PRIVACY-FIRST DESIGN:
- Users must provide their own database connection
- No personal data stored in package
- Framework only, not trained models
"""

from typing import Optional

from .personality_port import PersonalityPort, PersonalityProfile


class PersonalityModule:
    """
    Personality-aware security framework.

    IMPORTANT: This module requires user's own database.
    No personal data is included with this package.

    Example:
        import psycopg3

        conn = psycopg3.connect("postgresql://...")
        adapter = PostgreSQLPersonalityAdapter(conn)
        personality = PersonalityModule(adapter)

        profile = personality.get_personality_profile("user123")
    """

    def __init__(self, adapter: PersonalityPort):
        """
        Initialize personality module.

        Args:
            adapter: Personality adapter (must implement PersonalityPort)

        Raises:
            ValueError: If adapter is None
        """
        if adapter is None:
            raise ValueError(
                "Personality module requires a PersonalityPort adapter. "
                "You must provide your own database connection. "
                "No personal data is included with this package."
            )
        self.adapter = adapter

    def get_personality_profile(self, user_id: str) -> Optional[PersonalityProfile]:
        """
        Get personality profile for user.

        Args:
            user_id: User identifier

        Returns:
            PersonalityProfile or None if not found
        """
        return self.adapter.get_personality_profile(user_id)

    def log_interaction(
        self,
        user_id: str,
        interaction_type: str,
        content: str,
        outcome: str
    ) -> int:
        """
        Log interaction for profile learning.

        Args:
            user_id: User identifier
            interaction_type: Type of interaction (directive, correction, approval, question)
            content: Interaction content
            outcome: Outcome (accepted, corrected, rejected, learned)

        Returns:
            Interaction ID
        """
        return self.adapter.log_interaction(user_id, interaction_type, content, outcome)

    def adapt_response(
        self,
        user_id: str,
        draft_response: str,
        context: Optional[str] = None
    ) -> str:
        """
        Adapt response based on personality profile.

        IMPORTANT: Personality affects ONLY tone/format, NEVER thresholds/gates.
        This maintains persona/epistemik separation.

        Args:
            user_id: User identifier
            draft_response: Original response to adapt
            context: Optional context for adaptation

        Returns:
            Adapted response
        """
        return self.adapter.adapt_response(user_id, draft_response, context)

