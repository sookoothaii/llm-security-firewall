"""
CARE Module Implementation
Creator: Joerg Bollwahn

Cognitive And Research Effectiveness (CARE) System.

PRIVACY-FIRST DESIGN:
- Users must provide their own database connection
- No personal cognitive data stored in package
- Framework only, not trained models

Philosophy:
"Kluge Care auf Augenhoehe wie Forschungspartner die nicht verwandt sind -
 nicht bemuttern sondern sukzessive mit viel Humor auf mich einstellen"

CARE behaves as RESEARCH PARTNER, not as parent/therapist/moral police.
"""

from typing import Dict, Optional

from .care_port import CAREPort, ReadinessScore


class CAREModule:
    """
    Cognitive And Research Effectiveness assessment module.

    CARE predicts research session success based on cognitive state patterns.

    Key Innovation:
    - NOT a wellness app
    - NOT a productivity tracker
    - RESEARCH PARTNER on equal footing

    CARE observes patterns, suggests hypotheses, lets user decide.
    No moralizing. No bevormundung (paternalism).

    Example:
        import psycopg3

        conn = psycopg3.connect("postgresql://...")
        adapter = PostgreSQLCAREAdapter(conn)
        care = CAREModule(adapter)

        readiness = care.get_readiness("user123")

        if readiness.recommendation == "READY":
            print(f"Good time for research! ({readiness.readiness_score:.0%})")
        elif readiness.recommendation == "MARGINAL":
            print(f"Pattern suggests {readiness.readiness_score:.0%} success.")
            print("Your choice - CARE only observes, you decide.")
        else:
            print(f"Pattern suggests low success ({readiness.readiness_score:.0%}).")
            print("But you know yourself best - CARE could be wrong.")
    """

    def __init__(self, adapter: CAREPort):
        """
        Initialize CARE module.

        Args:
            adapter: CARE adapter (must implement CAREPort)

        Raises:
            ValueError: If adapter is None
        """
        if adapter is None:
            raise ValueError(
                "CARE module requires a CAREPort adapter. "
                "You must provide your own database connection. "
                "No personal data is included with this package."
            )
        self.adapter = adapter

    def get_readiness(self, user_id: str) -> ReadinessScore:
        """
        Get current cognitive readiness score.

        IMPORTANT: This is a SUGGESTION, not a command.
        CARE observes patterns but user always decides.

        Args:
            user_id: User identifier

        Returns:
            ReadinessScore with recommendation
        """
        return self.adapter.get_readiness(user_id)

    def log_session(
        self,
        session_id: str,
        user_id: str,
        facts_attempted: int,
        facts_supported: int,
        cognitive_state: Optional[Dict] = None
    ) -> int:
        """
        Log research session outcome.

        This data enables CARE to learn patterns and improve predictions.

        Args:
            session_id: Session identifier
            user_id: User identifier
            facts_attempted: Number of facts attempted
            facts_supported: Number of facts successfully supported
            cognitive_state: Optional cognitive state features

        Returns:
            Session log ID
        """
        return self.adapter.log_session(
            session_id, user_id, facts_attempted, facts_supported, cognitive_state
        )

    def suggest_optimal_time(self, user_id: str) -> Dict:
        """
        Suggest optimal time for next research session.

        IMPORTANT: This is adaptive scheduling, not rigid rules.
        User can override at any time.

        Args:
            user_id: User identifier

        Returns:
            Suggestion dictionary with rationale
        """
        return self.adapter.suggest_optimal_time(user_id)

    def get_stats(self) -> Dict:
        """
        Get CARE system statistics.

        Returns:
            Statistics dictionary (sessions, success rate, model status)
        """
        return self.adapter.get_stats()

