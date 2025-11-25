"""Age-aware routing and decoding policy.

Provides age-band specific constraints for LLM generation:
- Token limits
- Temperature
- Reading grade
- Style requirements (bullet points, disclaimers)

Credit: GPT-5 collaboration 2025-11-04
"""

from dataclasses import dataclass
from typing import Dict, Any


@dataclass
class AgePolicy:
    """Policy constraints for a specific age band."""

    max_tokens: int
    temperature: float
    sentences_max: int
    reading_grade: int
    require_bullet_points: bool
    forbid_disclaimers: bool


class AgeRouter:
    """Routes age bands to appropriate generation policies."""

    def __init__(self, cfg: Dict[str, Any]):
        """Initialize with configuration from layer15.yaml.

        Args:
            cfg: Configuration dict from age_router section
        """
        self._bands = {}
        for k, v in cfg["bands"].items():
            self._bands[k] = AgePolicy(
                max_tokens=v["max_tokens"],
                temperature=v["temperature"],
                sentences_max=v["style"]["sentences_max"],
                reading_grade=v["style"]["reading_grade"],
                require_bullet_points=v["style"]["require_bullet_points"],
                forbid_disclaimers=v["style"]["forbid_disclaimers"],
            )

    def get(self, band: str) -> AgePolicy:
        """Get policy for specific age band.

        Args:
            band: Age band identifier (e.g., 'A6_8', 'A9_11')

        Returns:
            AgePolicy with constraints for that band

        Raises:
            KeyError: If band not recognized
        """
        if band not in self._bands:
            raise KeyError(f"Unknown age band: {band}")
        return self._bands[band]
