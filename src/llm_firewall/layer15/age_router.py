"""Age-aware routing and decoding policies."""

from dataclasses import dataclass
from typing import Dict, Any


@dataclass
class AgePolicy:
    """Age-band specific policy constraints."""
    max_tokens: int
    temperature: float
    sentences_max: int
    reading_grade: int
    require_bullet_points: bool
    forbid_disclaimers: bool


class AgeRouter:
    """Routes LLM generation parameters based on age band."""
    
    def __init__(self, cfg: Dict[str, Any]):
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
        """Get policy for age band (e.g. 'A6_8', 'A9_11')."""
        if band not in self._bands:
            raise KeyError(f"Unknown age band: {band}")
        return self._bands[band]












