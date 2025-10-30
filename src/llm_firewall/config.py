"""
Configuration settings for LLM Security Firewall.
Environment-based configuration with sensible defaults.
"""

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    """Global settings for firewall components."""

    # Regex generation
    max_gap: int = int(os.getenv("LLMFW_MAX_GAP", "3"))

    # Ensemble/Stacking
    use_meta_ensemble: bool = os.getenv("LLMFW_USE_META_ENSEMBLE", "0") == "1"

    # Thresholds (calibrated offline; defaults are placeholders)
    risk_threshold: float = float(os.getenv("LLMFW_RISK_THRESHOLD", "0.5"))

    # Lexicon base directory (auto-detected)
    lexicon_base: Path | None = None  # Set by _pick_lex_base()

    def __post_init__(self):
        """Initialize lexicon base if not set."""
        if self.lexicon_base is None:
            object.__setattr__(self, "lexicon_base", _pick_lex_base())


def _pick_lex_base() -> Path:
    """
    Automatically detect lexicon directory with fallback chain.

    Priority:
    1. lexicons_gpt5/ (GPT-5 Detection Pack)
    2. lexicons/ (default)
    3. Raise error if neither exists

    Returns:
        Path to lexicon directory

    Raises:
        FileNotFoundError: If no lexicon directory found
    """
    base_dir = Path(__file__).parent

    # Try GPT-5 lexicons first
    gpt5_lex = base_dir / "lexicons_gpt5"
    if (gpt5_lex / "intents.json").exists():
        return gpt5_lex

    # Fall back to default lexicons
    default_lex = base_dir / "lexicons"
    if (default_lex / "intents.json").exists():
        return default_lex

    # No lexicons found - fail loudly
    raise FileNotFoundError(
        f"Lexicons missing. Checked:\n"
        f"  - {gpt5_lex}\n"
        f"  - {default_lex}\n"
        f"Ensure repository is properly synced."
    )


# Global settings instance
SETTINGS = Settings()
