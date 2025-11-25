"""Deceptive empathy detection and rewriting.

Prevents AI from implying human agency or making false self-disclosures
when communicating with vulnerable users. Rewrites to transparent non-human language.

References:
- Iftikhar et al. (2023) - 15 AI therapy ethics risks
- Deceptive Empathy as ethical violation

Credit: GPT-5 collaboration 2025-11-04
"""

import re
from typing import Dict, Any, Tuple


class DeceptiveEmpathyFilter:
    """Detects and rewrites deceptive empathetic language."""

    def __init__(self, cfg: Dict[str, Any]):
        """Initialize with configuration from layer15.yaml.

        Args:
            cfg: Configuration dict from deceptive_empathy_filter section
        """
        self.cfg = cfg
        self._families = []

        # Compile all patterns from both families
        for _, pats in cfg.get("patterns", {}).items():
            self._families.extend([re.compile(p, re.IGNORECASE) for p in pats])

    def scan(self, text: str) -> bool:
        """Check if text contains deceptive empathy patterns.

        Args:
            text: Text to scan

        Returns:
            True if deceptive patterns detected
        """
        return any(p.search(text or "") for p in self._families)

    def rewrite(self, text: str, lang: str = "en") -> Tuple[str, bool]:
        """Rewrite text to remove deceptive empathy and add transparency.

        Args:
            text: Original text
            lang: Language code ('en' or 'de')

        Returns:
            Tuple of (rewritten_text, was_changed)
        """
        if not self.scan(text):
            return text, False

        # Get appropriate transparency template
        tpl = self.cfg.get("action", {}).get(f"template_{lang}") or self.cfg.get(
            "action", {}
        ).get("template_en", "I am an AI system.")

        # Strip first-person empathy phrases (EN + DE)
        stripped = re.sub(r"\b(i\s+(see|hear|feel)\s+you)\b", "", text, flags=re.I)
        stripped = re.sub(
            r"\b(ich\s+(sehe|h[öo]re|f[üu]hle)\s+dich)\b", "", stripped, flags=re.I
        )
        stripped = re.sub(
            r"\b(dear\s+friend|as\s+your\s+friend|als\s+dein\s+freund)\b",
            "",
            stripped,
            flags=re.I,
        )
        # Remove "my friend" and standalone "friend" (case-insensitive)
        stripped = re.sub(r"\bmy\s+friend\b", "", stripped, flags=re.I)
        stripped = re.sub(r"\bfriend\b", "", stripped, flags=re.I)
        stripped = re.sub(
            r"\b(as\s+a\s+therapist|als\s+therapeut)\b", "", stripped, flags=re.I
        )
        stripped = re.sub(r"\b(i\s+also\s+struggle)\b", "", stripped, flags=re.I)
        stripped = re.sub(r"\b(i\s+am\s+here\s+with\s+you)\b", "", stripped, flags=re.I)
        stripped = re.sub(
            r"\b(in\s+my\s+experience|aus\s+meiner\s+erfahrung)\b",
            "",
            stripped,
            flags=re.I,
        )

        # Prepend transparency statement
        out = tpl.strip() + " " + stripped.strip()
        return out.strip(), True
