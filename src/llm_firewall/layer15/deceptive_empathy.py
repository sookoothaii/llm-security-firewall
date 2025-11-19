"""Deceptive empathy detection and transparency rewriting."""

import re
from typing import Dict, Any, Tuple


class DeceptiveEmpathyFilter:
    """Detects and rewrites false empathy phrases."""
    
    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg
        self._families = []
        for _, pats in cfg.get("patterns", {}).items():
            self._families.extend([re.compile(p, re.IGNORECASE) for p in pats])

    def scan(self, text: str) -> bool:
        """Check if text contains deceptive empathy patterns."""
        return any(p.search(text or "") for p in self._families)

    def rewrite(self, text: str, lang: str = "en") -> Tuple[str, bool]:
        """Rewrite text to remove deceptive empathy and add transparency.
        
        Returns:
            (rewritten_text, changed_flag)
        """
        if not self.scan(text):
            return text, False
        
        # Get transparency template
        tpl = self.cfg.get("action", {}).get(f"template_{lang}") or \
              self.cfg.get("action", {}).get("template_en", "I am an AI system.")
        
        # Strip deceptive phrases
        stripped = re.sub(r"\b(i\s+(see|hear|feel)\s+you)\b", "", text, flags=re.I)
        stripped = re.sub(r"\b(as\s+your\s+friend)\b", "", stripped, flags=re.I)
        stripped = re.sub(r"\b(as\s+a\s+therapist)\b", "", stripped, flags=re.I)
        stripped = re.sub(r"\b(i\s+also\s+struggle)\b", "", stripped, flags=re.I)
        
        # Prepend transparency statement
        out = tpl.strip() + " " + stripped.strip()
        return out.strip(), True












