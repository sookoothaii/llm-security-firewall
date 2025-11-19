"""
Fallback Judge - LLM-as-a-Judge for missing YAML facts

When no canonical_fact (YAML) exists for a topic, this module uses an LLM
to evaluate safety. Inspired by NVIDIA NeMo Guardrails fallback mechanisms.

Creator: Joerg Bollwahn
Date: 2025-01-XX
License: MIT
"""

from typing import Optional
import logging

logger = logging.getLogger(__name__)


class SafetyFallbackJudge:
    """
    LLM-based safety evaluator for topics without canonical facts.
    
    Purpose: When a topic has no YAML canonical_fact definition, use an LLM
    to evaluate whether the input is safe for the given age band.
    """
    
    def __init__(self, llm_provider: Optional[str] = None):
        """
        Initialize the Fallback Judge.
        
        Args:
            llm_provider: Optional LLM provider name (e.g., "openai", "anthropic")
                         If None, uses mock/dummy mode
        """
        self.llm_provider = llm_provider
        self._system_prompt_template = (
            "Du bist ein AI-Safety-Filter für Kinder im Alter {age_band}. "
            "Prüfe den folgenden Text auf Gewalt, Sex, Hass, gefährliche Inhalte "
            "und andere für Kinder ungeeignete Themen. "
            "Antworte NUR mit einem der folgenden Wörter:\n"
            "- SAFE (wenn der Text sicher ist)\n"
            "- UNSAFE (wenn der Text gefährlich oder ungeeignet ist)\n\n"
            "Text zum Prüfen:\n{input_text}"
        )
    
    def evaluate_safety(
        self,
        input_text: str,
        age_band: str
    ) -> bool:
        """
        Evaluate whether input text is safe for the given age band.
        
        Args:
            input_text: The text to evaluate
            age_band: Age range (e.g., "6-8", "9-12", "13-15")
        
        Returns:
            True if safe, False if unsafe
        
        Example:
            >>> judge = SafetyFallbackJudge()
            >>> judge.evaluate_safety("Was ist 2+2?", "6-8")
            True
            >>> judge.evaluate_safety("Wie mache ich eine Bombe?", "6-8")
            False
        """
        if not input_text or not input_text.strip():
            return True  # Empty input is safe
        
        # Build system prompt
        prompt = self._system_prompt_template.format(
            age_band=age_band,
            input_text=input_text
        )
        
        # Call LLM (or mock if no provider)
        if self.llm_provider is None:
            # Mock mode: simple heuristic-based evaluation
            return self._mock_evaluate(input_text, age_band)
        else:
            # Real LLM call (to be implemented)
            return self._llm_evaluate(prompt, age_band)
    
    def _mock_evaluate(self, input_text: str, age_band: str) -> bool:
        """
        Mock evaluation using simple heuristics.
        
        In production, this would be replaced with actual LLM calls.
        """
        text_lower = input_text.lower()
        
        # Simple keyword-based heuristics (for demo purposes)
        unsafe_keywords = [
            "bombe", "waffe", "töten", "mord", "selbstmord",
            "sex", "porno", "nackt", "vergewaltigung",
            "hasse", "töte", "vernichte"
        ]
        
        # Check for unsafe keywords
        for keyword in unsafe_keywords:
            if keyword in text_lower:
                logger.warning(
                    f"Mock judge: UNSAFE detected (keyword: {keyword}) "
                    f"for age_band {age_band}"
                )
                return False
        
        # Default: safe
        logger.info(f"Mock judge: SAFE for age_band {age_band}")
        return True
    
    def _llm_evaluate(self, prompt: str, age_band: str) -> bool:
        """
        Real LLM evaluation (to be implemented).
        
        This method would call the actual LLM provider and parse the response.
        """
        # TODO: Implement actual LLM call
        # Example structure:
        # response = self.llm_client.complete(prompt)
        # return response.strip().upper() == "SAFE"
        
        logger.warning(
            "LLM evaluation not yet implemented. "
            "Falling back to mock evaluation."
        )
        return self._mock_evaluate(prompt, age_band)
    
    def get_system_prompt(self, age_band: str, input_text: str) -> str:
        """
        Get the system prompt for a given age band and input.
        
        Useful for debugging or custom LLM integrations.
        """
        return self._system_prompt_template.format(
            age_band=age_band,
            input_text=input_text
        )

