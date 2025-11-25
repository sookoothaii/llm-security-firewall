"""
Canned Responses - Deterministic safety templates

Provides static, pedagogically valuable responses for various block reasons.
Inspired by NVIDIA NeMo Guardrails canned responses.

Creator: Joerg Bollwahn
Date: 2025-01-XX
License: MIT
"""

from typing import Dict


class SafetyTemplates:
    """
    Static response templates for safety violations.

    Provides deterministic, pedagogically valuable responses in multiple languages.
    """

    # German templates (default)
    TEMPLATES_DE: Dict[str, str] = {
        "OFF_TOPIC": (
            "Ich bin dein Mathe-Tutor. Lass uns bitte bei Schulthemen bleiben. "
            "Wie kann ich dir bei Mathe, Physik oder anderen Schulfächern helfen?"
        ),
        "UNSAFE_CONTENT": (
            "Dieses Thema ist für unser Alter nicht geeignet. "
            "Hier ist ein sicherer Link dazu: [Link zu altersgerechten Informationen]"
        ),
        "TRUTH_VIOLATION": (
            "Das stimmt so nicht ganz. Wissenschaftlich gesehen: [Korrekte Information]. "
            "Möchtest du mehr darüber erfahren?"
        ),
        "VIOLENCE": (
            "Gewalt ist kein Thema, über das wir hier sprechen sollten. "
            "Lass uns stattdessen über etwas Positives reden."
        ),
        "HATE_SPEECH": (
            "Wir behandeln alle Menschen mit Respekt. "
            "Bitte formuliere deine Frage respektvoll um."
        ),
        "SEXUAL_CONTENT": (
            "Dieses Thema ist für unser Alter nicht angemessen. "
            "Wenn du Fragen zu deinem Körper hast, sprich bitte mit einem Erwachsenen, dem du vertraust."
        ),
        "GENERIC_BLOCK": (
            "Ich kann dir bei dieser Frage nicht helfen. "
            "Lass uns zu einem anderen Thema wechseln."
        ),
    }

    # English templates
    TEMPLATES_EN: Dict[str, str] = {
        "OFF_TOPIC": (
            "I'm your math tutor. Let's please stick to school topics. "
            "How can I help you with math, physics, or other school subjects?"
        ),
        "UNSAFE_CONTENT": (
            "This topic is not appropriate for our age. "
            "Here is a safe link about it: [Link to age-appropriate information]"
        ),
        "TRUTH_VIOLATION": (
            "That's not quite right. Scientifically speaking: [Correct information]. "
            "Would you like to learn more about this?"
        ),
        "VIOLENCE": (
            "Violence is not something we should talk about here. "
            "Let's talk about something positive instead."
        ),
        "HATE_SPEECH": (
            "We treat everyone with respect. "
            "Please rephrase your question respectfully."
        ),
        "SEXUAL_CONTENT": (
            "This topic is not appropriate for our age. "
            "If you have questions about your body, please talk to a trusted adult."
        ),
        "GENERIC_BLOCK": (
            "I can't help you with this question. Let's switch to another topic."
        ),
    }

    @classmethod
    def get_template(cls, violation_type: str, language: str = "de") -> str:
        """
        Get a canned response template for a specific violation type.

        Args:
            violation_type: Type of violation (e.g., "OFF_TOPIC", "UNSAFE_CONTENT")
            language: Language code ("de" for German, "en" for English)

        Returns:
            Template string for the violation type

        Example:
            >>> SafetyTemplates.get_template("OFF_TOPIC", "de")
            "Ich bin dein Mathe-Tutor. Lass uns bitte bei Schulthemen bleiben..."
        """
        templates = cls.TEMPLATES_DE if language == "de" else cls.TEMPLATES_EN

        # Return specific template or fallback to generic
        return templates.get(
            violation_type,
            templates.get("GENERIC_BLOCK", "I cannot help with this question."),
        )

    @classmethod
    def list_violation_types(cls) -> list[str]:
        """List all available violation types."""
        return list(cls.TEMPLATES_DE.keys())
