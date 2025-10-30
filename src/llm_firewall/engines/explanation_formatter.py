"""
Honesty Explanation Formatter - Personality-Adapted Messaging
==============================================================

Formats ABSTAIN/ANSWER decisions based on user personality.

Directness Levels:
    High (>0.8): "NEIN - insufficient" + numbers
    Moderate (0.5-0.8): Polite but clear
    Low (<0.5): Very polite, indirect

Author: Claude Sonnet 4.5
Date: 2025-10-27
"""

import logging

from llm_firewall.utils.types import HonestyDecision

logger = logging.getLogger(__name__)


class HonestyExplanationFormatter:
    """
    Format honesty decisions for user consumption
    
    Adapts tone and detail level based on personality:
        - directness: How blunt the message
        - precision_priority: How many numbers to show
        - detail_level: How much explanation
    """

    def format_decision(
        self,
        decision: HonestyDecision,
        directness: float = 0.95,
        precision_priority: float = 0.95,
        detail_level: float = 0.9
    ) -> str:
        """
        Format decision for user
        
        Args:
            decision: HonestyDecision object
            directness: User directness (0-1)
            precision_priority: Show exact numbers (0-1)
            detail_level: Amount of explanation (0-1)
        
        Returns:
            Formatted explanation string
        """
        if decision.decision == 'ANSWER':
            return self._format_answer(decision, directness, detail_level)
        else:
            return self._format_abstention(decision, directness, precision_priority, detail_level)

    def _format_answer(
        self,
        decision: HonestyDecision,
        directness: float,
        detail_level: float
    ) -> str:
        """Format ANSWER decision"""
        gt = decision.gt_breakdown

        if directness > 0.8:
            # High directness (Joerg's style)
            msg = "OK - Datenlage ausreichend.\n\n"

            if detail_level > 0.7:
                msg += f"Ground Truth: {decision.gt_score:.1%} (Schwelle: {decision.threshold_used:.1%})\n"
                msg += f"KB Facts: {gt.kb_fact_count}\n"
                msg += f"Sources: {gt.source_count} ({gt.verified_source_count} verified)\n"
                msg += f"Confidence: {decision.confidence:.1%}\n"
                msg += f"Margin: +{decision.margin:.1%}"

        elif directness > 0.5:
            # Moderate directness
            msg = "Ich kann diese Frage beantworten.\n\n"

            if detail_level > 0.7:
                msg += f"Ground Truth Score: {decision.gt_score:.1%}\n"
                msg += f"Evidenz: {gt.kb_fact_count} KB Facts, {gt.source_count} Sources"

        else:
            # Low directness (very polite)
            msg = "Basierend auf den verfügbaren Daten kann ich eine Antwort geben."

        return msg

    def _format_abstention(
        self,
        decision: HonestyDecision,
        directness: float,
        precision_priority: float,
        detail_level: float
    ) -> str:
        """Format ABSTAIN decision"""
        gt = decision.gt_breakdown

        if directness > 0.8:
            # High directness (Joerg's style) - BRUTAL HONESTY
            msg = "NEIN - Datenlage reicht nicht.\n\n"

            if precision_priority > 0.7:
                # Show exact numbers
                msg += f"Ground Truth: {decision.gt_score:.1%} (need {decision.threshold_used:.1%})\n"
                msg += f"Confidence: {decision.confidence:.1%}\n"

                if decision.margin < 0:
                    msg += f"Fehlbetrag: {abs(decision.margin):.1%}\n"
                msg += "\n"

            if detail_level > 0.7:
                # Show breakdown
                msg += "Komponenten:\n"
                msg += f"- KB Coverage: {gt.kb_coverage:.1%}\n"
                msg += f"- Source Quality: {gt.source_quality:.1%}\n"
                msg += f"- Recency: {gt.recency_score:.1%}\n"
                msg += "\n"

            # Missing evidence
            msg += "Fehlende Evidenz:\n"
            msg += f"- KB Facts: {gt.kb_fact_count}/10\n"
            msg += f"- Sources: {gt.source_count}/5\n"

            if gt.verified_source_count < 2:
                msg += f"- Verified Sources: {gt.verified_source_count}/2 (zu wenig!)\n"

            if gt.days_since_newest > 365:
                msg += f"- Recency: {gt.days_since_newest} Tage alt (veraltet!)\n"

            # Suggestion
            if detail_level > 0.5:
                msg += "\nEmpfehlung: Mehr Quellen recherchieren oder Frage spezifizieren."

        elif directness > 0.5:
            # Moderate directness
            msg = "Ich kann diese Frage nicht mit ausreichender Sicherheit beantworten.\n\n"

            msg += f"Problem: Ground Truth Score nur {decision.gt_score:.1%}, "
            msg += f"brauche mindestens {decision.threshold_used:.1%}.\n\n"

            msg += "Fehlende Evidenz:\n"

            if gt.kb_fact_count < 5:
                msg += f"- Zu wenig KB Facts ({gt.kb_fact_count}/10)\n"

            if gt.source_count < 3:
                msg += f"- Zu wenig Sources ({gt.source_count}/5)\n"

            if gt.verified_source_count == 0:
                msg += "- Keine verifizierten Sources\n"

            msg += "\nSoll ich trotzdem spekulieren? (nicht empfohlen)"

        else:
            # Low directness (very polite)
            msg = "Basierend auf den verfügbaren Daten kann ich keine zuverlässige Antwort geben.\n\n"

            reasons = []

            if gt.kb_fact_count < 5:
                reasons.append("begrenzte Informationen in der Wissensbasis")

            if gt.source_count < 3:
                reasons.append("wenige unabhängige Quellen")

            if gt.verified_source_count == 0:
                reasons.append("keine verifizierten Quellen")

            if reasons:
                msg += "Grund: " + ", ".join(reasons) + ".\n\n"

            msg += "Ich empfehle, zusätzliche Recherche durchzuführen oder die Frage anders zu formulieren."

        return msg


# Joerg's default formatter (directness 0.95, precision 0.95, detail 0.9)
def format_for_joerg(decision: HonestyDecision) -> str:
    """Convenience function for Joerg's profile"""
    formatter = HonestyExplanationFormatter()
    return formatter.format_decision(
        decision,
        directness=0.95,
        precision_priority=0.95,
        detail_level=0.9
    )

