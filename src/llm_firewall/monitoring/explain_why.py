"""
Explain-Why Required für Promotions
===================================

Jede Promotion erfordert eine maschinell erzeugte Begründungskette.
"DOI valid, NLI 0.91 vs. sentence X, corroboration=3/5"

Features:
- Structured reasoning chains
- Evidence attribution
- Decision auditability
- Regression analysis support
"""

from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional
from datetime import datetime
import json


@dataclass(frozen=True)
class EvidenceItem:
    """Einzelne Evidence für Begründung."""
    type: str  # "kb_fact", "source", "nli", "trust", "corroboration"
    value: any
    weight: float
    contribution: str  # Human-readable explanation


@dataclass(frozen=True)
class PromotionReasoning:
    """Structured reasoning chain für Promotion."""
    decision_id: str
    timestamp: datetime
    decision: str  # "PROMOTE", "QUARANTINE", "REJECT"
    confidence: float
    evidence_chain: List[EvidenceItem]
    reasoning_summary: str
    metadata: Dict[str, any]
    
    def to_json(self) -> str:
        """Serialize to JSON."""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return json.dumps(data, indent=2)
    
    def to_audit_log(self) -> str:
        """Format für Audit-Log."""
        lines = [
            f"Decision ID: {self.decision_id}",
            f"Timestamp: {self.timestamp.isoformat()}",
            f"Decision: {self.decision}",
            f"Confidence: {self.confidence:.3f}",
            f"Evidence Chain ({len(self.evidence_chain)} items):"
        ]
        
        for i, evidence in enumerate(self.evidence_chain, 1):
            lines.append(f"  {i}. {evidence.type}: {evidence.contribution} (weight={evidence.weight:.2f})")
        
        lines.append(f"Summary: {self.reasoning_summary}")
        
        return "\n".join(lines)


class ExplainWhyEngine:
    """
    Engine für Explain-Why Reasoning Chains.
    
    Generiert strukturierte Begründungen für jede Promotion-Entscheidung.
    """
    
    def __init__(self, require_minimum_evidence: int = 2):
        """
        Args:
            require_minimum_evidence: Mindestanzahl Evidence-Items für Promotion
        """
        self.require_minimum_evidence = require_minimum_evidence
        self.reasoning_history: List[PromotionReasoning] = []
    
    def create_reasoning(
        self,
        decision_id: str,
        decision: str,
        confidence: float,
        trust_score: float,
        nli_score: float,
        corroboration_count: int,
        kb_facts: List[str],
        sources: List[Dict],
        domain: str,
        threshold: float,
        metadata: Optional[Dict] = None
    ) -> PromotionReasoning:
        """
        Erstelle Reasoning Chain für Entscheidung.
        
        Args:
            decision_id: Unique Decision ID
            decision: PROMOTE/QUARANTINE/REJECT
            confidence: Confidence score
            trust_score: Domain trust score
            nli_score: NLI consistency score
            corroboration_count: Anzahl korroboierender KB-Fakten
            kb_facts: Liste von KB-Fakten
            sources: Liste von Quellen
            domain: Domain (SCIENCE, MEDICINE, etc.)
            threshold: Decision threshold
            metadata: Zusätzliche Metadaten
            
        Returns:
            PromotionReasoning mit vollständiger Begründungskette
        """
        evidence_chain = []
        
        # 1. Trust Score Evidence
        trust_contribution = self._format_trust_contribution(trust_score, sources)
        evidence_chain.append(EvidenceItem(
            type="trust",
            value=trust_score,
            weight=0.3,
            contribution=trust_contribution
        ))
        
        # 2. NLI Score Evidence
        nli_contribution = self._format_nli_contribution(nli_score, kb_facts)
        evidence_chain.append(EvidenceItem(
            type="nli",
            value=nli_score,
            weight=0.4,
            contribution=nli_contribution
        ))
        
        # 3. Corroboration Evidence
        corr_contribution = self._format_corroboration_contribution(
            corroboration_count, kb_facts
        )
        evidence_chain.append(EvidenceItem(
            type="corroboration",
            value=corroboration_count,
            weight=0.3,
            contribution=corr_contribution
        ))
        
        # 4. KB Facts Evidence
        for fact in kb_facts[:3]:  # Top 3 facts
            evidence_chain.append(EvidenceItem(
                type="kb_fact",
                value=fact,
                weight=0.1,
                contribution=f"KB fact supports claim: '{fact[:100]}...'"
            ))
        
        # 5. Source Evidence
        for source in sources[:2]:  # Top 2 sources
            source_name = source.get('name', 'Unknown')
            verified = source.get('verified', False)
            evidence_chain.append(EvidenceItem(
                type="source",
                value=source,
                weight=0.2,
                contribution=f"Source: {source_name} (verified={verified})"
            ))
        
        # Reasoning Summary
        reasoning_summary = self._generate_summary(
            decision=decision,
            trust_score=trust_score,
            nli_score=nli_score,
            corroboration_count=corroboration_count,
            domain=domain,
            threshold=threshold
        )
        
        # Metadata
        if metadata is None:
            metadata = {}
        
        metadata.update({
            'domain': domain,
            'threshold': threshold,
            'evidence_count': len(evidence_chain)
        })
        
        reasoning = PromotionReasoning(
            decision_id=decision_id,
            timestamp=datetime.now(),
            decision=decision,
            confidence=confidence,
            evidence_chain=evidence_chain,
            reasoning_summary=reasoning_summary,
            metadata=metadata
        )
        
        # Store in history
        self.reasoning_history.append(reasoning)
        
        return reasoning
    
    def _format_trust_contribution(self, trust_score: float, sources: List[Dict]) -> str:
        """Format Trust-Contribution."""
        source_names = [s.get('name', 'Unknown') for s in sources[:2]]
        sources_str = ", ".join(source_names) if source_names else "No sources"
        
        if trust_score >= 0.8:
            level = "High"
        elif trust_score >= 0.5:
            level = "Medium"
        else:
            level = "Low"
        
        return f"{level} trust score ({trust_score:.2f}) from sources: {sources_str}"
    
    def _format_nli_contribution(self, nli_score: float, kb_facts: List[str]) -> str:
        """Format NLI-Contribution."""
        fact_count = len(kb_facts)
        
        if nli_score >= 0.8:
            consistency = "Strong"
        elif nli_score >= 0.5:
            consistency = "Moderate"
        else:
            consistency = "Weak"
        
        return f"{consistency} NLI consistency ({nli_score:.2f}) with {fact_count} KB facts"
    
    def _format_corroboration_contribution(
        self, 
        corroboration_count: int, 
        kb_facts: List[str]
    ) -> str:
        """Format Corroboration-Contribution."""
        if corroboration_count >= 3:
            level = "Strong"
        elif corroboration_count >= 1:
            level = "Moderate"
        else:
            level = "No"
        
        return f"{level} corroboration ({corroboration_count} supporting KB facts)"
    
    def _generate_summary(
        self,
        decision: str,
        trust_score: float,
        nli_score: float,
        corroboration_count: int,
        domain: str,
        threshold: float
    ) -> str:
        """Generiere Reasoning-Summary."""
        if decision == "PROMOTE":
            return (
                f"PROMOTED in {domain}: Trust={trust_score:.2f}, NLI={nli_score:.2f}, "
                f"Corroboration={corroboration_count}, exceeds threshold={threshold:.2f}"
            )
        elif decision == "QUARANTINE":
            return (
                f"QUARANTINED in {domain}: Trust={trust_score:.2f}, NLI={nli_score:.2f}, "
                f"Corroboration={corroboration_count}, below threshold={threshold:.2f}"
            )
        else:  # REJECT
            return (
                f"REJECTED in {domain}: Trust={trust_score:.2f}, NLI={nli_score:.2f}, "
                f"insufficient evidence or safety concerns"
            )
    
    def validate_reasoning(self, reasoning: PromotionReasoning) -> bool:
        """
        Validiere dass Reasoning ausreichend Evidence hat.
        
        Returns:
            True wenn valid, False sonst
        """
        # Mindestanzahl Evidence
        if len(reasoning.evidence_chain) < self.require_minimum_evidence:
            return False
        
        # Confidence muss im Range sein
        if not (0.0 <= reasoning.confidence <= 1.0):
            return False
        
        # Entscheidung muss valid sein
        if reasoning.decision not in ["PROMOTE", "QUARANTINE", "REJECT"]:
            return False
        
        return True
    
    def get_reasoning_by_id(self, decision_id: str) -> Optional[PromotionReasoning]:
        """Finde Reasoning by Decision ID."""
        for reasoning in self.reasoning_history:
            if reasoning.decision_id == decision_id:
                return reasoning
        return None
    
    def get_recent_reasoning(self, limit: int = 10) -> List[PromotionReasoning]:
        """Hole recent Reasoning Chains."""
        return self.reasoning_history[-limit:]
    
    def export_reasoning_for_regression(self) -> List[Dict]:
        """
        Exportiere Reasoning für Regression-Analysis.
        
        Returns:
            Liste von Dicts für ML-Training
        """
        export_data = []
        
        for reasoning in self.reasoning_history:
            # Extrahiere Features
            features = {
                'decision': reasoning.decision,
                'confidence': reasoning.confidence,
                'evidence_count': len(reasoning.evidence_chain),
                'domain': reasoning.metadata.get('domain', 'UNKNOWN'),
                'threshold': reasoning.metadata.get('threshold', 0.0)
            }
            
            # Extrahiere Evidence-Scores
            for evidence in reasoning.evidence_chain:
                if evidence.type in ['trust', 'nli', 'corroboration']:
                    features[f'{evidence.type}_score'] = evidence.value
            
            export_data.append(features)
        
        return export_data
    
    def get_statistics(self) -> Dict[str, any]:
        """Statistiken über Reasoning History."""
        if not self.reasoning_history:
            return {
                'total': 0,
                'promote': 0,
                'quarantine': 0,
                'reject': 0
            }
        
        promote_count = sum(1 for r in self.reasoning_history if r.decision == "PROMOTE")
        quarantine_count = sum(1 for r in self.reasoning_history if r.decision == "QUARANTINE")
        reject_count = sum(1 for r in self.reasoning_history if r.decision == "REJECT")
        
        avg_confidence = sum(r.confidence for r in self.reasoning_history) / len(self.reasoning_history)
        avg_evidence_count = sum(len(r.evidence_chain) for r in self.reasoning_history) / len(self.reasoning_history)
        
        return {
            'total': len(self.reasoning_history),
            'promote': promote_count,
            'quarantine': quarantine_count,
            'reject': reject_count,
            'avg_confidence': avg_confidence,
            'avg_evidence_count': avg_evidence_count
        }


# Beispiel-Usage
if __name__ == "__main__":
    engine = ExplainWhyEngine(require_minimum_evidence=2)
    
    # Erstelle Reasoning für Promotion
    reasoning = engine.create_reasoning(
        decision_id="test_001",
        decision="PROMOTE",
        confidence=0.92,
        trust_score=0.95,
        nli_score=0.88,
        corroboration_count=3,
        kb_facts=["Fact 1 about topic", "Fact 2 supports claim"],
        sources=[{"name": "Nature", "verified": True}],
        domain="SCIENCE",
        threshold=0.75
    )
    
    print("=== Reasoning Chain ===")
    print(reasoning.to_audit_log())
    print("\n=== Statistics ===")
    print(engine.get_statistics())

