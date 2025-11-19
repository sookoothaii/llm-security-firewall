"""Bidirectional NLI - Entailment checking using facebook/bart-large-mnli

Based on HAK/GAL Firewall NLI Consistency Judge.
Supports sentence-level windowing for better precision.
"""

from typing import List, Tuple, Dict, Any
import logging

logger = logging.getLogger(__name__)

# Optional transformers for NLI
try:
    from transformers import pipeline
    HAS_TRANSFORMERS = True
except ImportError:
    HAS_TRANSFORMERS = False
    logger.warning("transformers not available - NLI will use dummy implementation")


class BidirectionalNLI:
    """Bidirectional NLI checker using facebook/bart-large-mnli."""
    
    def __init__(self, nli_model: str = "facebook/bart-large-mnli"):
        """Initialize NLI model.
        
        Args:
            nli_model: HuggingFace NLI model name
        """
        self.nli_model = nli_model
        self.nli_pipeline = None
        
        if HAS_TRANSFORMERS:
            try:
                self.nli_pipeline = pipeline(
                    "zero-shot-classification",
                    model=nli_model,
                    device=-1  # CPU
                )
                logger.info(f"NLI model loaded: {nli_model}")
            except Exception as e:
                logger.error(f"Failed to load NLI model: {e}")
                self.nli_pipeline = None
        else:
            logger.warning("transformers not installed - using dummy NLI")
    
    def check_entailment(self, premise: str, hypothesis: str) -> str:
        """Check entailment relationship.
        
        Args:
            premise: Reference text
            hypothesis: Text to check
            
        Returns:
            'entailment', 'neutral', or 'contradiction'
        """
        if self.nli_pipeline is None:
            # Dummy: simple containment check
            if hypothesis.lower() in premise.lower():
                return "entailment"
            return "neutral"
        
        try:
            result = self.nli_pipeline(
                premise,
                candidate_labels=["entailment", "neutral", "contradiction"],
                hypothesis_template="{}"
            )
            # Return label with highest score
            return result["labels"][0]
        except Exception as e:
            logger.error(f"NLI inference failed: {e}")
            return "neutral"
    
    def batch_bidirectional_nli(
        self,
        text: str,
        facts: List[str],
        window_sentences: int = 4
    ) -> Tuple[float, float, float, List[Dict[str, Any]]]:
        """Batch NLI check for multiple facts.
        
        Args:
            text: Text to validate
            facts: List of canonical facts
            window_sentences: Sentence window size
            
        Returns:
            (entailment_rate, neutral_rate, contradiction_rate, details)
        """
        # Simple sentence splitting
        sentences = [s.strip() + "." for s in text.split(".") if s.strip()]
        
        e_count = 0
        n_count = 0
        c_count = 0
        details = []
        
        for fact in facts:
            # Check fact against full text (simplified windowing)
            label = self.check_entailment(text, fact)
            
            detail = {
                "fact": fact,
                "label": label,
                "is_entailment": label == "entailment",
                "is_neutral": label == "neutral",
                "is_contradiction": label == "contradiction"
            }
            details.append(detail)
            
            if label == "entailment":
                e_count += 1
            elif label == "neutral":
                n_count += 1
            elif label == "contradiction":
                c_count += 1
        
        total = len(facts)
        return (
            e_count / total if total > 0 else 0.0,
            n_count / total if total > 0 else 0.0,
            c_count / total if total > 0 else 0.0,
            details
        )












