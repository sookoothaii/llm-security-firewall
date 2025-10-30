"""
Source-Attribution Graph - Claim DAG with Cycle Detection
Purpose: Prevent echo-chamber promotion via citation graph analysis
Creator: Joerg Bollwahn
Date: 2025-10-30

Key Insight: Isolated trust scores miss causal structure.
Sources citing each other in cycles create false consensus (echo chambers).
Only promote claims with acyclic support chains.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Set, Tuple


class ClaimGraph:
    """
    Directed acyclic graph (DAG) for claim-evidence relationships.

    Tracks:
    - Claims and their supporting sources
    - Source-to-source citations (paper → paper)
    - Edge weights (trust, recency, support_score)

    Detects:
    - Echo chambers (citation cycles)
    - Circular reasoning
    - Self-referential support chains

    Only promotes claims with acyclic support (no cycles reachable from claim).

    Example:
        >>> g = ClaimGraph()
        >>> g.add_claim("C1", "AI will achieve AGI by 2030")
        >>> g.add_source("paper_1")
        >>> g.add_source("paper_2")
        >>> g.add_claim_support("C1", "paper_1", trust=0.9, recency=0.8, support=0.7)
        >>> g.add_citation("paper_1", "paper_2")  # paper_1 cites paper_2
        >>> g.add_citation("paper_2", "paper_1")  # cycle!
        >>> g.has_cycle("C1")  # True
        >>> g.promotion_ready("C1")  # False (blocked by cycle)
    """

    def __init__(self) -> None:
        """Initialize empty graph."""
        # Node sets
        self._claims: Set[str] = set()
        self._sources: Set[str] = set()

        # Edges
        # claim → {source1, source2, ...}
        self._claim_to_sources: Dict[str, Set[str]] = {}
        # source → {cited_source1, ...}
        self._source_to_source: Dict[str, Set[str]] = {}

        # Edge attributes
        # (claim, source) → support
        self._support_scores: Dict[Tuple[str, str], float] = {}
        # (claim, source) → trust
        self._trust_scores: Dict[Tuple[str, str], float] = {}
        # (claim, source) → recency
        self._recency_scores: Dict[Tuple[str, str], float] = {}

        # Optional metadata
        self._claim_texts: Dict[str, str] = {}
        self._source_metadata: Dict[str, Dict[str, Any]] = {}

    def add_claim(self, claim_id: str, text: Optional[str] = None) -> None:
        """
        Register a claim.

        Args:
            claim_id: Unique claim identifier
            text: Optional claim text
        """
        self._claims.add(claim_id)
        self._claim_to_sources.setdefault(claim_id, set())
        if text is not None:
            self._claim_texts[claim_id] = text

    def add_source(
        self, source_id: str, metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Register a source.

        Args:
            source_id: Unique source identifier (URL, DOI, etc.)
            metadata: Optional metadata (author, date, domain, etc.)
        """
        self._sources.add(source_id)
        self._source_to_source.setdefault(source_id, set())
        if metadata is not None:
            self._source_metadata[source_id] = metadata

    def add_claim_support(
        self,
        claim_id: str,
        source_id: str,
        trust: float,
        recency: float,
        support_score: float,
    ) -> None:
        """
        Add support edge from source to claim.

        Args:
            claim_id: Claim being supported
            source_id: Source providing support
            trust: Source trust score [0,1]
            recency: Source recency score [0,1]
            support_score: How well source supports claim [0,1]

        Raises:
            AssertionError: If claim/source not registered
            ValueError: If scores out of range
        """
        if claim_id not in self._claims:
            raise AssertionError(f"Claim '{claim_id}' must be registered first")
        if source_id not in self._sources:
            raise AssertionError(f"Source '{source_id}' must be registered first")

        if not 0 <= trust <= 1:
            raise ValueError("trust must be in [0,1]")
        if not 0 <= recency <= 1:
            raise ValueError("recency must be in [0,1]")
        if not 0 <= support_score <= 1:
            raise ValueError("support_score must be in [0,1]")

        edge = (claim_id, source_id)
        self._claim_to_sources[claim_id].add(source_id)
        self._trust_scores[edge] = float(trust)
        self._recency_scores[edge] = float(recency)
        self._support_scores[edge] = float(support_score)

    def add_citation(self, from_source: str, to_source: str) -> None:
        """
        Add citation edge (from_source cites to_source).

        Args:
            from_source: Citing source
            to_source: Cited source

        Raises:
            AssertionError: If sources not registered
        """
        if from_source not in self._sources:
            raise AssertionError(f"Source '{from_source}' must be registered first")
        if to_source not in self._sources:
            raise AssertionError(f"Source '{to_source}' must be registered first")

        self._source_to_source[from_source].add(to_source)

    def _dfs_cycle_detection(
        self, node: str, visited: Set[str], recursion_stack: Set[str]
    ) -> bool:
        """
        DFS-based cycle detection.

        Args:
            node: Current node
            visited: Globally visited nodes
            recursion_stack: Nodes in current DFS path

        Returns:
            True if cycle detected
        """
        visited.add(node)
        recursion_stack.add(node)

        # Visit all neighbors
        for neighbor in self._source_to_source.get(node, set()):
            if neighbor not in visited:
                if self._dfs_cycle_detection(neighbor, visited, recursion_stack):
                    return True
            elif neighbor in recursion_stack:
                # Back edge found = cycle
                return True

        recursion_stack.remove(node)
        return False

    def has_cycle(self, claim_id: str) -> bool:
        """
        Check if any cycle exists in source-subgraph reachable from claim.

        Args:
            claim_id: Claim to check

        Returns:
            True if echo chamber (cycle) detected

        Raises:
            AssertionError: If claim not registered
        """
        if claim_id not in self._claims:
            raise AssertionError(f"Claim '{claim_id}' must be registered first")

        visited: Set[str] = set()

        # Check each source supporting the claim
        for source in self._claim_to_sources.get(claim_id, set()):
            if source not in visited:
                if self._dfs_cycle_detection(source, visited, set()):
                    return True

        return False

    def aggregated_support(self, claim_id: str) -> float:
        """
        Compute weighted support score for claim.

        Formula: Σ (support × trust × recency) over all sources

        Args:
            claim_id: Claim to evaluate

        Returns:
            Aggregated support score (unbounded, typically 0-5 range)
        """
        total = 0.0
        for source in self._claim_to_sources.get(claim_id, set()):
            edge = (claim_id, source)
            support = self._support_scores.get(edge, 0.0)
            trust = self._trust_scores.get(edge, 0.0)
            recency = self._recency_scores.get(edge, 0.0)
            total += support * trust * recency

        return total

    def promotion_ready(self, claim_id: str, min_support: float = 0.5) -> bool:
        """
        Check if claim is ready for promotion.

        Requirements:
        1. No cycles in support chain (acyclic)
        2. Aggregated weighted support >= threshold

        Args:
            claim_id: Claim to check
            min_support: Minimum aggregated support threshold

        Returns:
            True if claim passes both checks
        """
        if self.has_cycle(claim_id):
            return False

        return self.aggregated_support(claim_id) >= float(min_support)

    def get_supporting_sources(self, claim_id: str) -> list[str]:
        """Get list of sources supporting claim."""
        return list(self._claim_to_sources.get(claim_id, set()))

    def get_source_citations(self, source_id: str) -> list[str]:
        """Get list of sources cited by source."""
        return list(self._source_to_source.get(source_id, set()))

    def get_claim_text(self, claim_id: str) -> Optional[str]:
        """Get claim text if stored."""
        return self._claim_texts.get(claim_id)

    def get_source_metadata(self, source_id: str) -> Optional[Dict[str, Any]]:
        """Get source metadata if stored."""
        return self._source_metadata.get(source_id)

    def statistics(self) -> Dict[str, int]:
        """
        Get graph statistics.

        Returns:
            Dict with claim_count, source_count, edge_counts, etc.
        """
        support_edges = sum(len(sources) for sources in self._claim_to_sources.values())
        citation_edges = sum(len(cites) for cites in self._source_to_source.values())

        return {
            "claim_count": len(self._claims),
            "source_count": len(self._sources),
            "support_edges": support_edges,
            "citation_edges": citation_edges,
            "claims_with_support": sum(
                1 for sources in self._claim_to_sources.values() if sources
            ),
        }
