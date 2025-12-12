"""
Domain Ports for Orchestrator Service

Defines the core domain abstractions for routing and orchestrating detector services.
"""
from typing import Protocol, List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class DetectorConfig:
    """Konfiguration für einen einzelnen Detektor-Aufruf."""
    name: str  # "code_intent", "content_safety", "persuasion"
    mode: str  # "required" | "optional" | "conditional"
    timeout_ms: int = 200
    priority: int = 1  # 1=hoch, 3=niedrig


@dataclass
class RoutingDecision:
    """Eine Routing-Entscheidung für einen Request."""
    detector_configs: List[DetectorConfig]
    execution_strategy: str  # "parallel" | "sequential" | "immediate_block"
    total_timeout_ms: int
    decision_reason: str
    router_metadata: Dict[str, Any] = None  # Optional metadata for routing decisions
    
    def __post_init__(self):
        """Initialisiert router_metadata falls None."""
        if self.router_metadata is None:
            self.router_metadata = {}


@dataclass
class DetectorResult:
    """Ergebnis eines einzelnen Detektors."""
    detector_name: str
    success: bool
    score: Optional[float]
    blocked: bool
    metadata: Dict[str, Any]
    processing_time_ms: float
    error: Optional[str] = None


@dataclass
class AggregatedResult:
    """Aggregiertes Ergebnis aller Detektoren."""
    detector_results: Dict[str, DetectorResult]
    final_decision: bool  # True = blockieren
    final_score: float
    confidence: float
    router_metadata: Dict[str, Any]


class DetectorRouterPort(Protocol):
    """Port für den Router Service."""
    
    def analyze_and_route(self, text: str, context: Dict[str, Any]) -> RoutingDecision:
        """Analysiert Text/Kontext und trifft Routing-Entscheidung."""
        ...
    
    async def execute_detectors(
        self, 
        decision: RoutingDecision, 
        text: str, 
        context: Dict[str, Any]
    ) -> AggregatedResult:
        """Führt die gewählten Detektoren aus und aggregiert Ergebnisse."""
        ...

