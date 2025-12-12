"""
Feedback Collector - Phase 5.3

Sammelt und verwaltet Feedback für kontinuierliches Lernen.
Nutzt bestehende Redis/PostgreSQL Infrastruktur über FeedbackRepositoryPort.
"""

import asyncio
import json
import hashlib
import logging
from typing import Dict, List, Any, Optional, Protocol
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict

# Integration mit shared Components
import sys
from pathlib import Path as PathLib
sys.path.insert(0, str(PathLib(__file__).parent.parent.parent.parent.parent))
from detectors.shared.domain.ports import FeedbackRepositoryPort

logger = logging.getLogger(__name__)


class FeedbackType(Enum):
    """Arten von Feedback."""
    HUMAN_REVIEW = "human_review"
    AUTO_CORRECTION = "auto_correction"
    DETECTOR_PERFORMANCE = "detector_performance"
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    POLICY_EFFECTIVENESS = "policy_effectiveness"


class FeedbackSource(Enum):
    """Quellen des Feedbacks."""
    ADMIN = "admin"
    USER = "user"
    SYSTEM = "system"
    DETECTOR = "detector"


@dataclass
class FeedbackEntry:
    """Ein einzelnes Feedback-Eintrag."""
    id: str
    type: FeedbackType
    source: FeedbackSource
    data: Dict[str, Any]
    timestamp: datetime
    context_hash: str  # Hash des ursprünglichen Kontexts
    confidence: float = 1.0  # Wie vertrauenswürdig ist dieses Feedback?


@dataclass
class LearningBatch:
    """Batch von Feedback-Einträgen für Lernen."""
    entries: List[FeedbackEntry]
    batch_id: str
    created_at: datetime
    processed: bool = False


@dataclass
class DetectorPerformanceMetrics:
    """Leistungsmetriken für einen Detektor."""
    detector_name: str
    total_calls: int = 0
    successful_calls: int = 0
    avg_response_time: float = 0.0
    error_rate: float = 0.0
    false_positives: int = 0
    false_negatives: int = 0
    true_positives: int = 0
    true_negatives: int = 0

    def update_with_result(self, success: bool, response_time: float):
        """Aktualisiert Metriken mit einem Aufrufergebnis."""
        self.total_calls += 1
        if success:
            self.successful_calls += 1
        self.avg_response_time = (
            (self.avg_response_time * (self.total_calls - 1) + response_time)
            / self.total_calls
        )
        self.error_rate = 1 - (self.successful_calls / self.total_calls)

    def update_with_feedback(self, feedback_type: FeedbackType):
        """Aktualisiert Metriken basierend auf Feedback."""
        if feedback_type == FeedbackType.FALSE_POSITIVE:
            self.false_positives += 1
        elif feedback_type == FeedbackType.FALSE_NEGATIVE:
            self.false_negatives += 1
        elif feedback_type == FeedbackType.AUTO_CORRECTION:
            # Könnte sowohl FP als auch FN korrigieren
            pass

    def get_precision(self) -> float:
        """Berechnet Präzision des Detektors."""
        if (self.true_positives + self.false_positives) == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_positives)

    def get_recall(self) -> float:
        """Berechnet Recall des Detektors."""
        if (self.true_positives + self.false_negatives) == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_negatives)

    def get_f1_score(self) -> float:
        """Berechnet F1-Score."""
        precision = self.get_precision()
        recall = self.get_recall()
        if precision + recall == 0:
            return 0.0
        return 2 * (precision * recall) / (precision + recall)


class FeedbackCollector:
    """
    Sammelt und verwaltet Feedback für kontinuierliches Lernen.
    
    Nutzt bestehende Redis/PostgreSQL Infrastruktur über FeedbackRepositoryPort.
    """

    def __init__(
        self, 
        feedback_repository: Optional[FeedbackRepositoryPort] = None,
        storage_path: str = "feedback_storage"
    ):
        """
        Initialize Feedback Collector.
        
        Args:
            feedback_repository: Optional FeedbackRepositoryPort (Redis/PostgreSQL/Hybrid)
                                 Falls None, wird JSON-Fallback verwendet
            storage_path: Fallback storage path für JSON (wenn kein Repository)
        """
        self.feedback_repository = feedback_repository
        self.storage_path = PathLib(storage_path) if not feedback_repository else None
        if self.storage_path:
            self.storage_path.mkdir(parents=True, exist_ok=True)
        
        self.feedback_queue: asyncio.Queue = asyncio.Queue()
        self.performance_metrics: Dict[str, DetectorPerformanceMetrics] = defaultdict(
            lambda: DetectorPerformanceMetrics(detector_name="")
        )
        self.learning_batches: Dict[str, LearningBatch] = {}

        # In-Memory Cache für häufige Feedback-Muster
        self.feedback_patterns = defaultdict(list)

        # Starte Verarbeitungstask
        self.processing_task = None
        self.running = True

        storage_info = (
            f"FeedbackRepositoryPort ({type(feedback_repository).__name__})" 
            if feedback_repository 
            else f"JSON fallback ({storage_path})"
        )
        logger.info(f"FeedbackCollector initialized with {storage_info}")

    async def start(self):
        """Startet die asynchrone Verarbeitung."""
        if self.processing_task is None:
            self.processing_task = asyncio.create_task(self._process_feedback_queue())

    async def add_feedback(
        self,
        feedback_type: FeedbackType,
        source: FeedbackSource,
        data: Dict[str, Any],
        context: Dict[str, Any],
        confidence: float = 1.0
    ) -> str:
        """Fügt neues Feedback hinzu."""
        # Erstelle eindeutige ID
        feedback_id = hashlib.sha256(
            f"{feedback_type.value}{source.value}{json.dumps(data, sort_keys=True)}{datetime.utcnow().isoformat()}".encode()
        ).hexdigest()[:16]

        # Erstelle Context Hash
        context_hash = self._hash_context(context)

        entry = FeedbackEntry(
            id=feedback_id,
            type=feedback_type,
            source=source,
            data=data,
            timestamp=datetime.utcnow(),
            context_hash=context_hash,
            confidence=confidence
        )

        # Füge zur Warteschlange hinzu
        await self.feedback_queue.put(entry)

        # Aktualisiere Performance-Metriken wenn relevant
        if 'detector_name' in data:
            detector_name = data['detector_name']
            if detector_name not in self.performance_metrics:
                self.performance_metrics[detector_name] = DetectorPerformanceMetrics(
                    detector_name=detector_name
                )
            self.performance_metrics[detector_name].update_with_feedback(feedback_type)

        logger.info(f"Added feedback {feedback_id} of type {feedback_type.value}")
        return feedback_id

    async def add_detector_performance(
        self,
        detector_name: str,
        success: bool,
        response_time: float,
        metadata: Dict[str, Any] = None
    ):
        """Fügt Detektor-Performance-Feedback hinzu."""
        if detector_name not in self.performance_metrics:
            self.performance_metrics[detector_name] = DetectorPerformanceMetrics(
                detector_name=detector_name
            )

        self.performance_metrics[detector_name].update_with_result(success, response_time)

        # Auch als Feedback-Eintrag speichern
        await self.add_feedback(
            feedback_type=FeedbackType.DETECTOR_PERFORMANCE,
            source=FeedbackSource.SYSTEM,
            data={
                "detector_name": detector_name,
                "success": success,
                "response_time": response_time,
                "metadata": metadata or {}
            },
            context={},
            confidence=1.0
        )

    async def get_feedback_samples(
        self, 
        detector_name: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Holt Feedback-Samples aus dem Repository.
        
        Args:
            detector_name: Optional Filter nach Detektor
            limit: Maximale Anzahl Samples
            
        Returns:
            Liste von Feedback-Samples
        """
        if self.feedback_repository:
            try:
                samples = self.feedback_repository.get_samples(limit=limit)
                # Filter nach detector_name falls angegeben
                if detector_name:
                    samples = [
                        s for s in samples 
                        if s.get("detector_name") == detector_name or 
                           s.get("context", {}).get("detector_name") == detector_name
                    ]
                return samples
            except Exception as e:
                logger.warning(f"Failed to get samples from repository: {e}")
        
        return []

    async def _process_feedback_queue(self):
        """Verarbeitet Feedback-Einträge aus der Warteschlange."""
        while self.running:
            try:
                entry = await asyncio.wait_for(
                    self.feedback_queue.get(),
                    timeout=1.0
                )

                # Speichere Feedback
                await self._store_feedback(entry)

                # Analysiere Muster
                self._analyze_feedback_pattern(entry)

                # Erstelle Learning Batches (jede Stunde)
                await self._batch_feedback_if_needed(entry)

                self.feedback_queue.task_done()

            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error processing feedback: {e}", exc_info=True)

    async def _store_feedback(self, entry: FeedbackEntry):
        """Speichert Feedback dauerhaft über FeedbackRepositoryPort oder JSON-Fallback."""
        try:
            # Konvertiere FeedbackEntry zu Dict-Format für Repository
            sample_dict = {
                "id": entry.id,
                "text": entry.data.get("text", "")[:10000],  # Limit für PostgreSQL
                "detector_name": entry.data.get("detector_name", "orchestrator"),
                "final_score": entry.data.get("risk_score", entry.data.get("score", 0.0)),
                "blocked": entry.data.get("was_blocked", False),
                "timestamp": entry.timestamp.isoformat(),
                "context": {
                    "feedback_type": entry.type.value,
                    "feedback_source": entry.source.value,
                    "confidence": entry.confidence,
                    **entry.data.get("metadata", {})
                },
                "metadata": {
                    "feedback_type": entry.type.value,
                    "feedback_source": entry.source.value,
                    "confidence": entry.confidence,
                    "context_hash": entry.context_hash
                },
                "is_false_positive": entry.type == FeedbackType.FALSE_POSITIVE,
                "is_false_negative": entry.type == FeedbackType.FALSE_NEGATIVE,
                "priority": "high" if entry.type in [FeedbackType.FALSE_POSITIVE, FeedbackType.FALSE_NEGATIVE] else "medium"
            }
            
            # Nutze FeedbackRepositoryPort wenn verfügbar (Redis/PostgreSQL/Hybrid)
            if self.feedback_repository:
                try:
                    self.feedback_repository.add(sample_dict)
                    logger.debug(f"Feedback saved to repository: {entry.id}")
                    return
                except Exception as e:
                    logger.warning(f"Repository save failed, falling back to JSON: {e}")
            
            # JSON-Fallback (wenn kein Repository oder Repository-Fehler)
            if self.storage_path:
                storage_file = self.storage_path / f"feedback_{entry.timestamp.date()}.json"
                
                # Lade existierende Feedbacks
                existing = []
                if storage_file.exists():
                    with open(storage_file, 'r', encoding='utf-8') as f:
                        existing = json.load(f)
                
                # Konvertiere Entry zu Dict (datetime serialization)
                entry_dict = asdict(entry)
                entry_dict['type'] = entry.type.value
                entry_dict['source'] = entry.source.value
                entry_dict['timestamp'] = entry.timestamp.isoformat()
                
                # Füge neuen Eintrag hinzu
                existing.append(entry_dict)
                
                # Speichere zurück
                with open(storage_file, 'w', encoding='utf-8') as f:
                    json.dump(existing, f, indent=2, default=str)
                
                logger.debug(f"Feedback saved to JSON: {entry.id}")
            else:
                logger.warning(f"No storage available for feedback {entry.id}")

        except Exception as e:
            logger.error(f"Failed to store feedback: {e}", exc_info=True)

    def _analyze_feedback_pattern(self, entry: FeedbackEntry):
        """Analysiert Feedback auf wiederkehrende Muster."""
        # Analysiere nach Typ und Kontext
        key = f"{entry.type.value}_{entry.context_hash[:8]}"
        self.feedback_patterns[key].append(entry)

        # Wenn wir mehrere ähnliche Feedbacks haben, könnte das ein Muster sein
        if len(self.feedback_patterns[key]) >= 3:
            logger.warning(
                f"Pattern detected for {key}: "
                f"{len(self.feedback_patterns[key])} similar feedbacks"
            )

    async def _batch_feedback_if_needed(self, entry: FeedbackEntry):
        """Erstellt Batches für batch processing."""
        # Einfache Implementierung: Batch pro Stunde
        current_hour = entry.timestamp.replace(minute=0, second=0, microsecond=0)
        batch_id = f"batch_{current_hour.strftime('%Y%m%d_%H')}"

        if batch_id not in self.learning_batches:
            self.learning_batches[batch_id] = LearningBatch(
                entries=[],
                batch_id=batch_id,
                created_at=current_hour
            )

        self.learning_batches[batch_id].entries.append(entry)

        # Wenn Batch groß genug, markiere zur Verarbeitung
        if len(self.learning_batches[batch_id].entries) >= 100:
            logger.info(f"Batch {batch_id} reached 100 entries, ready for processing")

    def _hash_context(self, context: Dict[str, Any]) -> str:
        """Erstellt Hash eines Kontexts für Vergleichszwecke."""
        # Entferne variable Felder wie timestamps
        stable_context = {
            k: v for k, v in context.items()
            if k not in ['timestamp', 'processing_time_ms', 'router_metadata']
        }

        return hashlib.sha256(
            json.dumps(stable_context, sort_keys=True).encode()
        ).hexdigest()

    def get_detector_metrics(self, detector_name: str) -> Optional[DetectorPerformanceMetrics]:
        """Gibt Leistungsmetriken für einen Detektor zurück."""
        return self.performance_metrics.get(detector_name)

    def get_all_metrics(self) -> Dict[str, DetectorPerformanceMetrics]:
        """Gibt Metriken für alle Detektoren zurück."""
        return dict(self.performance_metrics)

    def get_feedback_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Gibt Zusammenfassung der letzten Feedback-Einträge."""
        from datetime import timezone
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        summary = defaultdict(int)
        
        # 1. Zähle aus internen Batches
        for batch in self.learning_batches.values():
            if batch.created_at >= cutoff:
                for entry in batch.entries:
                    if entry.timestamp >= cutoff:
                        summary[entry.type.value] += 1
        
        # 2. Zähle aus FeedbackRepository (wichtig für False Negatives von Code Intent)
        if self.feedback_repository:
            try:
                # Hole alle Samples aus dem Repository
                # get_samples() kann verschiedene Signaturen haben:
                # - get_samples(limit=100) 
                # - get_samples(detector_name=None, limit=100)
                try:
                    # Versuche mit limit als Keyword-Argument
                    samples = self.feedback_repository.get_samples(limit=10000)
                except TypeError:
                    # Fallback: Versuche ohne Parameter (nutzt default limit)
                    samples = self.feedback_repository.get_samples()
                
                logger.info(f"Retrieved {len(samples)} samples from repository for feedback summary")
                
                # Filter nach Zeitraum und zähle nach Feedback-Typ
                for sample in samples:
                    # Prüfe Timestamp
                    sample_time = sample.get('timestamp')
                    if isinstance(sample_time, str):
                        try:
                            # Handle verschiedene Timestamp-Formate
                            # Format 1: 2025-12-13T01:15:23.684000 (ohne Zeitzone)
                            # Format 2: 2025-12-13T01:15:23.684000Z (mit Z)
                            # Format 3: 2025-12-13T01:15:23+00:00 (mit Zeitzone)
                            
                            # Entferne 'Z' und ersetze durch '+00:00'
                            if sample_time.endswith('Z'):
                                sample_time = sample_time[:-1] + '+00:00'
                            # Wenn kein Zeitzone, füge UTC hinzu (behandle als UTC)
                            elif '+' not in sample_time and '-' not in sample_time[-6:]:
                                # Keine Zeitzone vorhanden, behandle als UTC
                                if '.' in sample_time:
                                    # Format: 2025-12-13T01:15:23.684000
                                    sample_time = sample_time + '+00:00'
                                else:
                                    # Format: 2025-12-13T01:15:23
                                    sample_time = sample_time + '+00:00'
                            
                            sample_dt = datetime.fromisoformat(sample_time)
                            # Mache timezone-aware wenn nicht schon
                            if sample_dt.tzinfo is None:
                                from datetime import timezone
                                sample_dt = sample_dt.replace(tzinfo=timezone.utc)
                            sample_time = sample_dt
                        except Exception as e:
                            logger.warning(f"Failed to parse timestamp '{sample.get('timestamp', 'N/A')}': {e}")
                            # Bei Parsing-Fehler: verwende aktuelles Datum (behandle als aktuell)
                            from datetime import timezone
                            sample_time = datetime.now(timezone.utc)
                    elif not isinstance(sample_time, datetime):
                        # Wenn kein Timestamp, verwende aktuelles Datum (behandle als aktuell)
                        from datetime import timezone
                        sample_time = datetime.now(timezone.utc)
                    else:
                        # Wenn datetime, aber keine timezone, füge UTC hinzu
                        if sample_time.tzinfo is None:
                            from datetime import timezone
                            sample_time = sample_time.replace(tzinfo=timezone.utc)
                    
                    # Prüfe ob Sample im Zeitraum liegt (oder kein Timestamp = aktuell)
                    if sample_time >= cutoff:
                        # Prüfe is_false_negative und is_false_positive Flags (höchste Priorität)
                        if sample.get('is_false_negative', False):
                            summary['false_negative'] += 1
                            logger.debug(f"Found false negative: {sample.get('text', '')[:50]}...")
                        elif sample.get('is_false_positive', False):
                            summary['false_positive'] += 1
                        
                        # Prüfe auch feedback_type in metadata/context (Fallback)
                        feedback_type = (
                            sample.get('metadata', {}).get('feedback_type') or
                            sample.get('context', {}).get('feedback_type') or
                            sample.get('feedback_type')
                        )
                        if feedback_type and feedback_type not in ['false_negative', 'false_positive']:
                            # Nur zählen wenn nicht schon als FP/FN gezählt
                            summary[feedback_type] += 1
                
                logger.debug(f"Feedback summary from repository: {dict(summary)}")
            except Exception as e:
                logger.warning(f"Failed to get feedback summary from repository: {e}", exc_info=True)

        return dict(summary)

    async def shutdown(self):
        """Stoppt den Feedback Collector sauber."""
        self.running = False
        
        if self.processing_task:
            self.processing_task.cancel()
            try:
                await self.processing_task
            except asyncio.CancelledError:
                pass

        logger.info("FeedbackCollector shutdown complete")

