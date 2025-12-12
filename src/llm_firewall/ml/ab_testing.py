"""
A/B Testing Framework für Quantum vs Classical Models
======================================================

Misst Performance-Vorteile von Quantum-Inspired ML vs klassischen Modellen.

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-08
License: MIT
"""

import time
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
from collections import defaultdict
import statistics

logger = logging.getLogger(__name__)


@dataclass
class ABTestMetrics:
    """Metriken für A/B-Test-Eintrag."""
    timestamp: str
    detector_type: str  # "quantum" or "classical"
    inference_time_ms: float
    confidence_score: float
    risk_score: float
    final_verdict: str  # "block" or "allow"
    text_hash: str  # Hash für Deduplizierung
    matched_patterns: List[str]
    error: Optional[str] = None


class ABTestLogger:
    """Logger für A/B-Test-Metriken."""
    
    def __init__(self, log_dir: str = "logs/ab_testing"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.metrics: List[ABTestMetrics] = []
        self.log_file = self.log_dir / f"ab_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
    
    def log_metrics(
        self,
        detector_type: str,
        inference_time_ms: float,
        confidence_score: float,
        risk_score: float,
        final_verdict: str,
        text: str,
        matched_patterns: List[str] = None,
        error: Optional[str] = None
    ):
        """Logge Metriken für einen Request."""
        import hashlib
        
        # Hash Text für Deduplizierung
        text_hash = hashlib.sha256(text.encode()).hexdigest()[:16]
        
        metrics = ABTestMetrics(
            timestamp=datetime.now().isoformat(),
            detector_type=detector_type,
            inference_time_ms=inference_time_ms,
            confidence_score=confidence_score,
            risk_score=risk_score,
            final_verdict=final_verdict,
            text_hash=text_hash,
            matched_patterns=matched_patterns or [],
            error=error
        )
        
        self.metrics.append(metrics)
        
        # Append to log file
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(metrics)) + "\n")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Berechne Statistiken aus geloggten Metriken."""
        if not self.metrics:
            return {}
        
        quantum_metrics = [m for m in self.metrics if m.detector_type == "quantum"]
        classical_metrics = [m for m in self.metrics if m.detector_type == "classical"]
        
        stats = {
            "total_requests": len(self.metrics),
            "quantum": self._calculate_stats(quantum_metrics),
            "classical": self._calculate_stats(classical_metrics),
            "comparison": {}
        }
        
        if quantum_metrics and classical_metrics:
            stats["comparison"] = self._compare_models(quantum_metrics, classical_metrics)
        
        return stats
    
    def _calculate_stats(self, metrics: List[ABTestMetrics]) -> Dict[str, Any]:
        """Berechne Statistiken für eine Modell-Gruppe."""
        if not metrics:
            return {}
        
        inference_times = [m.inference_time_ms for m in metrics if m.error is None]
        confidence_scores = [m.confidence_score for m in metrics if m.error is None]
        risk_scores = [m.risk_score for m in metrics if m.error is None]
        
        blocks = sum(1 for m in metrics if m.final_verdict == "block")
        
        return {
            "count": len(metrics),
            "errors": sum(1 for m in metrics if m.error is not None),
            "blocks": blocks,
            "allows": len(metrics) - blocks,
            "block_rate": blocks / len(metrics) if metrics else 0.0,
            "inference_time": {
                "mean": statistics.mean(inference_times) if inference_times else 0.0,
                "median": statistics.median(inference_times) if inference_times else 0.0,
                "p95": self._percentile(inference_times, 0.95) if inference_times else 0.0,
                "p99": self._percentile(inference_times, 0.99) if inference_times else 0.0,
            },
            "confidence": {
                "mean": statistics.mean(confidence_scores) if confidence_scores else 0.0,
                "median": statistics.median(confidence_scores) if confidence_scores else 0.0,
            },
            "risk_score": {
                "mean": statistics.mean(risk_scores) if risk_scores else 0.0,
                "median": statistics.median(risk_scores) if risk_scores else 0.0,
            }
        }
    
    def _compare_models(
        self,
        quantum_metrics: List[ABTestMetrics],
        classical_metrics: List[ABTestMetrics]
    ) -> Dict[str, Any]:
        """Vergleiche Quantum vs Classical."""
        quantum_stats = self._calculate_stats(quantum_metrics)
        classical_stats = self._calculate_stats(classical_metrics)
        
        comparison = {
            "latency_improvement": {
                "mean": classical_stats["inference_time"]["mean"] - quantum_stats["inference_time"]["mean"],
                "p95": classical_stats["inference_time"]["p95"] - quantum_stats["inference_time"]["p95"],
                "improvement_percent": (
                    (classical_stats["inference_time"]["mean"] - quantum_stats["inference_time"]["mean"]) /
                    classical_stats["inference_time"]["mean"] * 100
                    if classical_stats["inference_time"]["mean"] > 0 else 0.0
                )
            },
            "confidence_difference": {
                "mean": quantum_stats["confidence"]["mean"] - classical_stats["confidence"]["mean"],
            },
            "block_rate_difference": {
                "absolute": quantum_stats["block_rate"] - classical_stats["block_rate"],
                "relative_percent": (
                    (quantum_stats["block_rate"] - classical_stats["block_rate"]) /
                    classical_stats["block_rate"] * 100
                    if classical_stats["block_rate"] > 0 else 0.0
                )
            }
        }
        
        return comparison
    
    def _percentile(self, data: List[float], p: float) -> float:
        """Berechne Percentile."""
        if not data:
            return 0.0
        sorted_data = sorted(data)
        index = int(len(sorted_data) * p)
        return sorted_data[min(index, len(sorted_data) - 1)]
    
    def export_report(self, output_path: Optional[str] = None) -> str:
        """Exportiere Vergleichsbericht."""
        stats = self.get_statistics()
        
        report_lines = [
            "=" * 80,
            "A/B TEST REPORT: Quantum vs Classical",
            "=" * 80,
            f"Total Requests: {stats.get('total_requests', 0)}",
            "",
            "QUANTUM MODEL:",
            f"  Requests: {stats.get('quantum', {}).get('count', 0)}",
            f"  Errors: {stats.get('quantum', {}).get('errors', 0)}",
            f"  Block Rate: {stats.get('quantum', {}).get('block_rate', 0.0):.2%}",
            f"  Mean Latency: {stats.get('quantum', {}).get('inference_time', {}).get('mean', 0.0):.2f}ms",
            f"  P95 Latency: {stats.get('quantum', {}).get('inference_time', {}).get('p95', 0.0):.2f}ms",
            f"  Mean Confidence: {stats.get('quantum', {}).get('confidence', {}).get('mean', 0.0):.3f}",
            "",
            "CLASSICAL MODEL:",
            f"  Requests: {stats.get('classical', {}).get('count', 0)}",
            f"  Errors: {stats.get('classical', {}).get('errors', 0)}",
            f"  Block Rate: {stats.get('classical', {}).get('block_rate', 0.0):.2%}",
            f"  Mean Latency: {stats.get('classical', {}).get('inference_time', {}).get('mean', 0.0):.2f}ms",
            f"  P95 Latency: {stats.get('classical', {}).get('inference_time', {}).get('p95', 0.0):.2f}ms",
            f"  Mean Confidence: {stats.get('classical', {}).get('confidence', {}).get('mean', 0.0):.3f}",
            "",
        ]
        
        if stats.get("comparison"):
            comp = stats["comparison"]
            report_lines.extend([
                "COMPARISON:",
                f"  Latency Improvement: {comp.get('latency_improvement', {}).get('improvement_percent', 0.0):.1f}%",
                f"  Mean Latency Diff: {comp.get('latency_improvement', {}).get('mean', 0.0):.2f}ms",
                f"  P95 Latency Diff: {comp.get('latency_improvement', {}).get('p95', 0.0):.2f}ms",
                f"  Confidence Diff: {comp.get('confidence_difference', {}).get('mean', 0.0):.3f}",
                f"  Block Rate Diff: {comp.get('block_rate_difference', {}).get('absolute', 0.0):.2%}",
                "",
            ])
        
        report_lines.append("=" * 80)
        
        report = "\n".join(report_lines)
        
        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(report)
        
        return report


# Global logger instance
_ab_logger: Optional[ABTestLogger] = None


def get_ab_logger() -> ABTestLogger:
    """Get global A/B test logger instance."""
    global _ab_logger
    if _ab_logger is None:
        _ab_logger = ABTestLogger()
    return _ab_logger
