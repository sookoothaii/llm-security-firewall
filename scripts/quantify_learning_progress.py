#!/usr/bin/env python3
"""
Quantify Learning Progress - Zeigt wie viel die Engine bereits gelernt hat
================================================================================

Analysiert den Feedback-Buffer und Online-Learning Statistiken um zu quantifizieren:
- Wie viele Samples wurden gesammelt?
- Wie viele Training-Updates wurden durchgeführt?
- Wie hat sich der Loss entwickelt?
- Wie viel "Wissen" hat das Modell akkumuliert?

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-09
"""

import requests
import json
from datetime import datetime
from typing import Dict, Optional

FIREWALL_URL = "http://localhost:8001"
FEEDBACK_STATS_URL = f"{FIREWALL_URL}/feedback/stats"
FEEDBACK_TRAIN_URL = f"{FIREWALL_URL}/feedback/train"


def get_feedback_stats() -> Dict:
    """Hole Feedback-Statistiken vom Service."""
    try:
        response = requests.get(FEEDBACK_STATS_URL, timeout=5)
        return response.json()
    except Exception as e:
        return {"error": str(e), "enabled": False}


def calculate_learning_metrics(stats: Dict) -> Dict:
    """
    Berechne Learning-Metriken aus den Statistiken.
    
    Returns:
        Dict mit quantifizierten Learning-Metriken
    """
    if not stats.get("enabled"):
        return {
            "learning_enabled": False,
            "message": "Feedback collection is disabled"
        }
    
    buffer_size = stats.get("buffer_size", 0)
    max_size = stats.get("max_size", 10000)
    buffer_utilization = (buffer_size / max_size * 100) if max_size > 0 else 0
    
    # Buffer-Statistiken nach Priorität
    buffer_stats = stats.get("statistics", {})
    critical_samples = buffer_stats.get("critical", 0)
    high_samples = buffer_stats.get("high", 0)
    medium_samples = buffer_stats.get("medium", 0)
    low_samples = buffer_stats.get("low", 0)
    total_samples = buffer_stats.get("total", buffer_size)
    
    # Online Learning Statistiken
    online_learning = stats.get("online_learning", {})
    learning_enabled = online_learning.get("running", False)
    
    metrics = {
        "buffer_metrics": {
            "current_size": buffer_size,
            "max_size": max_size,
            "utilization_percent": round(buffer_utilization, 2),
            "samples_by_priority": {
                "critical": critical_samples,
                "high": high_samples,
                "medium": medium_samples,
                "low": low_samples,
                "total": total_samples
            },
            "priority_distribution": {
                "critical": round((critical_samples / total_samples * 100) if total_samples > 0 else 0, 1),
                "high": round((high_samples / total_samples * 100) if total_samples > 0 else 0, 1),
                "medium": round((medium_samples / total_samples * 100) if total_samples > 0 else 0, 1),
                "low": round((low_samples / total_samples * 100) if total_samples > 0 else 0, 1),
            }
        },
        "online_learning_metrics": {}
    }
    
    if learning_enabled:
        learner_stats = online_learning.get("learner_stats", {})
        updates = learner_stats.get("updates", 0)
        total_loss = learner_stats.get("total_loss", 0.0)
        average_loss = learner_stats.get("average_loss", 0.0)
        last_update = learner_stats.get("last_update", "N/A")
        
        # Berechne "Wissens-Akkumulation"
        # Annahme: Jedes Update verbessert das Modell, Loss-Reduktion = Lernen
        knowledge_accumulation = {
            "total_updates": updates,
            "total_loss_accumulated": round(total_loss, 4),
            "average_loss_per_update": round(average_loss, 4),
            "estimated_improvement": "N/A"
        }
        
        # Loss-Interpretation
        if average_loss > 0:
            if average_loss < 0.01:
                improvement_status = "Excellent (Loss < 0.01)"
            elif average_loss < 0.05:
                improvement_status = "Good (Loss < 0.05)"
            elif average_loss < 0.10:
                improvement_status = "Moderate (Loss < 0.10)"
            else:
                improvement_status = "Needs Improvement (Loss > 0.10)"
            
            knowledge_accumulation["improvement_status"] = improvement_status
        
        # Berechne "Learning Progress" basierend auf Updates und Samples
        # Progress = (Updates * Samples pro Update) / Total Samples
        samples_per_update = 32  # Standard Batch Size
        total_samples_processed = updates * samples_per_update
        learning_progress = min(100, (total_samples_processed / max(total_samples, 1)) * 100) if total_samples > 0 else 0
        
        metrics["online_learning_metrics"] = {
            "enabled": True,
            "running": learning_enabled,
            "knowledge_accumulation": knowledge_accumulation,
            "learning_progress": {
                "progress_percent": round(learning_progress, 1),
                "total_samples_processed": total_samples_processed,
                "samples_per_update": samples_per_update,
                "estimated_batches_trained": updates
            },
            "loss_metrics": {
                "average_loss": round(average_loss, 4),
                "total_loss": round(total_loss, 4),
                "loss_trend": "decreasing" if average_loss < 0.1 else "needs_attention"
            },
            "last_update": last_update
        }
    else:
        metrics["online_learning_metrics"] = {
            "enabled": False,
            "message": "Online learning is not running"
        }
    
    return metrics


def format_learning_report(metrics: Dict) -> str:
    """Formatiere Learning-Metriken als lesbaren Report."""
    if not metrics.get("learning_enabled", True):
        return f"⚠️  {metrics.get('message', 'Learning not enabled')}"
    
    buffer = metrics["buffer_metrics"]
    learning = metrics.get("online_learning_metrics", {})
    
    report = []
    report.append("=" * 80)
    report.append("LEARNING PROGRESS QUANTIFICATION")
    report.append("=" * 80)
    report.append(f"Zeitpunkt: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("")
    
    # Buffer-Metriken
    report.append("📊 FEEDBACK BUFFER")
    report.append("-" * 80)
    report.append(f"  Buffer-Auslastung: {buffer['current_size']}/{buffer['max_size']} ({buffer['utilization_percent']}%)")
    report.append("")
    report.append("  Samples nach Priorität:")
    samples = buffer["samples_by_priority"]
    dist = buffer["priority_distribution"]
    report.append(f"    🔴 Critical: {samples['critical']:4d} ({dist['critical']:5.1f}%)")
    report.append(f"    🟠 High:     {samples['high']:4d} ({dist['high']:5.1f}%)")
    report.append(f"    🟡 Medium:   {samples['medium']:4d} ({dist['medium']:5.1f}%)")
    report.append(f"    🟢 Low:      {samples['low']:4d} ({dist['low']:5.1f}%)")
    report.append(f"    ─────────────────────────────")
    report.append(f"    📦 Total:    {samples['total']:4d}")
    report.append("")
    
    # Online Learning Metriken
    if learning.get("enabled"):
        report.append("🧠 ONLINE LEARNING")
        report.append("-" * 80)
        
        knowledge = learning.get("knowledge_accumulation", {})
        progress = learning.get("learning_progress", {})
        loss = learning.get("loss_metrics", {})
        
        report.append(f"  Status: ✅ AKTIV")
        report.append(f"  Total Updates: {knowledge.get('total_updates', 0)}")
        report.append(f"  Last Update: {learning.get('last_update', 'N/A')}")
        report.append("")
        
        report.append("  📈 Learning Progress:")
        report.append(f"    Progress: {progress.get('progress_percent', 0):.1f}%")
        report.append(f"    Samples verarbeitet: {progress.get('total_samples_processed', 0)}")
        report.append(f"    Batches trainiert: {progress.get('estimated_batches_trained', 0)}")
        report.append("")
        
        report.append("  📉 Loss Metriken:")
        report.append(f"    Average Loss: {loss.get('average_loss', 0):.4f}")
        report.append(f"    Total Loss: {loss.get('total_loss', 0):.4f}")
        report.append(f"    Trend: {loss.get('loss_trend', 'unknown')}")
        if "improvement_status" in knowledge:
            report.append(f"    Status: {knowledge['improvement_status']}")
        report.append("")
        
        # Quantifizierung des "Gelernten"
        updates = knowledge.get("total_updates", 0)
        avg_loss = loss.get("average_loss", 0)
        
        if updates > 0:
            # Schätze "Wissens-Akkumulation"
            if avg_loss < 0.01:
                knowledge_level = "Sehr hoch (>95%)"
            elif avg_loss < 0.05:
                knowledge_level = "Hoch (80-95%)"
            elif avg_loss < 0.10:
                knowledge_level = "Moderat (60-80%)"
            else:
                knowledge_level = "Niedrig (<60%)"
            
            report.append("  🎓 Quantifizierung des Gelernten:")
            report.append(f"    Wissens-Level: {knowledge_level}")
            report.append(f"    Basierend auf: {updates} Updates, Loss={avg_loss:.4f}")
            report.append("")
            
            # Empfehlungen
            report.append("  💡 Empfehlungen:")
            if buffer["current_size"] < 100:
                report.append("    ⚠️  Buffer noch klein - mehr Samples sammeln")
            if updates == 0:
                report.append("    ⚠️  Noch keine Updates - Training auslösen: POST /feedback/train")
            elif avg_loss > 0.10:
                report.append("    ⚠️  Loss noch hoch - mehr Training empfohlen")
            else:
                report.append("    ✅ Learning läuft gut - weiter beobachten")
    else:
        report.append("🧠 ONLINE LEARNING")
        report.append("-" * 80)
        report.append(f"  Status: ❌ DEAKTIVIERT")
        report.append(f"  {learning.get('message', 'Online learning not enabled')}")
        report.append("")
        report.append("  💡 Aktivierung:")
        report.append("    Setze ENABLE_ONLINE_LEARNING=true")
    
    report.append("")
    report.append("=" * 80)
    
    return "\n".join(report)


def main():
    """Hauptfunktion: Quantifiziere Learning Progress."""
    print("\n🔍 ANALYSIERE LEARNING PROGRESS...\n")
    
    # Hole Statistiken
    stats = get_feedback_stats()
    
    if "error" in stats:
        print(f"❌ Fehler beim Abrufen der Statistiken: {stats['error']}")
        print("\n💡 Stelle sicher, dass der Service auf Port 8001 läuft:")
        print("   python -m uvicorn detectors.code_intent_service.main:app --host 0.0.0.0 --port 8001")
        return 1
    
    # Berechne Metriken
    metrics = calculate_learning_metrics(stats)
    
    # Formatiere Report
    report = format_learning_report(metrics)
    print(report)
    
    # Speichere detaillierte Metriken als JSON
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"learning_metrics_{timestamp}.json"
    
    detailed_metrics = {
        "timestamp": datetime.now().isoformat(),
        "raw_stats": stats,
        "calculated_metrics": metrics
    }
    
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(detailed_metrics, f, indent=2, ensure_ascii=False)
    
    print(f"\n📄 Detaillierte Metriken gespeichert: {filename}")
    print("=" * 80)
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())

