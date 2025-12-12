#!/usr/bin/env python3
"""
Learning Progress Monitor - Überwacht und steuert Online Learning
================================================================================

Überwacht kontinuierlich den Learning-Progress und löst automatisch Training aus,
wenn genug neue Samples vorhanden sind oder der Loss zu hoch ist.

Features:
- Kontinuierliches Monitoring (alle N Sekunden)
- Automatisches Training bei Bedarf
- Dashboard-ähnliche Anzeige
- Konfigurierbare Thresholds

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-09
"""

import requests
import json
import time
import sys
from datetime import datetime
from typing import Dict, Optional

FIREWALL_URL = "http://localhost:8001"
FEEDBACK_STATS_URL = f"{FIREWALL_URL}/feedback/stats"
FEEDBACK_TRAIN_URL = f"{FIREWALL_URL}/feedback/train"

# Konfiguration
MONITOR_INTERVAL = 30  # Sekunden zwischen Checks
AUTO_TRAIN_ENABLED = True
MIN_SAMPLES_FOR_TRAINING = 10
AUTO_TRAIN_THRESHOLD = 20  # Trainiere wenn 20+ neue Samples (reduziert von 50 für kleinere Buffers)
AUTO_TRAIN_BUFFER_THRESHOLD = 0.5  # Oder wenn Buffer >50% voll (für größere Buffers)
LOSS_ALERT_THRESHOLD = 0.15  # Warnung wenn Loss > 0.15
LOSS_CRITICAL_THRESHOLD = 0.25  # Kritisch wenn Loss > 0.25


class LearningMonitor:
    """Monitor für Online Learning Progress."""
    
    def __init__(self):
        self.last_buffer_size = 0
        self.last_update_count = 0
        self.training_count = 0
        self.start_time = datetime.now()
        self.history = []
    
    def get_stats(self) -> Dict:
        """Hole aktuelle Statistiken."""
        try:
            response = requests.get(FEEDBACK_STATS_URL, timeout=5)
            return response.json()
        except Exception as e:
            return {"error": str(e), "enabled": False}
    
    def trigger_training(self, batch_size: int = 32) -> Dict:
        """Löse Training aus."""
        try:
            response = requests.post(
                f"{FEEDBACK_TRAIN_URL}?batch_size={batch_size}",
                timeout=120
            )
            return response.json()
        except Exception as e:
            return {"error": str(e), "success": False}
    
    def should_trigger_training(self, stats: Dict) -> tuple[bool, str]:
        """
        Entscheide ob Training ausgelöst werden sollte.
        
        Returns:
            (should_train, reason)
        """
        if not stats.get("enabled"):
            return False, "Feedback collection disabled"
        
        buffer_size = stats.get("buffer_size", 0)
        max_size = stats.get("max_size", 10000)
        
        if buffer_size < MIN_SAMPLES_FOR_TRAINING:
            return False, f"Not enough samples ({buffer_size} < {MIN_SAMPLES_FOR_TRAINING})"
        
        # ENHANCED: Prüfe auf Buffer-Füllstand (für größere Buffers)
        buffer_fill_ratio = buffer_size / max_size if max_size > 0 else 0
        if buffer_fill_ratio >= AUTO_TRAIN_BUFFER_THRESHOLD:
            return True, f"Buffer fill ratio {buffer_fill_ratio:.1%} >= {AUTO_TRAIN_BUFFER_THRESHOLD:.1%}"
        
        # Prüfe auf neue Samples
        new_samples = buffer_size - self.last_buffer_size
        
        if new_samples >= AUTO_TRAIN_THRESHOLD:
            return True, f"{new_samples} new samples (threshold: {AUTO_TRAIN_THRESHOLD})"
        
        # ENHANCED: Wenn Buffer groß genug ist und noch kein Training gelaufen, trainiere initial
        if buffer_size >= MIN_SAMPLES_FOR_TRAINING * 2 and self.last_buffer_size == 0:
            return True, f"Initial training with {buffer_size} samples"
        
        # Prüfe auf hohen Loss
        online_learning = stats.get("online_learning", {})
        if online_learning.get("running"):
            learner_stats = online_learning.get("learner_stats", {})
            avg_loss = learner_stats.get("average_loss", 0.0)
            updates = learner_stats.get("updates", 0)
            
            # Wenn Loss zu hoch und schon Updates gemacht wurden
            if avg_loss > LOSS_CRITICAL_THRESHOLD and updates > 0:
                return True, f"High loss ({avg_loss:.4f} > {LOSS_CRITICAL_THRESHOLD})"
        
        return False, "No trigger condition met"
    
    def format_dashboard(self, stats: Dict, training_result: Optional[Dict] = None) -> str:
        """Formatiere Dashboard-Anzeige."""
        lines = []
        
        # Header
        lines.append("=" * 80)
        lines.append("LEARNING PROGRESS MONITOR")
        lines.append("=" * 80)
        lines.append(f"Zeitpunkt: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Laufzeit: {(datetime.now() - self.start_time).total_seconds():.0f}s")
        lines.append(f"Trainings ausgelöst: {self.training_count}")
        lines.append("")
        
        if "error" in stats:
            lines.append(f"❌ Fehler: {stats['error']}")
            return "\n".join(lines)
        
        if not stats.get("enabled"):
            lines.append("❌ Feedback Collection: DEAKTIVIERT")
            return "\n".join(lines)
        
        # Buffer-Statistiken
        buffer_size = stats.get("buffer_size", 0)
        max_size = stats.get("max_size", 10000)
        new_samples = buffer_size - self.last_buffer_size
        
        lines.append("📊 FEEDBACK BUFFER")
        lines.append("-" * 80)
        lines.append(f"  Buffer: {buffer_size}/{max_size} ({buffer_size/max_size*100:.1f}%)")
        lines.append(f"  Neue Samples seit letztem Check: {new_samples:+d}")
        
        buffer_stats = stats.get("statistics", {})
        if buffer_stats:
            lines.append(f"  Prioritäten: 🔴{buffer_stats.get('critical', 0)} "
                        f"🟠{buffer_stats.get('high', 0)} "
                        f"🟡{buffer_stats.get('medium', 0)} "
                        f"🟢{buffer_stats.get('low', 0)}")
        lines.append("")
        
        # Online Learning Statistiken
        online_learning = stats.get("online_learning", {})
        if online_learning.get("running"):
            learner_stats = online_learning.get("learner_stats", {})
            updates = learner_stats.get("updates", 0)
            avg_loss = learner_stats.get("average_loss", 0.0)
            total_loss = learner_stats.get("total_loss", 0.0)
            last_update = online_learning.get("last_update", "N/A")
            
            new_updates = updates - self.last_update_count
            
            lines.append("🧠 ONLINE LEARNING")
            lines.append("-" * 80)
            lines.append(f"  Status: ✅ AKTIV")
            lines.append(f"  Total Updates: {updates} ({new_updates:+d} seit letztem Check)")
            lines.append(f"  Average Loss: {avg_loss:.4f}")
            lines.append(f"  Total Loss: {total_loss:.4f}")
            lines.append(f"  Last Update: {last_update}")
            
            # Loss-Status
            if avg_loss < 0.01:
                loss_status = "✅ Excellent"
                knowledge_level = "Sehr hoch (>95%)"
            elif avg_loss < 0.05:
                loss_status = "✅ Good"
                knowledge_level = "Hoch (80-95%)"
            elif avg_loss < 0.10:
                loss_status = "⚠️  Moderate"
                knowledge_level = "Moderat (60-80%)"
            elif avg_loss < LOSS_ALERT_THRESHOLD:
                loss_status = "⚠️  Needs Improvement"
                knowledge_level = "Niedrig (40-60%)"
            else:
                loss_status = "❌ Critical"
                knowledge_level = "Sehr niedrig (<40%)"
            
            lines.append(f"  Loss-Status: {loss_status}")
            lines.append(f"  Wissens-Level: {knowledge_level}")
            lines.append("")
            
            # Training-Ergebnis
            if training_result:
                if training_result.get("success"):
                    lines.append("🎯 TRAINING ERGEBNIS")
                    lines.append("-" * 80)
                    lines.append(f"  ✅ Training erfolgreich!")
                    lines.append(f"  Samples verwendet: {training_result.get('samples_used', 0)}")
                    lines.append(f"  Loss: {training_result.get('loss', 0):.4f}")
                    lines.append(f"  Dauer: {training_result.get('training_time', 0):.2f}s")
                    lines.append("")
                else:
                    lines.append("❌ TRAINING FEHLGESCHLAGEN")
                    lines.append("-" * 80)
                    lines.append(f"  Fehler: {training_result.get('error', 'Unknown')}")
                    lines.append("")
        else:
            lines.append("🧠 ONLINE LEARNING")
            lines.append("-" * 80)
            lines.append("  Status: ❌ DEAKTIVIERT")
            lines.append("")
        
        # Empfehlungen
        lines.append("💡 EMPFEHLUNGEN")
        lines.append("-" * 80)
        
        if buffer_size < 100:
            lines.append("  ⚠️  Buffer noch klein - mehr Samples sammeln")
        
        if online_learning.get("running"):
            learner_stats = online_learning.get("learner_stats", {})
            updates = learner_stats.get("updates", 0)
            avg_loss = learner_stats.get("average_loss", 0.0)
            
            if updates == 0:
                lines.append("  ⚠️  Noch keine Updates - Training auslösen empfohlen")
            elif avg_loss > LOSS_CRITICAL_THRESHOLD:
                lines.append(f"  ❌ Loss kritisch hoch ({avg_loss:.4f}) - mehr Training nötig")
            elif avg_loss > LOSS_ALERT_THRESHOLD:
                lines.append(f"  ⚠️  Loss noch hoch ({avg_loss:.4f}) - weiter trainieren")
            else:
                lines.append("  ✅ Learning läuft gut - weiter beobachten")
        
        lines.append("")
        lines.append("=" * 80)
        
        return "\n".join(lines)
    
    def monitor_loop(self, auto_train: bool = True):
        """Haupt-Monitoring-Loop."""
        print("🚀 Learning Monitor gestartet")
        print(f"   Auto-Training: {'✅ ENABLED' if auto_train else '❌ DISABLED'}")
        print(f"   Check-Interval: {MONITOR_INTERVAL}s")
        print(f"   Auto-Train Threshold: {AUTO_TRAIN_THRESHOLD} neue Samples")
        print("")
        print("Drücke Ctrl+C zum Beenden\n")
        
        try:
            while True:
                # Hole Statistiken
                stats = self.get_stats()
                
                # Prüfe ob Training ausgelöst werden sollte
                training_result = None
                if auto_train and AUTO_TRAIN_ENABLED:
                    should_train, reason = self.should_trigger_training(stats)
                    if should_train:
                        print(f"🔄 Auto-Training auslösen: {reason}")
                        buffer_size = stats.get("buffer_size", 0)
                        batch_size = min(32, buffer_size)
                        training_result = self.trigger_training(batch_size=batch_size)
                        
                        if training_result.get("success"):
                            self.training_count += 1
                            print(f"✅ Training erfolgreich (Loss: {training_result.get('loss', 0):.4f})")
                        else:
                            print(f"❌ Training fehlgeschlagen: {training_result.get('error', 'Unknown')}")
                        print()
                
                # Zeige Dashboard
                dashboard = self.format_dashboard(stats, training_result)
                print(dashboard)
                
                # Update History
                if "error" not in stats and stats.get("enabled"):
                    online_learning = stats.get("online_learning", {})
                    if online_learning.get("running"):
                        learner_stats = online_learning.get("learner_stats", {})
                        self.history.append({
                            "timestamp": datetime.now().isoformat(),
                            "buffer_size": stats.get("buffer_size", 0),
                            "updates": learner_stats.get("updates", 0),
                            "avg_loss": learner_stats.get("average_loss", 0.0)
                        })
                
                # Update last values
                if "error" not in stats:
                    self.last_buffer_size = stats.get("buffer_size", 0)
                    online_learning = stats.get("online_learning", {})
                    if online_learning.get("running"):
                        learner_stats = online_learning.get("learner_stats", {})
                        self.last_update_count = learner_stats.get("updates", 0)
                
                # Warte auf nächsten Check
                time.sleep(MONITOR_INTERVAL)
                
        except KeyboardInterrupt:
            print("\n\n🛑 Monitor gestoppt")
            print(f"   Gesamtlaufzeit: {(datetime.now() - self.start_time).total_seconds():.0f}s")
            print(f"   Trainings ausgelöst: {self.training_count}")
            print(f"   History-Einträge: {len(self.history)}")
            
            # Speichere History
            if self.history:
                filename = f"learning_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(self.history, f, indent=2, ensure_ascii=False)
                print(f"   History gespeichert: {filename}")


def main():
    """Hauptfunktion."""
    import argparse
    
    # CRITICAL: global Deklaration muss VOR der Verwendung der Variablen sein
    global MONITOR_INTERVAL, AUTO_TRAIN_ENABLED, AUTO_TRAIN_THRESHOLD
    
    parser = argparse.ArgumentParser(description="Learning Progress Monitor")
    parser.add_argument("--interval", type=int, default=MONITOR_INTERVAL,
                       help=f"Check-Interval in Sekunden (default: {MONITOR_INTERVAL})")
    parser.add_argument("--no-auto-train", action="store_true",
                       help="Deaktiviere automatisches Training")
    parser.add_argument("--train-threshold", type=int, default=AUTO_TRAIN_THRESHOLD,
                       help=f"Auto-Train Threshold für neue Samples (default: {AUTO_TRAIN_THRESHOLD})")
    parser.add_argument("--once", action="store_true",
                       help="Führe nur einen Check durch (kein kontinuierliches Monitoring)")
    
    args = parser.parse_args()
    
    # Update globale Konfiguration
    MONITOR_INTERVAL = args.interval
    AUTO_TRAIN_ENABLED = not args.no_auto_train
    AUTO_TRAIN_THRESHOLD = args.train_threshold
    
    monitor = LearningMonitor()
    
    if args.once:
        # Einmaliger Check
        stats = monitor.get_stats()
        dashboard = monitor.format_dashboard(stats)
        print(dashboard)
    else:
        # Kontinuierliches Monitoring
        monitor.monitor_loop(auto_train=AUTO_TRAIN_ENABLED)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

