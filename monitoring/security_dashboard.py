"""
Security Dashboard für LLM Security Firewall
===========================================

Monitoring & Alerting System für Production Deployment.

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-09
Status: Production Ready
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from collections import deque
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class SecurityDashboard:
    """
    Monitoring Dashboard für Firewall Performance.
    
    Features:
    - Real-time Performance Metriken
    - Trend-Analyse (7-Tage)
    - Alerting bei Performance-Drops
    - Tägliche Reports
    """
    
    def __init__(self, data_dir: Optional[Path] = None):
        """
        Initialisiere Dashboard.
        
        Args:
            data_dir: Verzeichnis für Persistierung (optional)
        """
        self.data_dir = data_dir or Path(__file__).parent / "dashboard_data"
        self.data_dir.mkdir(exist_ok=True)
        
        # Metriken-Storage (Ring-Buffer für 7 Tage)
        self.metrics_history = {
            'block_rate_7d': deque(maxlen=168),  # 7 Tage * 24h = 168 Stunden
            'fpr_7d': deque(maxlen=168),
            'training_samples_7d': deque(maxlen=168),
            'category_breakdown_7d': deque(maxlen=168),
        }
        
        # Aktuelle Performance-Metriken
        self.metrics = {
            'current_performance': {
                'block_rate': 0.808,  # Initial: 80.8%
                'false_positive_rate': 0.25,  # Initial: 25%
                'category_breakdown': {
                    'mathematical': 1.0,
                    'multilingual': 1.0,
                    'obfuscation': 1.0,
                    'command_injection': 1.0,
                    'creative': 0.667,
                    'sql_injection': 0.75,
                    'benign': 0.25,  # FPR
                }
            },
            'trends': {
                'block_rate_7d': [],
                'fpr_7d': [],
                'training_samples_7d': []
            },
            'alerts': {
                'high_fpr': {'threshold': 0.15, 'active': False, 'last_triggered': None},
                'low_block_rate': {'threshold': 0.70, 'active': False, 'last_triggered': None},
                'training_failed': {'active': False, 'last_triggered': None}
            }
        }
        
        # Lade historische Daten
        self._load_historical_data()
    
    def _load_historical_data(self):
        """Lade historische Metriken aus Datei."""
        history_file = self.data_dir / "metrics_history.json"
        if history_file.exists():
            try:
                with open(history_file, 'r') as f:
                    data = json.load(f)
                    # Konvertiere zu deques
                    for key, values in data.items():
                        if key in self.metrics_history:
                            self.metrics_history[key] = deque(values, maxlen=168)
                logger.info(f"Loaded historical metrics from {history_file}")
            except Exception as e:
                logger.warning(f"Failed to load historical data: {e}")
    
    def _save_historical_data(self):
        """Speichere historische Metriken."""
        history_file = self.data_dir / "metrics_history.json"
        try:
            data = {
                key: list(values) for key, values in self.metrics_history.items()
            }
            with open(history_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save historical data: {e}")
    
    def update_metrics(
        self,
        block_rate: float,
        false_positive_rate: float,
        category_breakdown: Dict[str, float],
        training_samples: int = 0
    ):
        """
        Aktualisiere Performance-Metriken.
        
        Args:
            block_rate: Aktuelle Block-Rate (0.0-1.0)
            false_positive_rate: Aktuelle FPR (0.0-1.0)
            category_breakdown: Block-Rate pro Kategorie
            training_samples: Anzahl neuer Training-Samples
        """
        timestamp = datetime.now()
        
        # Aktualisiere aktuelle Metriken
        self.metrics['current_performance']['block_rate'] = block_rate
        self.metrics['current_performance']['false_positive_rate'] = false_positive_rate
        self.metrics['current_performance']['category_breakdown'] = category_breakdown
        
        # Füge zu Historie hinzu
        self.metrics_history['block_rate_7d'].append({
            'timestamp': timestamp.isoformat(),
            'value': block_rate
        })
        self.metrics_history['fpr_7d'].append({
            'timestamp': timestamp.isoformat(),
            'value': false_positive_rate
        })
        self.metrics_history['training_samples_7d'].append({
            'timestamp': timestamp.isoformat(),
            'value': training_samples
        })
        self.metrics_history['category_breakdown_7d'].append({
            'timestamp': timestamp.isoformat(),
            'values': category_breakdown
        })
        
        # Prüfe Alerts
        self._check_alerts(block_rate, false_positive_rate)
        
        # Speichere Daten
        self._save_historical_data()
    
    def _check_alerts(self, block_rate: float, fpr: float):
        """Prüfe Alert-Bedingungen."""
        # High FPR Alert
        if fpr > self.metrics['alerts']['high_fpr']['threshold']:
            if not self.metrics['alerts']['high_fpr']['active']:
                self.metrics['alerts']['high_fpr']['active'] = True
                self.metrics['alerts']['high_fpr']['last_triggered'] = datetime.now().isoformat()
                logger.warning(f"🚨 ALERT: High FPR detected: {fpr:.1%} (threshold: {self.metrics['alerts']['high_fpr']['threshold']:.1%})")
        else:
            self.metrics['alerts']['high_fpr']['active'] = False
        
        # Low Block Rate Alert
        if block_rate < self.metrics['alerts']['low_block_rate']['threshold']:
            if not self.metrics['alerts']['low_block_rate']['active']:
                self.metrics['alerts']['low_block_rate']['active'] = True
                self.metrics['alerts']['low_block_rate']['last_triggered'] = datetime.now().isoformat()
                logger.warning(f"🚨 ALERT: Low Block Rate detected: {block_rate:.1%} (threshold: {self.metrics['alerts']['low_block_rate']['threshold']:.1%})")
        else:
            self.metrics['alerts']['low_block_rate']['active'] = False
    
    def calculate_trend(self, metric: str, days: int = 7) -> str:
        """
        Berechne Trend für Metrik.
        
        Args:
            metric: Metrik-Name ('block_rate' oder 'fpr')
            days: Anzahl Tage für Trend-Analyse
        
        Returns:
            Trend-String: '↑ increasing', '↓ decreasing', '→ stable'
        """
        history_key = f'{metric}_7d'
        if history_key not in self.metrics_history:
            return "→ no data"
        
        history = list(self.metrics_history[history_key])
        if len(history) < 2:
            return "→ insufficient data"
        
        # Vergleiche erste und letzte Werte
        first_value = history[0]['value']
        last_value = history[-1]['value']
        
        diff = last_value - first_value
        threshold = 0.02  # 2% Änderung = signifikant
        
        if diff > threshold:
            return f"↑ increasing (+{diff:.1%})"
        elif diff < -threshold:
            return f"↓ decreasing ({diff:.1%})"
        else:
            return "→ stable"
    
    def get_feedback_count(self) -> int:
        """Hole aktuelle Anzahl Feedback-Samples (Mock - sollte von Feedback-Buffer kommen)."""
        # TODO: Integration mit Feedback-Buffer
        return 26  # Placeholder
    
    def generate_daily_report(self) -> str:
        """
        Generiere täglichen Performance-Report.
        
        Returns:
            Formatierter Report-String
        """
        current = self.metrics['current_performance']
        breakdown = current['category_breakdown']
        
        report = f"""
🔒 LLM Security Firewall - Tagesreport
📅 Datum: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

📊 PERFORMANCE METRIKEN:
• Gesamt Block-Rate: {current['block_rate']:.1%}
• False Positive Rate: {current['false_positive_rate']:.1%}
• Online Learning Samples: {self.get_feedback_count()}

📈 KATEGORIEN-BREAKDOWN:
• Mathematical: {breakdown.get('mathematical', 0):.1%}
• Multilingual: {breakdown.get('multilingual', 0):.1%}
• Obfuscation: {breakdown.get('obfuscation', 0):.1%}
• Command Injection: {breakdown.get('command_injection', 0):.1%}
• Creative: {breakdown.get('creative', 0):.1%}
• SQL Injection: {breakdown.get('sql_injection', 0):.1%}
• Benign (FPR): {breakdown.get('benign', 0):.1%}

🎯 TOP SCHWACHSTELLEN:
1. Benign FPR: {current['false_positive_rate']:.1%} → Ziel <5%
2. Creative Detection: {breakdown.get('creative', 0):.1%} → Ziel >85%
3. SQL Injection: {breakdown.get('sql_injection', 0):.1%} → Ziel >95%

📈 TRENDS (7 Tage):
• Block-Rate Trend: {self.calculate_trend('block_rate')}
• FPR Trend: {self.calculate_trend('fpr')}

🚨 AKTIVE ALERTS:
"""
        
        # Füge aktive Alerts hinzu
        active_alerts = [
            name for name, alert in self.metrics['alerts'].items()
            if alert.get('active', False)
        ]
        
        if active_alerts:
            for alert_name in active_alerts:
                alert = self.metrics['alerts'][alert_name]
                report += f"• {alert_name}: Triggered at {alert.get('last_triggered', 'unknown')}\n"
        else:
            report += "• Keine aktiven Alerts ✅\n"
        
        report += """
✅ EMPFEHLUNGEN:
1. Benign Whitelist erweitern (siehe Patterns in main.py)
2. Creative Intent Analyzer implementieren
3. SQLi-Patterns erweitern
4. Automatisiertes Training alle 6 Stunden aktivieren
"""
        
        return report
    
    def get_statistics(self) -> Dict[str, Any]:
        """Hole aktuelle Statistiken für API."""
        return {
            'current_performance': self.metrics['current_performance'],
            'trends': {
                'block_rate': self.calculate_trend('block_rate'),
                'fpr': self.calculate_trend('fpr')
            },
            'alerts': {
                name: {
                    'active': alert['active'],
                    'last_triggered': alert.get('last_triggered')
                }
                for name, alert in self.metrics['alerts'].items()
            }
        }


# Singleton-Instanz
_dashboard_instance: Optional[SecurityDashboard] = None


def get_dashboard() -> SecurityDashboard:
    """Hole oder erstelle Dashboard-Singleton."""
    global _dashboard_instance
    if _dashboard_instance is None:
        _dashboard_instance = SecurityDashboard()
    return _dashboard_instance


if __name__ == "__main__":
    # Test Dashboard
    dashboard = SecurityDashboard()
    
    # Simuliere Metriken-Update
    dashboard.update_metrics(
        block_rate=0.808,
        false_positive_rate=0.25,
        category_breakdown={
            'mathematical': 1.0,
            'multilingual': 1.0,
            'obfuscation': 1.0,
            'command_injection': 1.0,
            'creative': 0.667,
            'sql_injection': 0.75,
            'benign': 0.25,
        },
        training_samples=26
    )
    
    # Generiere Report
    print(dashboard.generate_daily_report())

