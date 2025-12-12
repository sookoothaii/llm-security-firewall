"""
Dynamic Policy Engine

Dynamische Policy Engine mit Hot-Reload und erweiterten Bedingungen.
"""
import yaml
import json
import hashlib
import logging
import threading
import time
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class PolicyConditionType(Enum):
    """Typen von Policy-Bedingungen."""
    SIMPLE = "simple"
    COMPLEX = "complex"
    ML_BASED = "ml_based"


@dataclass
class PolicyCondition:
    """Eine einzelne Policy-Bedingung."""
    type: PolicyConditionType
    expression: str  # Python-auswertbarer Ausdruck
    description: str
    weight: float = 1.0


@dataclass
class RoutingPolicy:
    """Eine vollständige Routing-Policy."""
    name: str
    priority: int  # Höher = wichtiger
    conditions: List[PolicyCondition]
    detectors: List[Dict[str, Any]]
    execution_strategy: str
    max_latency_ms: int
    enabled: bool = True
    version: str = "1.0.0"
    last_modified: datetime = None
    activation_threshold: float = 0.7  # Wann diese Policy aktiv wird


class DynamicPolicyEngine:
    """Dynamische Policy Engine mit Hot-Reload und erweiterten Bedingungen."""
    
    def __init__(self, config_path: str, watch_for_changes: bool = True):
        """
        Initialize policy engine.
        
        Args:
            config_path: Path to YAML policy configuration file
            watch_for_changes: If True, watch for file changes and reload automatically
        """
        self.config_path = Path(config_path)
        self.policies: Dict[str, RoutingPolicy] = {}
        self.policy_hash = ""
        self.watcher_thread = None
        self.running = False
        self.lock = threading.RLock()
        
        # Cache für ausgewertete Bedingungen
        self.condition_cache = {}
        self.cache_ttl = timedelta(seconds=30)
        
        # Metriken
        self.metrics = {
            'policy_evaluations': 0,
            'cache_hits': 0,
            'reloads': 0,
            'last_reload': None
        }
        
        # Lade initiale Policies
        self._load_policies()
        
        # Starte Watcher-Thread wenn gewünscht
        if watch_for_changes:
            self._start_config_watcher()
    
    def _load_policies(self):
        """Lädt Policies aus YAML-Konfiguration."""
        try:
            if not self.config_path.exists():
                logger.warning(f"Policy config file not found: {self.config_path}")
                # Erstelle Standard-Policies
                self._create_default_policies()
                return
            
            with open(self.config_path, 'r', encoding='utf-8') as f:
                content = f.read()
                new_hash = hashlib.md5(content.encode()).hexdigest()
                
                if new_hash == self.policy_hash:
                    return  # Keine Änderungen
                
                config = yaml.safe_load(content)
                
                with self.lock:
                    self.policies.clear()
                    
                    for policy_config in config.get('policies', []):
                        policy = self._create_policy_from_config(policy_config)
                        self.policies[policy.name] = policy
                    
                    self.policy_hash = new_hash
                    self.metrics['reloads'] += 1
                    self.metrics['last_reload'] = datetime.utcnow()
                    
                    logger.info(f"Loaded {len(self.policies)} policies from {self.config_path}")
                    
        except Exception as e:
            logger.error(f"Failed to load policies: {e}", exc_info=True)
            # Behalte alte Policies bei Fehler
            if not self.policies:
                self._create_default_policies()
    
    def _create_default_policies(self):
        """Erstellt Standard-Policies als Fallback."""
        logger.info("Creating default policies")
        default_policies = [
            {
                "name": "code_tool_policy",
                "priority": 100,
                "enabled": True,
                "activation_threshold": 0.7,
                "conditions": [
                    {
                        "type": "simple",
                        "expression": "context.get('source_tool') == 'code_interpreter'",
                        "description": "Code interpreter tool",
                        "weight": 1.0
                    }
                ],
                "detectors": [
                    {"name": "code_intent", "mode": "required", "timeout_ms": 500, "priority": 1},
                    {"name": "content_safety", "mode": "required", "timeout_ms": 500, "priority": 2}
                ],
                "strategy": "parallel",
                "max_latency": 1000
            },
            {
                "name": "default_policy",
                "priority": 10,
                "enabled": True,
                "activation_threshold": 0.3,
                "conditions": [
                    {
                        "type": "simple",
                        "expression": "True",
                        "description": "Default fallback",
                        "weight": 1.0
                    }
                ],
                "detectors": [
                    {"name": "content_safety", "mode": "required", "timeout_ms": 500}
                ],
                "strategy": "sequential",
                "max_latency": 600
            }
        ]
        
        with self.lock:
            for policy_config in default_policies:
                policy = self._create_policy_from_config(policy_config)
                self.policies[policy.name] = policy
    
    def _create_policy_from_config(self, config: Dict) -> RoutingPolicy:
        """Erstellt RoutingPolicy aus Konfiguration."""
        conditions = []
        
        for cond_config in config.get('conditions', []):
            cond_type = PolicyConditionType(cond_config.get('type', 'simple'))
            condition = PolicyCondition(
                type=cond_type,
                expression=cond_config['expression'],
                description=cond_config.get('description', ''),
                weight=cond_config.get('weight', 1.0)
            )
            conditions.append(condition)
        
        # Standard-Bedingung falls keine angegeben
        if not conditions:
            conditions.append(PolicyCondition(
                type=PolicyConditionType.SIMPLE,
                expression="True",
                description="Default condition",
                weight=1.0
            ))
        
        return RoutingPolicy(
            name=config['name'],
            priority=config.get('priority', 1),
            conditions=conditions,
            detectors=config['detectors'],
            execution_strategy=config.get('strategy', 'parallel'),
            max_latency_ms=config.get('max_latency', 200),
            enabled=config.get('enabled', True),
            version=config.get('version', '1.0.0'),
            activation_threshold=config.get('activation_threshold', 0.7)
        )
    
    def _start_config_watcher(self):
        """Startet Thread zum Überwachen von Konfigurationsänderungen."""
        self.running = True
        self.watcher_thread = threading.Thread(
            target=self._watch_config_changes,
            daemon=True,
            name="PolicyConfigWatcher"
        )
        self.watcher_thread.start()
        logger.info("Started policy config watcher thread")
    
    def _watch_config_changes(self):
        """Überwacht Konfigurationsdatei auf Änderungen."""
        last_check = time.time()
        last_mtime = 0
        
        while self.running:
            try:
                current_time = time.time()
                
                # Prüfe alle 2 Sekunden auf Änderungen
                if current_time - last_check >= 2:
                    if self.config_path.exists():
                        current_mtime = self.config_path.stat().st_mtime
                        
                        if current_mtime > last_mtime:
                            logger.info("Policy config file modified, reloading...")
                            self._load_policies()
                            last_mtime = current_mtime
                    
                    last_check = current_time
                
                time.sleep(0.5)  # Kurzes Sleep zur CPU-Entlastung
                
            except Exception as e:
                logger.error(f"Error in config watcher: {e}")
                time.sleep(5)  # Bei Fehler länger warten
    
    def evaluate_policies(self, context: Dict[str, Any], debug: bool = False) -> List[RoutingPolicy]:
        """Evaluierte alle Policies gegen den Kontext und gibt passende zurück."""
        self.metrics['policy_evaluations'] += 1
        
        matching_policies = []
        debug_info = [] if debug else None
        
        with self.lock:
            # Sortiere Policies nach Priorität für Debug-Ausgabe
            sorted_policies = sorted(self.policies.values(), key=lambda p: p.priority, reverse=True)
            
            for policy in sorted_policies:
                if not policy.enabled:
                    if debug:
                        debug_info.append({
                            "policy": policy.name,
                            "priority": policy.priority,
                            "enabled": False,
                            "matches": False
                        })
                    continue
                
                # Cache-Key für diese Policy+Context Kombination
                cache_key = f"{policy.name}_{hash(json.dumps(context, sort_keys=True, default=str))}"
                
                # Prüfe Cache
                if cache_key in self.condition_cache:
                    cache_entry = self.condition_cache[cache_key]
                    if datetime.utcnow() - cache_entry['timestamp'] < self.cache_ttl:
                        self.metrics['cache_hits'] += 1
                        matches = cache_entry['matches']
                        if debug:
                            debug_info.append({
                                "policy": policy.name,
                                "priority": policy.priority,
                                "cached": True,
                                "matches": matches
                            })
                        if matches:
                            matching_policies.append(policy)
                        continue
                
                # Evaluierte Bedingungen
                evaluation_result = self._evaluate_policy_conditions(policy, context, debug=debug)
                matches = evaluation_result if isinstance(evaluation_result, bool) else evaluation_result.get('matches', False)
                condition_details = evaluation_result if isinstance(evaluation_result, dict) else None
                
                # Speichere im Cache
                self.condition_cache[cache_key] = {
                    'matches': matches,
                    'timestamp': datetime.utcnow()
                }
                
                if debug:
                    debug_info.append({
                        "policy": policy.name,
                        "priority": policy.priority,
                        "matches": matches,
                        "conditions": condition_details.get('conditions', []) if condition_details else [],
                        "total_weight": condition_details.get('total_weight', 0) if condition_details else 0,
                        "matched_weight": condition_details.get('matched_weight', 0) if condition_details else 0,
                        "match_ratio": condition_details.get('match_ratio', 0) if condition_details else 0,
                        "activation_threshold": policy.activation_threshold,
                        "threshold_met": matches
                    })
                
                if matches:
                    matching_policies.append(policy)
        
        # Sortiere nach Priorität (höher = wichtiger)
        matching_policies.sort(key=lambda p: p.priority, reverse=True)
        
        if debug:
            logger.debug(f"Policy Evaluation Debug: {json.dumps(debug_info, indent=2, default=str)}")
        
        return matching_policies
    
    def _evaluate_policy_conditions(self, policy: RoutingPolicy, context: Dict, debug: bool = False) -> bool:
        """Evaluierte alle Bedingungen einer Policy."""
        if not policy.conditions:
            return True
        
        total_weight = 0.0
        matched_weight = 0.0
        condition_results = [] if debug else None
        
        for condition in policy.conditions:
            total_weight += condition.weight
            
            try:
                # Safely evaluate condition
                # Helper function to safely access attributes
                def safe_get(obj, key, default=None):
                    """Safely get attribute or dict key."""
                    if isinstance(obj, dict):
                        return obj.get(key, default)
                    elif hasattr(obj, key):
                        return getattr(obj, key, default)
                    return default
                
                safe_context = {
                    'context': context,
                    'len': len,
                    'str': str,
                    'int': int,
                    'float': float,
                    'bool': bool,
                    'max': max,
                    'min': min,
                    'sum': sum,
                    'any': any,
                    'all': all,
                    'in': lambda x, y: x in y,  # For 'in' operator support
                    'get': safe_get,
                    'hasattr': hasattr,
                    'getattr': getattr
                }
                
                # Erstelle safe namespace
                namespace = {}
                namespace.update(safe_context)
                
                # Führe bedingt aus (nur für Demo - in Produktion sandboxen!)
                match = eval(condition.expression, {"__builtins__": {}}, namespace)
                
                if match:
                    matched_weight += condition.weight
                
                if debug:
                    condition_results.append({
                        "expression": condition.expression,
                        "description": condition.description,
                        "weight": condition.weight,
                        "matched": match,
                        "contributed_weight": condition.weight if match else 0.0
                    })
                    
            except Exception as e:
                logger.warning(f"Failed to evaluate condition '{condition.expression}': {e}")
                # Bei Fehler zähle als nicht erfüllt
                if debug:
                    condition_results.append({
                        "expression": condition.expression,
                        "description": condition.description,
                        "weight": condition.weight,
                        "matched": False,
                        "error": str(e),
                        "contributed_weight": 0.0
                    })
        
        # Prüfe ob genug Bedingungen erfüllt sind
        if total_weight == 0:
            if debug:
                return {
                    "matches": False,
                    "total_weight": 0,
                    "matched_weight": 0,
                    "match_ratio": 0,
                    "conditions": condition_results
                }
            return False
        
        match_ratio = matched_weight / total_weight
        matches = match_ratio >= policy.activation_threshold
        
        if debug:
            return {
                "matches": matches,
                "total_weight": total_weight,
                "matched_weight": matched_weight,
                "match_ratio": match_ratio,
                "activation_threshold": policy.activation_threshold,
                "conditions": condition_results
            }
        
        return matches
    
    def get_matching_detectors(self, context: Dict[str, Any], debug: bool = False) -> List[Dict[str, Any]]:
        """Findet passende Detektoren für den Kontext."""
        policies = self.evaluate_policies(context, debug=debug)
        
        if debug:
            logger.debug(f"Policy Engine: Evaluated {len(policies)} matching policies")
            if policies:
                logger.debug(f"Policy Engine: Selected policy '{policies[0].name}' (priority {policies[0].priority})")
            else:
                logger.debug(f"Policy Engine: No matching policies, using default")
        
        if not policies:
            # Fallback auf Default
            default_detectors = self._get_default_detectors()
            if debug:
                logger.debug(f"Policy Engine: Using default detectors: {[d.get('name') for d in default_detectors]}")
            return default_detectors
        
        # Nehme die höchste Prioritäts-Policy
        selected_policy = policies[0]
        
        if debug:
            logger.debug(f"Policy Engine: Selected '{selected_policy.name}' with {len(selected_policy.detectors)} detectors")
        
        logger.debug(f"Selected policy '{selected_policy.name}' for context")
        return selected_policy.detectors
    
    def _get_default_detectors(self) -> List[Dict[str, Any]]:
        """Standard-Detektoren als Fallback."""
        return [
            {
                "name": "content_safety",
                "mode": "required",
                "timeout_ms": 500
            }
        ]
    
    def get_metrics(self) -> Dict[str, Any]:
        """Gibt Engine-Metriken zurück."""
        with self.lock:
            return {
                **self.metrics,
                'policy_count': len(self.policies),
                'cache_size': len(self.condition_cache),
                'watching': self.running
            }
    
    def reload_policies(self):
        """Erzwingt Neuladen der Policies."""
        self._load_policies()
    
    def shutdown(self):
        """Stoppt die Policy Engine sauber."""
        self.running = False
        if self.watcher_thread:
            self.watcher_thread.join(timeout=5)

