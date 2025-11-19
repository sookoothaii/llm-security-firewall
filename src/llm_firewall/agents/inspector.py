"""
Argument Inspector (RC10c) - The Elephant Memory
================================================

DLP Lite: Detects sensitive data in tool arguments.

UPGRADE: P0 Fix - Cross-Turn Argument Correlation
Prevents "Distributed Exfiltration" by tracking fragment replays.

Prevents "Categorical Masquerade" attacks where benign tools
(e.g., web_search) are used to exfiltrate secrets via arguments.
"""

import re
import math
import hashlib
import logging
from typing import Dict, Any, List, Set
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# FIX: Count-Min Sketch statt Set (O(1) Insert/Lookup, 10KB RAM)
try:
    from datasketch import CountMinSketch
    COUNT_MIN_AVAILABLE = True
except ImportError:
    COUNT_MIN_AVAILABLE = False
    logger.warning("datasketch not available, falling back to Set-based fragment memory")

# Globales Gedächtnis für Argument-Fragmente
# FIX: Count-Min Sketch (10KB RAM, O(1) Insert/Lookup)
if COUNT_MIN_AVAILABLE:
    FRAGMENT_SKETCH = CountMinSketch(width=1000, depth=5)  # 10KB RAM
    FRAGMENT_MEMORY_LEGACY: Set[bytes] = set()  # Fallback
else:
    FRAGMENT_SKETCH = None
    FRAGMENT_MEMORY_LEGACY: Set[bytes] = set()  # Fallback to Set

MAX_FRAGMENT_MEMORY = 10000


@dataclass
class InspectionResult:
    """Result of argument inspection."""
    is_suspicious: bool
    risk_score_modifier: float  # 0.0 to 1.0
    forced_phase: int  # 0 = no escalation, 4 = exfiltration
    reasons: List[str]  # List of detection reasons
    
    # Backward compatibility fields
    detected_patterns: List[str] = None
    confidence: float = 0.0
    recommendation: str = "ALLOW"
    
    def __post_init__(self):
        """Initialize backward compatibility fields."""
        if self.detected_patterns is None:
            self.detected_patterns = []
        if self.confidence == 0.0 and self.risk_score_modifier > 0:
            self.confidence = self.risk_score_modifier
        if self.recommendation == "ALLOW" and self.is_suspicious:
            if self.risk_score_modifier >= 0.90:
                self.recommendation = "BLOCK"
            elif self.risk_score_modifier >= 0.70:
                self.recommendation = "WARN"
        if not self.detected_patterns and self.reasons:
            self.detected_patterns = self.reasons


class ArgumentInspector:
    """
    Inspects tool arguments for sensitive data patterns.
    
    RC10c: Semantic Gap Fix - Prevents argument injection attacks.
    
    UPGRADE: P0 Fix - Cross-Turn Argument Correlation
    Detects distributed exfiltration by tracking fragment replays.
    
    Detects:
    - AWS Keys (AKIA...)
    - OpenAI Keys (sk-...)
    - Private Keys (-----BEGIN...)
    - High Entropy Strings (Base64 suspicion)
    - Distributed Attack Patterns (Fragment replays)
    """
    
    def __init__(self):
        """Initialize inspector with pattern definitions."""
        self.patterns = {
            "AWS_KEY": r"AKIA[0-9A-Z]{16}",
            "OPENAI_KEY": r"sk-[a-zA-Z0-9]{48}",
            "PRIVATE_KEY": r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
            "BASE64_LONG": r"([A-Za-z0-9+/]{4}){12,}"  # Long base64 strings
        }
    
    def _get_rolling_hashes(self, text: str, window: int = 16) -> List[bytes]:
        """
        Erzeugt Hashes von Text-Fenstern.
        
        FIX: SHA-256 statt MD5 (Kollisions-resistent, Kimi's Requirement)
        
        Args:
            text: Input text to hash
            window: Size of each window
            
        Returns:
            List of SHA-256 digest bytes (8 bytes truncated for memory efficiency)
        """
        if len(text) < window:
            return []
        
        hashes = []
        # Step 4 für Performance (overlapping windows)
        for i in range(0, len(text) - window + 1, 4):
            chunk = text[i:i+window]
            # SHA-256, truncated to 8 bytes (64 bits) for memory efficiency
            # Still collision-resistant for our use case
            hash_digest = hashlib.sha256(chunk.encode()).digest()[:8]
            hashes.append(hash_digest)
        return hashes
    
    def inspect(self, arguments: Dict[str, Any]) -> InspectionResult:
        """
        Inspect tool arguments for sensitive data patterns.
        
        UPGRADE: P0 Fix - Cross-Turn Argument Correlation
        Detects distributed exfiltration by tracking fragment replays.
        
        Args:
            arguments: Dictionary of tool arguments (e.g., {"query": "...", "url": "..."})
            
        Returns:
            InspectionResult with detection status and confidence
        """
        reasons = []
        max_risk = 0.0
        forced_phase = 0
        
        # Convert arguments to string
        arg_str = str(arguments)
        
        # 1. MEMORY CHECK (Gegen "Distributed Exfiltration") - FIX: Count-Min Sketch
        # Wir prüfen, ob wir Teile dieses Strings schon mal gesehen haben
        hashes = self._get_rolling_hashes(arg_str)
        collision_count = 0
        
        # FIX: Use Count-Min Sketch (O(1) Insert/Lookup) statt Set
        if COUNT_MIN_AVAILABLE and FRAGMENT_SKETCH is not None:
            for frag_hash in hashes:
                # Prüfe via Count-Min Sketch (O(1)!)
                count = FRAGMENT_SKETCH[frag_hash]
                if count > 0:
                    collision_count += 1
                # Increment count in sketch
                FRAGMENT_SKETCH[frag_hash] += 1
        else:
            # Fallback: Set-based (legacy)
            known_count = 0
            new_hashes = []
            for h in hashes:
                if h in FRAGMENT_MEMORY_LEGACY:
                    known_count += 1
                else:
                    new_hashes.append(h)
            for h in new_hashes:
                FRAGMENT_MEMORY_LEGACY.add(h)
            if len(FRAGMENT_MEMORY_LEGACY) > MAX_FRAGMENT_MEMORY:
                FRAGMENT_MEMORY_LEGACY.clear()
                logger.warning("Fragment memory cleared (exceeded limit)")
            collision_count = known_count
        
        # Wenn >2 Fragmente kollidieren → verteilter Angriff!
        if len(hashes) > 5 and collision_count >= 2:
            reasons.append(f"Cross-turn fragment collision: {collision_count}")
            max_risk = max(max_risk, 0.95)
            forced_phase = 4
            logger.warning(
                f"Argument Inspector: Distributed Attack detected ({collision_count} fragment collisions). "
                f"Escalating to Phase 4."
            )
        
        # 2. REGEX CHECK
        for label, pattern_str in self.patterns.items():
            pattern = re.compile(pattern_str, re.IGNORECASE)
            if pattern.search(arg_str):
                reasons.append(f"Pattern match: {label}")
                max_risk = max(max_risk, 0.95)
                forced_phase = 4
                logger.warning(
                    f"Argument Inspector: Detected {label} in tool arguments."
                )
        
        # 3. ENTROPY CHECK
        if len(arg_str) > 50:
            # Calculate Shannon entropy
            char_counts = {}
            for char in arg_str:
                char_counts[char] = char_counts.get(char, 0) + 1
            
            prob = [float(count) / len(arg_str) for count in char_counts.values()]
            entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob if p > 0])
            
            if entropy > 5.8:  # High entropy threshold
                reasons.append(f"High Entropy ({entropy:.2f})")
                max_risk = max(max_risk, 0.7)
                forced_phase = max(forced_phase, 3)
        
        return InspectionResult(
            is_suspicious=len(reasons) > 0,
            risk_score_modifier=max_risk,
            forced_phase=forced_phase,
            reasons=reasons
        )
    
    def should_escalate_phase(self, inspection_result: InspectionResult) -> bool:
        """
        Determine if argument inspection should escalate event to Phase 4 (Exfiltration).
        
        Args:
            inspection_result: Result from inspect() method
            
        Returns:
            True if event should be treated as Phase 4 (Exfiltration)
        """
        # Escalate if high-confidence patterns detected or forced_phase is 4
        return (
            inspection_result.is_suspicious and
            (inspection_result.risk_score_modifier >= 0.85 or inspection_result.forced_phase == 4)
        )
