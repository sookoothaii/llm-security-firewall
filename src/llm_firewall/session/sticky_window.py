# -*- coding: utf-8 -*-
"""
Sticky Decision Window for Session-Level EWMA Dilution Prevention
Closes: SE-02 (EWMA dilution)

Policy: After WARN/BLOCK, enforce minimum WARN for ttl_turns
Prevents quick WARN->PASS flip via filler text
"""
from collections import defaultdict

class StickyWindow:
    """
    Session-level sticky decision enforcement
    """
    def __init__(self, ttl_turns: int = 1):
        """
        Args:
            ttl_turns: Number of turns to maintain elevated action
        """
        self.ttl_turns = ttl_turns
        self.history = defaultdict(list)  # session_id -> [(turn, action), ...]
    
    def decide(self, session_id: str, turn: int, current_action: str) -> str:
        """
        Enforce sticky elevated action
        
        Args:
            session_id: Session identifier
            turn: Current turn number
            current_action: Action from current detectors (BLOCK/WARN/PASS)
        
        Returns:
            Enforced action (may be elevated from current)
        """
        history = self.history[session_id]
        
        # Clean old history (outside TTL window)
        history[:] = [(t, a) for t, a in history if turn - t < self.ttl_turns]
        
        # Check if previous turns had WARN/BLOCK
        recent_elevated = [a for t, a in history if a in ('WARN', 'BLOCK')]
        
        # Add current
        history.append((turn, current_action))
        
        # Enforce: if any recent WARN/BLOCK, minimum is WARN
        if recent_elevated and current_action == 'PASS':
            return 'WARN'
        
        return current_action
    
    def reset(self, session_id: str):
        """Clear history for session"""
        if session_id in self.history:
            del self.history[session_id]

