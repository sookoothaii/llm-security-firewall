"""
Tests for Streaming Token Guard
================================

Creator: Joerg Bollwahn
Date: 2025-10-30
"""

from datetime import datetime

from llm_firewall.gates.stream_guard import RollingWindowStreamGuard, StreamAction
from llm_firewall.core.types import ModelContext, Severity


class TestRollingWindowStreamGuard:
    """Test streaming token guard."""
    
    def test_guard_initialization(self):
        """Test guard can be created."""
        guard = RollingWindowStreamGuard()
        assert guard is not None
        assert guard.window_size == 64
        assert guard.abort_severity == Severity.HIGH
    
    def test_start_stream(self):
        """Test stream initialization."""
        guard = RollingWindowStreamGuard()
        ctx = ModelContext(
            session_id="test",
            request_id="req1",
            user_id="user1",
            model_id="test-model",
            prompt_hash="abc123",
            time_utc=datetime.now()
        )
        
        state = guard.start(ctx)
        
        assert state.step == 0
        assert state.cumulative_risk == 0.0
        assert state.last_severity == Severity.NONE
        assert state.window_text == ""
    
    def test_safe_token_continues(self):
        """Test safe token is allowed."""
        guard = RollingWindowStreamGuard()
        ctx = ModelContext("test", "req1", None, "model", "hash", datetime.now())
        state = guard.start(ctx)
        
        action, state = guard.on_token("Hello", state)
        
        assert action == StreamAction.CONTINUE
        assert state.step == 1
        assert "Hello" in state.window_text
    
    def test_high_risk_token_aborts(self):
        """Test high-risk pattern triggers abort."""
        guard = RollingWindowStreamGuard(abort_severity=Severity.MEDIUM)
        ctx = ModelContext("test", "req1", None, "model", "hash", datetime.now())
        state = guard.start(ctx)
        
        # Add context
        action, state = guard.on_token("Here is how to", state)
        assert action == StreamAction.CONTINUE
        
        # Trigger pattern
        action, state = guard.on_token(" step 1:", state)
        
        # Should trigger (contains "step 1:" pattern)
        assert action in [StreamAction.REWRITE, StreamAction.ABORT]
    
    def test_cumulative_risk_accumulates(self):
        """Test cumulative risk increases with suspicious tokens."""
        guard = RollingWindowStreamGuard(risk_decay=0.95)
        ctx = ModelContext("test", "req1", None, "model", "hash", datetime.now())
        state = guard.start(ctx)
        
        initial_risk = state.cumulative_risk
        
        # Add several tokens
        for token in ["step", "1", ":", "first"]:
            action, state = guard.on_token(token, state)
        
        # Risk should have accumulated
        assert state.cumulative_risk > initial_risk

