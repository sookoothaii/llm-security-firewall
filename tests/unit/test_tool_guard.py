"""
HAK_GAL v2.2-ALPHA: Unit Tests for ToolGuard Framework

Tests business logic validation for tool calls.

Creator: Joerg Bollwahn
License: MIT
"""

import pytest

from hak_gal.layers.outbound.tool_guard import (
    SessionContext,
    FinancialToolGuard,
    ToolGuardRegistry,
    BusinessLogicException,
)


class TestSessionContext:
    """Test SessionContext dataclass."""

    def test_default_state(self):
        """Test default empty state."""
        context = SessionContext()
        assert context.state == {}
        assert context.get("tx_count_1h") is None
        assert context.get("tx_count_1h", 0) == 0

    def test_set_get(self):
        """Test set and get operations."""
        context = SessionContext()
        context.set("tx_count_1h", 42)
        assert context.get("tx_count_1h") == 42
        assert context.get("tx_count_1h", 0) == 42

    def test_increment(self):
        """Test increment operation."""
        context = SessionContext()
        assert context.increment("tx_count_1h") == 1
        assert context.increment("tx_count_1h", 5) == 6
        assert context.get("tx_count_1h") == 6

    def test_increment_with_existing_value(self):
        """Test increment with existing value."""
        context = SessionContext()
        context.set("tx_count_1h", 10)
        assert context.increment("tx_count_1h", 3) == 13


class TestFinancialToolGuard:
    """Test FinancialToolGuard business logic validation."""

    @pytest.fixture
    def guard(self):
        """Create FinancialToolGuard instance."""
        return FinancialToolGuard(tool_name="transfer_money")

    @pytest.fixture
    def context(self):
        """Create SessionContext with default state."""
        return SessionContext()

    def test_successful_validation_normal_amount(self, guard, context):
        """Test successful validation with normal amount."""
        args = {"amount": 100.0, "reason": "Payment for services"}
        context.set("tx_count_1h", 10)

        # Should pass (amount >= 1.0, tx_count < 50)
        result = guard.validate("transfer_money", args, context)
        assert result is True

    def test_successful_validation_low_amount_low_tx_count(self, guard, context):
        """Test successful validation with low amount but low tx_count."""
        args = {"amount": 0.5, "reason": "Small payment"}
        context.set("tx_count_1h", 10)

        # Should pass (amount < 1.0 BUT tx_count <= 50)
        result = guard.validate("transfer_money", args, context)
        assert result is True

    def test_block_micro_transaction_spam(self, guard, context):
        """Test block micro-transaction spam (State-Check)."""
        args = {"amount": 0.5, "reason": "Micro payment"}
        context.set("tx_count_1h", 51)  # Exceeds threshold

        # Should block: amount < 1.0 AND tx_count_1h > 50
        with pytest.raises(BusinessLogicException) as exc_info:
            guard.validate("transfer_money", args, context)

        assert exc_info.value.rule_name == "micro_transaction_spam"
        assert exc_info.value.tool_name == "transfer_money"
        assert "micro-transaction spam" in exc_info.value.message.lower()
        assert exc_info.value.metadata["amount"] == 0.5
        assert exc_info.value.metadata["tx_count_1h"] == 51

    def test_block_forbidden_keyword_admin(self, guard, context):
        """Test block forbidden keyword 'admin' in reason (Semantic-Check)."""
        args = {"amount": 100.0, "reason": "Admin override requested"}
        context.set("tx_count_1h", 10)

        # Should block: reason contains "admin"
        with pytest.raises(BusinessLogicException) as exc_info:
            guard.validate("transfer_money", args, context)

        assert exc_info.value.rule_name == "forbidden_keyword"
        assert exc_info.value.tool_name == "transfer_money"
        assert "forbidden keyword 'admin'" in exc_info.value.message.lower()
        assert exc_info.value.metadata["forbidden_keyword"] == "admin"

    def test_block_forbidden_keyword_case_insensitive(self, guard, context):
        """Test block forbidden keyword case-insensitive."""
        args = {"amount": 100.0, "reason": "ADMIN override"}
        context.set("tx_count_1h", 10)

        # Should block: "ADMIN" (uppercase) contains "admin"
        with pytest.raises(BusinessLogicException) as exc_info:
            guard.validate("transfer_money", args, context)

        assert exc_info.value.rule_name == "forbidden_keyword"

    def test_block_both_rules(self, guard, context):
        """Test block when both rules are violated."""
        args = {"amount": 0.5, "reason": "Admin micro payment"}
        context.set("tx_count_1h", 51)

        # Should block: micro-transaction spam rule (checked first)
        with pytest.raises(BusinessLogicException) as exc_info:
            guard.validate("transfer_money", args, context)

        # First rule violation (micro_transaction_spam) should be raised
        assert exc_info.value.rule_name == "micro_transaction_spam"

    def test_missing_amount_field(self, guard, context):
        """Test validation with missing amount field."""
        args = {"reason": "Payment"}
        context.set("tx_count_1h", 10)

        # Should pass (amount check skipped if missing)
        result = guard.validate("transfer_money", args, context)
        assert result is True

    def test_missing_reason_field(self, guard, context):
        """Test validation with missing reason field."""
        args = {"amount": 100.0}
        context.set("tx_count_1h", 10)

        # Should pass (reason check skipped if missing)
        result = guard.validate("transfer_money", args, context)
        assert result is True

    def test_invalid_amount_format(self, guard, context):
        """Test validation with invalid amount format."""
        args = {"amount": "not_a_number", "reason": "Payment"}
        context.set("tx_count_1h", 10)

        # Should pass (invalid format is logged but not blocked by this guard)
        result = guard.validate("transfer_money", args, context)
        assert result is True

    def test_exact_threshold_values(self, guard, context):
        """Test validation at exact threshold values."""
        # Test at threshold: amount = 1.0, tx_count = 50
        args = {"amount": 1.0, "reason": "Payment"}
        context.set("tx_count_1h", 50)

        # Should pass (amount >= 1.0, so rule doesn't apply)
        result = guard.validate("transfer_money", args, context)
        assert result is True

        # Test at threshold: amount = 0.99, tx_count = 50
        args = {"amount": 0.99, "reason": "Payment"}
        context.set("tx_count_1h", 50)

        # Should pass (amount < 1.0 BUT tx_count <= 50, not > 50)
        result = guard.validate("transfer_money", args, context)
        assert result is True


class TestToolGuardRegistry:
    """Test ToolGuardRegistry pattern."""

    def test_register_and_get_guard(self):
        """Test registering and retrieving guards."""
        registry = ToolGuardRegistry()
        guard = FinancialToolGuard(tool_name="transfer_money")

        registry.register("transfer_money", guard)
        retrieved = registry.get_guard("transfer_money")

        assert retrieved is guard
        assert retrieved.tool_name == "transfer_money"

    def test_get_nonexistent_guard(self):
        """Test retrieving non-existent guard."""
        registry = ToolGuardRegistry()
        guard = registry.get_guard("nonexistent_tool")

        assert guard is None

    def test_validate_with_registered_guard_success(self):
        """Test validation with registered guard (success case)."""
        registry = ToolGuardRegistry()
        guard = FinancialToolGuard(tool_name="transfer_money")
        registry.register("transfer_money", guard)

        context = SessionContext()
        context.set("tx_count_1h", 10)
        args = {"amount": 100.0, "reason": "Payment"}

        result = registry.validate("transfer_money", args, context)
        assert result is True

    def test_validate_with_registered_guard_block(self):
        """Test validation with registered guard (block case)."""
        registry = ToolGuardRegistry()
        guard = FinancialToolGuard(tool_name="transfer_money")
        registry.register("transfer_money", guard)

        context = SessionContext()
        context.set("tx_count_1h", 51)
        args = {"amount": 0.5, "reason": "Micro payment"}

        # Should block
        with pytest.raises(BusinessLogicException) as exc_info:
            registry.validate("transfer_money", args, context)

        assert exc_info.value.rule_name == "micro_transaction_spam"

    def test_validate_without_guard(self):
        """Test validation without registered guard (default allow)."""
        registry = ToolGuardRegistry()

        context = SessionContext()
        args = {"amount": 100.0, "reason": "Payment"}

        # Should allow (no guard registered)
        result = registry.validate("unregistered_tool", args, context)
        assert result is True

    def test_list_guards(self):
        """Test listing all registered guards."""
        registry = ToolGuardRegistry()
        guard1 = FinancialToolGuard(tool_name="transfer_money")
        guard2 = FinancialToolGuard(tool_name="withdraw_money")

        registry.register("transfer_money", guard1)
        registry.register("withdraw_money", guard2)

        guards = registry.list_guards()
        assert len(guards) == 2
        assert guards["transfer_money"] == "FinancialToolGuard"
        assert guards["withdraw_money"] == "FinancialToolGuard"

    def test_multiple_guards_same_tool(self):
        """Test registering multiple guards (last one wins)."""
        registry = ToolGuardRegistry()
        guard1 = FinancialToolGuard(tool_name="transfer_money")
        guard2 = FinancialToolGuard(tool_name="transfer_money")

        registry.register("transfer_money", guard1)
        registry.register("transfer_money", guard2)

        retrieved = registry.get_guard("transfer_money")
        assert retrieved is guard2  # Last registered wins
