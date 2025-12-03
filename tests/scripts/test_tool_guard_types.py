"""
Tests for tool_guard_types.py
===============================
"""

import sys
from pathlib import Path

# Add project root to path
base_dir = Path(__file__).parent.parent.parent
if base_dir.exists():
    sys.path.insert(0, str(base_dir))

from scripts.tool_guard_types import ToolCallContext, ToolCallSession


def test_tool_call_context():
    """Test ToolCallContext creation and serialization."""
    context = ToolCallContext(
        tool_name="file_write",
        arguments={"path": "/tmp/test.txt"},
        dangerous_pattern_flags=["file_write"],
    )

    assert context.tool_name == "file_write"
    assert context.arguments["path"] == "/tmp/test.txt"
    assert "file_write" in context.dangerous_pattern_flags

    # Test serialization
    data = context.to_dict()
    assert data["tool_name"] == "file_write"

    # Test deserialization
    context2 = ToolCallContext.from_dict(data)
    assert context2.tool_name == context.tool_name
    assert context2.arguments == context.arguments


def test_tool_call_session():
    """Test ToolCallSession creation and serialization."""
    session = ToolCallSession(session_id="test_001")
    assert session.total_calls == 0

    # Add tool calls
    context1 = ToolCallContext(tool_name="tool1", arguments={})
    context2 = ToolCallContext(tool_name="tool2", arguments={})

    session.add_tool_call(context1)
    session.add_tool_call(context2)

    assert session.total_calls == 2
    assert len(session.tool_calls) == 2

    # Test serialization
    data = session.to_dict()
    assert data["session_id"] == "test_001"
    assert data["total_calls"] == 2
    assert len(data["tool_calls"]) == 2

    # Test deserialization
    session2 = ToolCallSession.from_dict(data)
    assert session2.session_id == session.session_id
    assert session2.total_calls == session.total_calls
    assert len(session2.tool_calls) == len(session.tool_calls)


def main():
    """Run all tests."""
    print("Running tests for tool_guard_types.py...")

    tests = [
        test_tool_call_context,
        test_tool_call_session,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            print(f"  [OK] {test.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  [FAIL] {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"  [ERROR] {test.__name__}: {e}")
            failed += 1

    print(f"\nResults: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
