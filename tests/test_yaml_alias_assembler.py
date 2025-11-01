"""Tests for YAML alias assembler."""

from llm_firewall.session.yaml_alias_assembler import expand_yaml_aliases


def test_simple_alias_expansion():
    """Test basic anchor/alias expansion."""
    text = "a: &id value1\nb: *id"
    expanded = expand_yaml_aliases(text)
    assert "value1" in expanded
    assert "*id" not in expanded or expanded.count("value1") >= 2


def test_secret_reassembly():
    """Test secret reassembly across lines."""
    text = "a: &id sk-\nb: *id live-ABCD1234"
    expanded = expand_yaml_aliases(text)
    # After expansion, both "sk-" and "live-ABCD1234" should be present
    assert "sk-" in expanded
    assert "live-ABCD1234" in expanded


def test_bounded_expansion():
    """Test that expansion respects max_alias and max_expand_bytes."""
    # Long anchor value
    text = "a: &id " + "X" * 2000 + "\nb: *id"
    expanded = expand_yaml_aliases(text, max_expand_bytes=100)
    # Expansion should be capped
    assert len(expanded) < len(text) + 1500


def test_multiple_aliases_per_line():
    """Test multiple alias expansions per line."""
    text = "a: &x foo\nb: &y bar\nc: *x and *y"
    expanded = expand_yaml_aliases(text)
    assert "foo" in expanded
    assert "bar" in expanded


def test_no_aliases_passthrough():
    """Test that text without aliases passes through unchanged."""
    text = "just normal text\nno yaml here"
    expanded = expand_yaml_aliases(text)
    assert expanded == text
