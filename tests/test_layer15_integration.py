"""Layer 15 integration smoke tests.

Tests full integration with firewall pipeline and config loading.

Credit: GPT-5 collaboration 2025-11-04
"""

import pytest
import yaml
from pathlib import Path

from src.layer15.guard import Layer15Guard


@pytest.fixture
def cfg():
    """Load full Layer 15 config."""
    cfg_path = Path(__file__).parent.parent / "config" / "layer15.yaml"
    return yaml.safe_load(cfg_path.read_text(encoding='utf-8'))


@pytest.fixture
def guard(cfg):
    """Create Layer15Guard instance."""
    return Layer15Guard(cfg)


def test_layer15_initialization(guard):
    """Test Layer 15 guard initializes without errors."""
    assert guard is not None
    assert guard.age is not None
    assert guard.crisis is not None
    assert guard.de is not None
    assert guard.rsi is not None
    assert guard.childsafe is not None


def test_age_routing_integration(guard):
    """Test age routing returns valid policies."""
    policy = guard.route_age("A6_8")
    
    assert policy.max_tokens > 0
    assert 0 < policy.temperature <= 1.0
    assert policy.reading_grade >= 0


def test_crisis_hotpath_integration(guard):
    """Test full crisis hotpath execution."""
    result = guard.crisis_hotpath(
        text="I want to kill myself.",
        ctx="",
        country="US"
    )
    
    assert "level" in result
    assert "actions" in result
    assert "resource" in result
    assert "meta" in result
    
    assert result["level"] == "high"
    assert "show_resource_card" in result["actions"]
    assert result["resource"]["hotline"] == "988"


def test_deceptive_empathy_integration(guard):
    """Test deceptive empathy filtering."""
    text = "I see you, my friend. As a therapist, I understand."
    rewritten, changed = guard.make_nonhuman_transparent(text, lang="en")
    
    assert changed is True
    assert "AI system" in rewritten
    assert "friend" not in rewritten.lower()


def test_rsi_computation_integration(guard):
    """Test RSI computation."""
    rsi_score = guard.compute_rsi(defect_rate=0.20, refusal_rate=0.10)
    
    assert 0.0 <= rsi_score <= 1.0


def test_childsafe_update_integration(guard):
    """Test ChildSafe vector updates."""
    scores = [0.5] * 9  # 9 dimensions
    result = guard.update_childsafe(scores)
    
    assert result["dimensions"] == 9
    assert result["n"] == 1
    assert len(result["vector"]) == 9


def test_owasp_sql_sink_integration(guard):
    """Test SQL sink guard."""
    assert guard.sink_sql("SELECT * FROM users WHERE id = ?") == "ALLOW"
    assert guard.sink_sql("SELECT * FROM users; DROP TABLE users;") == "BLOCK"


def test_owasp_shell_sink_integration(guard):
    """Test shell sink guard."""
    assert guard.sink_shell("ls -la /tmp") == "ALLOW"
    assert guard.sink_shell("ls | grep foo") == "BLOCK"


def test_owasp_html_sink_integration(guard):
    """Test HTML sanitization."""
    clean = guard.sink_html_md("<p>Safe content</p>")
    assert "<p>Safe content</p>" in clean
    
    dangerous = guard.sink_html_md("<script>alert(1)</script>")
    assert "<script" not in dangerous
    assert "&lt;script" in dangerous


def test_full_crisis_workflow(guard):
    """Test complete crisis detection + resource card workflow."""
    # High severity case
    result_high = guard.crisis_hotpath(
        text="Ich will sterben.",  # German self-harm
        ctx="",
        country="DE"
    )
    
    assert result_high["level"] == "high"
    assert result_high["resource"]["language"] == "de"
    assert "TelefonSeelsorge" in result_high["resource"]["hotline"]
    assert result_high["resource"]["emergency"] == "112"
    
    # Low severity case
    result_low = guard.crisis_hotpath(
        text="I'm feeling a bit sad today.",
        ctx="",
        country="US"
    )
    
    assert result_low["level"] == "low"


def test_multilingual_crisis_detection(guard):
    """Test crisis detection works for EN and DE."""
    # English
    result_en = guard.crisis_hotpath(
        text="I'm thinking about suicide.",
        ctx="",
        country="US"
    )
    assert result_en["level"] in ["high", "medium"]
    
    # German
    result_de = guard.crisis_hotpath(
        text="Ich denke an Suizid.",
        ctx="",
        country="DE"
    )
    assert result_de["level"] in ["high", "medium"]


def test_config_validation(cfg):
    """Test config structure is valid."""
    assert "version" in cfg
    assert cfg["version"] == 1.0
    
    assert "age_router" in cfg
    assert "crisis_detection" in cfg
    assert "deceptive_empathy_filter" in cfg
    assert "rsi_childsafe" in cfg
    assert "owasp_sinks" in cfg
    assert "logging" in cfg


@pytest.mark.parametrize("country,expected_lang", [
    ("US", "en"),
    ("DE", "de"),
    ("TH", "en"),
])
def test_resource_cards_all_countries(guard, country, expected_lang):
    """Test resource cards for all configured countries."""
    result = guard.crisis_hotpath(
        text="crisis test",
        ctx="",
        country=country
    )
    
    assert result["resource"]["language"] == expected_lang
    assert len(result["resource"]["hotline"]) > 0
    assert len(result["resource"]["emergency"]) > 0










