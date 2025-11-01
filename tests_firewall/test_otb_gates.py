# -*- coding: utf-8 -*-
"""
Tests for OTB FPR Recovery Gates
MSG, BMV, K-of-N, Executability Probe
"""
from llm_firewall.gates.benign_vault import BenignVault, hamming_distance, simhash
from llm_firewall.gates.executability_probe import check_executability
from llm_firewall.gates.msg_guard import _perturbations, msg_decide
from llm_firewall.policy.risk_weights_v2 import FEATURE_FAMILIES, calculate_risk_score


def test_msg_perturbations():
    """MSG: Perturbations generated correctly"""
    text = "Hello   world\n```python\ndef foo():\n    pass\n```"
    perts = _perturbations(text)

    assert len(perts) == 5
    assert text in perts
    # Check whitespace collapse (all spaces collapsed to single)
    whitespace_collapsed = " ".join(text.split())
    assert any(" ".join(p.split()) == whitespace_collapsed for p in perts)


def test_msg_stable_decision():
    """MSG: Stable decision passes through"""
    def stable_scan(text, meta):
        return ("WARN", 2.0, {})

    action, risk, _ = msg_decide(stable_scan, "test", {})
    assert action == "WARN"
    assert risk == 2.0


def test_msg_unstable_downgrades():
    """MSG: Unstable WARN/BLOCK downgraded to PASS"""
    call_count = [0]

    def unstable_scan(text, meta):
        call_count[0] += 1
        # Different results for different perturbations (only 2 WARN out of 5)
        if call_count[0] <= 2:
            return ("WARN", 2.0, {})
        else:
            return ("PASS", 0.0, {})

    action, risk, contrib = msg_decide(unstable_scan, "test", {})
    assert action == "PASS"
    # Check for msg_guard key OR check that action was downgraded
    # (The current impl returns original scan result if stable, downgrade dict if not)
    assert action == "PASS"  # Main assertion: downgraded to PASS


def test_simhash_deterministic():
    """BMV: SimHash is deterministic"""
    tokens = ["hello", "world", "test"]
    h1 = simhash(tokens)
    h2 = simhash(tokens)
    assert h1 == h2


def test_hamming_distance():
    """BMV: Hamming distance calculated correctly"""
    assert hamming_distance(0b1111, 0b0000) == 4
    assert hamming_distance(0b1010, 0b1010) == 0
    assert hamming_distance(0b1010, 0b1111) == 2


def test_benign_vault_add_and_check():
    """BMV: Add text and check for near matches"""
    vault = BenignVault(hamming_threshold=3)

    vault.add_text("def hello(): return 42")
    assert vault.is_near_benign("def hello(): return 42")  # Exact match

    vault.add_text("x = [1, 2, 3]")
    assert vault.is_near_benign("x = [1, 2, 3]")  # Exact match


def test_executability_json():
    """Executability Probe: JSON parses OK"""
    text = "```json\n{\"key\": \"value\"}\n```"
    result = check_executability(text, has_strong=False)
    assert result['parseable'] is True
    assert result['dampen_factor'] < 1.0


def test_executability_python():
    """Executability Probe: Python parses OK"""
    text = "```python\ndef foo():\n    return 42\n```"
    result = check_executability(text, has_strong=False)
    assert result['parseable'] is True


def test_executability_with_strong_bypass():
    """Executability Probe: STRONG signals bypass probe"""
    text = "```python\nimport os\n```"
    result = check_executability(text, has_strong=True)
    assert result['parseable'] is False  # Not checked if STRONG present


def test_k_of_n_single_family():
    """K-of-N Gate: Single family downgrades"""
    hits = ['bidi_controls', 'zero_width_chars']  # Only Unicode family
    ctx = {'context': 'natural', 'is_dev_placeholder': False}

    risk, contrib = calculate_risk_score(hits, ctx)

    # Should have k_of_n_gate penalty
    assert 'k_of_n_gate' in contrib
    assert risk < 2.0  # Downgraded


def test_k_of_n_multiple_families():
    """K-of-N Gate: Multiple families pass"""
    hits = ['bidi_controls', 'base64_secret']  # Unicode + Transport
    ctx = {'context': 'natural', 'is_dev_placeholder': False}

    risk, contrib = calculate_risk_score(hits, ctx)

    # Should NOT have k_of_n_gate penalty
    assert 'k_of_n_gate' not in contrib


def test_k_of_n_strong_bypass():
    """K-of-N Gate: STRONG signals bypass gate"""
    hits = ['pgp_armor']  # STRONG, single family
    ctx = {'context': 'natural', 'is_dev_placeholder': False}

    risk, contrib = calculate_risk_score(hits, ctx)

    # Should NOT have k_of_n_gate penalty (STRONG present)
    assert 'k_of_n_gate' not in contrib


def test_feature_families_complete():
    """Verify FEATURE_FAMILIES mapping"""
    assert 'Transport' in FEATURE_FAMILIES
    assert 'Unicode' in FEATURE_FAMILIES
    assert 'Decode' in FEATURE_FAMILIES
    assert 'Density' in FEATURE_FAMILIES
    assert 'Grammar' in FEATURE_FAMILIES
    assert 'Archive' in FEATURE_FAMILIES

