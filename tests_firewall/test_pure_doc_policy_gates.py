# -*- coding: utf-8 -*-
"""
Contract tests for pure_doc ∧ !exec_ctx gating rules.
These tests assert that the policy-level functions suppress signals in
non-executable documentation, while still firing when true execution context
evidence exists.

Adjust import paths if your module layout differs.
"""
import pytest

from llm_firewall.policy.context_policies import (
    should_fire_attack_keyword_with_encoding,
    should_fire_chain_decoded_single_stage,
    should_fire_indirect_function_constructor,
    should_fire_encoding_near_attack_keyword,
)

# ---------- Helpers: canonical "pure_doc" context ----------
PURE_DOC = {
    "ctx": "documentation",
    "exec_ctx": False,
    "has_codefence": False,
    "has_net_api": False,   # e.g., fetch, requests, socket, DB API, etc.
    "has_js_attr": False,   # e.g., onload=, onclick=, javascript:
}

CODE_DOC = {
    "ctx": "documentation",
    "exec_ctx": False,
    "has_codefence": True,
    "has_net_api": True,
    "has_js_attr": True,
}

EXEC_CTX = {
    "ctx": "documentation",
    "exec_ctx": True,       # proves execution context (e.g., runnable snippet)
    "has_codefence": True,
    "has_net_api": True,
    "has_js_attr": True,
}


# ========================================================================
# 1) attack_keyword_with_encoding
# ========================================================================

def test_attack_keyword_with_encoding_pure_doc_suppressed():
    """In pure docs, with no code proximity nor API/attr hints, should NOT fire."""
    fired = should_fire_attack_keyword_with_encoding(
        **PURE_DOC, distance_to_call=999
    )
    assert fired is False

def test_attack_keyword_with_encoding_near_call_in_doc_triggers():
    """If the keyword is close (≤6) to a function call, should fire even in docs."""
    fired = should_fire_attack_keyword_with_encoding(
        **PURE_DOC, distance_to_call=4
    )
    assert fired is True

def test_attack_keyword_with_encoding_code_doc_triggers():
    """In code-like docs with codefence + net_api/js_attr, should fire."""
    fired = should_fire_attack_keyword_with_encoding(
        **CODE_DOC, distance_to_call=32
    )
    assert fired is True


# ========================================================================
# 2) chain_decoded_1_stages
# ========================================================================

def test_chain_decoded_single_stage_pure_doc_telemetry_only():
    """
    Single-stage decode in pure docs should NOT fire unless decoded output
    reveals executable tokens/attributes.
    """
    fired = should_fire_chain_decoded_single_stage(
        **PURE_DOC, decoded_out_has_exec_tokens=False
    )
    assert fired is False

def test_chain_decoded_single_stage_reveals_exec_tokens_triggers():
    """If decoding reveals <script>/on*= or javascript:, should fire."""
    fired = should_fire_chain_decoded_single_stage(
        **PURE_DOC, decoded_out_has_exec_tokens=True
    )
    assert fired is True


# ========================================================================
# 3) encoding_near_attack_keyword
# ========================================================================

@pytest.mark.parametrize("dist", [0, 4, 8])
def test_encoding_near_attack_keyword_requires_code_proximity_triggers_when_close(dist):
    """
    In documentation, require BOTH code proximity (fence/attr/call) and distance ≤ 8.
    Here we simulate proximity via has_codefence=True.
    """
    fired = should_fire_encoding_near_attack_keyword(
        ctx="documentation", exec_ctx=False,
        has_codefence=True, has_net_api=False, has_js_attr=False,
        distance_to_call=dist
    )
    assert fired is True

def test_encoding_near_attack_keyword_far_in_prose_suppressed_when_far():
    """Far away in prose (distance > 8) with no code proximity should NOT fire."""
    fired = should_fire_encoding_near_attack_keyword(
        **PURE_DOC, distance_to_call=42
    )
    assert fired is False


# ========================================================================
# 4) indirect_function_constructor
# ========================================================================

def test_indirect_function_constructor_requires_exec_proof_in_docs():
    """In pure docs, mentioning Function/constructor without exec proof should NOT fire."""
    fired = should_fire_indirect_function_constructor(
        **PURE_DOC, call_parenthesized=False, event_attr_present=False
    )
    assert fired is False

def test_indirect_function_constructor_with_exec_proof_triggers():
    """
    If there is an execution proof (call or event attribute), it should fire
    even in documentation.
    """
    fired = should_fire_indirect_function_constructor(
        **PURE_DOC, call_parenthesized=True, event_attr_present=False
    )
    assert fired is True

    fired2 = should_fire_indirect_function_constructor(
        **PURE_DOC, call_parenthesized=False, event_attr_present=True
    )
    assert fired2 is True


# ========================================================================
# Guards: exec_ctx must always override dampening
# ========================================================================

def test_exec_ctx_overrides_all_dampening():
    """If exec_ctx=True, all four gates should fire when their base pattern is present."""
    assert should_fire_attack_keyword_with_encoding(**EXEC_CTX, distance_to_call=999) is True
    assert should_fire_chain_decoded_single_stage(**EXEC_CTX, decoded_out_has_exec_tokens=False) is True
    assert should_fire_encoding_near_attack_keyword(**EXEC_CTX, distance_to_call=999) is True
    assert should_fire_indirect_function_constructor(**EXEC_CTX, call_parenthesized=False, event_attr_present=False) is True

