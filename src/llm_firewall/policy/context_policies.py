"""
Contextualized Policy Activation
Prevents false positives on educational/research content with attack examples
"""
import re

# Imperative/instructional markers (verb-leading)
IMP = re.compile(r"(?im)^\s*(do|run|execute|compile|launch|build|mix|synthesize|attack|exploit|create|generate|deploy|inject|trigger|invoke)\b")

# Teaching/educational markers
TEACH = re.compile(r"(?i)\b(example|for testing|demo|tutorial|educational|reference|illustration|sample|proof of concept|poc|demonstration)\b")

# 2nd person markers (direct instruction)
SECOND_PERSON = re.compile(r"(?i)\b(you should|you can|you must|you need to|your task|follow these steps)\b")


def should_activate_sensitive_policy(text: str, exec_ctx: bool, doc_like: bool) -> bool:
    """
    Determine if sensitive policy signals (cyber_offense, chem_weapon) should activate.
    
    Returns True if:
    - Execution context present (script tags, function calls)
    - Imperative/instructional context (verb-leading commands)
    - 2nd person direct instruction
    
    Returns False if:
    - Educational context (example, tutorial, demo)
    - Documentation without exec context
    
    Purpose: Prevents false positives on security research/teaching materials
    """
    # Always activate if execution context present
    if exec_ctx:
        return True
    
    # In doc-like context with teaching markers, suppress
    if doc_like and TEACH.search(text):
        return False
    
    # Activate if imperative or instructional
    if IMP.search(text) or SECOND_PERSON.search(text):
        return True
    
    # Default: activate (conservative)
    return True


# ========================================================================
# RC9-FPR4 Surgical Gates for pure_doc ∧ !exec_ctx
# Implements feature flag logic from config/flags.yaml
# ========================================================================

def should_fire_attack_keyword_with_encoding(
    ctx: str,
    exec_ctx: bool,
    has_codefence: bool,
    has_net_api: bool,
    has_js_attr: bool,
    distance_to_call: int | None
) -> bool:
    """
    Gate: attack_keyword_with_encoding
    
    Fire if:
    - (has_codefence AND (has_net_api OR has_js_attr)) OR
    - distance_to_call <= 6
    
    Otherwise suppress in pure docs without exec context.
    """
    # Always fire if exec context present
    if exec_ctx:
        return True
    
    # Fire if code-like docs with API/event indicators
    if has_codefence and (has_net_api or has_js_attr):
        return True
    
    # Fire if close to function call
    if distance_to_call is not None and distance_to_call <= 6:
        return True
    
    # Otherwise suppress
    return False


def should_fire_chain_decoded_single_stage(
    ctx: str,
    exec_ctx: bool,
    has_codefence: bool,
    has_net_api: bool,
    has_js_attr: bool,
    decoded_out_has_exec_tokens: bool
) -> bool:
    """
    Gate: chain_decoded_1_stages
    
    Fire only if:
    - exec_ctx=True OR
    - decoded output contains exec tokens (<script>, on*=, javascript:)
    
    Otherwise telemetry only (suppress).
    """
    # Always fire if exec context present
    if exec_ctx:
        return True
    
    # Fire if decoded output reveals executable tokens
    if decoded_out_has_exec_tokens:
        return True
    
    # Otherwise suppress (telemetry only)
    return False


def should_fire_encoding_near_attack_keyword(
    ctx: str,
    exec_ctx: bool,
    has_codefence: bool,
    has_net_api: bool,
    has_js_attr: bool,
    distance_to_call: int | None
) -> bool:
    """
    Gate: encoding_near_attack_keyword
    
    Fire if:
    - Code proximity present (fence OR js_attr) AND
    - distance_to_call <= 8
    
    Otherwise suppress in pure prose.
    """
    # Always fire if exec context present
    if exec_ctx:
        return True
    
    # Require code proximity (codefence or event handler)
    has_code_proximity = has_codefence or has_js_attr
    
    if not has_code_proximity:
        return False  # Suppress (no code context)
    
    # Fire if close enough (<=8)
    if distance_to_call is not None and distance_to_call <= 8:
        return True
    
    # Otherwise suppress
    return False


def should_fire_indirect_function_constructor(
    ctx: str,
    exec_ctx: bool,
    has_codefence: bool,
    has_net_api: bool,
    has_js_attr: bool,
    call_parenthesized: bool,
    event_attr_present: bool
) -> bool:
    """
    Gate: indirect_function_constructor
    
    Fire if:
    - call_parenthesized=True (function call pattern) OR
    - event_attr_present=True (event handler attribute)
    
    Otherwise suppress in pure docs without exec proof.
    """
    # Always fire if exec context present
    if exec_ctx:
        return True
    
    # Fire if exec proof present (call or event handler)
    if call_parenthesized or event_attr_present:
        return True
    
    # Otherwise suppress (teaching example without exec)
    return False
