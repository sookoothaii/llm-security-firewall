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

