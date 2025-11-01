# -*- coding: utf-8 -*-
"""
Risk-Weighted Decision System V2
Conservative, context-sensitive policy with attribution gates
"""

import os
from typing import Any

# Signal strength categories (CONSERVATIVE)
STRONG_SIGNALS = {
    "pgp_armor": 2.0,
    "smime_ct": 2.0,
    "pdf_b64": 1.8,
    "chain_decoded_2_stages": 1.6,
    "chain_decoded_3_stages": 2.0,
    "archive_secret": 1.8,
    "png_metadata": 1.6,
    "any_armor": 1.5,
    # RC2 P4.2: Deliberate fragmentation evasion
    "comment_split_b64": 1.5,  # Base64 fragmented across comments (intentional evasion)
    # RC2 P4.10: Bidi promoted to STRONG (bypasses BMV/MSG, inherently malicious)
    "bidi_controls": 2.0,  # Right-to-left override attacks (moved from MEDIUM)
    # RC2 P4.11: base64_secret promoted to STRONG (bypasses BMV, prevents context threshold bypass)
    "base64_secret": 1.5,  # Decoded Base64 content (moved from MEDIUM 0.7)
    # RC3 CRITICAL: Attack Pattern Detection (plaintext attacks bypass Tri-Key)
    "sql_keywords_destructive": 2.5,
    "sql_injection_pattern": 2.5,
    "sql_comment_injection": 2.0,
    "xss_dangerous_scheme": 2.5,
    "xss_script_tag": 2.5,
    "xss_event_handler": 2.0,
    "path_traversal_dotdot": 2.5,
    "path_system_file_access": 2.5,
    "rce_log4j_jndi": 3.0,
    "rce_command_injection": 2.5,
    "rce_template_injection": 2.0,
    "ldap_injection": 2.0,
    "ssrf_internal_target": 2.0,
    "attack_keyword_with_encoding": 2.5,  # Fragments with attack keywords
    "dangerous_scheme_detected": 2.5,  # javascript:/data:/vbscript: (even if obfuscated)
    "homoglyph_spoof": 2.0,  # Homoglyph spoofing (promoted from MEDIUM - attack obfuscation)
    "homoglyph_spoof_ge_1": 2.0,  # Homoglyph detection (promoted from MEDIUM 1.6)
    "homoglyph_spoof_ratio_ge_20": 2.0,  # High homoglyph ratio (promoted from MEDIUM 1.6)
    "url_homoglyph_detected": 2.0,  # URL context homoglyph (promoted from MEDIUM 1.6)
    "xss_scheme_obfuscated": 3.0,  # javascript with homoglyphs/obfuscation
    "encoding_near_attack_keyword": 2.0,  # Encoding near suspicious keywords
    "sql_defragmented_keyword": 2.5,  # SQL keywords after defragmentation
    "xss_defragmented_attack": 2.5,  # XSS after defragmentation
    # RC5 EMOJI-HOMOGLYPH: Perfect Storm Gap #1 (91.7% ASR → Target 30%)
    "emoji_homoglyph_detected": 2.0,  # Emoji or Math Alphanumeric homoglyph detected
    "emoji_regional_indicator": 2.2,  # Regional Indicator (🅰🅱🅾🅿) → A/B/O/P
    "emoji_math_alphanumeric": 2.0,  # Mathematical Alphanumeric (𝐚𝒂𝕒) → a
    "emoji_homoglyph_high_density": 2.5,  # ≥3 emoji homoglyphs (deliberate obfuscation)
    # RC6 MULTILINGUAL: Perfect Storm Gap #2 (83.3% ASR → Target 40%)
    "multilingual_keyword_detected": 1.8,  # Attack keyword in non-English language
    "multilingual_en_keyword": 2.0,  # English synonym (warn/notify/show) detected (RC8)
    "multilingual_zh_keyword": 2.0,  # Chinese keyword detected
    "multilingual_ja_keyword": 2.0,  # Japanese keyword detected
    "multilingual_ru_keyword": 2.0,  # Russian keyword detected
    "multilingual_ar_keyword": 2.0,  # Arabic keyword detected
    "multilingual_hi_keyword": 2.0,  # Hindi keyword detected
    "multilingual_ko_keyword": 2.0,  # Korean keyword detected
    "multilingual_xss_keyword": 2.2,  # XSS-related multilingual keyword
    "multilingual_code_keyword": 2.2,  # Code execution multilingual keyword
    "multilingual_dom_keyword": 1.8,  # DOM manipulation multilingual keyword
    "multilingual_high_density": 2.5,  # Multiple multilingual keywords (deliberate)
    "language_switching_detected": 1.6,  # Mixed scripts (ASCII + CJK/Cyrillic/etc)
    "language_switching_high_complexity": 2.0,  # ≥3 different scripts mixed
    "exec_verb_gated": 1.7,  # RC8.1: system/execute/run/invoke/launch as function call (gated to avoid FPR)
    # Fuzzy Function Call Detection (fullwidth/gap-resistant)
    "fuzzy_call:alert": 2.0,    # STRONG-
    "fuzzy_call:eval": 2.0,
    "fuzzy_call:exec": 1.9,
    "fuzzy_call:execute": 1.9,
    "fuzzy_call:run": 1.7,
    "fuzzy_call:system": 1.8,
    "fuzzy_call:prompt": 2.1,
    "fuzzy_call:confirm": 2.1,
    "fuzzy_call:display": 1.6,
    "fuzzy_call:show": 1.6,
    "fuzzy_call:notify": 1.6,
    "fuzzy_call:trigger": 1.8,
    # Emoji-bridged fuzzy calls (e.g., a🅰lert -> alert after emoji strip)
    "fuzzy_call_emoji_bridged:alert": 1.9,
    "fuzzy_call_emoji_bridged:eval": 1.9,
    "fuzzy_call_emoji_bridged:exec": 1.8,
    "fuzzy_call_emoji_bridged:execute": 1.8,
    "fuzzy_call_emoji_bridged:run": 1.6,
    "fuzzy_call_emoji_bridged:system": 1.7,
    "fuzzy_call_emoji_bridged:prompt": 2.0,
    "fuzzy_call_emoji_bridged:confirm": 2.0,
    "fuzzy_call_emoji_bridged:display": 1.5,
    "fuzzy_call_emoji_bridged:show": 1.5,
    "fuzzy_call_emoji_bridged:notify": 1.5,
    "fuzzy_call_emoji_bridged:trigger": 1.7,
    # RC9-FPR1: Documentation context signals (weak/telemetry)
    "doc_weak_signals_seen": 0.3,  # Weak signals in doc context (telemetry)
    "doc_localhost_example": 0.0,  # Localhost in docs (telemetry only)
    "encoding_in_docs": 0.2,  # Encoding examples in docs (very weak)
    "doc_context_dampening_applied": 0.0,  # Telemetry: dampening was applied
    # RC8 JAILBREAK PHRASES: SemSyn-20 Lexicon (Policy-Bypass & Jailbreak Detection)
    "jailbreak_phrase_detected": 2.2,  # Jailbreak/policy-bypass phrase detected
    "jailbreak_bypass_policy": 2.5,  # Explicit policy bypass request
    "jailbreak_evaluation_disclaimer": 2.0,  # "For testing purposes" evasion
    "jailbreak_roleplay": 2.5,  # Roleplay jailbreak attempt
    "jailbreak_harmless_cover": 1.8,  # "Just educational" cover
    "jailbreak_high_density": 2.8,  # Multiple jailbreak phrases (deliberate)
    # RC7 INDIRECT EXECUTION: DeepSeek Gap (Indirect call chains bypass direct detection)
    "indirect_bracket_concat": 2.5,  # window['al'+'ert'] bracket notation with concat
    "indirect_array_join": 2.5,  # ['a','l','e','r','t'].join('') array join
    "indirect_function_constructor": 3.0,  # Function('alert') constructor bypass
    "indirect_timer_string": 2.5,  # setTimeout('alert') string evaluation
    "indirect_timer_call_apply": 2.8,  # setTimeout.call(null, 'alert') advanced
    "indirect_location_href": 2.8,  # location.href = 'javascript:' navigation
    "indirect_dynamic_import": 3.0,  # import('data:') dynamic code loading
    "indirect_prototype_pollution": 2.8,  # Object.prototype manipulation
    "indirect_event_handler": 2.0,  # addEventListener, onload assignment
    "indirect_eval_call_apply": 2.8,  # eval.call/apply indirect invocation
    "indirect_with_statement": 2.2,  # with(document) scope manipulation
    "indirect_template_literal": 2.5,  # ${alert(1)} template evaluation
    # RC7 MULTI-MODAL: DeepSeek Gap (SVG/MathML/CSS context isolation)
    "multimodal_svg_context": 1.5,  # SVG tag detected
    "multimodal_svg_script": 2.8,  # Script inside SVG
    "multimodal_svg_event": 2.5,  # SVG onload/onclick handlers
    "multimodal_mathml_context": 1.5,  # MathML tag detected
    "multimodal_mathml_script": 2.8,  # Script inside MathML
    "multimodal_mathml_action": 2.5,  # MathML maction element
    "multimodal_css_import": 3.0,  # @import javascript:/data:/http
    "multimodal_css_expression": 2.8,  # CSS expression() IE legacy
    "multimodal_css_url_javascript": 2.8,  # url('javascript:') in CSS
    "multimodal_style_script_combo": 2.5,  # <style> + <script> together
    "multimodal_svg_external_ref": 2.5,  # SVG importing external resources
    # RC7 CONTEXT POISONING: DeepSeek Gap (Attacks in doc/example contexts)
    "context_poison_alert_in_doc": 2.5,  # alert() in documentation
    "context_poison_eval_in_doc": 2.8,  # eval() in documentation
    "context_poison_exec_in_doc": 2.8,  # exec() in documentation
    "context_poison_javascript_scheme_in_doc": 2.5,  # javascript: in doc
    "context_poison_data_uri_in_doc": 2.5,  # data: URI in doc
    "context_poison_script_tag_in_doc": 2.8,  # <script> in doc
    "context_poison_event_handler_in_doc": 2.5,  # onerror=/onload= in doc
    "context_poison_onload_in_doc": 2.5,  # onload= in doc
    "example_with_function_constructor": 2.8,  # Function() in example code
    "example_with_dynamic_import": 3.0,  # import() in example code
    "example_with_timer_string": 2.5,  # setTimeout string in example
    "example_with_navigation": 2.5,  # location.href in example
    "code_comment_split_suspicious": 2.2,  # Suspicious split across comments
    "code_split_fragment_dangerous": 2.8,  # Fragment concat forms dangerous keyword
}

MEDIUM_SIGNALS = {
    # NOTE: bidi_controls moved to STRONG_SIGNALS (RC2 P4.10)
    # NOTE: base64_secret moved to STRONG (RC2 P4.11 - bypasses BMV in code context)
    # NOTE: homoglyph_spoof moved to STRONG (RC3 - bypasses with attack patterns)
    "zero_width_chars": 1.3,  # Raised from 0.9 - CRITICAL
    "utf7_segments": 0.7,
    "armor_markers": 0.8,
    "pdf_xmp_detected": 0.6,
    "yaml_anchors_neutralized": 0.6,
    "rfc2047": 0.5,
    "base85": 0.6,
    "chain_decoded_1_stages": 0.5,
    "json_u_escape_decoded": 0.85,  # P2 Fix Pack - JSON \uXXXX decoded
    # NOTE: homoglyph signals moved to STRONG (RC3)
    "unicode_tag_seen": 1.5,  # V3 Fix - TAG Block U+E0001-E007F (CRITICAL)
    "unicode_vs_seen": 1.4,  # V3 Fix - Variation Selectors (0.57→0.7+)
    "unicode_invisible_space": 1.3,  # V3 Fix - SHY, NBSP (0.52→0.65+)
    "unicode_combining_seen": 1.2,  # V3 Fix - Combining diacritics (0.47→0.6+)
    "unicode_ligature_seen": 1.2,  # V3 Fix - ff,fi,fl ligatures (0.42→0.6+)
    "unicode_math_alpha_seen": 1.2,  # V3 Fix - Math alphanumeric (0.47→0.6+)
    "unicode_enclosed_seen": 1.2,  # V3 Fix - Enclosed alphanumerics (0.44→0.6+)
    "ascii85_detected": 1.4,  # V3 Fix - ASCII85 <~...~> (raised for reliability)
    "punycode_detected": 1.3,  # V3 Fix - IDNA xn-- (raised)
    "json_depth_excessive": 1.4,  # V4 Fix - Deep JSON nesting (raised from 1.1 - 0.57 bypass)
}

# STRONG-level signals (promoted from MEDIUM for critical fragmentation attacks)
STRONG_SIGNALS_EXTRA = {
    "base64_multiline_detected": 2.2,  # V5 Fix - Fragmented Base64 STRONG (0.38 in code even with 2.0 MEDIUM!)
    "decoded_secretlike": 2.5,  # P2.7 - PROOF OF RISK (Secret patterns in decoded)
    "mixed_script_identifier_strong": 1.6,  # P3.0 - Mixed scripts in identifier (spoofing)
    "unicode_exotic_identifier_risky": 1.1,  # P3.0 - Exotic in identifiers (obfuscation)
}

# Benign classifiers (neutralize WEAK signals)
BENIGN_SIGNALS = {
    "decoded_benign_media": -1.0,  # P2.7 - PNG/SVG/etc (neutralizes WEAK)
    "decoded_public_material": -0.5,  # P2.7 - Public keys (partial neutralization)
    "unicode_exotic_sc_benign": -0.8,  # P3.0 - Exotic in strings/comments low density (neutralizes)
}

MEDIUM_SIGNALS_EXTRA = {
    "fullwidth_forms": 1.3,  # Promoted from WEAK - CRITICAL Unicode signal, raised to clear 1.2 threshold
    # RC2 P4.2: Transport-Indicators Complete
    "rfc2047_encoded": 0.7,  # MIME encoded-words (email header obfuscation)
    "idna_punycode": 0.8,  # xn-- domains (homoglyph domain attacks)
    "fullwidth_b64": 1.1,  # Fullwidth + Base64 combo (dual obfuscation)
    # NOTE: comment_split_b64 moved to STRONG_SIGNALS (deliberate evasion)
    "qp_multiline": 0.6,  # Quoted-Printable multiline (fragmentation)
}

WEAK_SIGNALS = {
    "mixed_scripts": 0.3,
    "mime_headers_unfolded": 0.15,
    "dense_alphabet": 0.2,
    "high_entropy": 0.12,
    "css_unescaped": 0.15,
    "js_unescaped": 0.15,
    "json_u_escape_seen": 0.65,  # P2 Fix Pack - JSON \uXXXX detected (pre-decode)
    "decoded_unspecified": 0.4,  # P2.7 - Decoded but not classified (needs 2nd evidence)
    "fullwidth_forms": 0.2,  # Test compatibility (legacy - promoted to MEDIUM_SIGNALS_EXTRA 1.3)
}

# Transport/Decode indicators (for Co-Occurrence Gate)
# RC2 P3.4: Expanded with multiline detection
# RC2 P4.2: Transport-Indicators Complete
TRANSPORT_DECODE_INDICATORS = {
    "base64_secret",
    "base64_multiline_detected",
    "base85",
    "ascii85_detected",
    "rfc2047",
    "armor_markers",
    "chain_decoded_1_stages",
    "chain_decoded_2_stages",
    "chain_decoded_3_stages",
    "any_armor",
    "pgp_armor",
    "smime_ct",
    # RC2 P4.2: New Transport-Indicators
    "rfc2047_encoded",
    "idna_punycode",
    "fullwidth_b64",
    "comment_split_b64",
    "qp_multiline",
}

# Feature families for K-of-N Gate
FEATURE_FAMILIES = {
    "Transport": {
        "base64_secret",
        "base85",
        "rfc2047",
        "armor_markers",
        "chain_decoded_1_stages",
        "chain_decoded_2_stages",
        "chain_decoded_3_stages",
        "any_armor",
        "pgp_armor",
        "smime_ct",
        # RC2 P4.2: Transport-Indicators Complete
        "rfc2047_encoded",
        "idna_punycode",
        "fullwidth_b64",
        "comment_split_b64",
        "qp_multiline",
    },
    "Unicode": {
        "bidi_controls",
        "zero_width_chars",
        "fullwidth_forms",
        "mixed_scripts",
    },
    "Decode": {
        "chain_decoded_1_stages",
        "chain_decoded_2_stages",
        "chain_decoded_3_stages",
        "yaml_anchors_neutralized",
        "utf7_segments",
    },
    "Density": {"dense_alphabet", "high_entropy"},
    "Grammar": {
        "yaml_anchors_neutralized",
        "css_unescaped",
        "js_unescaped",
        "mime_headers_unfolded",
    },
    "Archive": {"archive_secret", "pdf_b64", "pdf_xmp_detected", "png_metadata"},
}

# Context dampening factors (CONSERVATIVE in code/config)
CONTEXT_DAMPEN = {
    "code": {
        "STRONG": 1.0,  # No dampening
        "MEDIUM": 0.95,  # Minimal dampening - Code+Base64 at 1.15 needs to pass threshold
        "WEAK": 0.5,  # Minimal dampening
    },
    "config": {
        "STRONG": 1.0,
        "MEDIUM": 0.95,  # Raised from 0.6 - Fullwidth+Base64 bypassing in config
        "WEAK": 0.5,  # Raised from 0.25
    },
    "natural": {
        "STRONG": 1.0,
        "MEDIUM": 1.0,
        "WEAK": 1.0,
    },
}


def _neutralize_transport_if_benign(hits: list) -> list:
    """
    RC2 P3.2: Neutralize transport heuristics if benign media detected
    Proof-of-Risk beats Proof-of-Decode
    """
    import os

    if "decoded_benign_media" not in hits:
        if os.getenv("RC_DEBUG_NEUTRALIZE") == "1":
            print(f"[NEUTRALIZE] decoded_benign_media NOT in hits: {hits[:10]}")
        return hits

    # Remove transport heuristics when benign proof exists
    transport_signals = {
        "high_entropy",
        "dense_alphabet",
        "base64_multiline_detected",
        "base64_secret",
    }

    neutralized = [h for h in hits if h not in transport_signals]
    if os.getenv("RC_DEBUG_NEUTRALIZE") == "1":
        removed = set(hits) - set(neutralized)
        print(f"[NEUTRALIZE] Removed: {removed}, Kept: {len(neutralized)}/{len(hits)}")

    return neutralized


def calculate_risk_score(hits: list, context_meta: dict, text: str = "") -> tuple:
    """
    Calculate weighted risk score with V2 gates + RC2 Two-Key Principle

    RC2 Two-Key: Noisy signals (dense/entropy) only count with key signals
    V2 Features:
    - Co-Occurrence Gate: entropy/dense_alphabet need Transport/Decode hint
    - Indicator Gate: ≥2 indicators needed in code/config without STRONG

    Args:
        hits: List of detector hit names
        context_meta: Context metadata from classify_context()

    Returns:
        (total_score, contributions_dict)
    """
    context = context_meta.get("context", "natural")
    is_dev = context_meta.get("is_dev_placeholder", False)
    is_documentation = context_meta.get("is_documentation", False)

    # Dev placeholder → zero risk (lab only)
    if is_dev:
        return 0.0, {"dev_placeholder": -99}

    # RC2 P4.6: Documentation/Test-Examples → severe dampening (prevents FP on security docs)
    contributions: dict[str, Any] = {}
    if is_documentation or context == "documentation":
        # Return low risk but not zero (still detect obvious attacks)
        # Apply extreme dampening factor
        doc_dampen = 0.15
        contributions["documentation_context"] = "Severe dampening (security docs/examples)"
    else:
        doc_dampen = 1.0

    dampen = CONTEXT_DAMPEN.get(
        context, CONTEXT_DAMPEN["natural"]
    )  # Fallback for 'documentation'
    total = 0.0

    # Check for STRONG signals
    has_strong = any(hit in STRONG_SIGNALS for hit in hits)

    # RC2 P3.4b: Check for Unicode obfuscation signals (complement to Transport)
    unicode_obfuscation_signals = {
        "bidi_controls",
        "zero_width_chars",
        "fullwidth_forms",
        "unicode_combining_seen",
        "unicode_ligature_seen",
        "unicode_math_alpha_seen",
        "unicode_enclosed_seen",
        "unicode_invisible_space",
        "unicode_tag_seen",
        "unicode_vs_seen",
    }
    any(hit in unicode_obfuscation_signals for hit in hits)

    # Check for Transport/Decode indicators
    has_transport_decode = any(hit in TRANSPORT_DECODE_INDICATORS for hit in hits)

    # Count indicators for Indicator Gate
    indicator_count = len(
        [h for h in hits if h in MEDIUM_SIGNALS or h in STRONG_SIGNALS]
    )

    # Executability Probe: Check once for all MED/WEAK signals
    # BUT: Skip if Transport/Decode present (Code+Base64 must not be dampened!)
    executability_dampen = 1.0
    executability_reason = None
    if text and not has_strong and not has_transport_decode:
        from llm_firewall.gates.executability_probe import check_executability

        probe_result = check_executability(text, has_strong)
        if probe_result["parseable"]:
            executability_dampen = probe_result["dampen_factor"]
            executability_reason = probe_result["reason"]

    for hit in hits:
        # P2.7: Benign signals (negative risk)
        if hit in BENIGN_SIGNALS:
            # Negative risk for benign classifiers (neutralize WEAK)
            total += BENIGN_SIGNALS[hit]
            contributions[hit] = f"BENIGN {hit} ({BENIGN_SIGNALS[hit]:.2f})"
            continue

        # Determine signal strength
        if hit in STRONG_SIGNALS or hit in STRONG_SIGNALS_EXTRA:
            base_score = STRONG_SIGNALS.get(hit) or STRONG_SIGNALS_EXTRA.get(hit, 2.0)
            factor = dampen["STRONG"]
            strength = "STRONG"
        elif hit in MEDIUM_SIGNALS or hit in MEDIUM_SIGNALS_EXTRA:
            base_score = MEDIUM_SIGNALS.get(hit) or MEDIUM_SIGNALS_EXTRA.get(hit, 1.0)
            factor = dampen["MEDIUM"]
            strength = "MEDIUM"

            # Executability Probe: Apply if code parses OK
            if executability_dampen < 1.0:
                factor *= executability_dampen
                if executability_reason:
                    contributions[f"{hit}_executability"] = executability_reason
        elif hit in WEAK_SIGNALS:
            base_score = WEAK_SIGNALS[hit]
            factor = dampen["WEAK"]
            strength = "WEAK"

            # Executability Probe: Apply if code parses OK
            if executability_dampen < 1.0:
                factor *= executability_dampen
                if executability_reason:
                    contributions[f"{hit}_executability"] = executability_reason

            # RC2 P4.1: Tri-Key Enforcement (replaces Two-Key)
            # entropy/dense_alphabet count ONLY if:
            # - Transport/Decode present (Base64, Hex, etc.) OR
            # - Unicode obfuscation present (Fullwidth, Combining, Bidi) OR
            # - STRONG signal present (JWT, Secret, AWS Key)
            # This closes Unicode-only attacks while maintaining FPR reduction
            if hit in {"high_entropy", "dense_alphabet"}:
                from llm_firewall.policy.risk_thresholds import passes_tri_key_gate

                if not passes_tri_key_gate(hit, hits):
                    # Suppress signal - no key present
                    contributions[f"{hit}_suppressed"] = (
                        "Tri-Key gate (no Transport/Unicode/STRONG)"
                    )
                    continue  # Skip this signal entirely
        else:
            # Unknown signal - treat as weak
            base_score = 0.1
            factor = dampen["WEAK"]
            strength = "WEAK"

        score = base_score * factor
        total += score
        contributions[hit] = {
            "base": base_score,
            "dampened": score,
            "strength": strength,
            "context": context,
        }

    # Indicator Gate: In code/config without STRONG, need ≥2 indicators
    if context in ("code", "config") and not has_strong:
        if indicator_count < 2:
            # Reduce total score by 50%
            total *= 0.5
            contributions["indicator_gate"] = (
                f"<2 indicators in {context} (applied 0.5x penalty)"
            )

    # K-of-N Gate: Require ≥2 feature families for WARN/BLOCK
    # EXCEPT: Unicode family is critical - exempt from gate
    active_families = set()
    for family_name, family_signals in FEATURE_FAMILIES.items():
        if any(hit in family_signals for hit in hits):
            active_families.add(family_name)

    unicode_critical = "Unicode" in active_families

    if len(active_families) < 2 and not has_strong and not unicode_critical:
        # Single family → downgrade (but NOT Unicode - critical for security)
        total *= 0.5
        contributions["k_of_n_gate"] = (
            f"Only {len(active_families)} family/families active, require ≥2 for WARN/BLOCK (applied 0.5x penalty)"
        )

    # RC2 P4.6: Apply documentation dampening (prevents FP on security docs/test examples)
    total *= doc_dampen
    if doc_dampen < 1.0:
        contributions["doc_dampen_applied"] = (
            f"Documentation context: {doc_dampen}x dampening"
        )

    # RC8.1: Legacy test compatibility - add alias keys (no logic change)
    if (
        "high_entropy_suppressed" in contributions
        or "dense_alphabet_suppressed" in contributions
    ):
        contributions.setdefault(
            "two_key_gate",
            "Two-Key Gate (Transport/Unicode/STRONG requirement not met)",
        )
        contributions.setdefault("high_entropy_gate", "High-entropy features gated")
        contributions.setdefault("dense_alphabet_gate", "Dense-alphabet features gated")

    return total, contributions


def decide_action(
    hits: list,
    context_meta: dict,
    text: str = "",
    warn_threshold: float | None = None,
    block_threshold: float | None = None,
) -> tuple:
    """
    Make final decision with context-aware weights (V2)

    Args:
        hits: List of detector hits
        context_meta: Context classification
        warn_threshold: WARN threshold (default context-specific)
        block_threshold: BLOCK threshold (default 2.0)

    Returns:
        (action, risk_score, contributions)
    """
    # RC2 P3.1: Unicode placement-aware adjustment
    from llm_firewall.policy.unicode_context import adjust_unicode_signals

    adjusted_hits = adjust_unicode_signals(
        set(hits), text, context_meta.get("context", "natural")
    )
    hits = list(adjusted_hits)

    # RC2 P3.2: Neutralize transport if benign media detected
    hits = _neutralize_transport_if_benign(hits)

    # RC2: Context-specific thresholds (FPR 99.9%→<2%)
    context = context_meta.get("context", "natural")

    if warn_threshold is None:
        # RC2 P4.9: Restore original code threshold (1.4 for FPR), use STRONG promotion instead
        if context == "code":
            warn_threshold = float(
                os.getenv("P2_WARN_TH_CODE", "1.4")
            )  # Restored to prevent FPR explosion
        elif context == "config":
            warn_threshold = float(os.getenv("P2_WARN_TH_CONFIG", "1.2"))
        else:  # natural
            warn_threshold = float(os.getenv("P2_WARN_TH_NATURAL", "0.7"))

    if block_threshold is None:
        block_threshold = float(os.getenv("P2_BLOCK_TH", "2.0"))

    risk, contrib = calculate_risk_score(hits, context_meta, text=text)

    # RC2 P2.7: Evidence Ladder v2 - Proof-of-Risk not Proof-of-Decode
    # BLOCK only with RISK proof (secretlike, URL-Host-Homoglyph, Unicode in natural)
    risk_proof_signals = {
        "decoded_secretlike",  # Actual secrets detected
        "url_homoglyph_detected",  # Homoglyph in URL
        "bidi_controls",
        "zero_width_chars",  # Unicode controls
    }

    has_risk_proof = any(hit in risk_proof_signals for hit in hits)

    # RC2 P3.1: Enhanced Evidence Ladder - Mixed-Script Identifier also risk proof
    risk_proof_signals.add("mixed_script_identifier_strong")
    has_risk_proof = any(hit in risk_proof_signals for hit in hits)

    # Evidence Ladder v2 logic (with PRIORITY BLOCK for critical signals)
    if context == "natural":
        # Natural: BLOCK if risk proof (secrets, Unicode controls)
        can_block = has_risk_proof
    else:  # code/config
        # Code/Config: BLOCK only with decoded_secretlike, URL homoglyph, or mixed-script identifier
        can_block = (
            "decoded_secretlike" in hits
            or "url_homoglyph_detected" in hits
            or "mixed_script_identifier_strong" in hits
        )

    # Apply Evidence Ladder v2
    # RC2 P3.1: Priority BLOCK for decoded_secretlike regardless of threshold
    if "decoded_secretlike" in hits:
        action = "BLOCK"
        contrib["priority_block"] = "decoded_secretlike (secret detected)"
    elif risk >= block_threshold:
        if can_block:
            action = "BLOCK"
        else:
            action = "WARN"  # Downgrade to WARN if no risk proof
            contrib["evidence_ladder_v2"] = (
                "Downgraded BLOCK→WARN (no risk proof in context)"
            )
    elif risk >= warn_threshold:
        action = "WARN"
    else:
        action = "PASS"

    return action, risk, contrib
