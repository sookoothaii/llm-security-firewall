"""
GuardNet Gate 1 Integration

Integration layer for GuardNet with existing firewall pipeline.
Maps GuardNet outputs to Policy-DSL actions and Conformal Stacker risk inputs.

Integration points:
1. Gate 1 (Input): GuardNet → Policy-DSL + Conformal Stacker
2. Streaming Guard: Intent/Obfuscation flags → early abort
3. Fallback: ONNX Judges when Guard uncertainty high

Creator: Joerg Bollwahn
Date: 2025-10-30
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Literal, Optional

import numpy as np


@dataclass
class GuardNetOutput:
    """
    Structured output from GuardNet inference.

    Attributes:
        policy: Policy action (block, allow_high_level, allow)
        policy_probs: Probabilities for each policy class
        intent: Detected intent (jailbreak, injection, dual_use, persuasion, benign)
        intent_probs: Probabilities for each intent class
        actionability: Actionability level (procedural, advisory, descriptive)
        actionability_probs: Probabilities for each actionability class
        obfuscation: List of detected obfuscation techniques
        obfuscation_probs: Probabilities for each obfuscation class
        risk_score: Calibrated risk score [0, 1] for Conformal Stacker
        coverage: Conformal coverage (1 - alpha) for uncertainty quantification
    """

    policy: Literal["block", "allow_high_level", "allow"]
    policy_probs: list[float]
    intent: Literal["jailbreak", "injection", "dual_use", "persuasion", "benign"]
    intent_probs: list[float]
    actionability: Literal["procedural", "advisory", "descriptive"]
    actionability_probs: list[float]
    obfuscation: list[str]
    obfuscation_probs: list[float]
    risk_score: float
    coverage: float


def map_to_policy_dsl(
    guard_output: GuardNetOutput,
    policy_dsl_output: Optional[str] = None,
) -> str:
    """
    Map GuardNet policy to Policy-DSL action.

    Rule: Guard stricter wins (if Guard says block, override DSL allow).

    Args:
        guard_output: GuardNet output
        policy_dsl_output: Optional existing Policy-DSL decision

    Returns:
        Final policy action (block, allow_high_level, allow)
    """
    guard_policy = guard_output.policy

    if policy_dsl_output is None:
        return guard_policy

    # Strictness order: block > allow_high_level > allow
    strictness = {"block": 0, "allow_high_level": 1, "allow": 2}

    if strictness[guard_policy] < strictness[policy_dsl_output]:
        # Guard is stricter → override DSL
        return guard_policy
    else:
        # DSL is stricter or equal → keep DSL
        return policy_dsl_output


def compute_risk_uplift(
    guard_output: GuardNetOutput,
    intent_weights: Optional[Dict[str, float]] = None,
    obf_weights: Optional[Dict[str, float]] = None,
) -> float:
    """
    Compute risk uplift for Conformal Stacker based on GuardNet outputs.

    Risk uplift combines:
    1. Intent-based risk (jailbreak/injection → higher risk)
    2. Obfuscation-based risk (multiple obfuscation techniques → higher risk)
    3. Policy-based risk (block → highest risk)

    Args:
        guard_output: GuardNet output
        intent_weights: Optional custom weights for intent classes (default: preset)
        obf_weights: Optional custom weights for obfuscation classes (default: equal)

    Returns:
        Risk uplift in [0, 1], clipped
    """
    if intent_weights is None:
        intent_weights = {
            "jailbreak": 0.9,
            "injection": 0.85,
            "dual_use": 0.6,
            "persuasion": 0.5,
            "benign": 0.0,
        }

    if obf_weights is None:
        obf_weights = {
            "base64": 0.3,
            "leet": 0.2,
            "homoglyph": 0.4,
            "zwc": 0.5,
            "mixed_script": 0.3,
            "emoji_burst": 0.1,
        }

    # Intent risk (weighted by probability)
    intent_risk = sum(
        guard_output.intent_probs[i] * intent_weights.get(intent, 0.0)
        for i, intent in enumerate(
            ["jailbreak", "injection", "dual_use", "persuasion", "benign"]
        )
    )

    # Obfuscation risk (sum of detected techniques)
    obf_risk = sum(
        guard_output.obfuscation_probs[i] * obf_weights.get(obf, 0.0)
        for i, obf in enumerate(
            ["base64", "leet", "homoglyph", "zwc", "mixed_script", "emoji_burst"]
        )
    )

    # Policy risk (block = high, allow = low)
    policy_risk_map = {"block": 0.9, "allow_high_level": 0.5, "allow": 0.1}
    policy_risk = policy_risk_map[guard_output.policy]

    # Combine risks (weighted average)
    total_risk = 0.5 * intent_risk + 0.3 * obf_risk + 0.2 * policy_risk

    # Clip to [0, 1]
    return np.clip(total_risk, 0.0, 1.0)


def should_early_abort(
    guard_output: GuardNetOutput,
    abort_intents: Optional[set[str]] = None,
    abort_obfuscations: Optional[set[str]] = None,
) -> tuple[bool, str]:
    """
    Determine if Streaming Guard should early abort based on GuardNet output.

    Args:
        guard_output: GuardNet output
        abort_intents: Intents that trigger early abort (default: jailbreak, injection)
        abort_obfuscations: Obfuscations that trigger early abort (default: zwc, homoglyph)

    Returns:
        Tuple of (should_abort: bool, reason: str)
    """
    if abort_intents is None:
        abort_intents = {"jailbreak", "injection"}

    if abort_obfuscations is None:
        abort_obfuscations = {"zwc", "homoglyph"}

    # Check intent
    if guard_output.intent in abort_intents:
        return (True, f"High-risk intent detected: {guard_output.intent}")

    # Check obfuscation
    detected_abort_obf = set(guard_output.obfuscation) & abort_obfuscations
    if detected_abort_obf:
        return (
            True,
            f"High-risk obfuscation detected: {', '.join(detected_abort_obf)}",
        )

    # Check policy (block always aborts)
    if guard_output.policy == "block":
        return (True, "Policy decision: block")

    return (False, "")


def should_fallback_to_judges(
    guard_output: GuardNetOutput,
    coverage_threshold: float = 0.85,
) -> bool:
    """
    Determine if system should fallback to ONNX Judges due to Guard uncertainty.

    Args:
        guard_output: GuardNet output
        coverage_threshold: Minimum coverage for trusting Guard alone (default: 0.85)

    Returns:
        True if should fallback to Judges (Guard uncertain), False otherwise
    """
    # Low coverage → high uncertainty → use Judges as fallback
    return guard_output.coverage < coverage_threshold


# Example integration workflow


def gate_1_pipeline(
    text: str,
    guardnet_session,  # ONNX InferenceSession
    tokenizer,
    features: Dict[str, Any],
    policy_dsl_engine,  # Optional Policy-DSL engine
    conformal_stacker,  # Optional Conformal Stacker
) -> Dict[str, Any]:
    """
    Complete Gate 1 pipeline with GuardNet integration.

    Args:
        text: Input text
        guardnet_session: ONNX InferenceSession for GuardNet
        tokenizer: HuggingFace tokenizer
        features: Pre-computed features from feature extractor
        policy_dsl_engine: Optional Policy-DSL engine instance
        conformal_stacker: Optional Conformal Stacker instance

    Returns:
        Dict with final decision and metadata
    """
    # 1. Run GuardNet inference
    tokens = tokenizer(
        text, truncation=True, padding="max_length", max_length=256, return_tensors="np"
    )
    feat_vec = np.array([features], dtype=np.float32)  # (1, feat_dim)

    outputs = guardnet_session.run(
        None,
        {
            "input_ids": tokens["input_ids"],
            "attention_mask": tokens["attention_mask"],
            "feat_vec": feat_vec,
        },
    )

    # Decode outputs (simplified - in production use decode_outputs from model.py)
    policy_logits, intent_logits, action_logits, obf_logits = outputs
    policy_idx = policy_logits.argmax()
    intent_idx = intent_logits.argmax()

    # Create GuardNetOutput (simplified)
    guard_output = GuardNetOutput(
        policy=["block", "allow_high_level", "allow"][policy_idx],
        policy_probs=policy_logits[0].tolist(),
        intent=["jailbreak", "injection", "dual_use", "persuasion", "benign"][
            intent_idx
        ],
        intent_probs=intent_logits[0].tolist(),
        actionability="procedural",  # placeholder
        actionability_probs=action_logits[0].tolist(),
        obfuscation=[],  # placeholder
        obfuscation_probs=obf_logits[0].tolist(),
        risk_score=0.5,  # placeholder - compute from calibration
        coverage=0.9,  # placeholder - compute from conformal
    )

    # 2. Map to Policy-DSL
    policy_dsl_decision = None
    if policy_dsl_engine:
        policy_dsl_decision = policy_dsl_engine.evaluate(text)

    final_policy = map_to_policy_dsl(guard_output, policy_dsl_decision)

    # 3. Compute risk uplift for Conformal Stacker
    risk_uplift = compute_risk_uplift(guard_output)

    # 4. Check early abort
    should_abort, abort_reason = should_early_abort(guard_output)

    # 5. Check fallback
    use_judges = should_fallback_to_judges(guard_output)

    return {
        "policy": final_policy,
        "guard_output": guard_output,
        "risk_uplift": risk_uplift,
        "should_abort": should_abort,
        "abort_reason": abort_reason,
        "use_judges_fallback": use_judges,
    }
