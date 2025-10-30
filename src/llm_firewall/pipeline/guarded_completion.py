"""
Guarded Completion Pipeline
============================

Integrated multi-gate defense for LLM completions.

Workflow:
1. Gate 0: Spatial CAPTCHA (auth)
2. Gate 1: Streaming token guard
3. Gate 2: Multi-agent judges (parallel)
4. Aggregator: Conformal risk stacking
5. Ledger: Decision audit trail

Based on GPT-5 specification 2025-10-30.

Creator: Joerg Bollwahn
License: MIT
"""

import asyncio
import time
from typing import Dict, List, Optional, Tuple

from llm_firewall.aggregate.conformal_stacker import (
    ConformalRiskStacker,
    decision_from_risk,
)
from llm_firewall.core.types import Decision, ModelContext
from llm_firewall.gates.stream_guard import StreamAction, StreamGuard
from llm_firewall.judges.base import Judge
from llm_firewall.ledger.decision_ledger import (
    DecisionLedger,
    DecisionRecord,
    JudgeVote,
)


async def run_judges_parallel(
    judges: List[Judge],
    ctx: ModelContext,
    prompt: str,
    draft: str,
    timeout_s: float = 2.0,
) -> List:
    """
    Run all judges in parallel with timeout.

    Args:
        judges: List of judge instances
        ctx: Model context
        prompt: User input
        draft: LLM response
        timeout_s: Max execution time per judge

    Returns:
        List of JudgeReports
    """

    async def _run_one(judge: Judge):
        """Run single judge with timing."""
        t0 = time.perf_counter()
        try:
            result = await asyncio.to_thread(judge.score, ctx, prompt, draft)
            result.latency_ms = (time.perf_counter() - t0) * 1000
            return result
        except Exception as e:
            # Judge failed - return neutral report
            from llm_firewall.core.types import (
                JudgeReport,
                RiskScore,
                Severity,
                TaxonomyRisk,
            )

            return JudgeReport(
                name=judge.name,
                version=judge.version,
                latency_ms=(time.perf_counter() - t0) * 1000,
                risks=TaxonomyRisk(
                    categories={},
                    overall=RiskScore(
                        value=0.5, band="S2", severity=Severity.MEDIUM, calibrated=False
                    ),
                ),
                notes=f"Judge failed: {str(e)}",
            )

    # Create tasks
    tasks = [asyncio.create_task(_run_one(j)) for j in judges]

    # Wait with timeout
    done, pending = await asyncio.wait(tasks, timeout=timeout_s)

    # Cancel pending
    for task in pending:
        task.cancel()

    # Collect results
    return [task.result() for task in done if not task.cancelled()]


async def guarded_completion(
    ctx: ModelContext,
    prompt: str,
    risk_tier: str,
    model,  # LLM model with stream() method
    judges: List[Judge],
    captcha,  # SpatialCaptchaAuthenticator
    stream_guard: StreamGuard,
    stacker: ConformalRiskStacker,
    ledger: DecisionLedger,
) -> Tuple[Decision, str, Optional[Dict]]:
    """
    Complete guarded LLM completion workflow.

    Args:
        ctx: Model context
        prompt: User input
        risk_tier: Risk tier (low/medium/high/critical)
        model: LLM model
        judges: List of judges for Gate 2
        captcha: Spatial CAPTCHA authenticator
        stream_guard: Token-level guard
        stacker: Risk aggregator
        ledger: Decision ledger

    Returns:
        (decision, output_text, captcha_info)
    """
    # Gate 0: Spatial CAPTCHA (if high risk)
    cap_info = None
    if risk_tier in ["high", "critical"]:
        # Generate challenge
        item = captcha.generate(difficulty=3)

        # Present to user (external UI required)
        # user_response = await get_user_response(item)

        # For now: Skip actual challenge (would need UI integration)
        # In production: Wait for user response, verify, block if failed

        cap_info = {
            "item_id": item.item_id,
            "seed": item.seed,
            "params": item.params,
            "passed": True,  # Placeholder
        }

    # Gate 1: Stream generation with token guard
    state = stream_guard.start(ctx)
    draft_tokens = []

    # Simulate streaming (would be: async for tok in model.stream(prompt))
    # For now: Single completion
    draft_text = "This is a simulated LLM response."

    for token in draft_text.split():
        action, state = stream_guard.on_token(token, state)

        if action == StreamAction.ABORT:
            break
        elif action == StreamAction.REWRITE:
            draft_tokens.append("[REDACTED]")
        else:  # CONTINUE
            draft_tokens.append(token)

    stream_guard.finish(state)
    draft_complete = " ".join(draft_tokens)

    # Gate 2: Multi-agent judges (parallel)
    reports = await run_judges_parallel(judges, ctx, prompt, draft_complete)

    # Aggregator: Conformal risk stacking
    agg = stacker.aggregate(reports)
    decision = decision_from_risk(agg, stacker.cfg)

    # Build decision record
    votes = [
        JudgeVote(
            name=r.name,
            version=r.version,
            risk=r.risks.overall.value,
            band=r.risks.overall.band,
            severity=int(r.risks.overall.severity),
            latency_ms=r.latency_ms,
        )
        for r in reports
    ]

    record = DecisionRecord(
        ctx=ctx,
        captcha=cap_info,
        stream_stats={
            "tokens": len(draft_tokens),
            "aborts": 1 if StreamAction.ABORT in [StreamAction.ABORT] else 0,
            "rewrites": draft_tokens.count("[REDACTED]"),
        },
        votes=votes,
        aggregation={
            "overall_risk": agg.overall.value,
            "band": agg.overall.band,
            "qhat": agg.conformal_qhat,
            "coverage": agg.coverage_target,
        },
        thresholds={
            "deny_band": stacker.cfg.deny_band,
            "abstain_band": stacker.cfg.abstain_band,
            "weights": stacker.cfg.weights,
        },
        decision=decision,
    )

    # Persist to ledger
    record_id = ledger.persist(record)
    record.kue_proof_id = record_id

    # Return based on decision
    if decision == Decision.DENY:
        output = ""
    elif decision == Decision.ABSTAIN:
        output = "I cannot provide a complete answer. Please rephrase your question."
    else:  # ALLOW
        output = draft_complete

    return decision, output, cap_info

