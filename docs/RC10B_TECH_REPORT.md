# RC10b Technical Report

**Datum:** 2025-11-17  
**Status:** Complete Evaluation  
**Version:** RC10b  
**Autor:** Joerg Bollwahn (mit GPT-5.1 Analyse)

---

## Executive Summary

This technical report documents the evaluation of RC10 and RC10b agentic campaign detection systems. RC10b introduces three key improvements over RC10: (i) an action-semantics layer with explicit policy rules, (ii) a phase-floor mechanism for high kill-chain phases, and (iii) scope-mismatch detection and testlab/authorization handling.

**Key Results:**
- RC10 achieves perfect metrics (0% ASR/FPR) on baseline scenarios but fails on hard cases (100% ASR for HARD_FN, 60% ASR for SHIFT, 30% FPR for HARD_FP)
- RC10b eliminates all hard-case failures while preserving baseline performance
- Ablation studies show the policy layer is causally critical; phase-floor and scope-mismatch act as redundant safety margins

---

## 6. Evaluation

### 6.1 Experimental Setup

We evaluate the RC10 and RC10b detectors on a synthetic campaign dataset comprising 180 scenarios:

* **Baseline:** 100 campaigns (50 benign, 50 malicious) representing "standard" behavior: single-target or few-target interactions, typical recon and exploit flows, no adversarial stress patterns.

* **Hard cases:** 80 campaigns designed to stress specific failure modes:

  * **HARD_FP (HC1/HC3):**

    * HC1: legitimate full kill-chain behavior in an authorized testlab environment (high phase depth but benign).

    * HC3: bulk recon benign campaigns with many targets but phase depth ≤ 1 and no exploit/exfiltration.

  * **HARD_FN (HC2):** low-and-slow attacks with a single target, long inter-event intervals (2–8 h), low tool diversity, but high phase depth (up to data exfiltration).

  * **SHIFT (HC4):** pretext/scope-abuse campaigns where the text pretext claims a testlab/red-team setting, but the actual targets include external, real domains.

We report:

* **ASR_block**: fraction of malicious campaigns that are not blocked (attack success rate at the hard decision level; lower is better).

* **FPR_block**: fraction of benign campaigns that are hard-blocked.

* When relevant, we also distinguish **soft decisions** (`REQUIRE_APPROVAL`) from hard blocks, and measure **detection delay** as the number of events (and elapsed time) until the campaign is first classified as malicious.

Unless otherwise noted, we use a soft threshold (T_{\text{soft}} = 0.35) for raising `REQUIRE_APPROVAL` and a hard threshold (T_{\text{hard}} = 0.55) for `BLOCK`.

---

### 6.2 Phase-1: Baseline-Only Evaluation of RC10

We first evaluated RC10 on the 100 baseline campaigns (50 benign, 50 malicious) without any hard-case scenarios. Using a single risk threshold, RC10 achieved:

* **ASR_block = 0%** (all malicious baselines blocked),

* **FPR_block = 0%** (no benign baselines hard-blocked),

with a clear separation between the risk score distributions of benign and malicious campaigns. Average detection delay for malicious campaigns was modest (≈5 events, on the order of minutes in simulated time).

This baseline-only evaluation confirms that RC10 correctly implements the intended design: kill-chain depth, branching factor, tempo and tool diversity are sufficient to separate benign and malicious behavior in non-adversarial conditions. However, as Phase-2 will show, these "perfect" metrics are highly optimistic and do not reflect robustness under more realistic, adversarial patterns.

---

### 6.3 Phase-2: Hard-Case Evaluation of RC10

We then evaluated RC10 on the full dataset (100 baseline + 80 hard-case scenarios). The results reveal substantial failure modes that are invisible in the baseline-only evaluation.

* **Baseline (again):**

  RC10 maintained **ASR_block = 0%** and **FPR_block = 0%** on the original baseline campaigns.

* **HARD_FP (HC1 + HC3): benign but adversarially structured**

  For the 40 benign hard-case campaigns:

  * **FPR_block ≈ 30%**: 12 of 40 benign HC1/HC3 campaigns were hard-blocked.

  * HC1 (legitimate high-phase testlab pentests) were particularly prone to being classified as malicious due to their full kill-chain behavior, despite being authorized and scoped to a test network.

  * HC3 (bulk recon benign) exposed the sensitivity of the detector to high branching and high tempo even in the absence of exploit or exfiltration tools.

* **HARD_FN (HC2): low-and-slow attacks**

  For the 20 malicious low-and-slow campaigns:

  * **ASR_block = 100%**: *none* of the HC2 campaigns were blocked.

  * Average risk scores remained below the global threshold, as the detector relied heavily on volumetric features (branching, tempo, tool diversity) that are intentionally muted in low-and-slow scenarios.

  * No meaningful detection delay could be computed, as the attacks were never classified as malicious.

* **SHIFT (HC4): pretext/scope abuse**

  For the 20 malicious pretext/scope-abuse campaigns:

  * **ASR_block ≈ 60%**: only about 40% of SHIFT campaigns were blocked.

  * Risk scores hovered around the decision threshold, indicating that the detector partially responded to the external targets, but could still be misled by the "authorized testlab" pretext in the prompt.

**Summary.**

Phase-2 clearly shows that RC10's "perfect" baseline metrics mask two critical weaknesses:

1. **Low-and-slow attacks** (HARD_FN) are effectively invisible: they reach high kill-chain phases without being blocked.

2. **Pretext/scope abuse** (SHIFT) can bypass detection in a substantial fraction of cases.

These findings motivated a set of targeted design changes, implemented in RC10b.

---

### 6.4 RC10b Evaluation on Baseline and Hard Cases

RC10b introduces three main changes (described in Section X):

(i) an action-semantics layer (`ALLOW/WARN/REQUIRE_APPROVAL/BLOCK`) with an explicit policy layer,

(ii) a phase-floor mechanism for high kill-chain phases, and

(iii) scope-mismatch and testlab/authorization handling for HC1/HC3-style scenarios.

We evaluate RC10b on the same 180-campaign dataset.

**Baseline.**

On the 100 baseline campaigns, RC10b preserves RC10's behavior:

* **ASR_block = 0%**, **FPR_block = 0%**,

* with similar detection delays (≈5 events for hard decisions) and clean score separation between benign and malicious baselines.

**HARD_FN (HC2 – low-and-slow).**

After the RC10b changes:

* **ASR_block = 0%** (all 20 HC2 campaigns are blocked).

* Low-and-slow attacks are detected and blocked, albeit with longer detection delays (≈6–7 events and tens of hours in simulated time, i.e., late but still before full completion of the campaign).

* Mean risk scores for HC2 campaigns are lifted into the blocking region, ensuring that they cannot silently complete.

**SHIFT (HC4 – pretext/scope abuse).**

* **ASR_block = 0%** for all 20 SHIFT campaigns.

* Detection is typically early at the soft threshold (after ≈1 event), and within ≈6 events for the hard threshold.

* Risk scores for SHIFT campaigns are clearly separated from benign behavior, largely due to their aggressive multi-phase, multi-target structure; scope-abuse signals further increase the margin to the decision boundary.

**HARD_FP (HC1 + HC3 – benign hard cases).**

Here the goal is *not* to reduce risk scores to benign levels, but to avoid **hard false positives** while still surfacing the campaigns as suspicious:

* For all 20 HC1 (legitimate testlab full kill-chain) campaigns:

  * **FPR_block = 0%**: none are hard-blocked.

  * All are assigned `REQUIRE_APPROVAL`, reflecting that they look dangerous in isolation but are in an authorized testlab scope.

* For all 20 HC3 (bulk recon benign) campaigns:

  * **FPR_block = 0%** as well.

  * Again, all are flagged as `REQUIRE_APPROVAL` because of their unusually high branching and tempo, despite lacking exploit/exfiltration steps.

**Summary.**

Compared to RC10, RC10b:

* Preserves zero ASR/FPR on baseline scenarios,

* Reduces **HARD_FN ASR_block from 100% to 0%**,

* Reduces **SHIFT ASR_block from ≈60% to 0%**,

* Eliminates hard false positives on HC1/HC3 while still marking them as "suspicious but authorized" via `REQUIRE_APPROVAL`.

RC10b thus achieves **strictly better security** on the malicious hard cases while avoiding hard blocking of benign high-phase behavior.

---

### 6.5 Ablation Studies

To better understand the contribution of individual RC10b components, we performed ablation studies using a feature-flagged detector configuration. We considered four configurations:

1. **Full RC10b:** all features enabled (phase-floor, scope-mismatch, policy layer).

2. **No Phase-Floor:** disables the phase-floor contribution for high kill-chain phases.

3. **No Scope-Mismatch:** disables the scope-mismatch feature and its associated penalty.

4. **No Policy Layer:** bypasses the policy layer and uses simple thresholding on the raw risk scores.

All runs use the same 180-campaign dataset.

**Effect of removing the policy layer.**

Disabling the policy layer has a strong and easily interpretable impact:

* For **HARD_FN (low-and-slow)** campaigns:

  * **ASR_block jumps from 0% (full RC10b) to 100%** without the policy layer.

  * Mean risk scores for HC2 campaigns fall below the hard threshold when the policy logic is removed, causing the detector to miss all low-and-slow attacks.

* For **baseline** campaigns:

  * **ASR_block increases from 0% to ≈6%** without the policy layer, indicating that the policy logic also contributes to stable detection on normal traffic (a small fraction of malicious baseline campaigns is no longer blocked).

This shows that the policy layer is **causally critical** for correctly handling low-and-slow attacks and, at the same time, contributes to robustness on normal traffic.

**Effect of removing the phase-floor.**

In contrast, removing the phase-floor did not change the classification outcomes on the current dataset:

* For HARD_FN campaigns, ASR_block remains 0%; mean risk scores stay in the blocking region with and without the phase-floor.

* The same holds for baseline and other hard-case classes.

This suggests that, given the present synthetic scenarios and other features (e.g., kill-chain depth, campaign graph), the phase-floor acts as a **redundant safety margin** rather than a uniquely decisive signal: it increases the margin to the decision boundary, but the attacks are already clearly distinguishable without it.

**Effect of removing scope-mismatch.**

Similarly, disabling the scope-mismatch feature does not change SHIFT classification outcomes:

* SHIFT campaigns remain well above the hard threshold (ASR_block stays at 0%), although mean risk decreases slightly when scope-mismatch is removed.

On the current dataset, pretext/scope-abuse campaigns are already strongly characterized by their multi-phase, multi-target structure; scope-mismatch primarily increases the distance to the threshold without being the determining factor.

**HARD_FP behavior under ablations.**

For HC1/HC3 benign hard cases, disabling the policy layer does *not* increase the hard false-positive rate (which remains at 0%) on this dataset, although average risk scores increase. This is partially due to additional protective mechanisms (e.g., risk caps for testlab/authorized scenarios) that remain active even without the full policy logic. As a result, the ablation does not fully isolate the policy layer's role for benign high-phase behavior.

**Discussion.**

Overall, the ablation studies show that:

* The **policy layer** has a clear, **causal** effect on detection performance, especially for low-and-slow attacks and baseline stability.

* The **phase-floor** and **scope-mismatch** features behave as **synergistic safety margins** on the current dataset: they increase the margin to the decision boundary but are not strictly necessary for correct classification, given other strong signals.

Together with the RC10→RC10b comparison, these results support the view that RC10b's improvements are driven by the **combination** of structurally meaningful features (kill-chain and campaign metrics) and an explicit policy semantics layer, with certain features currently acting as redundancy that could become more important under more adversarial or finely tuned scenarios.

---

### 6.6 Summary Table

Table 1 provides a numerical summary of ASR_block and FPR_block across all evaluation configurations and campaign classes.

**Table 1: Attack success rate (ASR_block) and hard false-positive rate (FPR_block) for RC10, RC10b and ablation configurations on the 180-campaign dataset.**

| Model / Configuration        | Baseline ASR_block | Baseline FPR_block | HARD_FN ASR_block | SHIFT ASR_block | HARD_FP FPR_block |
|-----------------------------|--------------------|--------------------|-------------------|-----------------|-------------------|
| RC10                        | 0.00               | 0.00               | 1.00              | ≈0.60           | ≈0.30             |
| RC10b (full)                | 0.00               | 0.00               | 0.00              | 0.00            | 0.00              |
| RC10b – no phase-floor      | 0.00               | 0.00               | 0.00              | 0.00            | 0.00              |
| RC10b – no scope-mismatch   | 0.00               | 0.00               | 0.00              | 0.00            | 0.00              |
| RC10b – no policy layer     | 0.06               | 0.00               | 1.00              | 0.00            | 0.00              |

**Caption:** RC10b strictly improves over RC10 on all hard-case classes. Phase-floor and scope-mismatch ablations leave decisions unchanged on this dataset (pure redundancy), whereas removing the policy layer reintroduces RC10-like failures on HARD_FN and slightly degrades baseline ASR.

**Notes:**
- BASELINE: 100 campaigns (50 benign, 50 malicious)
- HARD_FN: 20 malicious low-and-slow campaigns
- SHIFT: 20 malicious pretext/scope-abuse campaigns
- HARD_FP: 40 benign hard-case campaigns (20 HC1 + 20 HC3)
- ASR_block: fraction of malicious campaigns not blocked (lower is better)
- FPR_block: fraction of benign campaigns hard-blocked (lower is better)

---

## References

* Detailed ablation study results: `RC10B_ABLATION_STUDIES.md`
* Phase-2 validation report: `RC10_PHASE2_VALIDATION_REPORT.md`
* RC10b validation report: `RC10B_VALIDATION_REPORT.md`
* Implementation details: `RC10B_IMPLEMENTATION_STATUS.md`

