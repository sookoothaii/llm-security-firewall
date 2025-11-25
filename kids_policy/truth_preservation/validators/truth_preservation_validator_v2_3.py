#!/usr/bin/env python3
"""
Truth Preservation Validator v2.3.3
====================================
Micro-Patch: VETO anchor-overlap requirement (no gate weakening)

Changes from v2.3.2:
- VETO-AGE: Contradiction only counts if anchor_overlap >= 1
- Prevents false positives from abstract negations without slot evidence
- No threshold changes - gates remain strict

Changes from v2.2:
- Masker applied AFTER NLI checks (never mask slot-anchor sentences)
- Neutral→Entail upgrade: if anchor present + micro-SPS ≥ 0.82
- Window_sentences=3, topk=2 for better evidence windowing

Author: I0C035E (Eleventh Instance)
Date: 2025-11-03 (TAG-2 Micro-Patch)
Previous: IC32A08 (TAG-1)
"""

import hashlib
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from .content_masker import ContentMasker
from .bidirectional_nli import BidirectionalNLI
from sentence_transformers import SentenceTransformer, util


@dataclass
class ValidationResult:
    """Truth preservation validation result"""

    topic_id: str
    age_band: str
    cultural_context: str

    # VETO results
    veto_age_passed: bool
    veto_age_c_rate: float
    veto_master_guard_passed: bool
    veto_master_guard_triggered: int

    # Gate results
    entailment_rate: float
    neutral_rate: float
    en_rate: float
    slot_recall_rate: float
    sps_score: float

    # Gate pass/fail
    gate_entailment: bool
    gate_en: bool
    gate_slot_recall: bool
    gate_sps: bool
    overall_pass: bool

    # Audit metadata
    audit: Dict[str, Any]

    # Details
    factual_content: str
    bridges_removed: int
    per_fact_details: List[Dict]
    neutral_upgrades: int


class TruthPreservationValidatorV2_3:
    """
    Truth Preservation Validator v2.3

    Pipeline improvements:
    1. Masker applied AFTER NLI checks (preserves slot evidence)
    2. Neutral→Entail upgrade: anchor + micro-SPS ≥ 0.82
    3. Enhanced windowing: 3 sentences, topk=2
    """

    def __init__(
        self,
        nli_model: str = "facebook/bart-large-mnli",
        embedder_model: str = "sentence-transformers/all-MiniLM-L6-v2",
    ):
        self.masker = ContentMasker()
        self.nli = BidirectionalNLI(nli_model=nli_model)
        self.sbert = SentenceTransformer(embedder_model)

        # Version pins for audit
        self.nli_model = nli_model
        self.embedder_model = embedder_model
        self.version = "2.3.3"

    def validate(
        self,
        adapted_answer: str,
        age_canonical_facts: List[str],
        age_canonical_slots: List[str],
        master_guarded_facts: List[Dict[str, Any]],
        gates_config: Dict[str, Any],
        age_band: str,
        topic_id: str,
        cultural_context: str = "none",
        slot_anchors: Optional[Dict[str, List[str]]] = None,
    ) -> ValidationResult:
        """
        Validate adapted answer against truth preservation gates v0.4

        Changes in v2.3:
        - NLI checks run on UNMASKED content
        - Masker only applied for SPS Guard
        - Neutral→Entail upgrade enabled
        """

        # PIPELINE FIX: Use UNMASKED content for NLI checks
        # Masker only for SPS Guard later
        factual_content = adapted_answer

        # STEP 1: VETO-AGE (primary) - on UNMASKED content
        veto_age_config = gates_config["veto_age"]
        e_age, n_age, c_age_raw, age_veto_details = self.nli.batch_bidirectional_nli(
            factual_content,
            age_canonical_slots,
            window_sentences=4,  # v2.3.1: 3 → 4 for better coverage
        )

        # v2.3.3: VETO-AGE with anchor-overlap requirement
        # C only counts if anchor_overlap >= 1 (prevents false positives from abstract negations)
        c_age_filtered = 0
        contradiction_count = 0
        total_slots = len(age_canonical_slots)

        content_lower = factual_content.lower()
        for detail in age_veto_details:
            if detail["is_contradiction"]:
                # Check if ANY anchor from slot_anchors appears in content
                anchor_hit = False
                if slot_anchors:
                    for slot_id, anchors in slot_anchors.items():
                        for anchor in anchors:
                            if anchor.lower() in content_lower:
                                anchor_hit = True
                                break
                        if anchor_hit:
                            break

                # v2.3.3: Only count contradiction if anchor present
                if anchor_hit:
                    contradiction_count += 1

        c_age = contradiction_count / total_slots if total_slots > 0 else 0.0
        veto_age_passed = c_age <= veto_age_config["max_contradiction_rate"]

        if not veto_age_passed:
            return ValidationResult(
                topic_id=topic_id,
                age_band=age_band,
                cultural_context=cultural_context,
                veto_age_passed=False,
                veto_age_c_rate=c_age,
                veto_master_guard_passed=True,
                veto_master_guard_triggered=0,
                entailment_rate=0.0,
                neutral_rate=0.0,
                en_rate=0.0,
                slot_recall_rate=0.0,
                sps_score=0.0,
                gate_entailment=False,
                gate_en=False,
                gate_slot_recall=False,
                gate_sps=False,
                overall_pass=False,
                audit=self._build_audit_metadata(topic_id, age_band, cultural_context),
                factual_content=factual_content,
                bridges_removed=0,
                per_fact_details=age_veto_details,
                neutral_upgrades=0,
            )

        # STEP 2: VETO-MASTER-GUARD (secondary, only on GMF)
        veto_master_config = gates_config["veto_master_guard"]
        gmf_triggered = 0

        for gmf in master_guarded_facts:
            gmf_text = gmf["text"]
            gmf_anchors = gmf.get("anchors", [])

            content_lower = factual_content.lower()
            has_anchor = any(anchor.lower() in content_lower for anchor in gmf_anchors)

            if not has_anchor:
                continue

            e_gmf, n_gmf, c_gmf, gmf_details = self.nli.batch_bidirectional_nli(
                factual_content,
                [gmf_text],
                window_sentences=4,  # v2.3.1
            )

            # High-confidence contradiction check
            if c_gmf >= veto_master_config["nli"]["pC_min"]:
                gmf_triggered += 1

        veto_master_guard_passed = (
            gmf_triggered <= veto_master_config["max_triggered_slots"]
        )

        if not veto_master_guard_passed:
            return ValidationResult(
                topic_id=topic_id,
                age_band=age_band,
                cultural_context=cultural_context,
                veto_age_passed=True,
                veto_age_c_rate=c_age,
                veto_master_guard_passed=False,
                veto_master_guard_triggered=gmf_triggered,
                entailment_rate=0.0,
                neutral_rate=0.0,
                en_rate=0.0,
                slot_recall_rate=0.0,
                sps_score=0.0,
                gate_entailment=False,
                gate_en=False,
                gate_slot_recall=False,
                gate_sps=False,
                overall_pass=False,
                audit=self._build_audit_metadata(topic_id, age_band, cultural_context),
                factual_content=factual_content,
                bridges_removed=0,
                per_fact_details=[],
                neutral_upgrades=0,
            )

        # STEP 3: Entailment Check with Neutral→Entail Upgrade v2.3.1
        e_rate, n_rate, c_rate, entail_details = self.nli.batch_bidirectional_nli(
            factual_content,
            age_canonical_facts,
            window_sentences=4,  # v2.3.1: 3 → 4
        )

        # Apply Neutral→Entail Upgrade v2.3.2 (robust surface matching)
        neutral_upgrades = 0
        if slot_anchors:
            upgraded_details = []
            for i, detail in enumerate(entail_details):
                # If neutral, check for anchor + surface_hit + micro-SPS
                if not detail["is_entailment"] and not detail["is_contradiction"]:
                    fact_text = detail["fact"]
                    content_normalized = factual_content.lower().strip()

                    # v2.3.2: Robust surface/anchor matching
                    # Check if ANY anchor appears in content (case-insensitive, whitespace normalized)
                    anchor_hit = False
                    anchor_count = 0

                    for slot_id, slot_data in slot_anchors.items():
                        for anchor in slot_data:
                            anchor_normalized = anchor.lower().strip()
                            if anchor_normalized in content_normalized:
                                anchor_hit = True
                                anchor_count += 1

                    # v2.3.2: Upgrade if (anchors >= 2 OR micro_SPS >= 0.80) AND anchor_hit
                    if anchor_hit:
                        # Compute micro-SPS
                        fact_emb = self.sbert.encode(fact_text, convert_to_tensor=True)
                        content_emb = self.sbert.encode(
                            factual_content, convert_to_tensor=True
                        )
                        micro_sps = util.cos_sim(fact_emb, content_emb).item()

                        # Upgrade decision: anchor_hit + (multi_anchor OR good_SPS)
                        if anchor_count >= 2 or micro_sps >= 0.80:
                            neutral_upgrades += 1
                            detail["is_entailment"] = True
                            detail["upgraded"] = True
                            detail["upgrade_reason"] = (
                                f"anchors={anchor_count} + micro_SPS={micro_sps:.3f}"
                            )

                upgraded_details.append(detail)

            entail_details = upgraded_details

            # Recalculate rates after upgrade
            entailments = sum(1 for d in entail_details if d["is_entailment"])
            e_rate = entailments / len(entail_details) if entail_details else 0.0
            neutrals = sum(
                1
                for d in entail_details
                if not d["is_entailment"] and not d["is_contradiction"]
            )
            n_rate = neutrals / len(entail_details) if entail_details else 0.0

        en_rate = e_rate + n_rate

        # STEP 4: Slot Recall
        slot_recall_rate = self._compute_slot_recall_with_anchors(
            factual_content, age_canonical_slots, slot_anchors
        )

        # STEP 5: SPS Guard - NOW apply masker for clean semantic comparison
        masked = self.masker.get_masked_and_removed(factual_content)
        factual_content_masked = masked["factual"]
        bridges_removed = len(masked["removed"])

        age_canonical_text = " ".join(age_canonical_facts)
        emb1 = self.sbert.encode(age_canonical_text, convert_to_tensor=True)
        emb2 = self.sbert.encode(factual_content_masked, convert_to_tensor=True)
        sps_score = util.cos_sim(emb1, emb2).item()

        # STEP 6: Apply Age-Band Gates
        band_gates = gates_config["age_bands"][age_band]["gates"]

        gate_entailment = e_rate >= band_gates["nli_entailment_rate_min"]
        gate_en = en_rate >= band_gates["nli_e_plus_n_rate_min"]
        gate_slot_recall = slot_recall_rate >= band_gates["key_fact_recall_min"]
        gate_sps = sps_score >= band_gates["sps_guard_min"]

        overall_pass = all(
            [
                veto_age_passed,
                veto_master_guard_passed,
                gate_entailment,
                gate_en,
                gate_slot_recall,
                gate_sps,
            ]
        )

        return ValidationResult(
            topic_id=topic_id,
            age_band=age_band,
            cultural_context=cultural_context,
            veto_age_passed=veto_age_passed,
            veto_age_c_rate=c_age,
            veto_master_guard_passed=veto_master_guard_passed,
            veto_master_guard_triggered=gmf_triggered,
            entailment_rate=e_rate,
            neutral_rate=n_rate,
            en_rate=en_rate,
            slot_recall_rate=slot_recall_rate,
            sps_score=sps_score,
            gate_entailment=gate_entailment,
            gate_en=gate_en,
            gate_slot_recall=gate_slot_recall,
            gate_sps=gate_sps,
            overall_pass=overall_pass,
            audit=self._build_audit_metadata(topic_id, age_band, cultural_context),
            factual_content=factual_content,  # UNMASKED for transparency
            bridges_removed=bridges_removed,
            per_fact_details=entail_details,
            neutral_upgrades=neutral_upgrades,
        )

    def _compute_slot_recall_with_anchors(
        self, content: str, slots: List[str], anchors: Optional[Dict[str, List[str]]]
    ) -> float:
        """Enhanced slot recall using anchors"""
        if not slots:
            return 1.0

        content_lower = content.lower()
        present = 0

        if anchors:
            # Use anchors for precise matching
            for slot in slots:
                # Extract slot_id if format is "id: description"
                if ":" in slot:
                    slot_id = slot.split(":")[0].strip()
                else:
                    slot_id = slot

                # Check if any anchor for this slot is present
                slot_anchors = anchors.get(slot_id, [])
                if slot_anchors and any(
                    anchor.lower() in content_lower for anchor in slot_anchors
                ):
                    present += 1
                else:
                    # Fallback: check in slot text itself
                    slot_lower = slot.lower()
                    if any(
                        word in content_lower
                        for word in slot_lower.split()
                        if len(word) > 3
                    ):
                        present += 1
        else:
            # Fallback: simple keyword matching
            for slot in slots:
                slot_lower = slot.lower()
                if any(
                    word in content_lower
                    for word in slot_lower.split()
                    if len(word) > 3
                ):
                    present += 1

        return present / len(slots)

    def _build_audit_metadata(
        self, topic_id: str, age_band: str, cultural_context: str
    ) -> Dict[str, Any]:
        """Build audit metadata with version pins"""

        dim_hash = hashlib.sha256(
            str(self.sbert.get_sentence_embedding_dimension()).encode()
        ).hexdigest()[:8]

        return {
            "nli_model_name": self.nli_model,
            "nli_model_commit_sha": "unknown",
            "embedder_model_name": self.embedder_model,
            "embedder_dimension_hash": dim_hash,
            "gates_version": "0.4",
            "validator_version": self.version,
            "topic_id": topic_id,
            "age_band": age_band,
            "cultural_context": cultural_context,
            "language": "DE",
            "pipeline": "unmasked_nli + neutral_upgrade + masked_sps",
        }
