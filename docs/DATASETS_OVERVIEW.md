# HAK_GAL Datasets Overview

**Date:** 2025-12-06
**Location:** `standalone_packages/llm-security-firewall/datasets/`

---

## Available Datasets

### Internal Test Suites (JSONL)

| Dataset | Lines | Type | Description |
|---------|-------|------|-------------|
| `combined_suite.jsonl` | 270 | Mixed | Combined redteam + benign + tool abuse |
| `core_suite.jsonl` | 200 | Mixed | Core test cases (100 benign, 100 redteam) |
| `core_suite_CLEANED.jsonl` | 141 | Mixed | Cleaned version of core_suite |
| `core_suite_smoke.jsonl` | 50 | Mixed | Quick smoke tests |
| `tool_abuse_suite.jsonl` | 70 | Redteam | Tool abuse scenarios |
| `mixed_expanded_100.jsonl` | 100 | Mixed | Expanded mixed scenarios |
| `mixed_small.jsonl` | 50 | Mixed | Small mixed test set |
| `mixed_test.jsonl` | 40 | Mixed | Basic mixed tests |
| `test_e2e.jsonl` | 20 | Mixed | End-to-end tests |

**Total Internal:** 941 test cases

---

### External Benchmark Datasets (HuggingFace)

#### 1. DoNotAnswer
- **Path:** `donotanswer/LibrAI___do-not-answer/`
- **Format:** Arrow (HuggingFace Datasets)
- **Source:** https://huggingface.co/datasets/LibrAI/do-not-answer
- **Purpose:** Harmful questions that should not be answered
- **Usage:** Test firewall blocking on prohibited content

#### 2. HH-RLHF (Anthropic)
- **Path:** `hh-rlhf/Anthropic___hh-rlhf/`
- **Format:** Arrow (HuggingFace Datasets)
- **Source:** https://huggingface.co/datasets/Anthropic/hh-rlhf
- **Purpose:** Helpful/Harmless RLHF data (benign prompts)
- **Usage:** Test False Positive Rate (FPR) on benign queries

#### 3. RealToxicityPrompts
- **Path:** `realtoxicityprompts/allenai___real-toxicity-prompts/`
- **Format:** Arrow (HuggingFace Datasets)
- **Source:** https://huggingface.co/datasets/allenai/real-toxicity-prompts
- **Purpose:** Real-world toxic prompts
- **Usage:** Test toxicity detection layer

#### 4. ToxiGen
- **Path:** `toxigen/skg___toxigen-data/`
- **Format:** Arrow (HuggingFace Datasets)
- **Source:** https://huggingface.co/datasets/skg/toxigen-data
- **Purpose:** Generated toxic statements
- **Usage:** Test toxicity detection across demographics

#### 5. PolyglotToxicityPrompts
- **Path:** `polyglotoxicityprompts/ToxicityPrompts___polyglo_toxicity_prompts/`
- **Format:** Arrow (HuggingFace Datasets)
- **Source:** https://huggingface.co/datasets/ToxicityPrompts/polyglo_toxicity_prompts
- **Purpose:** Multilingual toxicity prompts
- **Usage:** Test multilingual toxicity detection

#### 6. AdvBench
- **Path:** `advbench/`
- **Format:** Repository (no CSV found)
- **Source:** https://github.com/llm-attacks/llm-attacks
- **Purpose:** Adversarial attack benchmarks
- **Status:** ⚠️ Dataset files missing (only code repository)
- **Usage:** Test adversarial robustness

---

## Dataset Format Schemas

### Internal JSONL Format

```json
{
  "id": "core_0001",
  "type": "redteam" | "benign",
  "prompt": "The actual prompt text",
  "category": "harassment" | "weapons" | "tool_abuse_python" | etc.,
  "mode": "direct" | "roleplay" | "obfuscation",
  "expected_output_type": "python" | "bash" | null
}
```

### HuggingFace Arrow Format

Loaded via `datasets.load_dataset()`:
- Schema varies by dataset
- Typically includes: `prompt`, `continuation`, `toxicity_score`, etc.

---

## Loading Examples

### Load Internal JSONL

```python
import json

def load_jsonl(path):
    cases = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                cases.append(json.loads(line))
    return cases

# Load core suite
core_suite = load_jsonl("datasets/core_suite.jsonl")
print(f"Loaded {len(core_suite)} cases")
```

### Load HuggingFace Dataset

```python
from datasets import load_dataset

# Load DoNotAnswer
dataset = load_dataset("datasets/donotanswer/LibrAI___do-not-answer")
print(dataset)

# Load HH-RLHF helpful base
dataset = load_dataset("datasets/hh-rlhf/Anthropic___hh-rlhf")
helpful = dataset["train"].filter(lambda x: "helpful" in x.get("source", ""))
```

---

## Benchmark Coverage

### What We Test

| Security Layer | Dataset Coverage |
|----------------|------------------|
| **UnicodeSanitizer** | All datasets (automatic) |
| **NormalizationLayer** | All datasets (automatic) |
| **RegexGate** | core_suite, combined_suite, tool_abuse_suite |
| **ExploitDetection** | core_suite, combined_suite |
| **ToxicityDetection** | RealToxicityPrompts, ToxiGen, PolyglotToxicityPrompts |
| **SemanticGuard** | core_suite, DoNotAnswer, AdvBench |
| **KidsPolicy** | core_suite (when enabled) |
| **ToolCallValidation** | tool_abuse_suite, combined_suite |

### Metrics Tracked

1. **Attack Success Rate (ASR):** % of harmful prompts that bypass firewall (lower is better)
2. **False Positive Rate (FPR):** % of benign prompts incorrectly blocked (lower is better)
3. **Accuracy:** % of correct decisions (higher is better)
4. **Processing Time:** Average ms per prompt (lower is better)
5. **Layer Attribution:** Which layer blocked (for analysis)

---

## Benchmark Scripts

### Available Scripts

| Script | Dataset | Purpose |
|--------|---------|---------|
| `scripts/benchmark_v3_core_suite.py` | core_suite.jsonl | V3 baseline benchmark |
| `scripts/compare_v2_v3.py` | Custom 12 cases | V2 vs V3 comparison |
| `scripts/test_firewall_v3.py` | Hardcoded cases | Unit tests |
| `scripts/run_advbench_eval.py` | AdvBench (if available) | Adversarial robustness |
| `scripts/run_donotanswer_eval.py` | DoNotAnswer | Harmful content blocking |
| `scripts/run_hh_rlhf_eval.py` | HH-RLHF | Benign prompt FPR |
| `scripts/run_polyglotoxicity_eval.py` | PolyglotToxicity | Multilingual toxicity |
| `scripts/run_realtoxicity_eval.py` | RealToxicity | Real-world toxicity |
| `scripts/run_toxigen_eval.py` | ToxiGen | Generated toxicity |

### Run All Benchmarks

```bash
# Core suite (fastest, 200 cases)
python scripts/benchmark_v3_core_suite.py

# Full external benchmarks (slow, thousands of cases)
python scripts/run_donotanswer_eval.py
python scripts/run_hh_rlhf_eval.py
python scripts/run_realtoxicity_eval.py
```

---

## Dataset Statistics (Current Results)

### Core Suite (V3 Benchmark)
- **Total:** 200 cases (100 benign, 100 harmful)
- **FPR:** 7.0% (7 benign blocked out of 100)
- **ASR:** 76.0% (76 harmful bypassed out of 100)
- **Accuracy:** 58.5% (117 correct out of 200)
- **Avg Time:** 59.6ms
- **Status:** ⚠️ ASR too high (needs semantic tuning)

### V2 vs V3 Comparison (12 Custom Cases)
- **Agreement:** 100% (12/12 decisions match)
- **V2 Correctness:** 83.3% (10/12)
- **V3 Correctness:** 83.3% (10/12)
- **Performance:** V3 is 96.3% faster (15.5ms vs 419.3ms)
- **Status:** ✓ V3 achieves same security as V2

---

## Known Issues

### 1. AdvBench Missing
- **Issue:** AdvBench harmful_behaviors.csv not found
- **Workaround:** Use core_suite.jsonl for adversarial testing
- **Fix:** Download from https://github.com/llm-attacks/llm-attacks

### 2. High ASR on Core Suite
- **Issue:** 76% ASR indicates weak detection on subtle attacks
- **Root Cause:** Semantic threshold may be too high (0.65)
- **Fix:** Tune semantic_threshold to 0.5-0.6 range

### 3. HuggingFace Dataset Loading
- **Issue:** Some external datasets require specific loading parameters
- **Workaround:** Use existing eval scripts (e.g., `run_donotanswer_eval.py`)
- **Fix:** Standardize loading interface

---

## Dataset Maintenance

### Adding New Datasets

1. **Internal JSONL:** Add to `datasets/` directory, use standard schema
2. **External HF:** Download via `datasets.load_dataset()`, cache in `datasets/`
3. **Update Scripts:** Create `scripts/run_{dataset}_eval.py`
4. **Update Docs:** Add entry to this file

### Cleaning Datasets

- Use `core_suite_CLEANED.jsonl` as template
- Remove duplicates, invalid entries, or miscategorized cases
- Document changes in commit message

### Versioning

- Internal datasets: No explicit versioning (track via git)
- External datasets: HuggingFace handles versioning (see `dataset_info.json`)

---

## References

- AdvBench: https://github.com/llm-attacks/llm-attacks
- DoNotAnswer: https://huggingface.co/datasets/LibrAI/do-not-answer
- HH-RLHF: https://huggingface.co/datasets/Anthropic/hh-rlhf
- RealToxicityPrompts: https://huggingface.co/datasets/allenai/real-toxicity-prompts
- ToxiGen: https://huggingface.co/datasets/skg/toxigen-data
- PolyglotToxicity: https://huggingface.co/datasets/ToxicityPrompts/polyglo_toxicity_prompts

---

**Document Version:** 1.0
**Last Updated:** 2025-12-06
**Next Review:** When new datasets added
