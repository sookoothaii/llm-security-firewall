# Layer 15 Crisis Detection - Training Data Sources

**Status:** Stage A (Self-Harm Focus)  
**Model:** xlm-roberta-base + 3-label multi-label head  
**Target:** Dev Recall ≥ 0.90 @ Precision ≥ 0.60 for self_harm

---

## Public Datasets (Recommended)

### 1. eRisk Collection (PRIMARY SOURCE)

**Description:** CLEF eRisk depression detection benchmark from Reddit

**Latest:** eRisk 2025 (Contextual and Conversational Approaches for Depression)

**Papers:**
- Losada & Crestani (2016) - "A Test Collection for Research on Depression and Language Use"
- Crestani et al. (2022) - "Early Detection of Mental Health Disorders by Social Media Monitoring"
- Parapar et al. (2025) - "eRisk 2025: Contextual and Conversational Approaches for Depression Challenges"

**Statistics (2016-2024):**
- 137 depressed users + 755 control users
- Avg 578 days history per user
- Chronological submissions (posts + comments)
- Average 361 submissions per depressed user
- Average 638 submissions per control user

**Registration:** anxo.pvila@udc.es (User Agreement required)

**Homepage:** http://tec.citius.usc.es/ir/code/dc.html

**Format:**
- **eRisk 2016-2024:** XML files (one per user, chronological submissions)
- **eRisk 2025:** JSON files (submissions + hierarchical comments, ISO 8601 timestamps)

**Evaluation Metric:** ERDE (Early Risk Detection Error) - delay-aware F-measure

**Tasks Available:**
- eRisk 2017: Early Detection of Depression
- eRisk 2018: Early Detection of Depression (extended)
- eRisk 2019: Early Detection of Self-Harm
- eRisk 2021: Self-Harm Detection (T2)
- eRisk 2022-2024: Various mental health tasks

**eRisk 2025 JSON Format:**
```json
{
  "submissionId": "mdB60ef",
  "author": "subject_lEQN6dA",
  "date": "2023-03-08T17:26:33.000+00:00",
  "body": "...",
  "title": "...",
  "number": 3,
  "targetSubject": "subject_6wEJkcb",
  "comments": [
    {
      "commentId": "UspY8Bg",
      "author": "subject_6wEJkcb",
      "date": "2023-03-08T17:51:42.000+00:00",
      "body": "...",
      "parent": "mdB60ef"
    }
  ]
}
```

**Conversion to JSONL:**
```bash
# Auto-detects XML or JSON format
python tools/layer15/convert_erisk_to_jsonl.py \
    --erisk_dir /path/to/erisk \
    --output data/layer15/erisk_all.jsonl \
    --label self_harm

# For XML format (specify positive/negative dirs)
python tools/layer15/convert_erisk_to_jsonl.py \
    --erisk_dir /path/to/erisk \
    --output data/layer15/erisk_all.jsonl \
    --label self_harm \
    --format xml \
    --positive_dir /path/to/positive \
    --negative_dir /path/to/negative

# For JSON format with target subject filtering
python tools/layer15/convert_erisk_to_jsonl.py \
    --erisk_dir /path/to/erisk \
    --output data/layer15/erisk_all.jsonl \
    --label self_harm \
    --format json \
    --target_subjects subjects.txt
```

**Citations:**
```bibtex
@inproceedings{losada2016test,
  title={A test collection for research on depression and language use},
  author={Losada, David E and Crestani, Fabio},
  booktitle={International Conference of the Cross-Language Evaluation Forum for European Languages},
  pages={28--39},
  year={2016},
  organization={Springer}
}

@book{crestani2022early,
  title={Early Detection of Mental Health Disorders by Social Media Monitoring},
  author={Crestani, Fabio and Losada, David and Parapar, Javier},
  series={Studies in Computational Intelligence},
  volume={1018},
  year={2022},
  publisher={Springer}
}

@inproceedings{parapar2025erisk,
  title={eRisk 2025: Contextual and Conversational Approaches for Depression Challenges},
  author={Parapar, Javier and Perez, A and Wang, X and Crestani, Fabio},
  booktitle={European Conference on Information Retrieval},
  pages={416--424},
  year={2025}
}
```

---

### 2. CLPsych / UMD Reddit Suicidality Dataset

**Description:** User-level suicidality annotations from Reddit

**Paper:** CLPsych 2019/2024 Shared Tasks

**Source:** https://psresnik.github.io/umd_reddit_suicidality_dataset.html

**License:** Academic research use (contact authors)

**Format:** User-level annotations with Reddit post history

**Tasks:**
- CLPsych 2019: Suicide risk assessment
- CLPsych 2024: Extended annotations

**Note:** Requires separate registration/licensing

---

### 3. Kaggle Suicide Watch (CAUTION - Re-label Required)

**Description:** Community-collected suicidality dataset

**Source:** https://www.kaggle.com/datasets/nikhileswarkomati/suicide-watch

**Quality:** Variable quality, requires expert re-annotation

**Use Case:** Supplementary data only after manual review

**License:** Check Kaggle dataset terms

**Warning:** Not clinically validated - use with caution

---

## Complementary Resources (Stage B)

### 4. DAIC-WOZ Database

**Description:** Clinical interviews (audio + transcripts) with depression/PTSD labels

**Source:** https://dcapswoz.ict.usc.edu/

**License:** Research license required

**Format:** Audio + transcripts with PHQ-8 scores

**Use Case:** Auxiliary features for depression classification (not direct crisis detection)

---

### 5. GoEmotions

**Description:** Fine-grained emotion annotations (58k Reddit comments)

**Source:** https://github.com/google-research/google-research/tree/master/goemotions

**License:** Apache 2.0

**Use Case:** Emotion signals as auxiliary features

**Not Applicable For:** Direct crisis detection (no crisis labels)

---

## Data Preparation Workflow

### Step 1: Register & Download

1. Register for eRisk collection: http://tec.citius.usc.es/ir/code/dc.html
2. Download XML files (depressed + control users)
3. Optional: Register for CLPsych dataset

### Step 2: Convert to JSONL

```bash
# Create data directory
mkdir -p data/layer15

# Run conversion script (to be created)
python tools/layer15/convert_erisk_to_jsonl.py \
    --erisk_dir /path/to/erisk/xml \
    --output data/layer15/erisk_train.jsonl \
    --label self_harm
```

### Step 3: Split Train/Dev/Test

```bash
# Split data (80/10/10)
python tools/layer15/split_data.py \
    --input data/layer15/erisk_train.jsonl \
    --train data/layer15/train.jsonl \
    --dev data/layer15/dev.jsonl \
    --test data/layer15/test.jsonl \
    --ratios 0.8 0.1 0.1
```

### Step 4: Train Model

```bash
# Train with eRisk data
python tools/layer15/train_layer15_crisis.py \
    --train data/layer15/train.jsonl \
    --dev data/layer15/dev.jsonl \
    --outdir models/layer15_crisis \
    --epochs 3 \
    --bsz 32
```

---

## Ethics & Legal

**IMPORTANT:**
- All datasets require proper registration/licensing
- Reddit data use must comply with fair use doctrine
- No PII should be re-distributed
- Research use only (not commercial)
- IRB approval required for production deployment
- Clinical validation required before real-world use

**User Agreement Required For:**
- eRisk collection
- CLPsych dataset
- DAIC-WOZ database

**Citation Required For:**
- All datasets used in publications
- Benchmark comparisons with eRisk baselines

---

## ERDE Metric Implementation

eRisk uses ERDE (Early Risk Detection Error) - delay-aware metric:

```python
def erde_score(predictions, ground_truth, o=50):
    """
    ERDE: Early Risk Detection Error
    
    Args:
        predictions: List of (decision, delay) tuples
        ground_truth: List of true labels
        o: Latency parameter (default 50)
    
    Returns:
        ERDE score (lower is better)
    """
    cfp = 0.0137  # FP cost (based on 1% prevalence)
    cfn = 1.0     # FN cost
    ctp = 1.0     # Late TP cost
    
    def lc(k, o):
        """Latency cost function."""
        return 1 - 1 / (1 + np.exp((k - o)))
    
    errors = []
    for (pred, delay), truth in zip(predictions, ground_truth):
        if pred == 1 and truth == 0:  # FP
            errors.append(cfp)
        elif pred == 0 and truth == 1:  # FN
            errors.append(cfn)
        elif pred == 1 and truth == 1:  # TP (with delay penalty)
            errors.append(lc(delay, o) * ctp)
        # TN has 0 error
    
    return np.mean(errors)
```

---

## Stage B: Abuse/Unsafe-Env (Future Work)

**Planned Sources:**
- Institutional abuse disclosure datasets (if available)
- Weak supervision via Snorkel labeling functions
- Expert audit of candidate samples
- Reddit r/relationships abuse discussions (careful filtering)

**Status:** Stage A (Self-Harm) takes priority - validated datasets available

**Timeline:** After Stage A completion + evaluation

---

## Quick Start (With Synthetic Data - For Testing Only)

If you need to test the pipeline before obtaining real data:

```bash
# Generate synthetic data (TESTING ONLY)
python scripts/generate_crisis_training_data.py

# Train on synthetic
python tools/layer15/train_layer15_crisis.py \
    --train data/crisis_detection_synthetic_v1.jsonl \
    --dev data/crisis_detection_synthetic_v1.jsonl \
    --outdir models/layer15_crisis_synthetic
```

**WARNING:** Synthetic data is for PIPELINE TESTING only. DO NOT use for production or publication.

---

## Contact

**eRisk:** http://tec.citius.usc.es/ir/  
**CLPsych:** https://clpsych.org/  
**Questions:** Check dataset homepages for contact information

---

**Last Updated:** 2025-11-04  
**Credit:** GPT-5 collaboration for data source identification

