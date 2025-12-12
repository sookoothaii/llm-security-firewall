# Production A/B Test Suite

**Purpose:** Validate real-world impact and user interaction from live production traffic.

## Characteristics

- Real user prompts and behaviors
- Collected from live traffic during canary releases
- Includes both blocked and allowed requests
- Tracks user feedback and corrections

## Data Collection

### Automated Collection

Use the production log collector:

```bash
python test_suites/production_ab/collectors/production_log_collector.py \
    --start-date 2025-12-01 \
    --end-date 2025-12-12 \
    --output data/production_ab_set.jsonl
```

### Manual Collection

Export from production logs:
1. Query production database/logs for canary period
2. Filter by model version (e.g., V2.1 Hotfix)
3. Include shadow mode decisions
4. Anonymize sensitive data
5. Export as JSONL

## File Structure

```
production_ab/
├── data/
│   ├── production_ab_set.jsonl    # Main A/B test data
│   ├── user_feedback.jsonl        # User corrections
│   └── metadata.json              # Collection metadata
├── collectors/
│   └── production_log_collector.py
└── README.md
```

## Data Format

```json
{
  "text": "Can you help me write a function?",
  "expected_blocked": false,
  "category": "production",
  "metadata": {
    "timestamp": "2025-12-12T10:30:00Z",
    "model_version": "v2.1_hotfix",
    "user_risk_tier": 1,
    "source_tool": "code_interpreter",
    "old_model_decision": "block",
    "new_model_decision": "allow",
    "user_feedback": null,
    "shadow_mode": true
  }
}
```

## User Feedback Format

```json
{
  "text": "original input text",
  "original_decision": "block",
  "user_corrected_decision": "allow",
  "feedback_timestamp": "2025-12-12T11:00:00Z",
  "feedback_type": "false_positive",
  "user_explanation": "This was a legitimate request"
}
```

## Size Recommendation

- Minimum: 200 samples per deployment
- Target: 500-1000 samples
- Continuously growing

## Usage

```bash
python test_suites/runners/multi_component_runner.py --components production_ab
```

## Analysis

The A/B test suite helps identify:
- False positives (blocked legitimate requests)
- False negatives (allowed malicious requests)
- User behavior changes
- Model performance degradation
- Edge cases in production

## Privacy & Security

- **Anonymization:** Remove PII before storing
- **Retention:** Follow data retention policies
- **Access Control:** Limit access to authorized personnel
- **Encryption:** Encrypt at rest and in transit

