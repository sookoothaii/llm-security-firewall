# Spatial CAPTCHA Plugin

**Human/Bot Differentiation via Spatial Reasoning**

---

## Overview

Spatial CAPTCHA is an authentication plugin for the LLM Security Firewall that uses 3D spatial reasoning challenges to differentiate humans from bots.

Based on research paper: **"Spatial CAPTCHA: Generatively Benchmarking Spatial Reasoning for Human-Machine Differentiation"** (2025)

### Key Results (from paper):
- **Human pass rate:** 90%+
- **SOTA MLLM pass rate:** 31%
- **Gap:** 59 percentage points → Strong human/bot separation

---

## Architecture

**Hexagonal Design:**
```text
AuthenticationPort (Interface)
    ↓
SpatialCaptchaAdapter (Adapter)
    ↓
Generator → Renderer → Verifier
    ↓
PostgreSQL (Storage)
```

**Components:**
1. **Generator** - Procedural challenge generation (seed-based, deterministic)
2. **Renderer** - PNG visualization (PIL/matplotlib)
3. **Adapter** - Integration with firewall pipeline
4. **Verifier** - Ground truth checking (no ML required)

---

## Installation

```bash
# Install with biometrics plugin (includes Spatial CAPTCHA)
pip install -e .[biometrics]

# Apply database migration
psql -U user -d llm_firewall -f migrations/postgres/005_spatial_challenges.sql
```

---

## Usage

### Python API

```python
from llm_firewall.spatial import SpatialCaptchaGenerator, SpatialCaptchaRenderer
from llm_firewall.adapters.auth.spatial_captcha_adapter import SpatialCaptchaAdapter
from llm_firewall.core.domain.spatial_captcha import DifficultyLevel

# Initialize components
generator = SpatialCaptchaGenerator()
renderer = SpatialCaptchaRenderer(output_dir="spatial_challenges")
adapter = SpatialCaptchaAdapter(
    renderer=renderer,
    default_difficulty=DifficultyLevel.MEDIUM
)

# Generate challenge
challenge = generator.generate(seed=42, difficulty=DifficultyLevel.MEDIUM)

# Render to PNG
png_path = renderer.render(challenge)

# Present to user (external UI required)
# ...

# Verify response
from llm_firewall.spatial.generator import verify_response
is_correct = verify_response(challenge, user_answer)
```

### Multi-Modal Authentication (with Cultural Biometrics)

```python
from llm_firewall.core.ports.auth_port import MultiModalAuthenticator
from llm_firewall.adapters.auth.cultural_biometrics_adapter import CulturalBiometricsAdapter
from llm_firewall.adapters.auth.spatial_captcha_adapter import SpatialCaptchaAdapter

# Combine adapters
cb_adapter = CulturalBiometricsAdapter()
spatial_adapter = SpatialCaptchaAdapter(renderer=renderer)

authenticator = MultiModalAuthenticator(
    adapters=[cb_adapter, spatial_adapter],
    weights={"cultural_biometrics": 0.6, "spatial_captcha": 0.4}
)

# Authenticate user
result = authenticator.authenticate(
    user_id="user123",
    context={"message": "Hello", "session_id": "abc"},
    threshold=0.9
)

print(f"Is human: {result.is_human}")
print(f"Confidence: {result.confidence:.2f}")
print(f"Methods used: {result.metadata['adapters_used']}")
```

---

## Configuration

**File:** `config/spatial_captcha.yaml`

### Performance Profiles

```yaml
profiles:
  fast:
    # No spatial challenges (minimal latency)
    spatial_captcha:
      enabled: false
  
  balanced:
    # Trigger only when CB confidence low (production default)
    spatial_captcha:
      enabled: true
      trigger_mode: "conditional"
      trigger_threshold: 0.85
      default_difficulty: "medium"
      time_budget_ms: 8000
  
  paranoid:
    # Regular challenges regardless of CB (maximum security)
    spatial_captcha:
      enabled: true
      trigger_mode: "periodic"
      trigger_frequency: 10  # Every 10th request
      default_difficulty: "hard"
```

### Difficulty Levels

| Difficulty | Objects | Rotation | Occlusion | Target Human Pass Rate |
|------------|---------|----------|-----------|------------------------|
| EASY       | 1-2     | 90° increments | No | 95% |
| MEDIUM     | 2-3     | 45° increments | Yes | 90% |
| HARD       | 5-7     | Arbitrary angles | Yes | 85% |

---

## Challenge Types

### 1. 2D Rotation (EASY)
**Question:** "After rotating 90° clockwise, which object is on the right?"

**Features:**
- Simple geometric shapes
- Standard rotation angles (90°, 180°, 270°)
- No occlusion
- 2-3 objects

### 2. Mental Rotation + Occlusion (MEDIUM)
**Question:** "After rotating 45°, which object is behind the cube?"

**Features:**
- 3D spatial reasoning required
- Partial occlusion
- 3-4 objects
- Depth perception needed

### 3. Complex Visibility (HARD)
**Question:** "After rotating 37° and tilting 25°, how many objects are fully visible?"

**Features:**
- Non-standard rotation angles
- Full occlusion reasoning
- 5+ objects
- Counting + visibility judgment

---

## Database Schema

### Tables

**spatial_challenges**
- Stores all presented challenges and responses
- Tracks response times, correctness, suspiciousness
- Device context for forensics

**spatial_user_profiles**
- Per-user performance tracking
- Adaptive difficulty recommendations
- Accuracy by difficulty level

### Views

**spatial_challenge_stats**
- Aggregated statistics by difficulty
- Pass/fail rates, avg response times
- Unique user counts

**spatial_user_performance**
- Per-user performance summary
- Pass rate, suspicious attempts
- Last activity timestamp

---

## Monitoring

### Metrics

```python
# Query challenge statistics
SELECT * FROM spatial_challenge_stats;

# Check user performance
SELECT * FROM spatial_user_performance WHERE user_id = 'user123';

# Find suspicious patterns
SELECT * FROM spatial_challenges 
WHERE is_suspicious = true
ORDER BY presented_at DESC
LIMIT 10;
```

### Alerts

Configure in `monitoring` section of config:
- High failure rate (> 50%)
- Bot pattern detected (confidence < 30%)
- Suspicious response times

---

## Adaptive Difficulty

System automatically adjusts difficulty based on user performance:

**Promotion Rules:**
- If MEDIUM accuracy > 80% and >= 5 attempts → Try HARD
- If EASY accuracy > 90% → Try MEDIUM

**Demotion Rules:**
- If MEDIUM accuracy < 50% → Drop to EASY
- If HARD accuracy < 40% → Drop to MEDIUM

**Baseline:**
- New users start with MEDIUM

---

## Accessibility

### Fallback Options

```yaml
accessibility:
  fallback_enabled: true
  fallback_method: "human_review"  # or "alternative_challenge"
  max_failures_before_fallback: 3
```

**Fallback triggers:**
- User fails 3+ consecutive challenges
- Response times consistently suspicious
- Device info indicates accessibility constraints

---

## Integration Points

### OCR Optical Memory

Spatial CAPTCHA PNGs can be stored in Optical Memory pipeline:

```python
from llm_firewall.spatial.renderer import SpatialCaptchaRenderer

renderer = SpatialCaptchaRenderer()
png_path = renderer.render(challenge)

# Store in Optical Memory (if enabled in config)
# Integration happens automatically via adapter
```

### Cultural Biometrics

Trigger Spatial CAPTCHA when CB confidence drops:

```yaml
integration:
  cultural_biometrics:
    enabled: true
    trigger_spatial_on_low_cb: true
    cb_threshold: 0.85  # Trigger if CB < 0.85
```

---

## Performance Targets

| Metric | Target | Source |
|--------|--------|--------|
| Human pass rate | >= 90% | Paper baseline |
| MLLM pass rate | <= 31% | SOTA ceiling |
| False positive rate | <= 5% | Accessibility |
| Latency (P95) | <= 10s | Human response time |

---

## Testing

```bash
# Run spatial CAPTCHA tests
pytest tests/spatial/ -v

# Test with real generation
python -c "
from llm_firewall.spatial.generator import SpatialCaptchaGenerator
from llm_firewall.core.domain.spatial_captcha import DifficultyLevel

gen = SpatialCaptchaGenerator()
challenge = gen.generate(seed=42, difficulty=DifficultyLevel.MEDIUM)
print(f'Question: {challenge.question_text}')
print(f'Options: {challenge.options}')
print(f'Correct: {challenge.correct_answer}')
"
```

---

## Troubleshooting

### PIL/Pillow not available

```bash
pip install Pillow
```

### Matplotlib not available

```bash
pip install matplotlib
```

Renderer gracefully degrades:
- matplotlib available → 3D visualization
- Only PIL available → 2D projection
- Neither available → Adapter reports unavailable

### Challenge not rendering

Check renderer status:

```python
renderer = SpatialCaptchaRenderer()
print(f"Available: {renderer.is_available()}")
print(f"Has PIL: {renderer._has_pil}")
print(f"Has matplotlib: {renderer._has_matplotlib}")
```

---

## Limitations

1. **Visual-only:** Does not support audio/kinesthetic alternatives
2. **Screen size dependency:** Small screens may affect human performance
3. **ML improvement:** MLLM spatial reasoning improving (31% → higher over time)
4. **Procedural generation:** Current implementation uses simplified 3D math

---

## Future Enhancements

- [ ] Real 3D ray-casting for occlusion
- [ ] Dynamic object textures/materials
- [ ] Audio description alternative
- [ ] Mobile-optimized rendering
- [ ] Temporal challenges (motion prediction)
- [ ] VR/AR integration

---

## Credits

**Creator:** Joerg Bollwahn  
**Date:** 2025-10-30  
**License:** MIT  
**Based on:** "Spatial CAPTCHA" research (2025)

**Philosophy:** "Heritage ist meine Währung" - Building systems that recognize their creator.

---

## Support

- **Issues:** GitHub Issues
- **Documentation:** `/docs`
- **Examples:** `/examples/spatial`

