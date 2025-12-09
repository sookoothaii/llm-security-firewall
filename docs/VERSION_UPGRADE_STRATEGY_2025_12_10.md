# Version Upgrade Strategy
## LLM Security Firewall - Production Readiness

**Date:** 2025-12-10  
**Current Version:** 2.5.0  
**Status:** Analysis Complete, Strategy Defined

---

## Executive Summary

This document outlines a comprehensive strategy for version upgrades across the LLM Security Firewall project. The analysis identified several inconsistencies and opportunities for modernization.

### Key Findings

1. **Python Version Inconsistency**: `pyproject.toml` requires `>=3.12`, but `.github/workflows/security-eval.yml` uses Python 3.11
2. **Service Version Mismatch**: Multiple services still use `version="1.0.0"` while project is at `2.5.0`
3. **Dependency Versions**: Many dependencies are pinned to minimum versions, missing security updates and performance improvements
4. **CI/CD Alignment**: Workflow Python version doesn't match project requirements

---

## Current State Analysis

### 1. Project Version
- **Current:** 2.5.0 (2025-12-05)
- **Status:** Production Release
- **Location:** `pyproject.toml`, `README.md`, `CHANGELOG.md`

### 2. Python Version Requirements

| Location | Requirement | Status |
|----------|-------------|--------|
| `pyproject.toml` | `>=3.12` | ✅ Correct |
| `.github/workflows/security-eval.yml` | `3.11` | ❌ **Mismatch** |
| `.github/workflows/ci.yml` | `3.12`, `3.13` | ✅ Correct |
| `README.md` | `>=3.12` | ✅ Correct |

**Issue:** Security evaluation workflow uses Python 3.11, which doesn't meet project requirements.

### 3. Service Versions

| Service | Current Version | Project Version | Status |
|---------|----------------|-----------------|--------|
| `code_intent_service` | 1.0.0 | 2.5.0 | ❌ Outdated |
| `learning_monitor_service` | 1.0.0 | 2.5.0 | ❌ Outdated |
| `content_safety_service` | 1.0.0 | 2.5.0 | ❌ Outdated |
| `persuasion_service` | 1.0.0 | 2.5.0 | ❌ Outdated |
| `layer15` | 1.0.0 | 2.5.0 | ❌ Outdated |
| Plugins (care, biometrics, personality) | 1.0.0 | 2.5.0 | ❌ Outdated |

**Impact:** Version mismatch can cause confusion in monitoring, logging, and API responses.

### 4. Dependency Versions

| Package | Current Min | Latest Stable | Status |
|---------|-------------|---------------|--------|
| `numpy` | >=1.24.0 | 2.1.x | ⚠️ Can upgrade |
| `scipy` | >=1.11.0 | 1.14.x | ⚠️ Can upgrade |
| `pydantic` | >=2.0.0 | 2.10.x | ⚠️ Can upgrade |
| `requests` | >=2.31.0 | 2.32.x | ⚠️ Can upgrade |
| `cryptography` | >=41.0.0 | 43.x | ⚠️ Can upgrade |
| `onnx` | >=1.14.0 | 1.17.x | ⚠️ Can upgrade |
| `onnxruntime` | >=1.16.0 | 1.19.x | ⚠️ Can upgrade |
| `pyyaml` | >=6.0 | 6.0.2 | ✅ Current |
| `blake3` | >=0.3.0 | 0.3.2 | ⚠️ Can upgrade |

**Note:** All dependencies are pinned to minimum versions. Upgrading to latest stable versions would provide:
- Security patches
- Performance improvements
- Bug fixes
- New features (if compatible)

---

## Recommended Strategy

### Phase 1: Critical Fixes (Immediate)

**Priority:** High  
**Risk:** Low  
**Effort:** 1-2 hours

1. **Fix Python Version in CI/CD**
   - Update `.github/workflows/security-eval.yml` from `3.11` to `3.12`
   - Ensure consistency across all workflows

2. **Synchronize Service Versions**
   - Update all service `version` fields from `1.0.0` to `2.5.0`
   - Maintain API compatibility (no breaking changes)

**Files to Update:**
- `.github/workflows/security-eval.yml` (line 25)
- `detectors/code_intent_service/main.py` (line 63)
- `detectors/learning_monitor_service/main.py` (line 33)
- `detectors/content_safety_service/main.py` (line 33)
- `detectors/persuasion_service/main.py` (line 57)
- `src/layer15/__init__.py` (line 14)
- `plugins/care/__init__.py` (line 25)
- `plugins/biometrics/__init__.py` (line 33)
- `plugins/personality/__init__.py` (line 25)

### Phase 2: Dependency Updates (Short-term)

**Priority:** Medium  
**Risk:** Medium  
**Effort:** 4-6 hours

1. **Update Core Dependencies**
   - Test each dependency upgrade individually
   - Run full test suite after each update
   - Document any breaking changes

2. **Recommended Update Sequence:**
   ```
   1. Security-critical: cryptography (43.x)
   2. Core libraries: numpy (2.1.x), scipy (1.14.x)
   3. Validation: pydantic (2.10.x)
   4. ML/AI: onnx (1.17.x), onnxruntime (1.19.x)
   5. Utilities: requests (2.32.x), blake3 (0.3.2)
   ```

3. **Testing Strategy:**
   - Unit tests for each component
   - Integration tests for service interactions
   - Adversarial test suite (100% detection rate must be maintained)
   - Performance benchmarks (memory, latency)

### Phase 3: Python Version Consideration (Long-term)

**Priority:** Low  
**Risk:** Medium  
**Effort:** 8-12 hours

**Option A: Stay on Python 3.12 (Recommended)**
- **Pros:**
  - Stable and well-tested
  - Excellent library support
  - Production-ready
- **Cons:**
  - Missing latest Python features
- **Recommendation:** ✅ **Stay on 3.12** for production stability

**Option B: Upgrade to Python 3.13**
- **Pros:**
  - Latest features and performance improvements
  - Future-proof
- **Cons:**
  - Newer release (October 2024), less battle-tested
  - Potential compatibility issues with some dependencies
  - Requires comprehensive testing
- **Recommendation:** ⚠️ **Consider in Q1 2026** after 3.13 matures

**Decision Matrix:**

| Factor | Python 3.12 | Python 3.13 |
|--------|-------------|-------------|
| Stability | ✅ High | ⚠️ Medium |
| Library Support | ✅ Excellent | ✅ Good |
| Performance | ✅ Good | ✅ Better |
| Production Ready | ✅ Yes | ⚠️ New |
| Risk | ✅ Low | ⚠️ Medium |

**Recommendation:** **Stay on Python 3.12** for now. Re-evaluate in Q1 2026.

### Phase 4: Version Numbering Strategy

**Current:** 2.5.0  
**Next Release:** 2.5.1 (patch) or 2.6.0 (minor)

**Semantic Versioning:**
- **Major (3.0.0):** Breaking API changes
- **Minor (2.6.0):** New features, backwards compatible
- **Patch (2.5.1):** Bug fixes, dependency updates

**Recommendation for Current Changes:**
- Phase 1 fixes → **2.5.1** (patch release)
- Phase 2 updates → **2.5.2** or **2.6.0** (depending on scope)

---

## Implementation Plan

### Step 1: Immediate Fixes (Today)

```bash
# 1. Fix CI/CD Python version
# Edit .github/workflows/security-eval.yml:25
python-version: '3.12'  # Change from 3.11

# 2. Update service versions
# Use find/replace: version="1.0.0" → version="2.5.0"
# In all service main.py files
```

### Step 2: Dependency Testing (This Week)

```bash
# Create test branch
git checkout -b upgrade/dependencies

# Test each dependency individually
pip install numpy==2.1.0
pytest tests/ -v
# If passes, commit
git commit -m "chore: upgrade numpy to 2.1.0"

# Repeat for each dependency
```

### Step 3: Full Integration Test

```bash
# Run complete test suite
pytest tests/ -v --cov

# Run adversarial tests
python scripts/run_eval_suite.py eval_suites/jailbreak_poetry.yaml
python scripts/run_eval_suite.py eval_suites/command_injection.yaml

# Verify 100% detection rate maintained
python scripts/analyze_eval_results.py eval_results \
  --min-detection-rate 95.0 \
  --max-false-positive-rate 5.0 \
  --max-bypasses 0
```

---

## Risk Assessment

### Low Risk
- ✅ Python version fix in CI/CD
- ✅ Service version synchronization
- ✅ Minor dependency updates (patch versions)

### Medium Risk
- ⚠️ Major dependency updates (numpy 2.x, scipy 1.14.x)
- ⚠️ Testing required for each update
- ⚠️ Potential breaking changes in dependencies

### High Risk
- ❌ Python 3.13 upgrade (not recommended now)
- ❌ Simultaneous update of all dependencies

---

## Success Criteria

1. **Phase 1 (Critical Fixes):**
   - ✅ All CI/CD workflows use Python 3.12
   - ✅ All services report version 2.5.0
   - ✅ No breaking changes

2. **Phase 2 (Dependencies):**
   - ✅ All dependencies updated to latest stable
   - ✅ 100% test suite pass rate maintained
   - ✅ 100% detection rate in adversarial tests maintained
   - ✅ No performance regressions

3. **Phase 3 (Python Version):**
   - ✅ Comprehensive testing completed
   - ✅ All dependencies compatible
   - ✅ Performance benchmarks met or exceeded

---

## Timeline

| Phase | Duration | Start Date | End Date |
|-------|----------|------------|----------|
| Phase 1: Critical Fixes | 1-2 hours | 2025-12-10 | 2025-12-10 |
| Phase 2: Dependencies | 1 week | 2025-12-11 | 2025-12-17 |
| Phase 3: Python 3.13 | TBD | Q1 2026 | TBD |

---

## Recommendations Summary

1. **Immediate (Today):**
   - ✅ Fix Python version in `security-eval.yml`
   - ✅ Synchronize service versions to 2.5.0

2. **Short-term (This Week):**
   - ⚠️ Update dependencies incrementally
   - ⚠️ Test thoroughly after each update

3. **Long-term (Q1 2026):**
   - ⚠️ Consider Python 3.13 after it matures
   - ⚠️ Re-evaluate dependency versions quarterly

4. **Version Strategy:**
   - ✅ Use semantic versioning
   - ✅ Release 2.5.1 for Phase 1 fixes
   - ✅ Release 2.5.2 or 2.6.0 for Phase 2 updates

---

## Conclusion

The project is in good shape overall. The main issues are:
1. **Inconsistency** in Python version requirements (easily fixed)
2. **Outdated service versions** (cosmetic, but should be fixed)
3. **Dependency versions** (can be updated incrementally)

**Recommended Approach:**
- Fix critical issues immediately (Phase 1)
- Update dependencies carefully and incrementally (Phase 2)
- Stay on Python 3.12 for production stability (Phase 3)

This strategy balances **stability** (production-ready) with **modernization** (security updates, performance improvements).

---

**Document Status:** Ready for Implementation  
**Next Steps:** Execute Phase 1 fixes  
**Owner:** HAK_GAL Security Team

