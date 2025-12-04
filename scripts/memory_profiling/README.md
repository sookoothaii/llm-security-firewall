# Memory Profiling Suite

**Priority:** P0 (Production Stability)
**Target:** Reduce memory usage from 1.3GB to 300MB (4.3x reduction)

## Overview

This suite provides comprehensive memory profiling to identify the root cause of excessive memory usage in the LLM Security Firewall.

## Usage

### Prerequisites

```bash
pip install memory-profiler psutil
```

### Run Profiling

```bash
cd "D:\MCP Mods\HAK_GAL_HEXAGONAL\standalone_packages\llm-security-firewall"
.\.venv_hexa\Scripts\Activate.ps1
python scripts/memory_profiling/memory_profiling_suite.py
```

### Output

The script generates:
- **Memory snapshots** at each stage
- **Component profiles** (initialization, single request, batch)
- **Top allocations** from tracemalloc
- **Decision matrix** with optimization strategies
- **Report** in `scripts/memory_profiling/reports/MEMORY_PROFILING_REPORT_YYYYMMDD_HHMMSS.md`

## Components Profiled

1. **KidsPolicyEngine** (`HakGalFirewall_v2`)
   - Initialization memory
   - Single request memory
   - Batch processing memory
   - Peak memory usage

2. **Guard API** (public interface)
   - Memory overhead of public API
   - Request processing memory

## Expected Findings

Based on architecture analysis:
- **Embedding Detector:** ~800MB (PyTorch models)
- **Perplexity Detector:** ~200MB (GPT-2 model)
- **Kids Policy Engine:** ~200MB (session state, caches)
- **Other components:** ~100MB

## Optimization Strategies

### P0 (Immediate)
- **ONNX Export:** Reduce PyTorch dependency (60-70% reduction)
- **Lazy Loading:** Load models only when needed (20-30% reduction)

### P1 (Short-term)
- **Model Quantization:** FP32 → FP16 (50% model size reduction)
- **LRU Cache:** Limit embedding cache size (30-50MB reduction)

### P2 (Long-term)
- **Model Distillation:** Train smaller models (70-80% reduction)

## Report Structure

The generated report includes:
1. **Executive Summary:** High-level findings
2. **Memory Snapshots Timeline:** Memory at each stage
3. **Component Memory Profiles:** Detailed breakdown per component
4. **Decision Matrix:** Prioritized optimization strategies
5. **Recommendations:** Actionable next steps

## Next Steps

After profiling:
1. Review the generated report
2. Prioritize optimizations based on component profiles
3. Start with P0 items (highest impact)
4. Measure improvements after each optimization
