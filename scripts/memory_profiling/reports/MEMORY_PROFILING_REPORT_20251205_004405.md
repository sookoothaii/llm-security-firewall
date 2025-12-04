# Memory Profiling Report - LLM Security Firewall

**Date:** 2025-12-05T00:44:05.773613
**Version:** 2.4.1
**Target:** 300MB (Current: 1.3GB = 4.3x over target)

## Executive Summary

This report identifies the root cause of excessive memory usage.

## Memory Snapshots Timeline

| Label | RSS (MB) | VMS (MB) | Peak (MB) | Timestamp |
|-------|----------|----------|-----------|-----------|
| GuardAPI_before_init | 1291.1 | 3499.4 | 0.0 | 2025-12-05T00:43:43.729973 |
| GuardAPI_after_init | 1291.1 | 3499.4 | 0.0 | 2025-12-05T00:43:44.019962 |
| GuardAPI_before_request | 1291.1 | 3499.4 | 0.0 | 2025-12-05T00:43:44.173432 |
| GuardAPI_after_request | 1322.3 | 5085.0 | 22.0 | 2025-12-05T00:43:50.168338 |
| GuardAPI_before_batch | 1322.3 | 5085.0 | 22.0 | 2025-12-05T00:43:50.315176 |
| GuardAPI_after_batch | 1322.3 | 5085.1 | 22.0 | 2025-12-05T00:43:53.029703 |
| GuardAPI_final | 1322.2 | 5085.1 | 1322.2 | 2025-12-05T00:43:53.376485 |
| SemanticGroomingGuard_Embedding_before_init | 1321.2 | 5084.1 | 0.0 | 2025-12-05T00:43:53.530334 |
| SemanticGroomingGuard_Embedding_after_init | 1325.4 | 5080.3 | 5.3 | 2025-12-05T00:43:57.522254 |
| SemanticGroomingGuard_Embedding_before_request | 1325.4 | 5080.3 | 5.3 | 2025-12-05T00:43:57.672759 |
| SemanticGroomingGuard_Embedding_after_request | 1325.4 | 5080.3 | 5.3 | 2025-12-05T00:43:57.989294 |
| SemanticGroomingGuard_Embedding_before_batch | 1325.4 | 5080.3 | 5.3 | 2025-12-05T00:43:58.136281 |
| SemanticGroomingGuard_Embedding_after_batch | 1325.5 | 5080.4 | 5.3 | 2025-12-05T00:43:58.865740 |
| SemanticGroomingGuard_Embedding_final | 1325.5 | 5080.4 | 1325.5 | 2025-12-05T00:43:59.022106 |
| TruthPreservationValidator_BART_NLI_before_init | 1325.5 | 5080.4 | 0.0 | 2025-12-05T00:43:59.179215 |
| TruthPreservationValidator_BART_NLI_after_init | 1338.9 | 6845.6 | 15.0 | 2025-12-05T00:44:04.511635 |
| TruthPreservationValidator_BART_NLI_before_request | 1338.9 | 6845.6 | 15.0 | 2025-12-05T00:44:04.664834 |
| TruthPreservationValidator_BART_NLI_after_request | 1338.9 | 6845.6 | 15.0 | 2025-12-05T00:44:04.982964 |
| TruthPreservationValidator_BART_NLI_before_batch | 1338.9 | 6845.6 | 15.0 | 2025-12-05T00:44:05.133283 |
| TruthPreservationValidator_BART_NLI_after_batch | 1338.9 | 6845.6 | 15.0 | 2025-12-05T00:44:05.440267 |
| TruthPreservationValidator_BART_NLI_final | 1338.9 | 6845.6 | 1338.9 | 2025-12-05T00:44:05.616493 |
| final_after_all_tests | 1327.6 | 5279.2 | 1327.6 | 2025-12-05T00:44:05.772611 |

## Component Memory Profiles

### GuardAPI

- **Initialization:** 0.0 MB
- **Single Request:** 31.27 MB
- **Batch (100 requests):** 0.00 MB (0.000 MB/request)
- **Peak Memory:** 31.2 MB

**Top 10 Memory Allocations (tracemalloc):**

| File | Line | Size (MB) | Count |
|------|------|-----------|-------|
| <frozen importlib._bootstrap_external> | 753 | 3.40 | 28624 |
| <frozen abc> | 106 | 0.36 | 1452 |
| C:\Users\sooko\AppData\Local\Programs\Python\Python312\Lib\typing.py | 2901 | 0.22 | 944 |
| C:\Users\sooko\AppData\Local\Programs\Python\Python312\Lib\typing.py | 904 | 0.21 | 2323 |
| C:\Users\sooko\AppData\Local\Programs\Python\Python312\Lib\dataclasses.py | 473 | 0.18 | 1996 |
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\torch\nn\modules\module.py | 499 | 0.10 | 477 |
| C:\Users\sooko\AppData\Local\Programs\Python\Python312\Lib\dataclasses.py | 1233 | 0.10 | 376 |
| C:\Users\sooko\AppData\Local\Programs\Python\Python312\Lib\re\_compiler.py | 761 | 0.08 | 96 |
| C:\Users\sooko\AppData\Local\Programs\Python\Python312\Lib\typing.py | 171 | 0.07 | 696 |
| <frozen abc> | 107 | 0.06 | 348 |

### SemanticGroomingGuard_Embedding

- **Initialization:** 4.2 MB
- **Single Request:** 0.00 MB
- **Batch (100 requests):** 0.00 MB (0.000 MB/request)
- **Peak Memory:** 4.2 MB

**Top 10 Memory Allocations (tracemalloc):**

| File | Line | Size (MB) | Count |
|------|------|-----------|-------|
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\sentence_transformers\SentenceTransformer.py | 1152 | 0.06 | 9 |
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\torch\nn\modules\module.py | 499 | 0.03 | 124 |
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\torch\nn\modules\module.py | 511 | 0.02 | 124 |
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\torch\nn\modules\module.py | 510 | 0.02 | 124 |
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\torch\nn\modules\module.py | 509 | 0.02 | 124 |
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\torch\nn\modules\module.py | 508 | 0.02 | 124 |
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\torch\nn\modules\module.py | 507 | 0.02 | 124 |
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\torch\nn\modules\module.py | 506 | 0.02 | 124 |
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\torch\nn\modules\module.py | 505 | 0.02 | 124 |
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\torch\nn\modules\module.py | 504 | 0.02 | 124 |

### TruthPreservationValidator_BART_NLI

- **Initialization:** 13.4 MB
- **Single Request:** 0.00 MB
- **Batch (100 requests):** 0.00 MB (0.000 MB/request)
- **Peak Memory:** 13.4 MB

**Top 10 Memory Allocations (tracemalloc):**

| File | Line | Size (MB) | Count |
|------|------|-----------|-------|
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\torch\nn\modules\module.py | 499 | 0.10 | 477 |
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\torch\nn\modules\module.py | 511 | 0.06 | 477 |
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\torch\nn\modules\module.py | 510 | 0.06 | 477 |
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\torch\nn\modules\module.py | 509 | 0.06 | 477 |
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\torch\nn\modules\module.py | 508 | 0.06 | 477 |
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\torch\nn\modules\module.py | 507 | 0.06 | 477 |
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\torch\nn\modules\module.py | 506 | 0.06 | 477 |
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\torch\nn\modules\module.py | 505 | 0.06 | 477 |
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\torch\nn\modules\module.py | 504 | 0.06 | 477 |
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\torch\nn\modules\module.py | 503 | 0.06 | 477 |

## Decision Matrix for Optimization

| Component | Current (MB) | Target (MB) | Reduction Needed | Priority | Strategy |
|-----------|--------------|-------------|------------------|----------|----------|
| GuardAPI | 31.2 | 191.6 | -160.4 | P2 | Code Review + Optimization |
| TruthPreservationValidator_BART_NLI | 13.4 | 82.6 | -69.2 | P2 | Code Review + Optimization |
| SemanticGroomingGuard_Embedding | 4.2 | 25.8 | -21.6 | P2 | ONNX Export + Quantization |

## Recommendations

### Immediate Actions (P0)

1. **ONNX Export for Embedding Detector**
   - Current: PyTorch models loaded in memory
   - Expected reduction: 60-70% (from ~800MB to ~200MB)
   - Timeline: 1-2 weeks

2. **Lazy Loading for ML Models**
   - Load models only when needed
   - Expected reduction: 20-30% (from ~400MB to ~280MB)
   - Timeline: 1 week

### Short-term Actions (P1)

1. **Model Quantization (FP16)**
   - Reduce model precision from FP32 to FP16
   - Expected reduction: 50% of model size
   - Timeline: 2 weeks

2. **Embedding Cache with LRU Eviction**
   - Limit cache size to prevent unbounded growth
   - Expected reduction: 30-50MB
   - Timeline: 1 week

### Long-term Actions (P2)

1. **Model Distillation**
   - Train smaller models with similar accuracy
   - Expected reduction: 70-80% of model size
   - Timeline: 4-6 weeks
