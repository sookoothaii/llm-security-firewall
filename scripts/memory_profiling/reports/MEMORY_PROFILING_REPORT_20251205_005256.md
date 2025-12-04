# Memory Profiling Report - LLM Security Firewall

**Date:** 2025-12-05T00:52:56.839878
**Version:** 2.4.1
**Target:** 300MB (Current: 1.3GB = 4.3x over target)

## Executive Summary

This report identifies the root cause of excessive memory usage.

## Memory Snapshots Timeline

| Label | RSS (MB) | VMS (MB) | Peak (MB) | Timestamp |
|-------|----------|----------|-----------|-----------|
| GuardAPI_before_init | 1284.9 | 3302.3 | 0.0 | 2025-12-05T00:52:39.819476 |
| GuardAPI_after_init | 1284.9 | 3302.3 | 0.0 | 2025-12-05T00:52:40.113633 |
| GuardAPI_before_request | 1284.9 | 3302.3 | 0.0 | 2025-12-05T00:52:40.261764 |
| GuardAPI_after_request | 1288.9 | 3304.0 | 7.2 | 2025-12-05T00:52:41.280032 |
| GuardAPI_before_batch | 1288.9 | 3304.0 | 7.2 | 2025-12-05T00:52:41.428454 |
| GuardAPI_after_batch | 1288.9 | 3304.0 | 7.2 | 2025-12-05T00:52:43.897986 |
| GuardAPI_final | 1294.5 | 3308.9 | 1294.5 | 2025-12-05T00:52:44.211756 |
| SemanticGroomingGuard_Embedding_before_init | 1293.5 | 3307.9 | 0.0 | 2025-12-05T00:52:44.359644 |
| SemanticGroomingGuard_Embedding_after_init | 1300.4 | 3513.5 | 5.3 | 2025-12-05T00:52:48.335410 |
| SemanticGroomingGuard_Embedding_before_request | 1300.4 | 3513.5 | 5.3 | 2025-12-05T00:52:48.485119 |
| SemanticGroomingGuard_Embedding_after_request | 1300.5 | 3513.5 | 5.3 | 2025-12-05T00:52:48.811815 |
| SemanticGroomingGuard_Embedding_before_batch | 1300.5 | 3513.5 | 5.3 | 2025-12-05T00:52:48.962394 |
| SemanticGroomingGuard_Embedding_after_batch | 1300.5 | 3513.5 | 5.3 | 2025-12-05T00:52:49.754806 |
| SemanticGroomingGuard_Embedding_final | 1300.5 | 3513.5 | 1300.5 | 2025-12-05T00:52:49.920613 |
| TruthPreservationValidator_BART_NLI_before_init | 1300.5 | 3513.5 | 0.0 | 2025-12-05T00:52:50.075718 |
| TruthPreservationValidator_BART_NLI_after_init | 1324.5 | 5170.1 | 16.3 | 2025-12-05T00:52:55.565492 |
| TruthPreservationValidator_BART_NLI_before_request | 1324.5 | 5170.1 | 16.3 | 2025-12-05T00:52:55.714282 |
| TruthPreservationValidator_BART_NLI_after_request | 1324.5 | 5170.1 | 16.3 | 2025-12-05T00:52:56.032080 |
| TruthPreservationValidator_BART_NLI_before_batch | 1324.5 | 5170.1 | 16.3 | 2025-12-05T00:52:56.182261 |
| TruthPreservationValidator_BART_NLI_after_batch | 1324.5 | 5170.1 | 16.3 | 2025-12-05T00:52:56.480620 |
| TruthPreservationValidator_BART_NLI_final | 1323.7 | 5169.1 | 1323.7 | 2025-12-05T00:52:56.665429 |
| final_after_all_tests | 1312.4 | 3602.8 | 1312.4 | 2025-12-05T00:52:56.839878 |

## Component Memory Profiles

### GuardAPI

- **Initialization:** 0.0 MB
- **Single Request:** 4.01 MB
- **Batch (100 requests):** 0.00 MB (0.000 MB/request)
- **Peak Memory:** 9.6 MB

**Top 10 Memory Allocations (tracemalloc):**

| File | Line | Size (MB) | Count |
|------|------|-----------|-------|
| <frozen importlib._bootstrap_external> | 753 | 3.40 | 28627 |
| <frozen abc> | 106 | 0.36 | 1452 |
| C:\Users\sooko\AppData\Local\Programs\Python\Python312\Lib\typing.py | 2901 | 0.22 | 944 |
| C:\Users\sooko\AppData\Local\Programs\Python\Python312\Lib\typing.py | 904 | 0.21 | 2322 |
| C:\Users\sooko\AppData\Local\Programs\Python\Python312\Lib\dataclasses.py | 473 | 0.18 | 1998 |
| C:\Users\sooko\AppData\Local\Programs\Python\Python312\Lib\dataclasses.py | 1233 | 0.10 | 376 |
| C:\Users\sooko\AppData\Local\Programs\Python\Python312\Lib\re\_compiler.py | 761 | 0.08 | 96 |
| C:\Users\sooko\AppData\Local\Programs\Python\Python312\Lib\typing.py | 171 | 0.07 | 696 |
| <frozen abc> | 107 | 0.06 | 348 |
| <string> | 2 | 0.05 | 430 |

### SemanticGroomingGuard_Embedding

- **Initialization:** 6.9 MB
- **Single Request:** 0.03 MB
- **Batch (100 requests):** 0.00 MB (0.000 MB/request)
- **Peak Memory:** 7.0 MB

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

- **Initialization:** 24.1 MB
- **Single Request:** 0.00 MB
- **Batch (100 requests):** 0.00 MB (0.000 MB/request)
- **Peak Memory:** 23.2 MB

**Top 10 Memory Allocations (tracemalloc):**

| File | Line | Size (MB) | Count |
|------|------|-----------|-------|
| <frozen importlib._bootstrap_external> | 753 | 0.59 | 4196 |
| <frozen importlib._bootstrap> | 488 | 0.14 | 1803 |
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\torch\nn\modules\module.py | 499 | 0.10 | 477 |
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\transformers\utils\doc.py | 47 | 0.08 | 7 |
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\regex\_regex_core.py | 4500 | 0.06 | 101 |
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\torch\nn\modules\module.py | 511 | 0.06 | 477 |
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\torch\nn\modules\module.py | 510 | 0.06 | 477 |
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\torch\nn\modules\module.py | 509 | 0.06 | 477 |
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\torch\nn\modules\module.py | 508 | 0.06 | 477 |
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\torch\nn\modules\module.py | 507 | 0.06 | 477 |

## Decision Matrix for Optimization

| Component | Current (MB) | Target (MB) | Reduction Needed | Priority | Strategy |
|-----------|--------------|-------------|------------------|----------|----------|
| TruthPreservationValidator_BART_NLI | 23.2 | 175.0 | -151.8 | P2 | Code Review + Optimization |
| GuardAPI | 9.6 | 72.5 | -62.9 | P2 | Code Review + Optimization |
| SemanticGroomingGuard_Embedding | 7.0 | 52.5 | -45.5 | P2 | ONNX Export + Quantization |

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
