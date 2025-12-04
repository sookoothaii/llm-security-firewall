# Memory Profiling Report - LLM Security Firewall

**Date:** 2025-12-05T00:48:14.620372
**Version:** 2.4.1
**Target:** 300MB (Current: 1.3GB = 4.3x over target)

## Executive Summary

This report identifies the root cause of excessive memory usage.

## Memory Snapshots Timeline

| Label | RSS (MB) | VMS (MB) | Peak (MB) | Timestamp |
|-------|----------|----------|-----------|-----------|
| GuardAPI_before_init | 1271.5 | 3345.9 | 0.0 | 2025-12-05T00:47:57.097654 |
| GuardAPI_after_init | 1271.5 | 3285.5 | 0.0 | 2025-12-05T00:47:57.393426 |
| GuardAPI_before_request | 1271.5 | 3285.5 | 0.0 | 2025-12-05T00:47:57.542508 |
| GuardAPI_after_request | 1274.2 | 3287.1 | 7.2 | 2025-12-05T00:47:58.575986 |
| GuardAPI_before_batch | 1274.2 | 3287.1 | 7.2 | 2025-12-05T00:47:58.721668 |
| GuardAPI_after_batch | 1274.2 | 3287.1 | 7.2 | 2025-12-05T00:48:01.101606 |
| GuardAPI_final | 1284.7 | 3298.1 | 1284.7 | 2025-12-05T00:48:01.395763 |
| SemanticGroomingGuard_Embedding_before_init | 1282.7 | 3296.1 | 0.0 | 2025-12-05T00:48:01.539979 |
| SemanticGroomingGuard_Embedding_after_init | 1287.5 | 3500.0 | 5.3 | 2025-12-05T00:48:05.638245 |
| SemanticGroomingGuard_Embedding_before_request | 1287.5 | 3500.0 | 5.3 | 2025-12-05T00:48:05.794357 |
| SemanticGroomingGuard_Embedding_after_request | 1287.5 | 3500.0 | 5.3 | 2025-12-05T00:48:06.103775 |
| SemanticGroomingGuard_Embedding_before_batch | 1287.5 | 3500.0 | 5.3 | 2025-12-05T00:48:06.252943 |
| SemanticGroomingGuard_Embedding_after_batch | 1287.5 | 3500.0 | 5.3 | 2025-12-05T00:48:06.996324 |
| SemanticGroomingGuard_Embedding_final | 1287.5 | 3500.0 | 1287.5 | 2025-12-05T00:48:07.156112 |
| TruthPreservationValidator_BART_NLI_before_init | 1287.5 | 3500.0 | 0.0 | 2025-12-05T00:48:07.307218 |
| TruthPreservationValidator_BART_NLI_after_init | 1317.4 | 5164.0 | 16.4 | 2025-12-05T00:48:13.327745 |
| TruthPreservationValidator_BART_NLI_before_request | 1317.4 | 5164.0 | 16.4 | 2025-12-05T00:48:13.482471 |
| TruthPreservationValidator_BART_NLI_after_request | 1317.4 | 5164.0 | 16.4 | 2025-12-05T00:48:13.792813 |
| TruthPreservationValidator_BART_NLI_before_batch | 1317.4 | 5164.0 | 16.4 | 2025-12-05T00:48:13.952139 |
| TruthPreservationValidator_BART_NLI_after_batch | 1317.4 | 5164.0 | 16.4 | 2025-12-05T00:48:14.261650 |
| TruthPreservationValidator_BART_NLI_final | 1316.4 | 5163.0 | 1316.4 | 2025-12-05T00:48:14.458968 |
| final_after_all_tests | 1304.1 | 3595.6 | 1304.1 | 2025-12-05T00:48:14.620372 |

## Component Memory Profiles

### GuardAPI

- **Initialization:** 0.0 MB
- **Single Request:** 2.75 MB
- **Batch (100 requests):** 0.00 MB (0.000 MB/request)
- **Peak Memory:** 13.3 MB

**Top 10 Memory Allocations (tracemalloc):**

| File | Line | Size (MB) | Count |
|------|------|-----------|-------|
| <frozen importlib._bootstrap_external> | 753 | 3.40 | 28630 |
| <frozen abc> | 106 | 0.36 | 1451 |
| C:\Users\sooko\AppData\Local\Programs\Python\Python312\Lib\typing.py | 2901 | 0.22 | 944 |
| C:\Users\sooko\AppData\Local\Programs\Python\Python312\Lib\typing.py | 904 | 0.21 | 2321 |
| C:\Users\sooko\AppData\Local\Programs\Python\Python312\Lib\dataclasses.py | 473 | 0.18 | 1998 |
| C:\Users\sooko\AppData\Local\Programs\Python\Python312\Lib\dataclasses.py | 1233 | 0.10 | 377 |
| C:\Users\sooko\AppData\Local\Programs\Python\Python312\Lib\re\_compiler.py | 761 | 0.08 | 96 |
| C:\Users\sooko\AppData\Local\Programs\Python\Python312\Lib\typing.py | 171 | 0.07 | 696 |
| <frozen abc> | 107 | 0.06 | 348 |
| <string> | 2 | 0.05 | 429 |

### SemanticGroomingGuard_Embedding

- **Initialization:** 4.7 MB
- **Single Request:** 0.00 MB
- **Batch (100 requests):** 0.00 MB (0.000 MB/request)
- **Peak Memory:** 4.7 MB

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

- **Initialization:** 29.9 MB
- **Single Request:** 0.00 MB
- **Batch (100 requests):** 0.00 MB (0.000 MB/request)
- **Peak Memory:** 29.0 MB

**Top 10 Memory Allocations (tracemalloc):**

| File | Line | Size (MB) | Count |
|------|------|-----------|-------|
| <frozen importlib._bootstrap_external> | 753 | 0.59 | 4196 |
| <frozen importlib._bootstrap> | 488 | 0.14 | 1804 |
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
| TruthPreservationValidator_BART_NLI | 29.0 | 185.0 | -156.0 | P2 | Code Review + Optimization |
| GuardAPI | 13.3 | 84.7 | -71.5 | P2 | Code Review + Optimization |
| SemanticGroomingGuard_Embedding | 4.7 | 30.3 | -25.5 | P2 | ONNX Export + Quantization |

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
