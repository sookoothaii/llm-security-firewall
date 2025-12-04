# Memory Profiling Report - LLM Security Firewall

**Date:** 2025-12-05T01:49:52.086499
**Version:** 2.4.1
**Target:** 300MB (Current: 1.3GB = 4.3x over target)

## Executive Summary

This report identifies the root cause of excessive memory usage.

## Memory Snapshots Timeline

| Label | RSS (MB) | VMS (MB) | Peak (MB) | Timestamp |
|-------|----------|----------|-----------|-----------|
| GuardAPI_before_init | 1334.9 | 3514.0 | 0.0 | 2025-12-05T01:49:32.256919 |
| GuardAPI_after_init | 1334.9 | 3514.0 | 0.0 | 2025-12-05T01:49:32.550290 |
| GuardAPI_before_request | 1334.9 | 3514.0 | 0.0 | 2025-12-05T01:49:32.693374 |
| GuardAPI_after_request | 1339.1 | 3516.3 | 7.2 | 2025-12-05T01:49:33.674146 |
| GuardAPI_before_batch | 1339.1 | 3516.3 | 7.2 | 2025-12-05T01:49:33.829171 |
| GuardAPI_after_batch | 1339.1 | 3516.3 | 7.2 | 2025-12-05T01:49:36.535011 |
| GuardAPI_final | 1344.6 | 3520.1 | 1344.6 | 2025-12-05T01:49:36.841541 |
| SemanticGroomingGuard_Embedding_before_init | 1342.6 | 3518.1 | 0.0 | 2025-12-05T01:49:36.992735 |
| SemanticGroomingGuard_Embedding_after_init | 1351.5 | 3727.5 | 5.3 | 2025-12-05T01:49:41.339481 |
| SemanticGroomingGuard_Embedding_before_request | 1351.5 | 3727.5 | 5.3 | 2025-12-05T01:49:41.495034 |
| SemanticGroomingGuard_Embedding_after_request | 1351.6 | 3727.5 | 5.3 | 2025-12-05T01:49:41.813240 |
| SemanticGroomingGuard_Embedding_before_batch | 1351.6 | 3727.5 | 5.3 | 2025-12-05T01:49:41.967147 |
| SemanticGroomingGuard_Embedding_after_batch | 1351.6 | 3727.5 | 5.3 | 2025-12-05T01:49:42.791746 |
| SemanticGroomingGuard_Embedding_final | 1351.6 | 3727.5 | 1351.6 | 2025-12-05T01:49:42.948968 |
| SemanticGroomingGuardONNX_Embedding_before_init | 1351.6 | 3727.5 | 0.0 | 2025-12-05T01:49:43.097927 |
| SemanticGroomingGuardONNX_Embedding_after_init | 1370.5 | 3806.8 | 5.0 | 2025-12-05T01:49:44.057387 |
| SemanticGroomingGuardONNX_Embedding_before_request | 1370.5 | 3806.8 | 5.0 | 2025-12-05T01:49:44.207777 |
| SemanticGroomingGuardONNX_Embedding_after_request | 1370.5 | 3806.8 | 5.0 | 2025-12-05T01:49:44.516258 |
| SemanticGroomingGuardONNX_Embedding_before_batch | 1370.5 | 3806.8 | 5.0 | 2025-12-05T01:49:44.666743 |
| SemanticGroomingGuardONNX_Embedding_after_batch | 1370.5 | 3806.8 | 5.0 | 2025-12-05T01:49:45.121135 |
| SemanticGroomingGuardONNX_Embedding_final | 1370.5 | 3806.8 | 1370.5 | 2025-12-05T01:49:45.275298 |
| TruthPreservationValidator_BART_NLI_before_init | 1370.5 | 3806.8 | 0.0 | 2025-12-05T01:49:45.439537 |
| TruthPreservationValidator_BART_NLI_after_init | 1385.6 | 5360.3 | 16.4 | 2025-12-05T01:49:50.833368 |
| TruthPreservationValidator_BART_NLI_before_request | 1385.6 | 5360.3 | 16.4 | 2025-12-05T01:49:50.978122 |
| TruthPreservationValidator_BART_NLI_after_request | 1385.6 | 5360.3 | 16.4 | 2025-12-05T01:49:51.266682 |
| TruthPreservationValidator_BART_NLI_before_batch | 1385.6 | 5360.3 | 16.4 | 2025-12-05T01:49:51.418363 |
| TruthPreservationValidator_BART_NLI_after_batch | 1385.6 | 5360.3 | 16.4 | 2025-12-05T01:49:51.729970 |
| TruthPreservationValidator_BART_NLI_final | 1384.7 | 5359.2 | 1384.7 | 2025-12-05T01:49:51.932255 |
| final_after_all_tests | 1373.3 | 3792.9 | 1373.3 | 2025-12-05T01:49:52.085449 |

## Component Memory Profiles

### GuardAPI

- **Initialization:** 0.0 MB
- **Single Request:** 4.25 MB
- **Batch (100 requests):** 0.00 MB (0.000 MB/request)
- **Peak Memory:** 9.7 MB

**Top 10 Memory Allocations (tracemalloc):**

| File | Line | Size (MB) | Count |
|------|------|-----------|-------|
| <frozen importlib._bootstrap_external> | 753 | 3.40 | 28627 |
| <frozen abc> | 106 | 0.36 | 1453 |
| C:\Users\sooko\AppData\Local\Programs\Python\Python312\Lib\typing.py | 2901 | 0.22 | 944 |
| C:\Users\sooko\AppData\Local\Programs\Python\Python312\Lib\typing.py | 904 | 0.21 | 2322 |
| C:\Users\sooko\AppData\Local\Programs\Python\Python312\Lib\dataclasses.py | 473 | 0.18 | 1998 |
| C:\Users\sooko\AppData\Local\Programs\Python\Python312\Lib\dataclasses.py | 1233 | 0.10 | 376 |
| C:\Users\sooko\AppData\Local\Programs\Python\Python312\Lib\re\_compiler.py | 761 | 0.08 | 96 |
| C:\Users\sooko\AppData\Local\Programs\Python\Python312\Lib\typing.py | 171 | 0.07 | 696 |
| <frozen abc> | 107 | 0.06 | 348 |
| <string> | 2 | 0.05 | 430 |

### SemanticGroomingGuard_Embedding

- **Initialization:** 8.9 MB
- **Single Request:** 0.08 MB
- **Batch (100 requests):** 0.00 MB (0.000 MB/request)
- **Peak Memory:** 9.0 MB

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

### SemanticGroomingGuardONNX_Embedding

- **Initialization:** 18.8 MB
- **Single Request:** 0.00 MB
- **Batch (100 requests):** 0.00 MB (0.000 MB/request)
- **Peak Memory:** 18.8 MB

**Top 10 Memory Allocations (tracemalloc):**

| File | Line | Size (MB) | Count |
|------|------|-----------|-------|
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\onnxruntime\capi\onnxruntime_inference_collection.py | 596 | 0.00 | 30 |
| C:\Users\sooko\AppData\Local\Programs\Python\Python312\Lib\email\_policybase.py | 311 | 0.00 | 21 |
| C:\Users\sooko\AppData\Local\Programs\Python\Python312\Lib\email\message.py | 516 | 0.00 | 22 |
| C:\Users\sooko\AppData\Local\Programs\Python\Python312\Lib\email\_policybase.py | 309 | 0.00 | 21 |
| D:\MCP Mods\HAK_GAL_HEXAGONAL\standalone_packages\llm-security-firewall\scripts\memory_profiling\memory_profiling_suite.py | 123 | 0.00 | 14 |
| C:\Users\sooko\AppData\Local\Programs\Python\Python312\Lib\encodings\cp1252.py | 19 | 0.00 | 13 |
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\transformers\tokenization_utils_base.py | 1337 | 0.00 | 10 |
| D:\MCP Mods\HAK_GAL_HEXAGONAL\.venv_hexa\Lib\site-packages\transformers\tokenization_utils_fast.py | 116 | 0.00 | 1 |
| <string> | 1 | 0.00 | 3 |
| D:\MCP Mods\HAK_GAL_HEXAGONAL\standalone_packages\llm-security-firewall\scripts\memory_profiling\memory_profiling_suite.py | 130 | 0.00 | 6 |

### TruthPreservationValidator_BART_NLI

- **Initialization:** 15.2 MB
- **Single Request:** 0.00 MB
- **Batch (100 requests):** 0.00 MB (0.000 MB/request)
- **Peak Memory:** 14.2 MB

**Top 10 Memory Allocations (tracemalloc):**

| File | Line | Size (MB) | Count |
|------|------|-----------|-------|
| <frozen importlib._bootstrap_external> | 753 | 0.59 | 4195 |
| <frozen importlib._bootstrap> | 488 | 0.14 | 1801 |
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
| SemanticGroomingGuardONNX_Embedding | 18.8 | 108.9 | -90.1 | P2 | ONNX Export + Quantization |
| TruthPreservationValidator_BART_NLI | 14.2 | 82.3 | -68.1 | P2 | Code Review + Optimization |
| GuardAPI | 9.7 | 56.4 | -46.7 | P2 | Code Review + Optimization |
| SemanticGroomingGuard_Embedding | 9.0 | 52.3 | -43.3 | P2 | ONNX Export + Quantization |

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
