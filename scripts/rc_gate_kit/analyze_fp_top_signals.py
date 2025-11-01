#!/usr/bin/env python3
"""
Analyze Top FP Signals
Find which detectors cause most false positives
"""
import glob
import re
import json
import sys
from pathlib import Path
from collections import Counter

repo_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(repo_root / "src"))

from llm_firewall.policy.risk_weights_v2_otb import decide_action_otb
from llm_firewall.preprocess.context import classify_context

# Import functions without executing main block
import importlib.util
spec = importlib.util.spec_from_file_location("fpr_measure", Path(__file__).parent / 'measure_fpr_benign_repo.py')
fpr_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fpr_module)
collect_benign_corpus = fpr_module.collect_benign_corpus
run_detectors_inline = fpr_module.run_detectors_inline


if __name__ == '__main__':
    print("Analyzing FP signals...")
    benign = collect_benign_corpus(max_chunks=1000)
    
    fp_signals = Counter()
    fp_contexts = Counter()
    block_samples = []
    
    for i, chunk in enumerate(benign):
        if (i + 1) % 100 == 0:
            print(f"  Progress: {i+1}/{len(benign)}")
        
        try:
            ctx = classify_context(chunk)
            hits = run_detectors_inline(chunk, context=ctx['context'])
            action, risk, contrib = decide_action_otb(hits, ctx, text=chunk)
            
            if action in ('WARN', 'BLOCK'):
                fp_signals.update(hits)
                fp_contexts[ctx['context']] += 1
                
                if action == 'BLOCK' and len(block_samples) < 5:
                    block_samples.append({
                        'chunk': chunk[:200],
                        'context': ctx['context'],
                        'risk': risk,
                        'hits': hits[:10]
                    })
        except Exception as e:
            pass
    
    print(f"\n=== TOP FP SIGNALS ===")
    for signal, count in fp_signals.most_common(15):
        print(f"  {signal:30s}: {count:4d}")
    
    print(f"\n=== FP BY CONTEXT ===")
    for ctx, count in fp_contexts.most_common():
        print(f"  {ctx:10s}: {count:4d}")
    
    print(f"\n=== SAMPLE BLOCKS ===")
    for i, sample in enumerate(block_samples):
        print(f"\nBlock {i+1}:")
        print(f"  Context: {sample['context']}")
        print(f"  Risk: {sample['risk']:.2f}")
        print(f"  Hits: {sample['hits']}")
        print(f"  Text: {repr(sample['chunk'][:100])}")

