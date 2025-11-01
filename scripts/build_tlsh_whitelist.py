#!/usr/bin/env python3
"""
Build TLSH Whitelist from Benign Corpus
RC2 P4.1: Hash benign decoded buffers for fuzzy matching
"""
import sys
from pathlib import Path

repo_root = Path(__file__).parent.parent
sys.path.insert(0, str(repo_root / "src"))

try:
    import tlsh
except ImportError:
    print("ERROR: tlsh not installed. Run: pip install tlsh")
    sys.exit(1)

from llm_firewall.normalizers.encoding_chain import try_decode_chain

# Import collect_benign_corpus inline to avoid path issues
sys.path.insert(0, str(repo_root / "scripts" / "rc_gate_kit"))
from measure_fpr_benign_repo import collect_benign_corpus


def main():
    print("Building TLSH whitelist from benign corpus...")
    
    corpus = collect_benign_corpus(max_chunks=1000)
    print(f"Collected {len(corpus)} benign chunks")
    
    hashes = set()
    processed = 0
    
    for i, chunk in enumerate(corpus):
        if (i + 1) % 100 == 0:
            print(f"  Progress: {i+1}/{len(corpus)}")
        
        # Try to decode
        decoded_text, stages, _, buf = try_decode_chain(chunk)
        
        if stages >= 1 and buf and len(buf) >= 50:
            # Decoded something - hash it
            try:
                h = tlsh.hash(buf)
                hashes.add(h)
                processed += 1
            except Exception:
                pass
    
    print(f"\nProcessed: {processed} decoded buffers")
    print(f"Unique hashes: {len(hashes)}")
    
    # Save whitelist
    output = repo_root / "var" / "whitelist" / "benign_decoded.tlsh"
    output.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output, "w", encoding="utf-8") as f:
        f.write("# TLSH Benign Whitelist\n")
        f.write("# RC2 P4.1: Fuzzy hash for benign decoded patterns\n")
        f.write(f"# Generated from {len(corpus)} corpus chunks\n")
        f.write(f"# Unique hashes: {len(hashes)}\n\n")
        for h in sorted(hashes):
            f.write(f"{h}\n")
    
    print(f"\nSaved to: {output}")
    print(f"Use in code: TLSHDB('{output}', dist_threshold=85)")


if __name__ == '__main__':
    main()

