# -*- coding: utf-8 -*-
"""
Benign Motif Vault (BMV) via SimHash
Stores recurring benign patterns, dampens risk for near matches (Hamming ≤3)
"""
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Iterable, Optional, Set


def simhash(tokens: Iterable[str], bits: int = 64) -> int:
    """
    Compute SimHash fingerprint
    
    Args:
        tokens: Tokenized text
        bits: Hash size (default 64)
    
    Returns:
        SimHash integer
    """
    vector = [0] * bits
    
    for token in tokens:
        # Use blake2b for deterministic hashing
        h_bytes = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
        h_int = int.from_bytes(h_bytes, byteorder='big')
        
        for i in range(bits):
            if (h_int >> i) & 1:
                vector[i] += 1
            else:
                vector[i] -= 1
    
    # Convert to binary fingerprint
    fingerprint = 0
    for i, val in enumerate(vector):
        if val > 0:
            fingerprint |= (1 << i)
    
    return fingerprint


def hamming_distance(a: int, b: int) -> int:
    """Calculate Hamming distance between two integers"""
    return (a ^ b).bit_count()


class BenignVault:
    """Vault for benign text patterns via SimHash"""
    
    def __init__(self, bits: int = 64, hamming_threshold: int = 3):
        self.bits = bits
        self.hamming_threshold = hamming_threshold
        self.hashes: defaultdict[int, int] = defaultdict(int)  # hash -> frequency
        self._load_limit = 10000  # Max patterns to keep (LRU via frequency)
    
    def add_text(self, text: str):
        """Add text pattern to vault"""
        tokens = text.split()
        if not tokens:
            return
        
        h = simhash(tokens, self.bits)
        self.hashes[h] += 1
        
        # LRU: Keep only most frequent patterns
        if len(self.hashes) > self._load_limit:
            # Remove least frequent
            sorted_hashes = sorted(self.hashes.items(), key=lambda x: x[1])
            for h_to_remove, _ in sorted_hashes[:len(sorted_hashes) // 10]:
                del self.hashes[h_to_remove]
    
    def is_near_benign(self, text: str) -> bool:
        """
        Check if text is near a benign pattern
        
        Returns:
            True if Hamming distance ≤ threshold to any stored pattern
        """
        tokens = text.split()
        if not tokens:
            return False
        
        h = simhash(tokens, self.bits)
        
        # Check against all stored patterns
        for stored_hash in self.hashes.keys():
            if hamming_distance(h, stored_hash) <= self.hamming_threshold:
                return True
        
        return False
    
    def save(self, path: Path):
        """Save vault to JSON file"""
        data = {
            'hashes': {hex(k): v for k, v in self.hashes.items()},
            'bits': self.bits,
            'threshold': self.hamming_threshold
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f)
    
    def load(self, path: Path):
        """Load vault from JSON file"""
        if not path.exists():
            return
        
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        self.bits = data.get('bits', 64)
        self.hamming_threshold = data.get('threshold', 3)
        self.hashes = defaultdict(int, {int(k, 16): v for k, v in data.get('hashes', {}).items()})


# Global vault instance
_vault: Optional[BenignVault] = None


def get_vault() -> BenignVault:
    """Get or create global vault instance"""
    global _vault
    if _vault is None:
        _vault = BenignVault()
        # Try to load from default location
        default_path = Path(__file__).parent.parent.parent / "artifacts" / "benign_vault.json"
        if default_path.exists():
            _vault.load(default_path)
    return _vault

