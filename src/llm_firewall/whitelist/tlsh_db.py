# -*- coding: utf-8 -*-
"""
TLSH Whitelist Database
RC2 P4.1: Fuzzy hash matching for benign patterns
Apache-2.0 License for TLSH
"""
import os
from pathlib import Path
from typing import Optional

try:
    import tlsh
    TLSH_AVAILABLE = True
except ImportError:
    TLSH_AVAILABLE = False
    tlsh = None


class TLSHDB:
    """TLSH-based whitelist for benign patterns"""
    
    def __init__(self, path: str, dist_threshold: int = 85):
        """
        Args:
            path: Path to whitelist file (one hash per line)
            dist_threshold: Maximum TLSH distance for match (default 85)
        """
        self.path = path
        self.dist_threshold = dist_threshold
        self._hashes = set()
        self._loaded = False
    
    def load(self):
        """Load hashes from file"""
        if not TLSH_AVAILABLE:
            self._loaded = True
            return
        
        if not os.path.exists(self.path):
            self._loaded = True
            return
        
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                h = line.strip()
                if h and not h.startswith('#'):
                    self._hashes.add(h)
        
        self._loaded = True
    
    def is_benign(self, buf: bytes) -> bool:
        """
        Check if buffer matches whitelist
        
        Args:
            buf: Decoded buffer to check
            
        Returns:
            True if matches benign whitelist
        """
        if not TLSH_AVAILABLE:
            return False
        
        if not self._loaded:
            self.load()
        
        if not self._hashes:
            return False
        
        # Compute hash for buffer
        try:
            h = tlsh.hash(buf)
        except Exception:
            return False
        
        # Check against whitelist
        for ref in self._hashes:
            try:
                d = tlsh.diff(h, ref)
            except Exception:
                continue
            
            if d <= self.dist_threshold:
                return True
        
        return False
    
    def add_to_whitelist(self, buf: bytes) -> Optional[str]:
        """
        Add buffer to whitelist
        
        Returns:
            TLSH hash if successful, None otherwise
        """
        if not TLSH_AVAILABLE:
            return None
        
        try:
            h = tlsh.hash(buf)
            self._hashes.add(h)
            return h
        except Exception:
            return None
    
    def save(self):
        """Save whitelist to file"""
        if not self._hashes:
            return
        
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("# TLSH Benign Whitelist\n")
            f.write("# RC2 P4.1: Fuzzy hash for benign patterns\n\n")
            for h in sorted(self._hashes):
                f.write(f"{h}\n")

