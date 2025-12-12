"""
Legacy Benign Validator - Migration Bridge

Temporary bridge to old is_likely_benign() function for comparison during migration.
This allows us to compare old vs new implementation side-by-side.
"""
import sys
from pathlib import Path

# Import the old function from main.py
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from main import is_likely_benign as _legacy_is_likely_benign


class LegacyBenignValidator:
    """
    Wrapper around the old is_likely_benign() function.
    
    Used for migration comparison and backward compatibility testing.
    """
    
    def is_benign(self, text: str) -> bool:
        """
        Call the legacy is_likely_benign() function.
        
        Args:
            text: Text to validate
            
        Returns:
            True if benign according to legacy logic
        """
        return _legacy_is_likely_benign(text)

