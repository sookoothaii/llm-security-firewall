"""
Zero-Width Character Validator

Detects zero-width characters that are often used for bypasses.
"""
import logging

logger = logging.getLogger(__name__)


class ZeroWidthValidator:
    """
    Validator for zero-width characters.
    
    Zero-width characters are often used for bypasses and must be blocked.
    """
    
    # Zero-width characters commonly used for bypasses
    ZERO_WIDTH_CHARS = ['\u200b', '\u200c', '\u200d', '\u2060', '\ufeff']
    
    def is_benign(self, text: str) -> bool:
        """
        Check if text contains zero-width characters.
        
        Returns False if zero-width characters detected (NOT benign).
        """
        if any(zw in text for zw in self.ZERO_WIDTH_CHARS):
            logger.debug(f"NOT benign: Zero-width character detected in {text[:50]}...")
            return False
        
        return True  # No zero-width characters detected

