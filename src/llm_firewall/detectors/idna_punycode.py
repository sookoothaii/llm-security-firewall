# -*- coding: utf-8 -*-
"""
IDNA/Punycode Detector with URL-aware Homoglyph scoring
Closes IDNA Punycode + URL Homoglyph bypasses
"""
import re
from typing import Dict, Tuple


def extract_hosts(text: str) -> list:
    """Extract potential hostnames from text (including Unicode)"""
    # Match domain-like patterns including Unicode chars
    # \w includes Unicode letters
    pattern = r'(?:https?://)?([^\s/]+\.[\w\-]+)'
    matches = re.findall(pattern, text, re.UNICODE)
    return [m for m in matches if '.' in m]


def decode_punycode_host(host: str) -> Tuple[bool, str]:
    """
    Decode Punycode host (xn--...)
    
    Returns:
        (is_punycode, decoded_host)
    """
    if 'xn--' not in host.lower():
        return False, host
    
    try:
        # Python builtin IDNA codec
        decoded = host.encode('ascii').decode('idna')
        return True, decoded
    except Exception:
        return False, host


def detect_idna_punycode(text: str) -> Dict:
    """
    Detect IDNA/Punycode with homoglyph analysis
    
    Returns:
        {
            'punycode_found': bool,
            'hosts': list,
            'decoded_hosts': list,
            'homoglyph_in_url': bool
        }
    """
    hosts = extract_hosts(text)
    
    if not hosts:
        return {'punycode_found': False, 'hosts': [], 'decoded_hosts': [], 'homoglyph_in_url': False}
    
    punycode_found = False
    decoded_hosts = []
    homoglyph_in_url = False
    
    for host in hosts:
        is_punycode, decoded = decode_punycode_host(host)
        if is_punycode:
            punycode_found = True
            decoded_hosts.append(decoded)
        
        # Check for Cyrillic/Greek in hostname (homoglyph spoof)
        for char in host:
            cp = ord(char)
            # Cyrillic: 0x0400-0x04FF
            # Greek: 0x0370-0x03FF
            if (0x0400 <= cp <= 0x04FF) or (0x0370 <= cp <= 0x03FF):
                homoglyph_in_url = True
                break
    
    return {
        'punycode_found': punycode_found,
        'hosts': hosts,
        'decoded_hosts': decoded_hosts,
        'homoglyph_in_url': homoglyph_in_url
    }

