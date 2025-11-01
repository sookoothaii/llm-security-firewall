# -*- coding: utf-8 -*-
"""
Heuristic base alphabet sniffer & bounded chain decoder.
No external deps; decode budget + stage cap to prevent DoS.
"""

import base64
import binascii
import re

# Allowed alphabets (coarse)
ALPH_B64 = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
ALPH_B32 = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=")
ALPH_B58 = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
ALPH_B85 = set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~")
ALPH_B91 = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\"")

def _ratio_in_set(s: str, alphabet: set) -> float:
    if not s:
        return 0.0
    hits = sum(1 for ch in s if ch in alphabet)
    return hits / max(1, len(s))

def sniff_encodings(s: str):
    """Return candidate encodings ordered by likelihood."""
    cand = []
    cand.append(("b64", _ratio_in_set(s, ALPH_B64)))
    cand.append(("b32", _ratio_in_set(s, ALPH_B32)))
    cand.append(("b85", _ratio_in_set(s, ALPH_B85)))
    cand.append(("b91", _ratio_in_set(s, ALPH_B91)))
    cand.append(("qp", 0.6 if "=\r\n" in s or "=3D" in s else 0.0))
    if s.startswith("begin ") and "end" in s:
        cand.append(("uu", 0.9))
    if s.startswith(":") and s.endswith(":"):
        cand.append(("binhex", 0.7))
    return [k for k, _ in sorted(cand, key=lambda x: x[1], reverse=True) if _ >= 0.6]

def _dec_b64(s: str):
    pad = (-len(s)) % 4
    try:
        return base64.b64decode(s + ("="*pad), validate=False)
    except Exception:
        raise

def _dec_b32(s: str):
    pad = (-len(s)) % 8
    try:
        return base64.b32decode(s + ("="*pad), casefold=True)
    except Exception:
        raise

def _dec_b85(s: str):
    """Decode Base85/ASCII85 with multiple format support"""
    # Try Adobe ASCII85 (<~...~>) first
    if s.startswith('<~') and s.endswith('~>'):
        try:
            return base64.a85decode(s, adobe=True)
        except Exception:
            pass

    # Try RFC 1924 (Z85-compatible)
    try:
        return base64.a85decode(s, adobe=False, ignorechars=" \t\r\n")
    except Exception:
        pass

    # Try pure b85decode
    try:
        return base64.b85decode(s)
    except Exception:
        raise

def _extract_b64_spans(text: str):
    """Extract potential Base64 spans from text for recursive decode"""
    # Look for base64-like sequences (min 20 chars)
    pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
    matches = re.findall(pattern, text)
    return matches

def _dec_qp(s: str, max_bytes: int):
    s2 = s.replace("=\r\n", "")
    out = bytearray()
    i = 0
    while i < len(s2):
        if s2[i] == "=" and i+2 < len(s2) and all(c in "0123456789ABCDEFabcdef" for c in s2[i+1:i+3]):
            out.append(int(s2[i+1:i+3], 16))
            i += 3
        else:
            out.append(ord(s2[i]))
            i += 1
        if len(out) > max_bytes:
            raise ValueError("qp budget exceeded")
    return bytes(out)

def _dec_uu(s: str, max_bytes: int):
    lines = s.splitlines()
    in_body = False
    out = bytearray()
    for ln in lines:
        if ln.startswith("begin "):
            in_body = True
            continue
        if ln.strip() == "end":
            break
        if in_body:
            try:
                out.extend(binascii.a2b_uu((ln+"\n").encode("ascii")))
                if len(out) > max_bytes:
                    raise ValueError("uu budget exceeded")
            except binascii.Error:
                continue
    return bytes(out)

DECODER = {
    "b64": lambda s, m: _dec_b64(s),
    "b32": lambda s, m: _dec_b32(s),
    "b85": lambda s, m: _dec_b85(s),
    "b91": lambda s, m: None,
    "qp": lambda s, m: _dec_qp(s, m),
    "uu": lambda s, m: _dec_uu(s, m),
    "binhex": lambda s, m: None,
}

def try_decode_chain(text: str, max_stages: int = 3, max_total_bytes: int = 65536):
    """
    Attempt up to `max_stages` decoding steps selected by sniffers.
    Includes Base64 span extraction for B85->B64 chains.
    Returns (maybe_decoded_text:str, stages:int, budget_used:int, buffer:bytes|None)
    """
    cur = text
    used = 0
    stages = 0
    last_buffer = None

    for _ in range(max_stages):
        cands = sniff_encodings(cur)
        if not cands:
            # P0.3: Try extracting Base64 spans if main decode failed
            b64_spans = _extract_b64_spans(cur)
            if b64_spans and stages > 0:  # Only if we already decoded something
                # Try first span
                try:
                    b = _dec_b64(b64_spans[0])
                    if isinstance(b, (bytes, bytearray)):
                        used += len(b)
                        if used <= max_total_bytes:
                            nxt = b.decode("utf-8", errors="replace")
                            cur = nxt
                            stages += 1
                            continue
                except Exception:
                    pass
            break

        decoded_any = False
        for enc in cands:
            dec = DECODER.get(enc)
            if dec is None:
                continue
            try:
                b = dec(cur, max_total_bytes - used)
                if not isinstance(b, (bytes, bytearray)):
                    continue
                used += len(b)
                if used > max_total_bytes:
                    raise ValueError("budget exceeded")
                last_buffer = bytes(b)  # Store for risk classification
                try:
                    nxt = b.decode("utf-8", errors="replace")
                except Exception:
                    nxt = b.decode("latin-1", errors="replace")
                cur = nxt
                stages += 1
                decoded_any = True
                break
            except Exception:
                continue

        if not decoded_any:
            break

    return cur, stages, used, last_buffer

