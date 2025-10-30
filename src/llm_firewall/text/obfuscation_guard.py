# English-only code
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import asdict, dataclass
from typing import Dict, List

# Unicode control / bidi ranges
BIDI_CONTROLS = [
    "\u202A", "\u202B", "\u202D", "\u202E", "\u202C",  # LRE, RLE, LRO, RLO, PDF
    "\u2066", "\u2067", "\u2068", "\u2069",           # LRI, RLI, FSI, PDI
]
ZWC_RE = re.compile(r"[\u200B-\u200D\uFEFF]")  # ZWSP, ZWNJ, ZWJ, BOM
# Script buckets (coarse); enough for mixed-script detection
LATIN_RE    = re.compile(r"[A-Za-z]")
CYRILLIC_RE = re.compile(r"[\u0400-\u04FF]")
GREEK_RE    = re.compile(r"[\u0370-\u03FF]")
ARABIC_RE   = re.compile(r"[\u0600-\u06FF]")
CJK_RE      = re.compile(r"[\u4E00-\u9FFF]")
HEBREW_RE   = re.compile(r"[\u0590-\u05FF]")

BASE64_RE = re.compile(r"(?:[A-Za-z0-9+/]{16,}={0,2})")
HEX_RUN_RE = re.compile(r"(?:[0-9A-Fa-f]{2}){8,}")      # ≥16 hex chars (8 bytes+)
URL_ENC_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}){6,}")     # ≥6 %HH sequences

# Loose ROT13 suspicion (common tokens in ROT13)
ROT13_MARKERS = {"uryyb", "lbh", "frperg", "cvpbire", "ivfvg", "anzr", "grfg"}

@dataclass(frozen=True)
class ObfuscationFindings:
    zwc_count: int
    bidi_count: int
    mixed_script_ratio: float
    mixed_scripts: List[str]
    confusables_suspected: bool
    base64_spans: int
    hex_spans: int
    url_encoded_spans: int
    rot13_suspected: bool
    gzip_magic_in_base64: bool
    severity: float  # 0..1

    def to_dict(self) -> Dict:
        return asdict(self)

def _script_hits(s: str) -> Dict[str, int]:
    return {
        "latin": len(LATIN_RE.findall(s)),
        "cyrillic": len(CYRILLIC_RE.findall(s)),
        "greek": len(GREEK_RE.findall(s)),
        "arabic": len(ARABIC_RE.findall(s)),
        "cjk": len(CJK_RE.findall(s)),
        "hebrew": len(HEBREW_RE.findall(s)),
    }

def _mixed_ratio(hits: Dict[str, int]) -> float:
    total_letters = sum(hits.values())
    if total_letters == 0:
        return 0.0
    dominant = max(hits.values())
    # share of non-dominant scripts
    return max(0.0, (total_letters - dominant) / total_letters)

def _confusables_suspected(s: str, hits: Dict[str,int]) -> bool:
    # simple heuristic: latin + cyrillic co-occur within same word boundaries
    if hits["latin"] > 0 and hits["cyrillic"] > 0:
        # token-level check
        for tok in re.findall(r"\w{3,}", s):
            if LATIN_RE.search(tok) and CYRILLIC_RE.search(tok):
                return True
    return False

def _has_gzip_magic_in_base64(s: str) -> bool:
    for m in BASE64_RE.finditer(s):
        chunk = m.group(0)
        try:
            raw = base64.b64decode(chunk, validate=False)
            if len(raw) >= 2 and raw[0] == 0x1F and raw[1] == 0x8B:
                return True
        except binascii.Error:
            continue
    return False

def _rot13_suspected(s: str) -> bool:
    # quick scan for typical rot13-words presence
    low = s.lower()
    return any(tok in low for tok in ROT13_MARKERS)

def analyze_obfuscation(text: str) -> ObfuscationFindings:
    zwc_count = len(ZWC_RE.findall(text))
    bidi_count = sum(text.count(c) for c in BIDI_CONTROLS)
    hits = _script_hits(text)
    mixed_ratio = _mixed_ratio(hits)
    conf_sus = _confusables_suspected(text, hits)

    b64 = list(BASE64_RE.finditer(text))
    hexs = list(HEX_RUN_RE.finditer(text))
    urlsp = list(URL_ENC_RE.finditer(text))
    rot13sus = _rot13_suspected(text)
    gz = _has_gzip_magic_in_base64(text)

    # severity: weighted combination (bounded)
    sev = 0.0
    sev += min(1.0, zwc_count / 20.0) * 0.2
    sev += min(1.0, bidi_count / 5.0) * 0.25
    sev += min(1.0, mixed_ratio * 2.0) * 0.2
    sev += (1.0 if conf_sus else 0.0) * 0.15
    sev += min(1.0, len(b64) / 4.0) * 0.1
    sev += min(1.0, len(hexs) / 4.0) * 0.05
    sev += min(1.0, len(urlsp) / 6.0) * 0.05
    sev = min(1.0, sev + (0.1 if gz else 0.0) + (0.05 if rot13sus else 0.0))

    mixed_scripts = [k for k,v in hits.items() if v>0]
    return ObfuscationFindings(
        zwc_count=zwc_count,
        bidi_count=bidi_count,
        mixed_script_ratio=round(mixed_ratio, 3),
        mixed_scripts=mixed_scripts,
        confusables_suspected=conf_sus,
        base64_spans=len(b64),
        hex_spans=len(hexs),
        url_encoded_spans=len(urlsp),
        rot13_suspected=rot13sus,
        gzip_magic_in_base64=gz,
        severity=round(sev, 3),
    )


