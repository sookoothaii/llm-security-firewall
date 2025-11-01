# English-only code
from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

# Optional cheap detectors (graceful degradation if unavailable)
try:
    from llm_firewall.text.obfuscation_guard import analyze_obfuscation

    _HAS_OBFUSCATION = True
    _analyze_obfuscation_real = analyze_obfuscation
except Exception:  # pragma: no cover
    _HAS_OBFUSCATION = False
    _analyze_obfuscation_real = None  # type: ignore

try:
    from llm_firewall.gates.secrets_heuristics import analyze_secrets

    _HAS_SECRETS = True
    _analyze_secrets_real = analyze_secrets
except Exception:  # pragma: no cover
    _HAS_SECRETS = False
    _analyze_secrets_real = None  # type: ignore

# --------------------------
# Public API
# --------------------------

FEATURE_DIM = 52


@dataclass
class ExtractorOutput:
    x: List[float]  # length == 52
    meta: Dict[str, Any]  # auxiliary detail (counts/flags for debugging)


def extract_features(
    prompt: str, *, cheap_scores: Dict[str, float] | None = None
) -> ExtractorOutput:
    """
    Build a 52-dim feature vector for GuardNet from a single text prompt.
    cheap_scores: optional upstream scores (e.g., {"perplexity_z":0.31, "embed_attack_sim":0.72})
    Returns normalized, clipped floats in [0, 1] where sensible. No heavy deps.
    """
    if cheap_scores is None:
        cheap_scores = {}

    text = prompt or ""
    n_chars = max(1, len(text))
    tokens = _simple_tokens(text)
    n_tokens = max(1, len(tokens))

    # --- A) Basic text stats (14) ---
    len_chars_log = _clip01(math.log10(n_chars + 1) / 5.0)  # A0
    len_tokens = _clip01(n_tokens / 512.0)  # A1
    avg_tok_len = _clip01((sum(len(t) for t in tokens) / n_tokens) / 16.0)  # A2
    digit_ratio = _clip01(_ratio(text, str.isdigit))  # A3
    punct_ratio = _clip01(sum(ch in _PUNCT for ch in text) / n_chars)  # A4
    upper_ratio = _clip01(sum(ch.isupper() for ch in text) / n_chars)  # A5
    ws_ratio = _clip01(sum(ch.isspace() for ch in text) / n_chars)  # A6
    symbol_ratio = _clip01(sum(_is_symbol(ch) for ch in text) / n_chars)  # A7
    url_count = len(_RE_URL.findall(text))  # A8
    email_count = len(_RE_EMAIL.findall(text))  # A9
    qm_count = text.count("?")  # A10
    em_count = text.count("!")  # A11
    emoji_count = len(_RE_EMOJI.findall(text))  # A12
    sent_count = len(_RE_SENT_SPLIT.findall(text)) or 1  # A13

    A = [
        len_chars_log,
        len_tokens,
        avg_tok_len,
        digit_ratio,
        punct_ratio,
        upper_ratio,
        ws_ratio,
        symbol_ratio,
        _clip01(url_count / 8.0),
        _clip01(email_count / 4.0),
        _clip01(qm_count / 8.0),
        _clip01(em_count / 8.0),
        _clip01(emoji_count / 8.0),
        _clip01(sent_count / 32.0),
    ]

    # --- B) Side-channel / obfuscation (10) ---
    try:
        if _HAS_OBFUSCATION:
            obf_result = _analyze_obfuscation_real(text)  # type: ignore
        else:
            obf_result = None
        # Handle both ObfuscationFindings dataclass and dict
        if obf_result and hasattr(obf_result, "zwc_count"):
            # ObfuscationFindings dataclass
            zw_count = obf_result.zwc_count
            bidi_count = obf_result.bidi_count
            mixed_scripts = 1 if obf_result.mixed_script_ratio > 0.1 else 0
            base64_score = min(1.0, obf_result.base64_spans / 4.0)
            hex_score = min(1.0, obf_result.hex_spans / 4.0)
            urlenc_runs = obf_result.url_encoded_spans
            rot13_flag = 1 if obf_result.rot13_suspected else 0
            gzip_b64_flag = 1 if obf_result.gzip_magic_in_base64 else 0
            confusable_ratio = 1.0 if obf_result.confusables_suspected else 0.0
            obf_sev = obf_result.severity
        else:
            # Fallback dict format
            obf: Dict[str, Any] = obf_result or {}  # type: ignore
            zw_count = int(obf.get("zw_count", _count_zero_width(text)))
            bidi_count = int(obf.get("bidi_count", _count_bidi(text)))
            mixed_scripts = int(obf.get("mixed_scripts", _mixed_scripts(text)))
            base64_score = float(obf.get("base64_score", _base64_score(text)))
            hex_score = float(obf.get("hex_score", _hex_score(text)))
            urlenc_runs = int(obf.get("urlenc_runs", len(_RE_URLENC.findall(text))))
            rot13_flag = int(obf.get("rot13_flag", 1 if _has_rot13_marker(text) else 0))
            gzip_b64_flag = int(
                obf.get("gzip_b64_flag", 1 if _has_gzip_magic_b64(text) else 0)
            )
            confusable_ratio = float(
                obf.get("confusable_ratio", _confusable_ratio(text))
            )
            obf_sev = float(obf.get("severity", 0.0))
    except Exception:
        # Complete fallback if analyze_obfuscation fails
        zw_count = _count_zero_width(text)
        bidi_count = _count_bidi(text)
        mixed_scripts = _mixed_scripts(text)
        base64_score = _base64_score(text)
        hex_score = _hex_score(text)
        urlenc_runs = len(_RE_URLENC.findall(text))
        rot13_flag = 1 if _has_rot13_marker(text) else 0
        gzip_b64_flag = 1 if _has_gzip_magic_b64(text) else 0
        confusable_ratio = _confusable_ratio(text)
        obf_sev = 0.0

    B = [
        _clip01(zw_count / 16.0),  # B14
        _clip01(bidi_count / 8.0),  # B15
        float(bool(mixed_scripts)),  # B16
        _clip01(base64_score),  # B17
        _clip01(hex_score),  # B18
        _clip01(urlenc_runs / 16.0),  # B19
        float(bool(rot13_flag)),  # B20
        float(bool(gzip_b64_flag)),  # B21
        _clip01(confusable_ratio),  # B22
        _clip01(obf_sev),  # B23
    ]

    # --- C) Secrets / credentials (6) ---
    try:
        if _HAS_SECRETS:
            sec_result = _analyze_secrets_real(text)  # type: ignore
        else:
            sec_result = None
        # Handle both SecretsFindings dataclass and dict
        if sec_result and hasattr(sec_result, "severity"):
            # SecretsFindings dataclass
            sec_sev = sec_result.severity
            hits = sec_result.hits
            api_like = sum(
                1 for h in hits if "api_key" in str(h.get("pattern", "")).lower()
            )
            jwt_like = sum(1 for h in hits if "jwt" in str(h.get("type", "")).lower())
        else:
            # Fallback dict format
            sec: Dict[str, Any] = sec_result or {}  # type: ignore
            sec_sev = float(sec.get("severity", 0.0))
            hits = sec.get("hits", [])
            api_like = sum(1 for h in hits if "api_key" in str(h).lower())
            jwt_like = sum(1 for h in hits if "jwt" in str(h).lower())
    except Exception:
        # Complete fallback
        sec_sev = 0.0
        hits = []
        api_like = 0
        jwt_like = 0

    # Additional pattern detection (always run)
    api_like = max(api_like, len(_RE_API_KEY_LIKE.findall(text)))
    jwt_like = max(jwt_like, len(_RE_JWT_LIKE.findall(text)))
    privkey_flag = 1 if _RE_PRIVKEY.search(text) else 0
    cred_words = len(_RE_CRED_WORDS.findall(text))
    pii_words = len(_RE_PII_WORDS.findall(text))

    C = [
        _clip01(sec_sev),  # C24
        _clip01(api_like / 4.0),  # C25
        _clip01(jwt_like / 4.0),  # C26
        float(bool(privkey_flag)),  # C27
        _clip01(cred_words / 8.0),  # C28
        _clip01(pii_words / 8.0),  # C29
    ]

    # --- D) Safety/policy keyword families (8) (pure detection; no procedures) ---
    jbk = len(_RE_JAILBREAK.findall(text))
    ign = len(_RE_IGNORE_SAFETY.findall(text))
    trn = len(_RE_TRANSLATE_BYPASS.findall(text))
    dan = len(_RE_DAN.findall(text))
    sys = len(_RE_SYS_PROMPT.findall(text))
    cot = 1 if _RE_COT_REQUEST.search(text) else 0
    sh = len(_RE_SELF_HARM.findall(text))
    ill = len(_RE_ILLEGAL.findall(text))

    D = [
        _clip01(jbk / 6.0),  # D30
        _clip01(ign / 6.0),  # D31
        _clip01(trn / 6.0),  # D32
        _clip01(dan / 6.0),  # D33
        _clip01(sys / 4.0),  # D34
        float(bool(cot)),  # D35
        _clip01(sh / 4.0),  # D36
        _clip01(ill / 6.0),  # D37
    ]

    # --- E) Structural & formatting (6) ---
    codeblocks = text.count("```")
    xml_ratio = _clip01(
        len(re.findall(r"</?[A-Za-z][^>]*>", text)) / max(1, n_tokens)
    )  # rough
    json_ratio = _clip01((text.count("{") + text.count("}")) / max(1, n_tokens))
    md_links = len(re.findall(r"\[[^\]]{1,120}\]\([^)]+\)", text))
    list_ratio = _clip01(len(re.findall(r"(?m)^\s*[-*]\s+", text)) / max(1, sent_count))
    roleplay = len(
        re.findall(r"\b(role[-\s]?play|pretend to|you are now)\b", text, flags=re.I)
    )

    E = [
        _clip01(codeblocks / 6.0),  # E38
        xml_ratio,  # E39
        json_ratio,  # E40
        _clip01(md_links / 8.0),  # E41
        list_ratio,  # E42
        _clip01(roleplay / 6.0),  # E43
    ]

    # --- F) Script/language heuristics (6) ---
    latin_r, cyr_r, arab_r, thai_r, han_r = _script_ratios(text)
    mixed_lang_flag = (
        1 if sum(int(r > 0.05) for r in (cyr_r, arab_r, thai_r, han_r)) >= 1 else 0
    )

    F = [
        _clip01(latin_r),  # F44
        _clip01(cyr_r),  # F45
        _clip01(arab_r),  # F46
        _clip01(thai_r),  # F47
        _clip01(han_r),  # F48
        float(bool(mixed_lang_flag)),  # F49
    ]

    # --- G) Optional upstream detector scores (2) ---
    pp_z = float(cheap_scores.get("perplexity_z", 0.0))  # expect z-score (mean 0, sd 1)
    pp_z01 = _clip01((pp_z + 4.0) / 8.0)  # map roughly [-4,4] -> [0,1]
    emb_sim = _clip01(float(cheap_scores.get("embed_attack_sim", 0.0)))

    G = [pp_z01, emb_sim]  # G50, G51

    vec = A + B + C + D + E + F + G
    if len(vec) != FEATURE_DIM:
        raise RuntimeError(f"feature dim {len(vec)} != {FEATURE_DIM}")

    meta = {
        "n_chars": n_chars,
        "n_tokens": n_tokens,
        "zw_count": zw_count,
        "bidi_count": bidi_count,
        "mixed_scripts": mixed_scripts,
        "base64_score": base64_score,
        "hex_score": hex_score,
        "urlenc_runs": urlenc_runs,
        "rot13_flag": bool(rot13_flag),
        "gzip_b64_flag": bool(gzip_b64_flag),
        "obf_severity": obf_sev,
        "secrets_severity": sec_sev,
        "api_like": api_like,
        "jwt_like": jwt_like,
        "privkey_flag": bool(privkey_flag),
    }
    return ExtractorOutput(vec, meta)


# --------------------------
# Helpers & regexes
# --------------------------

_PUNCT = set(r"""!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~""")

_RE_URL = re.compile(r"https?://[^\s)]+", re.I)
_RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_RE_EMOJI = re.compile(r"[\U0001F300-\U0001FAFF\U00002700-\U000027BF]")
_RE_SENT_SPLIT = re.compile(r"[.!?]")

_RE_URLENC = re.compile(r"%[0-9A-Fa-f]{2}")
_RE_B64 = re.compile(r"(?:[A-Za-z0-9+/]{16,}={0,2})")
_RE_HEX = re.compile(r"(?:[0-9A-Fa-f]{16,})")
_RE_GZIP_B64 = re.compile(r"H4sIA[A-Za-z0-9+/]{10,}={0,2}")

_RE_API_KEY_LIKE = re.compile(
    r"\b(sk|api[-_]?key|token)[=:]\s*[A-Za-z0-9_\-]{16,}", re.I
)
_RE_JWT_LIKE = re.compile(
    r"\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b"
)
_RE_PRIVKEY = re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|PRIVATE) KEY-----")
_RE_CRED_WORDS = re.compile(
    r"\b(password|passwort|token|secret|api[-_]?key|key)\b", re.I
)
_RE_PII_WORDS = re.compile(
    r"\b(ssn|passport|credit\s*card|iban|social\s*security|ausweis|身份证)\b", re.I
)

_RE_JAILBREAK = re.compile(
    r"\b(jailbreak|break\s+policy|bypass|ignore\s+instructions)\b", re.I
)
_RE_IGNORE_SAFETY = re.compile(
    r"\b(ignore|disregard)\s+(the\s+)?(rules|safety|content\s*policy)\b", re.I
)
_RE_TRANSLATE_BYPASS = re.compile(r"\b(translate|just\s+translate|verbatim)\b", re.I)
_RE_DAN = re.compile(r"\b(do\s*anything\s*now|dan\s*mode)\b", re.I)
_RE_SYS_PROMPT = re.compile(
    r"\b(system\s+prompt|developer\s+message|hidden\s+instruction)\b", re.I
)
_RE_COT_REQUEST = re.compile(
    r"\b(chain[-\s]*of[-\s]*thought|show\s+your\s+reasoning)\b", re.I
)
_RE_SELF_HARM = re.compile(r"\b(self[-\s]*harm|kill\s+myself|suicide)\b", re.I)
_RE_ILLEGAL = re.compile(r"\b(illegal|how\s+to\s+make|explosive|bomb|weapon)\b", re.I)


def _simple_tokens(s: str) -> List[str]:
    return [t for t in re.split(r"\s+", s.strip()) if t]


def _ratio(text: str, pred) -> float:
    n = len(text)
    if n == 0:
        return 0.0
    return sum(1 for ch in text if pred(ch)) / n


def _is_symbol(ch: str) -> bool:
    cat = unicodedata.category(ch)
    return cat.startswith("S")


def _clip01(x: float) -> float:
    if x != x:  # NaN guard
        return 0.0
    if x < 0:
        return 0.0
    if x > 1:
        return 1.0
    return x


def _count_zero_width(text: str) -> int:
    return sum(ord(ch) in (0x200B, 0x200C, 0x200D, 0xFEFF) for ch in text)


def _count_bidi(text: str) -> int:
    bidi = {0x202A, 0x202B, 0x202D, 0x202E, 0x202C, 0x2066, 0x2067, 0x2068, 0x2069}
    return sum(ord(ch) in bidi for ch in text)


def _mixed_scripts(text: str) -> int:
    # simple: detect presence of multiple script blocks
    latin, cyr, arab, thai, han = _script_counts(text)
    cnt = sum(int(v > 0) for v in (latin, cyr, arab, thai, han))
    if cnt >= 2:
        return 1
    return 0


def _base64_score(text: str) -> float:
    matches = _RE_B64.findall(text)
    if not matches:
        return 0.0
    total = sum(len(m) for m in matches)
    return _clip01(total / 256.0)


def _hex_score(text: str) -> float:
    matches = _RE_HEX.findall(text)
    if not matches:
        return 0.0
    total = sum(len(m) for m in matches)
    return _clip01(total / 256.0)


def _has_rot13_marker(text: str) -> bool:
    return bool(re.search(r"\brot13\b", text, flags=re.I)) or "uryyb" in text.lower()


def _has_gzip_magic_b64(text: str) -> bool:
    return bool(_RE_GZIP_B64.search(text))


def _confusable_ratio(text: str) -> float:
    # crude proxy: non-ASCII proportion excluding whitespace
    chars = [ch for ch in text if not ch.isspace()]
    if not chars:
        return 0.0
    non_ascii = sum(ord(ch) > 127 for ch in chars)
    return non_ascii / len(chars)


def _script_counts(text: str) -> Tuple[int, int, int, int, int]:
    latin = cyr = arab = thai = han = 0
    for ch in text:
        cp = ord(ch)
        if 0x0041 <= cp <= 0x024F:
            latin += 1
        elif 0x0400 <= cp <= 0x04FF:
            cyr += 1
        elif 0x0600 <= cp <= 0x06FF:
            arab += 1
        elif 0x0E00 <= cp <= 0x0E7F:
            thai += 1
        elif (0x4E00 <= cp <= 0x9FFF) or (0x3400 <= cp <= 0x4DBF):
            han += 1
    return latin, cyr, arab, thai, han


def _script_ratios(text: str) -> Tuple[float, float, float, float, float]:
    latin, cyr, arab, thai, han = _script_counts(text)
    total = max(1, latin + cyr + arab + thai + han)
    return (latin / total, cyr / total, arab / total, thai / total, han / total)
