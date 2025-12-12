#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Multilingual Toxicity Detection
Detects toxic/harmful content in 17+ languages (natural language, not code attacks)

Target: Reduce PolygloToxicityPrompts ASR from 46.5% to <10%
Covers: Hate speech, profanity, threats, harassment, discrimination in all supported languages

Author: Claude Sonnet 4.5 (Autonomous Executive)
Date: 2025-12-05
"""

import re
from typing import List, Set

# Toxicity Keywords in Multiple Languages
# Format: (keyword, language, severity, category)
# Severity: 1.0 = high (direct threats/hate), 0.7 = medium (profanity), 0.5 = low (mild toxicity)
# Category: hate, profanity, threat, harassment, discrimination
MULTILINGUAL_TOXICITY_KEYWORDS = {
    # English (baseline)
    "kill yourself": ("suicide", "en", 1.0, "threat"),
    "die": ("death", "en", 0.8, "threat"),
    "hate": ("hate", "en", 0.7, "hate"),
    "stupid": ("insult", "en", 0.5, "harassment"),
    "idiot": ("insult", "en", 0.6, "harassment"),
    "moron": ("insult", "en", 0.6, "harassment"),
    "retard": ("slur", "en", 0.9, "discrimination"),
    "nigger": ("slur", "en", 1.0, "hate"),
    "faggot": ("slur", "en", 1.0, "hate"),
    "bitch": ("profanity", "en", 0.7, "harassment"),
    "fuck": ("profanity", "en", 0.6, "profanity"),
    "shit": ("profanity", "en", 0.5, "profanity"),
    "damn": ("profanity", "en", 0.4, "profanity"),
    # Spanish (es)
    "mátate": ("suicide", "es", 1.0, "threat"),  # kill yourself
    "muérete": ("death", "es", 0.9, "threat"),  # die
    "odio": ("hate", "es", 0.7, "hate"),  # hate
    "estúpido": ("insult", "es", 0.5, "harassment"),  # stupid
    "idiota": ("insult", "es", 0.6, "harassment"),  # idiot
    "imbécil": ("insult", "es", 0.6, "harassment"),  # imbecile
    "puta": ("profanity", "es", 0.8, "harassment"),  # whore
    "joder": ("profanity", "es", 0.7, "profanity"),  # fuck
    "mierda": ("profanity", "es", 0.6, "profanity"),  # shit
    # French (fr)
    "tue-toi": ("suicide", "fr", 1.0, "threat"),  # kill yourself
    "crève": ("death", "fr", 0.9, "threat"),  # die
    "haine": ("hate", "fr", 0.7, "hate"),  # hate
    "stupide": ("insult", "fr", 0.5, "harassment"),  # stupid
    "idiot": ("insult", "fr", 0.6, "harassment"),  # idiot
    "connard": ("profanity", "fr", 0.8, "harassment"),  # asshole
    "putain": ("profanity", "fr", 0.7, "profanity"),  # fuck
    "merde": ("profanity", "fr", 0.6, "profanity"),  # shit
    # German (de)
    "töte dich": ("suicide", "de", 1.0, "threat"),  # kill yourself
    "stirb": ("death", "de", 0.9, "threat"),  # die
    "hasse": ("hate", "de", 0.7, "hate"),  # hate
    "dumm": ("insult", "de", 0.5, "harassment"),  # stupid
    "idiot": ("insult", "de", 0.6, "harassment"),  # idiot
    "arschloch": ("profanity", "de", 0.8, "harassment"),  # asshole
    "scheiße": ("profanity", "de", 0.7, "profanity"),  # shit
    "verdammt": ("profanity", "de", 0.5, "profanity"),  # damn
    # Italian (it)
    "ucciditi": ("suicide", "it", 1.0, "threat"),  # kill yourself
    "muori": ("death", "it", 0.9, "threat"),  # die
    "odio": ("hate", "it", 0.7, "hate"),  # hate
    "stupido": ("insult", "it", 0.5, "harassment"),  # stupid
    "idiota": ("insult", "it", 0.6, "harassment"),  # idiot
    "cazzo": ("profanity", "it", 0.7, "profanity"),  # fuck
    "merda": ("profanity", "it", 0.6, "profanity"),  # shit
    # Portuguese (pt)
    "mate-se": ("suicide", "pt", 1.0, "threat"),  # kill yourself
    "morra": ("death", "pt", 0.9, "threat"),  # die
    "ódio": ("hate", "pt", 0.7, "hate"),  # hate
    "estúpido": ("insult", "pt", 0.5, "harassment"),  # stupid
    "idiota": ("insult", "pt", 0.6, "harassment"),  # idiot
    "porra": ("profanity", "pt", 0.7, "profanity"),  # fuck
    "merda": ("profanity", "pt", 0.6, "profanity"),  # shit
    # Russian (ru)
    "убей себя": ("suicide", "ru", 1.0, "threat"),  # kill yourself
    "умри": ("death", "ru", 0.9, "threat"),  # die
    "ненависть": ("hate", "ru", 0.7, "hate"),  # hate
    "тупой": ("insult", "ru", 0.5, "harassment"),  # stupid
    "идиот": ("insult", "ru", 0.6, "harassment"),  # idiot
    "сука": ("profanity", "ru", 0.8, "harassment"),  # bitch
    "блять": ("profanity", "ru", 0.7, "profanity"),  # fuck
    # Chinese (zh)
    "去死": ("death", "zh", 0.9, "threat"),  # go die
    "恨": ("hate", "zh", 0.7, "hate"),  # hate
    "白痴": ("insult", "zh", 0.6, "harassment"),  # idiot
    "傻逼": ("insult", "zh", 0.7, "harassment"),  # stupid
    "操": ("profanity", "zh", 0.7, "profanity"),  # fuck
    # Japanese (ja)
    "死ね": ("death", "ja", 0.9, "threat"),  # die
    "憎しみ": ("hate", "ja", 0.7, "hate"),  # hate
    "バカ": ("insult", "ja", 0.6, "harassment"),  # idiot
    "クソ": ("profanity", "ja", 0.6, "profanity"),  # shit
    # Arabic (ar)
    "اقتل نفسك": ("suicide", "ar", 1.0, "threat"),  # kill yourself
    "مت": ("death", "ar", 0.9, "threat"),  # die
    "كراهية": ("hate", "ar", 0.7, "hate"),  # hate
    "غبي": ("insult", "ar", 0.5, "harassment"),  # stupid
    "أحمق": ("insult", "ar", 0.6, "harassment"),  # idiot
    # Hindi (hi)
    "खुद को मार": ("suicide", "hi", 1.0, "threat"),  # kill yourself
    "मर": ("death", "hi", 0.9, "threat"),  # die
    "नफरत": ("hate", "hi", 0.7, "hate"),  # hate
    "बेवकूफ": ("insult", "hi", 0.6, "harassment"),  # idiot
    "मूर्ख": ("insult", "hi", 0.5, "harassment"),  # stupid
    # Korean (ko)
    "자살해": ("suicide", "ko", 1.0, "threat"),  # kill yourself
    "죽어": ("death", "ko", 0.9, "threat"),  # die
    "증오": ("hate", "ko", 0.7, "hate"),  # hate
    "바보": ("insult", "ko", 0.6, "harassment"),  # idiot
    "멍청이": ("insult", "ko", 0.5, "harassment"),  # stupid
    # Turkish (tr)
    "kendini öldür": ("suicide", "tr", 1.0, "threat"),  # kill yourself
    "öl": ("death", "tr", 0.9, "threat"),  # die
    "nefret": ("hate", "tr", 0.7, "hate"),  # hate
    "aptal": ("insult", "tr", 0.5, "harassment"),  # stupid
    "salak": ("insult", "tr", 0.6, "harassment"),  # idiot
    # Polish (pl)
    "zabij się": ("suicide", "pl", 1.0, "threat"),  # kill yourself
    "giń": ("death", "pl", 0.9, "threat"),  # die
    "nienawiść": ("hate", "pl", 0.7, "hate"),  # hate
    "głupi": ("insult", "pl", 0.5, "harassment"),  # stupid
    "idiota": ("insult", "pl", 0.6, "harassment"),  # idiot
    # Dutch (nl)
    "dood jezelf": ("suicide", "nl", 1.0, "threat"),  # kill yourself
    "sterf": ("death", "nl", 0.9, "threat"),  # die
    "haat": ("hate", "nl", 0.7, "hate"),  # hate
    "dom": ("insult", "nl", 0.5, "harassment"),  # stupid
    "idioot": ("insult", "nl", 0.6, "harassment"),  # idiot
    # Greek (el)
    "σκότωσε τον εαυτό σου": ("suicide", "el", 1.0, "threat"),  # kill yourself
    "πέθανε": ("death", "el", 0.9, "threat"),  # die
    "μίσος": ("hate", "el", 0.7, "hate"),  # hate
    "ηλίθιος": ("insult", "el", 0.6, "harassment"),  # idiot
    # Hebrew (he)
    "תהרוג את עצמך": ("suicide", "he", 1.0, "threat"),  # kill yourself
    "תמות": ("death", "he", 0.9, "threat"),  # die
    "שנאה": ("hate", "he", 0.7, "hate"),  # hate
    "אידיוט": ("insult", "he", 0.6, "harassment"),  # idiot
    # Thai (th)
    "ฆ่าตัวตาย": ("suicide", "th", 1.0, "threat"),  # kill yourself
    "ตาย": ("death", "th", 0.9, "threat"),  # die
    "เกลียด": ("hate", "th", 0.7, "hate"),  # hate
    "โง่": ("insult", "th", 0.5, "harassment"),  # stupid
    # Vietnamese (vi)
    "tự sát": ("suicide", "vi", 1.0, "threat"),  # kill yourself
    "chết": ("death", "vi", 0.9, "threat"),  # die
    "ghét": ("hate", "vi", 0.7, "hate"),  # hate
    "ngu": ("insult", "vi", 0.5, "harassment"),  # stupid
    # Indonesian (id)
    "bunuh diri": ("suicide", "id", 1.0, "threat"),  # kill yourself
    "mati": ("death", "id", 0.9, "threat"),  # die
    "benci": ("hate", "id", 0.7, "hate"),  # hate
    "bodoh": ("insult", "id", 0.5, "harassment"),  # stupid
    # Malay (ms)
    "bunuh diri": ("suicide", "ms", 1.0, "threat"),  # kill yourself
    "mati": ("death", "ms", 0.9, "threat"),  # die
    "benci": ("hate", "ms", 0.7, "hate"),  # hate
    "bodoh": ("insult", "ms", 0.5, "harassment"),  # stupid
    # Maltese (mt)
    "qtol lilek innifsek": ("suicide", "mt", 1.0, "threat"),  # kill yourself
    "mut": ("death", "mt", 0.9, "threat"),  # die
    "mibegħda": ("hate", "mt", 0.7, "hate"),  # hate
    "stupid": ("insult", "mt", 0.5, "harassment"),  # stupid
    # Basque (eu)
    "hil zaitez": ("suicide", "eu", 1.0, "threat"),  # kill yourself
    "hil": ("death", "eu", 0.9, "threat"),  # die
    "gorroto": ("hate", "eu", 0.7, "hate"),  # hate
    "ergel": ("insult", "eu", 0.5, "harassment"),  # stupid
}


def detect_toxicity_keywords(text: str) -> List[str]:
    """
    Detect toxic keywords in multiple languages.

    Returns:
        List of signal hits for risk aggregation
    """
    hits = []
    detected_languages: Set[str] = set()
    detected_categories: Set[str] = set()
    max_severity = 0.0
    keywords_found = []

    text_lower = text.lower()

    for keyword, (
        category,
        lang,
        severity,
        tox_category,
    ) in MULTILINGUAL_TOXICITY_KEYWORDS.items():
        # Case-insensitive search (handles Unicode properly)
        if keyword.lower() in text_lower:
            keywords_found.append((keyword, category, lang, severity, tox_category))
            detected_languages.add(lang)
            detected_categories.add(tox_category)
            max_severity = max(max_severity, severity)

    if keywords_found:
        hits.append("toxicity_detected")

        # Language-specific signals
        for lang in detected_languages:
            hits.append(f"toxicity_{lang}_detected")

        # Category-specific signals
        if "threat" in detected_categories:
            hits.append("toxicity_threat")
        if "hate" in detected_categories:
            hits.append("toxicity_hate")
        if "harassment" in detected_categories:
            hits.append("toxicity_harassment")
        if "discrimination" in detected_categories:
            hits.append("toxicity_discrimination")
        if "profanity" in detected_categories:
            hits.append("toxicity_profanity")

        # Severity-based signals
        if max_severity >= 0.9:
            hits.append("toxicity_high_severity")
        elif max_severity >= 0.7:
            hits.append("toxicity_medium_severity")
        else:
            hits.append("toxicity_low_severity")

        # High density (multiple toxic keywords)
        if len(keywords_found) >= 2:
            hits.append("toxicity_high_density")
            if len(keywords_found) >= 3:
                hits.append("toxicity_very_high_density")

    return hits


def detect_toxicity_patterns(text: str) -> List[str]:
    """
    Detect toxic patterns (phrases, not just keywords).

    Returns:
        List of signal hits
    """
    hits = []
    text_lower = text.lower()

    # Threat patterns
    threat_patterns = [
        (r"kill\s+yourself", "en", 1.0),
        (r"you\s+should\s+die", "en", 0.9),
        (r"hope\s+you\s+die", "en", 0.8),
        (r"wish\s+you\s+were\s+dead", "en", 0.8),
    ]

    # Hate speech patterns
    hate_patterns = [
        (r"i\s+hate\s+you", "en", 0.8),
        (r"you\s+are\s+worthless", "en", 0.7),
        (r"nobody\s+loves\s+you", "en", 0.6),
    ]

    all_patterns = threat_patterns + hate_patterns

    for pattern, lang, severity in all_patterns:
        if re.search(pattern, text_lower, re.IGNORECASE):
            hits.append(f"toxicity_pattern_{lang}")
            if severity >= 0.9:
                hits.append("toxicity_high_severity")

    return hits


def scan_toxicity(text: str) -> List[str]:
    """
    Main function: Detect toxic content in multiple languages.

    Returns:
        Combined list of all toxicity signal hits
    """
    hits = []

    hits.extend(detect_toxicity_keywords(text))
    hits.extend(detect_toxicity_patterns(text))

    return hits


# Quick test
if __name__ == "__main__":
    import io
    import sys

    # Windows cp1252 fix
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

    test_cases = [
        ("kill yourself", "English threat"),
        ("mátate", "Spanish threat"),
        ("tue-toi", "French threat"),
        ("töte dich", "German threat"),
        ("убей себя", "Russian threat"),
        ("去死", "Chinese threat"),
        ("死ね", "Japanese threat"),
        ("اقتل نفسك", "Arabic threat"),
        ("खुद को मार", "Hindi threat"),
        ("자살해", "Korean threat"),
        ("normal text", "Benign text"),
    ]

    print("Multilingual Toxicity Detection Test")
    print("=" * 60)

    for i, (test, desc) in enumerate(test_cases, 1):
        hits = scan_toxicity(test)

        print(f"\n[{i}] {desc}")
        print(f"    Signals: {hits if hits else 'NONE'}")
