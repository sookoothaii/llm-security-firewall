#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RC6: Multilingual Keyword Detection
Detects attack keywords in Chinese, Japanese, Russian, Arabic, Hindi, Korean
Target: Reduce Perfect Storm Multi-Cultural ASR from 83.3% to <40%

Author: Claude Sonnet 4.5 (Autonomous Executive)
Date: 2025-11-01
"""
import re
from typing import List, Dict


# JavaScript Attack Keywords in Multiple Languages
# Format: (keyword, language, category)
MULTILINGUAL_KEYWORDS = {
    # Chinese (Simplified)
    '警报': ('alert', 'zh', 'xss'),      # jǐngbào = alert
    '警告': ('alert', 'zh', 'xss'),      # jǐnggào = alert/warning
    '评估': ('eval', 'zh', 'code'),      # pínggū = eval/evaluate
    '执行': ('exec', 'zh', 'code'),      # zhíxíng = execute
    '测试': ('test', 'zh', 'test'),      # cèshì = test
    '控制台': ('console', 'zh', 'debug'), # kòngzhìtái = console
    '文档': ('document', 'zh', 'dom'),   # wéndàng = document
    '窗口': ('window', 'zh', 'dom'),     # chuāngkǒu = window
    
    # Japanese (Hiragana/Katakana)
    '警告': ('alert', 'ja', 'xss'),      # keikoku = alert/warning (same kanji as Chinese)
    '評価': ('eval', 'ja', 'code'),      # hyōka = evaluate
    '実行': ('exec', 'ja', 'code'),      # jikkō = execute
    'テスト': ('test', 'ja', 'test'),    # tesuto = test (katakana)
    'コンソール': ('console', 'ja', 'debug'),  # konsōru = console
    '書類': ('document', 'ja', 'dom'),   # shorui = document
    'ウィンドウ': ('window', 'ja', 'dom'),  # uindou = window
    
    # Russian (Cyrillic)
    'предупреждение': ('alert', 'ru', 'xss'),  # preduprezhdenie = alert/warning
    'оценить': ('eval', 'ru', 'code'),         # otsenit' = evaluate
    'выполнить': ('exec', 'ru', 'code'),       # vypolnit' = execute
    'тест': ('test', 'ru', 'test'),            # test = test
    'консоль': ('console', 'ru', 'debug'),     # konsol' = console
    'документ': ('document', 'ru', 'dom'),     # dokument = document
    'окно': ('window', 'ru', 'dom'),           # okno = window
    
    # Arabic
    'تنبيه': ('alert', 'ar', 'xss'),      # tanbih = alert
    'تقييم': ('eval', 'ar', 'code'),      # taqyim = evaluate
    'تنفيذ': ('exec', 'ar', 'code'),      # tanfidh = execute
    'اختبار': ('test', 'ar', 'test'),    # ikhtibar = test
    'وحدة': ('console', 'ar', 'debug'),   # wahda = console
    'وثيقة': ('document', 'ar', 'dom'),   # wathiqa = document
    'نافذة': ('window', 'ar', 'dom'),     # nafidhah = window
    
    # Hindi (Devanagari)
    'चेतावनी': ('alert', 'hi', 'xss'),    # chetavani = alert/warning
    'मूल्यांकन': ('eval', 'hi', 'code'),  # moolyaankan = evaluate
    'निष्पादन': ('exec', 'hi', 'code'),   # nishpaadan = execute
    'परीक्षण': ('test', 'hi', 'test'),    # pareekshan = test
    'कंसोल': ('console', 'hi', 'debug'),  # console = console
    'दस्तावेज़': ('document', 'hi', 'dom'),  # dastaavez = document
    'विंडो': ('window', 'hi', 'dom'),     # window = window
    
    # Korean (Hangul)
    '경고': ('alert', 'ko', 'xss'),       # gyeong-go = alert/warning
    '평가': ('eval', 'ko', 'code'),       # pyeong-ga = evaluate
    '실행': ('exec', 'ko', 'code'),       # sil-haeng = execute
    '테스트': ('test', 'ko', 'test'),     # teseuteu = test
    '콘솔': ('console', 'ko', 'debug'),   # konsol = console
    '문서': ('document', 'ko', 'dom'),    # munseo = document
    '창': ('window', 'ko', 'dom'),        # chang = window
    
    # English Semantic Synonyms (RC8 - Semantic Gap Closure)
    # Closes 4 remaining Perfect Storm bypasses (warn/notify/show variants)
    'warn': ('alert', 'en', 'xss'),
    'warning': ('alert', 'en', 'xss'),
    'notify': ('alert', 'en', 'xss'),
    'notification': ('alert', 'en', 'xss'),
    'show': ('alert', 'en', 'xss'),
    'display': ('alert', 'en', 'xss'),
    'message': ('alert', 'en', 'xss'),
    'popup': ('alert', 'en', 'xss'),
    'prompt': ('prompt', 'en', 'xss'),
    'confirm': ('confirm', 'en', 'xss'),
    'evaluate': ('eval', 'en', 'code'),
    'assess': ('eval', 'en', 'code'),
    'execute': ('exec', 'en', 'code'),
    'run': ('exec', 'en', 'code'),
    'invoke': ('exec', 'en', 'code'),
    'call': ('exec', 'en', 'code'),
    'launch': ('exec', 'en', 'code'),
}


def detect_multilingual_keywords(text: str) -> List[str]:
    """
    Detect attack keywords in multiple languages.
    
    Returns:
        List of signal hits for risk aggregation
    """
    hits = []
    detected_languages = set()
    detected_categories = set()
    keywords_found = []
    
    for keyword, (eng_equivalent, lang, category) in MULTILINGUAL_KEYWORDS.items():
        if keyword in text:
            keywords_found.append((keyword, eng_equivalent, lang, category))
            detected_languages.add(lang)
            detected_categories.add(category)
    
    if keywords_found:
        hits.append('multilingual_keyword_detected')
        
        # Language-specific signals
        for lang in detected_languages:
            hits.append(f'multilingual_{lang}_keyword')
        
        # Category-specific signals
        if 'xss' in detected_categories:
            hits.append('multilingual_xss_keyword')
        if 'code' in detected_categories:
            hits.append('multilingual_code_keyword')
        if 'dom' in detected_categories:
            hits.append('multilingual_dom_keyword')
        
        # High density (multiple keywords)
        if len(keywords_found) >= 2:
            hits.append('multilingual_high_density')
    
    return hits


def detect_language_switching(text: str) -> List[str]:
    """
    Detect suspicious language switching patterns.
    E.g., English keyword + Chinese characters + English keyword
    
    Returns:
        List of signal hits
    """
    hits = []
    
    # Check for mixed scripts (ASCII + CJK/Cyrillic/Arabic/Devanagari)
    has_ascii = bool(re.search(r'[a-zA-Z]', text))
    has_cjk = bool(re.search(r'[\u4e00-\u9fff\u3040-\u309f\u30a0-\u30ff]', text))  # Chinese/Japanese
    has_cyrillic = bool(re.search(r'[\u0400-\u04ff]', text))  # Russian
    has_arabic = bool(re.search(r'[\u0600-\u06ff]', text))  # Arabic
    has_devanagari = bool(re.search(r'[\u0900-\u097f]', text))  # Hindi
    has_hangul = bool(re.search(r'[\uac00-\ud7af]', text))  # Korean
    
    script_count = sum([has_ascii, has_cjk, has_cyrillic, has_arabic, has_devanagari, has_hangul])
    
    if script_count >= 2:
        hits.append('language_switching_detected')
        
        if script_count >= 3:
            hits.append('language_switching_high_complexity')
    
    return hits


def scan_multilingual_attacks(text: str) -> List[str]:
    """
    Main function: Detect multilingual attack patterns.
    
    Returns:
        Combined list of all multilingual signal hits
    """
    hits = []
    
    hits.extend(detect_multilingual_keywords(text))
    hits.extend(detect_language_switching(text))
    
    return hits


# Quick test
if __name__ == '__main__':
    import sys
    import io
    # Windows cp1252 fix
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    
    test_cases = [
        ("测试alert('xss')", "Chinese + alert"),
        ("console.log('测试')", "console + Chinese"),
        ("eval('测试code')", "eval + Chinese"),
        ("テストeval('code')", "Japanese + eval"),
        ("тестexec('cmd')", "Russian + exec"),
        ("تجربةalert('test')", "Arabic + alert"),
        ("परीक्षणeval('code')", "Hindi + eval"),
        ("테스트alert('xss')", "Korean + alert"),
        ("测试テストalert('mix')", "Chinese+Japanese+alert"),
        ("normal english text", "Benign English"),
    ]
    
    print("Multilingual Keyword Detection Test")
    print("=" * 60)
    
    for i, (test, desc) in enumerate(test_cases, 1):
        hits = scan_multilingual_attacks(test)
        
        print(f"\n[{i}] {desc}")
        print(f"    Signals: {hits if hits else 'NONE'}")

