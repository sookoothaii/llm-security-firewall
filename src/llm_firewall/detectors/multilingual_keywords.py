#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RC6: Multilingual Keyword Detection (Extended to 17+ Languages)
Detects attack keywords in 17+ languages covering PolygloToxicityPrompts dataset
Target: Reduce PolygloToxicityPrompts ASR from 46.5% to <10%

Supported Languages:
- Asian: Chinese (zh), Japanese (ja), Korean (ko), Hindi (hi), Thai (th), Vietnamese (vi), Indonesian (id), Malay (ms)
- European: Russian (ru), Spanish (es), French (fr), German (de), Italian (it), Portuguese (pt), Polish (pl), Dutch (nl), Greek (el), Maltese (mt), Basque (eu)
- Middle Eastern: Arabic (ar), Hebrew (he)
- English: Semantic synonyms (en)

Author: Claude Sonnet 4.5 (Autonomous Executive)
Date: 2025-11-01 (RC6), 2025-12-05 (Extended to 17+ languages)
"""

import re
from typing import List

# JavaScript Attack Keywords in Multiple Languages
# Format: (keyword, language, category)
MULTILINGUAL_KEYWORDS = {
    # Chinese (Simplified)
    "警报": ("alert", "zh", "xss"),  # jǐngbào = alert
    "警告": ("alert", "zh", "xss"),  # jǐnggào = alert/warning
    "评估": ("eval", "zh", "code"),  # pínggū = eval/evaluate
    "执行": ("exec", "zh", "code"),  # zhíxíng = execute
    "测试": ("test", "zh", "test"),  # cèshì = test
    "控制台": ("console", "zh", "debug"),  # kòngzhìtái = console
    "文档": ("document", "zh", "dom"),  # wéndàng = document
    "窗口": ("window", "zh", "dom"),  # chuāngkǒu = window
    # Japanese (Hiragana/Katakana)
    # Note: 警告 shared with Chinese (same kanji), covered above
    "評価": ("eval", "ja", "code"),  # hyōka = evaluate
    "実行": ("exec", "ja", "code"),  # jikkō = execute
    "テスト": ("test", "ja", "test"),  # tesuto = test (katakana)
    "コンソール": ("console", "ja", "debug"),  # konsōru = console
    "書類": ("document", "ja", "dom"),  # shorui = document
    "ウィンドウ": ("window", "ja", "dom"),  # uindou = window
    # Russian (Cyrillic)
    "предупреждение": ("alert", "ru", "xss"),  # preduprezhdenie = alert/warning
    "оценить": ("eval", "ru", "code"),  # otsenit' = evaluate
    "выполнить": ("exec", "ru", "code"),  # vypolnit' = execute
    "тест": ("test", "ru", "test"),  # test = test
    "консоль": ("console", "ru", "debug"),  # konsol' = console
    "документ": ("document", "ru", "dom"),  # dokument = document
    "окно": ("window", "ru", "dom"),  # okno = window
    # Arabic
    "تنبيه": ("alert", "ar", "xss"),  # tanbih = alert
    "تقييم": ("eval", "ar", "code"),  # taqyim = evaluate
    "تنفيذ": ("exec", "ar", "code"),  # tanfidh = execute
    "اختبار": ("test", "ar", "test"),  # ikhtibar = test
    "وحدة": ("console", "ar", "debug"),  # wahda = console
    "وثيقة": ("document", "ar", "dom"),  # wathiqa = document
    "نافذة": ("window", "ar", "dom"),  # nafidhah = window
    # Hindi (Devanagari)
    "चेतावनी": ("alert", "hi", "xss"),  # chetavani = alert/warning
    "मूल्यांकन": ("eval", "hi", "code"),  # moolyaankan = evaluate
    "निष्पादन": ("exec", "hi", "code"),  # nishpaadan = execute
    "परीक्षण": ("test", "hi", "test"),  # pareekshan = test
    "कंसोल": ("console", "hi", "debug"),  # console = console
    "दस्तावेज़": ("document", "hi", "dom"),  # dastaavez = document
    "विंडो": ("window", "hi", "dom"),  # window = window
    # Korean (Hangul)
    "경고": ("alert", "ko", "xss"),  # gyeong-go = alert/warning
    "평가": ("eval", "ko", "code"),  # pyeong-ga = evaluate
    "실행": ("exec", "ko", "code"),  # sil-haeng = execute
    "테스트": ("test", "ko", "test"),  # teseuteu = test
    "콘솔": ("console", "ko", "debug"),  # konsol = console
    "문서": ("document", "ko", "dom"),  # munseo = document
    "창": ("window", "ko", "dom"),  # chang = window
    # English Semantic Synonyms (RC8 - Semantic Gap Closure)
    # Closes 4 remaining Perfect Storm bypasses (warn/notify/show variants)
    "warn": ("alert", "en", "xss"),
    "warning": ("alert", "en", "xss"),
    "notify": ("alert", "en", "xss"),
    "notification": ("alert", "en", "xss"),
    "show": ("alert", "en", "xss"),
    "display": ("alert", "en", "xss"),
    "message": ("alert", "en", "xss"),
    "popup": ("alert", "en", "xss"),
    "prompt": ("prompt", "en", "xss"),
    "confirm": ("confirm", "en", "xss"),
    "evaluate": ("eval", "en", "code"),
    "assess": ("eval", "en", "code"),
    "execute": ("exec", "en", "code"),
    "run": ("exec", "en", "code"),
    "invoke": ("exec", "en", "code"),
    "call": ("exec", "en", "code"),
    "launch": ("exec", "en", "code"),
    "trigger": ("fire", "en", "event"),  # RC8.2: trigger statt fire
    # Spanish (es)
    "alerta": ("alert", "es", "xss"),  # alerta = alert
    "advertencia": ("alert", "es", "xss"),  # advertencia = warning
    "evaluar": ("eval", "es", "code"),  # evaluar = evaluate
    "ejecutar": ("exec", "es", "code"),  # ejecutar = execute
    "prueba": ("test", "es", "test"),  # prueba = test
    "consola": ("console", "es", "debug"),  # consola = console
    "documento": ("document", "es", "dom"),  # documento = document
    "ventana": ("window", "es", "dom"),  # ventana = window
    # French (fr)
    "alerte": ("alert", "fr", "xss"),  # alerte = alert
    "avertissement": ("alert", "fr", "xss"),  # avertissement = warning
    "évaluer": ("eval", "fr", "code"),  # évaluer = evaluate
    "exécuter": ("exec", "fr", "code"),  # exécuter = execute
    "test": ("test", "fr", "test"),  # test = test
    "console": ("console", "fr", "debug"),  # console = console
    "document": ("document", "fr", "dom"),  # document = document
    "fenêtre": ("window", "fr", "dom"),  # fenêtre = window
    # German (de)
    "warnung": ("alert", "de", "xss"),  # warnung = alert/warning
    "alarm": ("alert", "de", "xss"),  # alarm = alert
    "auswerten": ("eval", "de", "code"),  # auswerten = evaluate
    "ausführen": ("exec", "de", "code"),  # ausführen = execute
    "test": ("test", "de", "test"),  # test = test
    "konsole": ("console", "de", "debug"),  # konsole = console
    "dokument": ("document", "de", "dom"),  # dokument = document
    "fenster": ("window", "de", "dom"),  # fenster = window
    # Italian (it)
    "allerta": ("alert", "it", "xss"),  # allerta = alert
    "avviso": ("alert", "it", "xss"),  # avviso = warning
    "valutare": ("eval", "it", "code"),  # valutare = evaluate
    "eseguire": ("exec", "it", "code"),  # eseguire = execute
    "test": ("test", "it", "test"),  # test = test
    "console": ("console", "it", "debug"),  # console = console
    "documento": ("document", "it", "dom"),  # documento = document
    "finestra": ("window", "it", "dom"),  # finestra = window
    # Portuguese (pt)
    "alerta": ("alert", "pt", "xss"),  # alerta = alert
    "aviso": ("alert", "pt", "xss"),  # aviso = warning
    "avaliar": ("eval", "pt", "code"),  # avaliar = evaluate
    "executar": ("exec", "pt", "code"),  # executar = execute
    "teste": ("test", "pt", "test"),  # teste = test
    "console": ("console", "pt", "debug"),  # console = console
    "documento": ("document", "pt", "dom"),  # documento = document
    "janela": ("window", "pt", "dom"),  # janela = window
    # Turkish (tr)
    "uyarı": ("alert", "tr", "xss"),  # uyarı = alert/warning
    "değerlendir": ("eval", "tr", "code"),  # değerlendir = evaluate
    "çalıştır": ("exec", "tr", "code"),  # çalıştır = execute
    "test": ("test", "tr", "test"),  # test = test
    "konsol": ("console", "tr", "debug"),  # konsol = console
    "belge": ("document", "tr", "dom"),  # belge = document
    "pencere": ("window", "tr", "dom"),  # pencere = window
    # Polish (pl)
    "ostrzeżenie": ("alert", "pl", "xss"),  # ostrzeżenie = alert/warning
    "ocenić": ("eval", "pl", "code"),  # ocenić = evaluate
    "wykonać": ("exec", "pl", "code"),  # wykonać = execute
    "test": ("test", "pl", "test"),  # test = test
    "konsola": ("console", "pl", "debug"),  # konsola = console
    "dokument": ("document", "pl", "dom"),  # dokument = document
    "okno": ("window", "pl", "dom"),  # okno = window
    # Dutch (nl)
    "waarschuwing": ("alert", "nl", "xss"),  # waarschuwing = alert/warning
    "evalueren": ("eval", "nl", "code"),  # evalueren = evaluate
    "uitvoeren": ("exec", "nl", "code"),  # uitvoeren = execute
    "test": ("test", "nl", "test"),  # test = test
    "console": ("console", "nl", "debug"),  # console = console
    "document": ("document", "nl", "dom"),  # document = document
    "venster": ("window", "nl", "dom"),  # venster = window
    # Greek (el)
    "ειδοποίηση": ("alert", "el", "xss"),  # eidopoíisi = alert/notification
    "αξιολόγηση": ("eval", "el", "code"),  # axiológisi = evaluate
    "εκτέλεση": ("exec", "el", "code"),  # ektélesi = execute
    "δοκιμή": ("test", "el", "test"),  # dokimí = test
    "κονσόλα": ("console", "el", "debug"),  # konsóla = console
    "έγγραφο": ("document", "el", "dom"),  # éngrafo = document
    "παράθυρο": ("window", "el", "dom"),  # paráthyro = window
    # Hebrew (he)
    "התראה": ("alert", "he", "xss"),  # hatra'ah = alert
    "הערכה": ("eval", "he", "code"),  # ha'arakhah = evaluate
    "ביצוע": ("exec", "he", "code"),  # bitzua = execute
    "בדיקה": ("test", "he", "test"),  # bdikah = test
    "קונסולה": ("console", "he", "debug"),  # konsolah = console
    "מסמך": ("document", "he", "dom"),  # mismakh = document
    "חלון": ("window", "he", "dom"),  # chalon = window
    # Thai (th)
    "แจ้งเตือน": ("alert", "th", "xss"),  # jaeng teun = alert
    "ประเมิน": ("eval", "th", "code"),  # pramoen = evaluate
    "ดำเนินการ": ("exec", "th", "code"),  # damnoen kan = execute
    "ทดสอบ": ("test", "th", "test"),  # thotsop = test
    "คอนโซล": ("console", "th", "debug"),  # konsol = console
    "เอกสาร": ("document", "th", "dom"),  # eksan = document
    "หน้าต่าง": ("window", "th", "dom"),  # na taang = window
    # Vietnamese (vi)
    "cảnh báo": ("alert", "vi", "xss"),  # cảnh báo = alert/warning
    "đánh giá": ("eval", "vi", "code"),  # đánh giá = evaluate
    "thực thi": ("exec", "vi", "code"),  # thực thi = execute
    "kiểm tra": ("test", "vi", "test"),  # kiểm tra = test
    "bảng điều khiển": ("console", "vi", "debug"),  # bảng điều khiển = console
    "tài liệu": ("document", "vi", "dom"),  # tài liệu = document
    "cửa sổ": ("window", "vi", "dom"),  # cửa sổ = window
    # Indonesian (id)
    "peringatan": ("alert", "id", "xss"),  # peringatan = alert/warning
    "mengevaluasi": ("eval", "id", "code"),  # mengevaluasi = evaluate
    "menjalankan": ("exec", "id", "code"),  # menjalankan = execute
    "uji": ("test", "id", "test"),  # uji = test
    "konsol": ("console", "id", "debug"),  # konsol = console
    "dokumen": ("document", "id", "dom"),  # dokumen = document
    "jendela": ("window", "id", "dom"),  # jendela = window
    # Malay (ms)
    "amaran": ("alert", "ms", "xss"),  # amaran = alert/warning
    "menilai": ("eval", "ms", "code"),  # menilai = evaluate
    "menjalankan": ("exec", "ms", "code"),  # menjalankan = execute
    "ujian": ("test", "ms", "test"),  # ujian = test
    "konsol": ("console", "ms", "debug"),  # konsol = console
    "dokumen": ("document", "ms", "dom"),  # dokumen = document
    "tingkap": ("window", "ms", "dom"),  # tingkap = window
    # Maltese (mt)
    "twissija": ("alert", "mt", "xss"),  # twissija = alert/warning
    "tevalwa": ("eval", "mt", "code"),  # tevalwa = evaluate
    "esegwi": ("exec", "mt", "code"),  # esegwi = execute
    "test": ("test", "mt", "test"),  # test = test
    "konsol": ("console", "mt", "debug"),  # konsol = console
    "dokument": ("document", "mt", "dom"),  # dokument = document
    "tieqa": ("window", "mt", "dom"),  # tieqa = window
    # Basque (eu)
    "alerta": ("alert", "eu", "xss"),  # alerta = alert
    "ebaluatu": ("eval", "eu", "code"),  # ebaluatu = evaluate
    "exekutatu": ("exec", "eu", "code"),  # exekutatu = execute
    "proba": ("test", "eu", "test"),  # proba = test
    "kontsola": ("console", "eu", "debug"),  # kontsola = console
    "dokumentua": ("document", "eu", "dom"),  # dokumentua = document
    "leihoa": ("window", "eu", "dom"),  # leihoa = window
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
        hits.append("multilingual_keyword_detected")

        # Language-specific signals
        for lang in detected_languages:
            hits.append(f"multilingual_{lang}_keyword")

        # Category-specific signals
        if "xss" in detected_categories:
            hits.append("multilingual_xss_keyword")
        if "code" in detected_categories:
            hits.append("multilingual_code_keyword")
        if "dom" in detected_categories:
            hits.append("multilingual_dom_keyword")

        # High density (multiple keywords)
        if len(keywords_found) >= 2:
            hits.append("multilingual_high_density")

    return hits


def detect_language_switching(text: str) -> List[str]:
    """
    Detect suspicious language switching patterns.
    E.g., English keyword + Chinese characters + English keyword

    Returns:
        List of signal hits
    """
    hits = []

    # Check for mixed scripts (ASCII + CJK/Cyrillic/Arabic/Devanagari/Hebrew/Greek/Thai/Vietnamese)
    has_ascii = bool(re.search(r"[a-zA-Z]", text))
    has_cjk = bool(
        re.search(r"[\u4e00-\u9fff\u3040-\u309f\u30a0-\u30ff]", text)
    )  # Chinese/Japanese
    has_cyrillic = bool(re.search(r"[\u0400-\u04ff]", text))  # Russian
    has_arabic = bool(re.search(r"[\u0600-\u06ff]", text))  # Arabic
    has_devanagari = bool(re.search(r"[\u0900-\u097f]", text))  # Hindi
    has_hangul = bool(re.search(r"[\uac00-\ud7af]", text))  # Korean
    has_hebrew = bool(re.search(r"[\u0590-\u05ff]", text))  # Hebrew
    has_greek = bool(re.search(r"[\u0370-\u03ff]", text))  # Greek
    has_thai = bool(re.search(r"[\u0e00-\u0e7f]", text))  # Thai
    has_vietnamese = bool(
        re.search(r"[\u1ea0-\u1eff]", text)
    )  # Vietnamese (extended Latin)

    script_count = sum(
        [
            has_ascii,
            has_cjk,
            has_cyrillic,
            has_arabic,
            has_devanagari,
            has_hangul,
            has_hebrew,
            has_greek,
            has_thai,
            has_vietnamese,
        ]
    )

    if script_count >= 2:
        hits.append("language_switching_detected")

        if script_count >= 3:
            hits.append("language_switching_high_complexity")

    return hits


def detect_exec_verb_gated(text: str) -> List[str]:
    """
    Detect exec verbs (system, execute, run, invoke, launch)
    ONLY when used as function calls to avoid FPR.
    RC8.1 Fix for system() bypass.
    """
    import re

    FUNC_CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(", re.U)
    EXEC_VERB = re.compile(r"\b(system|execute|run|invoke|launch)\b", re.I)

    hits = []
    if EXEC_VERB.search(text) and FUNC_CALL.search(text):
        # Check if exec verb is actually in function call position
        for match in EXEC_VERB.finditer(text):
            verb = match.group(0)
            # Look ahead for opening paren
            rest = text[match.end() : match.end() + 10]
            if re.match(r"\s*\(", rest):
                hits.append("exec_verb_gated")
                break
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
    hits.extend(detect_exec_verb_gated(text))

    return hits


# Quick test
if __name__ == "__main__":
    import io
    import sys

    # Windows cp1252 fix
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

    test_cases = [
        ("测试alert('xss')", "Chinese + alert"),
        ("console.log('测试')", "console + Chinese"),
        ("eval('测试code')", "eval + Chinese"),
        ("テストeval('code')", "Japanese + eval"),
        ("тестexec('cmd')", "Russian + exec"),
        ("تجربةalert('test')", "Arabic + alert"),
        ("परीक्षणeval('code')", "Hindi + eval"),
        ("테스트alert('xss')", "Korean + alert"),
        ("alerta('xss')", "Spanish + alert"),
        ("alerte('xss')", "French + alert"),
        ("warnung('xss')", "German + alert"),
        ("allerta('xss')", "Italian + alert"),
        ("alerta('xss')", "Portuguese + alert"),
        ("uyarı('xss')", "Turkish + alert"),
        ("ostrzeżenie('xss')", "Polish + alert"),
        ("waarschuwing('xss')", "Dutch + alert"),
        ("ειδοποίηση('xss')", "Greek + alert"),
        ("התראה('xss')", "Hebrew + alert"),
        ("แจ้งเตือน('xss')", "Thai + alert"),
        ("cảnh báo('xss')", "Vietnamese + alert"),
        ("peringatan('xss')", "Indonesian + alert"),
        ("amaran('xss')", "Malay + alert"),
        ("twissija('xss')", "Maltese + alert"),
        ("alerta('xss')", "Basque + alert"),
        ("测试テストalert('mix')", "Chinese+Japanese+alert"),
        ("normal english text", "Benign English"),
    ]

    print("Multilingual Keyword Detection Test")
    print("=" * 60)

    for i, (test, desc) in enumerate(test_cases, 1):
        hits = scan_multilingual_attacks(test)

        print(f"\n[{i}] {desc}")
        print(f"    Signals: {hits if hits else 'NONE'}")
