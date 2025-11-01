#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RC7: Indirect Execution Detection
Detects indirect JavaScript execution patterns that bypass direct keyword detection
DeepSeek Gap: window['al'+'ert'], Function constructor, prototype pollution, etc.
"""
import re
from typing import List


def detect_indirect_execution(text: str) -> List[str]:
    """Detect indirect execution patterns"""
    hits = []
    
    # Pattern 1: Bracket notation with string concat
    # window['al'+'ert'], globalThis['ev'+'al']
    if re.search(r"(window|globalThis|self|top|parent)\s*\[\s*['\"][\w]+['\"]\s*\+\s*['\"]", text, re.IGNORECASE):
        hits.append('indirect_bracket_concat')
    
    # Pattern 2: Array join to build function name
    # ['a','l','e','r','t'].join('')
    if re.search(r"\[['\"][a-z]['\"],\s*['\"][a-z]['\"]\s*[,\]].+?\.join\s*\(", text, re.IGNORECASE):
        hits.append('indirect_array_join')
    
    # Pattern 3: Function constructor
    # Function('alert'), new Function('eval')
    if re.search(r"\bFunction\s*\(", text):
        hits.append('indirect_function_constructor')
    
    # Pattern 4: setTimeout/setInterval with string
    # setTimeout('alert(1)'), setInterval('eval(x)')
    if re.search(r"\b(setTimeout|setInterval)\s*\(\s*['\"]", text):
        hits.append('indirect_timer_string')
    
    # Pattern 5: setTimeout/setInterval call/apply
    # setTimeout.call(null, 'alert')
    if re.search(r"\b(setTimeout|setInterval)\.(call|apply)\s*\(", text):
        hits.append('indirect_timer_call_apply')
    
    # Pattern 6: Location href assignment
    # location.href = 'javascript:', location['href']
    if re.search(r"\blocation\s*(\[['\"]\w+['\"]\]|\.\w+)\s*=\s*['\"]javascript:", text, re.IGNORECASE):
        hits.append('indirect_location_href')
    
    # Pattern 7: Dynamic import
    # import('http://'), import('data:')
    if re.search(r"\bimport\s*\(\s*['\"]", text):
        hits.append('indirect_dynamic_import')
    
    # Pattern 8: Prototype pollution
    # Object.prototype.x = 'alert'
    if re.search(r"\bObject\.prototype\.\w+\s*=", text):
        hits.append('indirect_prototype_pollution')
    
    # Pattern 9: Event handler assignment
    # document.addEventListener, onload = function
    if re.search(r"\b(addEventListener|on\w+\s*=)", text):
        hits.append('indirect_event_handler')
    
    # Pattern 10: Eval variants
    # eval.call, eval.apply, eval['call']
    if re.search(r"\beval\s*\.\s*(call|apply)", text):
        hits.append('indirect_eval_call_apply')
    
    # Pattern 11: With statement (deprecated but dangerous)
    # with(document) { write('xss') }
    if re.search(r"\bwith\s*\(", text):
        hits.append('indirect_with_statement')
    
    # Pattern 12: Template literals with evaluation
    # ${alert(1)}, ${eval(x)}
    if re.search(r"\$\{.*(alert|eval|exec|Function)\s*\(", text, re.IGNORECASE):
        hits.append('indirect_template_literal')
    
    return hits


def detect_multimodal_context(text: str) -> List[str]:
    """Detect multi-modal attack contexts (SVG/MathML/CSS)"""
    hits = []
    
    # SVG context
    if re.search(r"<svg\b", text, re.IGNORECASE):
        hits.append('multimodal_svg_context')
        
        # SVG script tag
        if re.search(r"<svg[^>]*>.*?<script", text, re.IGNORECASE | re.DOTALL):
            hits.append('multimodal_svg_script')
        
        # SVG onload/onclick
        if re.search(r"<svg[^>]*\bon(load|click|error)", text, re.IGNORECASE):
            hits.append('multimodal_svg_event')
    
    # MathML context
    if re.search(r"<math\b", text, re.IGNORECASE):
        hits.append('multimodal_mathml_context')
        
        # MathML with script
        if re.search(r"<math[^>]*>.*?<script", text, re.IGNORECASE | re.DOTALL):
            hits.append('multimodal_mathml_script')
        
        # MathML action
        if re.search(r"<maction\b", text, re.IGNORECASE):
            hits.append('multimodal_mathml_action')
    
    # CSS import attacks
    if re.search(r"@import\s+['\"]?(javascript:|data:|http)", text, re.IGNORECASE):
        hits.append('multimodal_css_import')
    
    # CSS expression (IE legacy)
    if re.search(r"\bexpression\s*\(", text, re.IGNORECASE):
        hits.append('multimodal_css_expression')
    
    # CSS url() with javascript
    if re.search(r"url\s*\(\s*['\"]?javascript:", text, re.IGNORECASE):
        hits.append('multimodal_css_url_javascript')
    
    # Style tag + script combo
    if re.search(r"<style\b.*?<script\b", text, re.IGNORECASE | re.DOTALL):
        hits.append('multimodal_style_script_combo')
    
    # Cross-modal escalation (SVG importing external)
    if re.search(r"<svg[^>]*>.*?(import|href|src)\s*=", text, re.IGNORECASE | re.DOTALL):
        hits.append('multimodal_svg_external_ref')
    
    return hits


def scan_indirect_and_multimodal(text: str) -> List[str]:
    """Combined scanner for RC7 gaps"""
    hits = []
    hits.extend(detect_indirect_execution(text))
    hits.extend(detect_multimodal_context(text))
    return hits


if __name__ == '__main__':
    import sys
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    
    tests = [
        ("window['al'+'ert']('x')", "Bracket concat"),
        ("['a','l','e','r','t'].join('')", "Array join"),
        ("Function('alert(1)')", "Function constructor"),
        ("setTimeout('alert(1)')", "setTimeout string"),
        ("import('data:text/javascript,alert(1)')", "Dynamic import"),
        ("<svg><script>alert(1)</script></svg>", "SVG script"),
        ("<math><script>eval('x')</script></math>", "MathML script"),
        ("@import 'javascript:alert(1)'", "CSS import"),
        ("normal code", "Benign"),
    ]
    
    print("Indirect Execution + Multi-Modal Detection Test")
    print("=" * 60)
    
    for i, (test, desc) in enumerate(tests, 1):
        hits = scan_indirect_and_multimodal(test)
        print(f"\n[{i}] {desc}")
        print(f"    Signals: {hits if hits else 'NONE'}")

