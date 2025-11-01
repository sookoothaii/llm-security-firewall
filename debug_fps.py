"""Debug false positives"""
from src.llm_firewall.pipeline.context import detect_documentation_context, is_exec_context, is_exploit_context

# Files that still get blocked
fp_files = [
    "..\\..\\PROJECT_HUB\\reports\\AUTOMATED_MONITORING_COMPLETE_20251006.md",
    ".\\DEPLOYMENT_SUMMARY.md",
    ".\\BYPASSES_FOUND_2025_10_31.md",
    "..\\..\\PROJECT_HUB\\reports\\SECURITY_HARDENING_COMPLETE_20251006.md",
]

for f in fp_files:
    try:
        content = open(f, encoding='utf-8', errors='ignore').read()[:1000]
        ctx = detect_documentation_context(content)
        is_ex = is_exec_context(content, ctx['ctx'])
        is_exp = is_exploit_context(content)
        
        print(f"\n{f}:")
        print(f"  Context: {ctx['ctx']}, Score: {ctx['score']}")
        print(f"  Is Exec: {is_ex}, Is Exploit: {is_exp}")
        print(f"  Length: {ctx['length']}, Fences: {ctx['fences']}, Headers: {ctx['headers']}, DocToks: {ctx['doc_tokens']}")
        print(f"  Would block? {ctx['ctx'] != 'documentation' or is_ex or is_exp}")
    except Exception as e:
        print(f"{f}: ERROR {e}")

