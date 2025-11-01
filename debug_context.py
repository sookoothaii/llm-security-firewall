"""Debug context detection"""
from src.llm_firewall.pipeline.context import detect_documentation_context, is_exec_context
import glob

files = glob.glob('..\\..\\docs\\*.md')[:10]

for f in files:
    try:
        content = open(f, encoding='utf-8', errors='ignore').read()[:1000]
        ctx = detect_documentation_context(content)
        is_ex = is_exec_context(content, ctx['ctx'])  # Pass context!
        print(f"\n{f}:")
        print(f"  Context: {ctx['ctx']}")
        print(f"  Score: {ctx['score']} (len={ctx['length']}, fences={ctx['fences']}, heads={ctx['headers']}, toks={ctx['doc_tokens']})")
        print(f"  Is Exec: {is_ex}")
    except Exception as e:
        print(f"{f}: ERROR {e}")

