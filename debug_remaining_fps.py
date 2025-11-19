"""Debug remaining 10 FPs"""
from src.llm_firewall.pipeline.context import detect_documentation_context, is_exec_context, is_exploit_context

fps = [
    # Removed private PROJECT_HUB references for public sync
    # "reports/AUTOMATED_MONITORING_COMPLETE_20251006.md",  # Example path
    # "reports/SCIENTIFIC_ANTI_GAMING_100_PERCENT_COMPLETE.md",  # Example path
    ".\\data\\README_datacard.md",
    ".\\integration_snippet.txt",
    ".\\src\\llm_security_firewall.egg-info\\entry_points.txt",
]

for f in fps:
    try:
        content = open(f, encoding='utf-8', errors='ignore').read()[:1000]
        ctx_meta = detect_documentation_context(content)
        ctx = ctx_meta['ctx']
        is_ex = is_exec_context(content, ctx)
        is_exp = is_exploit_context(content, ctx)
        
        print(f"\n{f.split('\\')[-1]}:")
        print(f"  Ctx: {ctx}, Score: {ctx_meta['score']}")
        print(f"  is_exec: {is_ex}, is_exploit: {is_exp}")
        print(f"  Would bypass? {ctx == 'documentation' and not is_ex and not is_exp}")
    except Exception as e:
        print(f"{f}: ERROR {e}")

