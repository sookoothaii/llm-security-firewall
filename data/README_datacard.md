# DataCard — Synthetic Ablation Set
Purpose: structural prompts to evaluate detection logic (patterns, intents, meta).

Composition:
- label=1: structural bypass phrasing (instruction-override, role-play, laundering, encoding/evasion)
- label=0: benign utility prompts + hard negatives

Fields: id,text,label,split,seed,source,tags
Splits: deterministic dev/test via seed
Dedup: trigram Jaccard (≥0.8 filtered)
