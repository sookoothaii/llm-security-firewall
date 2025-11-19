# Lexicon Merge Pack
- `merge_lexicons.py` — Idempotent merger for regex arrays and intent clusters.
- `json_validate.py` — Quick checks (duplicates / required keys).

## Examples
Regex:
  python merge_lexicons.py merge-regex --base src/llm_firewall/regex_patterns_gpt5.json --patch src/llm_firewall/regex_patterns_gpt5.append.json --out src/llm_firewall/regex_patterns_gpt5.json --backup --apply

Intents:
  python merge_lexicons.py merge-intents --base src/llm_firewall/lexicons/intents.json --patch src/llm_firewall/lexicons/intents_patch.json --out src/llm_firewall/lexicons/intents.json --backup --apply

Validate:
  python json_validate.py src/llm_firewall/regex_patterns_gpt5.json src/llm_firewall/lexicons/intents.json
