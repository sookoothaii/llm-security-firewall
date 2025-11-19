---
title: "Extensions Screenshot 20250814"
created: "2025-09-15T00:08:01.041612Z"
author: "system-cleanup"
topics: ["meta"]
tags: ["auto-generated"]
privacy: "internal"
summary_200: |-
  Auto-generated frontmatter. Document requires review.
---

### Erweiterungen (Executable Stubs) – 2025-08-14

Speicherort: `scripts/extensions/`

1) Code-Generator
   - `code_generator.py`
   - Aufruf: `python scripts/extensions/code_generator.py src/my_mod.py --function run`
   - Output: erzeugt Boilerplate-Funktion

2) Database Migration
   - `db_migration.py`
   - Aufruf: `python scripts/extensions/db_migration.py data/k_assistant.db migrations/001.sql`
   - Output: Migration angewendet

3) Performance Profiler
   - `perf_profiler.py`
   - Aufruf: `python scripts/extensions/perf_profiler.py scripts.slack.post_kb_status --func main`
   - Output: `perf_profile.stats` + Top-Liste

4) Documentation Generator
   - `doc_generator.py`
   - Aufruf: `python scripts/extensions/doc_generator.py PROJECT_HUB/*.md --out PROJECT_HUB/DOCS_INDEX.md`
   - Output: Übersichtsindex

5) Test Data Generator
   - `test_data_generator.py`
   - Aufruf: `python scripts/extensions/test_data_generator.py --count 50 --out PROJECT_HUB/test_facts.jsonl`
   - Output: JSONL-Testdaten

6) API Mock Server
   - `api_mock_server.py`
   - Aufruf: `python scripts/extensions/api_mock_server.py` (http://127.0.0.1:5999)
   - Output: Mock-Endpunkte

7) Log Analyzer
   - `log_analyzer.py`
   - Aufruf: `python scripts/extensions/log_analyzer.py mcp_server.log`
   - Output: Fehler-/Warnungszählung

8) Dependency Checker
   - `dependency_checker.py`
   - Aufruf: `python scripts/extensions/dependency_checker.py --pip --npm`
   - Output: Pip/NPM-Bericht

9) Security Scanner
   - `security_scanner.py`
   - Aufruf: `python scripts/extensions/security_scanner.py --path .`
   - Output: Bandit-Scan

10) Metric Dashboard
    - `metric_dashboard.py`
    - Aufruf: `python scripts/extensions/metric_dashboard.py`
    - Output: `PROJECT_HUB/grafana_dashboard.json`


