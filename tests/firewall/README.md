# tests_firewall Directory

**Status:** Active (Legacy Test Suite)

**Purpose:** Contains legacy test files from earlier development phases (RC7-RC10). These tests focus on specific attack patterns and bypass scenarios.

**Contents:**
- RC10 test suites (`rc10/`, `rc10_2/`)
- Attack pattern tests (ultra_break variants, AST gating, OTB gates)
- Phase 2 FPR weight tests
- Short snippet doc handling tests

**Note:** These tests are maintained for regression testing but are not part of the main `tests/` suite. They may contain older API patterns and should be migrated to `tests/` when refactored.
