## Summary
- What changed (short bullets)

## Evidence
- Attach `ablation.json` (CI artifact)
- Key deltas vs. A0:
  - ΔASR@Youden:
  - AUROC:
  - ECE:
  - Brier:

## Risk & Rollback
- Feature flags / env toggles
- Safe fallback path

## Checklist
- [ ] Canonicalizer in hot path
- [ ] Floors.json derived from benign set
- [ ] CI ablation gate passed
