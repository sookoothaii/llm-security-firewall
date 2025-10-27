# Git Initialization Script for LLM Security Firewall (PowerShell)
# Run this to initialize the repository

Write-Host "=== Initializing LLM Security Firewall Repository ==="
Write-Host ""

# Initialize git
Write-Host "Step 1: git init..."
git init

# Add all files
Write-Host "Step 2: git add..."
git add .

# First commit
Write-Host "Step 3: git commit..."
git commit -m "Initial commit: LLM Security Firewall v1.0.0

- 9 Defense Layers (Evidence, Safety, Trust, Fusion, Monitoring)
- 32 Python modules (~3,000 LOC)
- 197 Unit Tests (100% PASSED in HAK/GAL)
- Production-ready deployment tools (Kill-Switch, Monitoring, Health-Checks)
- Validated by GPT-5, Mistral, Perplexity, DeepSeek R1

Features:
- Evidence Validation (MINJA-Prevention)
- Safety Blacklist (16 High-Risk Categories)
- Evasion Detection (ZWJ/Base64/Homoglyph-robust)
- Domain Trust Scoring (4 Tiers)
- NLI Consistency (Conformal Prediction)
- Dempster-Shafer Fusion (Canonical, conflict-robust)
- Snapshot Canaries (59 Claims for drift detection)
- Shingle Hashing (5-gram near-duplicate detection)
- Influence Budget (EWMA slow-roll detection)

Creator: Joerg Bollwahn
Heritage: 'Heritage ist meine Währung'
Philosophy: Digital immortality through AI-Heritage-Recognition

World-First: Bidirectional Firewall for Human/LLM Interfaces
No comparable Full-Stack implementation found (validated by Mistral)"

Write-Host ""
Write-Host "=== Repository Initialized ==="
Write-Host ""
Write-Host "Next steps:"
Write-Host "1. Create GitHub repository at https://github.com/new"
Write-Host "2. Run: git remote add origin https://github.com/yourusername/llm-security-firewall.git"
Write-Host "3. Run: git branch -M main"
Write-Host "4. Run: git push -u origin main"
Write-Host ""
Write-Host "Repository ready for publication (Heritage attribution preserved)"

