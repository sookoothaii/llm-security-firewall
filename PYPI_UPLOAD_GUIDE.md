# PyPI Upload Guide - llm-security-firewall v5.0.0-rc1

**Package Built:** 2025-10-31  
**Creator:** Joerg Bollwahn  
**Build Status:** ✅ SUCCESS

---

## Package Files Ready

The following distribution files are in `dist/`:

```
llm_security_firewall-5.0.0rc1.tar.gz  (source distribution)
llm_security_firewall-5.0.0rc1-py3-none-any.whl  (wheel, platform-independent)
```

---

## Option A: TestPyPI (RECOMMENDED FIRST)

TestPyPI is a separate instance for testing. Safe to experiment!

### 1. Create TestPyPI Account

Visit: https://test.pypi.org/account/register/

### 2. Create API Token

1. Go to: https://test.pypi.org/manage/account/token/
2. Click "Add API token"
3. Name: `llm-security-firewall-test`
4. Scope: "Entire account" (for first upload) or specific project
5. **COPY TOKEN** (starts with `pypi-...`) - only shown once!

### 3. Upload to TestPyPI

```bash
# Navigate to project
cd "D:\MCP Mods\HAK_GAL_HEXAGONAL\standalone_packages\llm-security-firewall"

# Activate venv
.\.venv_hexa\Scripts\Activate.ps1

# Upload (will prompt for token)
twine upload --repository testpypi dist/*
```

When prompted:
- Username: `__token__`
- Password: `pypi-...` (your TestPyPI token)

### 4. Test Install from TestPyPI

```bash
# In a clean environment
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ llm-security-firewall

# Note: --extra-index-url needed for dependencies (numpy, scipy, etc.)
```

### 5. Verify Installation

```bash
python -c "import llm_firewall; print(llm_firewall.__version__)"
# Should print: 5.0.0rc1

llm-firewall --version
```

---

## Option B: Production PyPI (AFTER TestPyPI Success)

⚠️ **CAUTION:** This uploads to the REAL PyPI. Package name will be permanently reserved.

### 1. Create PyPI Account

Visit: https://pypi.org/account/register/

### 2. Create API Token

1. Go to: https://pypi.org/manage/account/token/
2. Click "Add API token"
3. Name: `llm-security-firewall-prod`
4. Scope: "Entire account" (for first upload) or specific project
5. **COPY TOKEN** - only shown once!

### 3. Upload to PyPI

```bash
# Navigate to project
cd "D:\MCP Mods\HAK_GAL_HEXAGONAL\standalone_packages\llm-security-firewall"

# Activate venv
.\.venv_hexa\Scripts\Activate.ps1

# Upload
twine upload dist/*
```

When prompted:
- Username: `__token__`
- Password: `pypi-...` (your Production PyPI token)

### 4. Install from PyPI

```bash
pip install llm-security-firewall
```

### 5. Package Will Be Available At:

- https://pypi.org/project/llm-security-firewall/
- `pip install llm-security-firewall` works globally

---

## Package Metadata

**From pyproject.toml:**

```toml
name = "llm-security-firewall"
version = "5.0.0rc1"
description = "Bidirectional Security Framework for Human/LLM Interfaces - 9 Core + 27 Hardening Layers, 597 Tests (100% PASS), MyPy Clean, CI GREEN"
authors = [{name = "Joerg Bollwahn", email = "info@hakgal.org"}]
license = {text = "MIT"}
requires-python = ">=3.12"
```

**Keywords:**
- llm, security, firewall, ai-safety
- adversarial-robustness, memory-poisoning
- evidence-validation, dempster-shafer, conformal-prediction

**Classifiers:**
- Development Status :: 4 - Beta
- License :: OSI Approved :: MIT License
- Programming Language :: Python :: 3.12/3.13/3.14/3.15
- Topic :: Security
- Topic :: Scientific/Engineering :: Artificial Intelligence

---

## After Upload: Update README

### Installation Section (after PyPI upload)

Replace:
```markdown
# Install from source
git clone https://github.com/sookoothaii/llm-security-firewall
cd llm-security-firewall
pip install -e .
```

With:
```markdown
# Install from PyPI
pip install llm-security-firewall

# Or install from source
git clone https://github.com/sookoothaii/llm-security-firewall
cd llm-security-firewall
pip install -e .
```

---

## Troubleshooting

### "The user 'username' isn't allowed to upload"

- Use `__token__` (with underscores) as username, NOT your PyPI username

### "File already exists"

- Package version already uploaded
- Cannot re-upload same version
- Increment version in `pyproject.toml` (e.g., `5.0.0rc2`)
- Rebuild: `python -m build`

### "Invalid distribution"

- Check `pyproject.toml` syntax
- Verify all required fields present
- Run: `twine check dist/*` (validates before upload)

### License Warnings (seen during build)

These are WARNINGS, not ERRORS:
```
SetuptoolsDeprecationWarning: `project.license` as a TOML table is deprecated
SetuptoolsDeprecationWarning: License classifiers are deprecated
```

**Fix (optional, not blocking):**

Change in `pyproject.toml`:
```toml
# FROM:
license = {text = "MIT"}

# TO:
license = "MIT"  # Simple string (requires setuptools>=77.0.0)
```

And remove classifier:
```toml
# REMOVE this line:
"License :: OSI Approved :: MIT License",
```

---

## Current Status

**Built:** ✅ dist/ contains .tar.gz and .whl  
**Committed:** ✅ pyproject.toml v5.0.0rc1 in git  
**Pushed:** ✅ GitHub updated  

**Next Steps:**
1. Upload to TestPyPI (test run)
2. Verify install works
3. If successful, upload to Production PyPI
4. Update README with `pip install` instructions
5. Announce release!

---

## Security Notes

**API Tokens:**
- Store securely (password manager)
- Never commit to git
- Can be revoked anytime in PyPI account settings

**Package Scope:**
- Release Candidate (rc1) signals "not final production"
- 8 P0 Blockers documented in README (transparent)
- Users informed via classifiers: `Development Status :: 4 - Beta`

---

**Autonome Entscheidung:** TestPyPI FIRST empfohlen per "Spatz in der Hand" Philosophie.

**Package bereit für Upload - Joerg's Credentials benötigt!**

