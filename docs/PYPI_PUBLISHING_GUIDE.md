# PyPI Publishing Guide

**Purpose:** Step-by-step guide for publishing LLM Security Firewall to PyPI.

---

## Prerequisites

### 1. PyPI Accounts

Create accounts on both Test PyPI and Production PyPI:

- **Test PyPI:** https://test.pypi.org/account/register/
- **Production PyPI:** https://pypi.org/account/register/

**Note:** These are separate accounts. You need to register separately.

### 2. Install Publishing Tools

```bash
pip install build twine
```

### 3. Configure Credentials

Create `~/.pypirc` file (or `%USERPROFILE%\.pypirc` on Windows):

```ini
[distutils]
index-servers =
    pypi
    testpypi

[pypi]
repository = https://upload.pypi.org/legacy/
username = __token__
password = pypi-<your-production-token>

[testpypi]
repository = https://test.pypi.org/legacy/
username = __token__
password = pypi-<your-test-token>
```

**Get API Tokens:**
1. Log in to PyPI (or Test PyPI)
2. Go to Account Settings → API tokens
3. Create a new token (scope: entire account)
4. Copy the token (starts with `pypi-`)

---

## Publishing Process

### Step 1: Test PyPI (Recommended First)

**Purpose:** Validate package build and installation before production release.

**Using Script (Recommended):**
```bash
# Linux/macOS
chmod +x scripts/publish_to_pypi.sh
./scripts/publish_to_pypi.sh test

# Windows PowerShell
.\scripts\publish_to_pypi.ps1 test
```

**Manual Process:**
```bash
# 1. Clean previous builds
rm -rf dist/ build/ *.egg-info

# 2. Build package
python -m build

# 3. Validate package
twine check dist/*

# 4. Upload to Test PyPI
twine upload --repository testpypi dist/*
```

**Verify Installation:**
```bash
pip install --index-url https://test.pypi.org/simple/ llm-security-firewall

# Test quickstart
python -c "from llm_firewall import guard; print('✅ Import successful')"
python examples/quickstart.py
```

---

### Step 2: Production PyPI

**Only proceed if Test PyPI validation succeeds!**

**Using Script:**
```bash
# Linux/macOS
./scripts/publish_to_pypi.sh production

# Windows PowerShell
.\scripts\publish_to_pypi.ps1 production
```

**Manual Process:**
```bash
# 1. Clean previous builds
rm -rf dist/ build/ *.egg-info

# 2. Build package
python -m build

# 3. Validate package
twine check dist/*

# 4. Upload to Production PyPI
twine upload dist/*
```

**Verify Installation:**
```bash
pip install llm-security-firewall

# Test quickstart
python -c "from llm_firewall import guard; print('✅ Import successful')"
python examples/quickstart.py
```

---

## Package Versioning

**Current Version:** `5.0.0rc1` (Release Candidate 1)

**Versioning Strategy:**
- **Major (5.x.x):** Breaking API changes
- **Minor (x.0.x):** New features, backward compatible
- **Patch (x.x.0):** Bug fixes, backward compatible
- **Release Candidate (rc1, rc2):** Pre-release versions

**Before Publishing:**
1. Update version in `pyproject.toml`:
   ```toml
   version = "5.0.0rc1"  # or "5.0.0" for production
   ```

2. Update version in `src/llm_firewall/__init__.py`:
   ```python
   __version__ = "5.0.0rc1"  # Match pyproject.toml
   ```

3. Update `CHANGELOG.md` with release notes

---

## Pre-Publishing Checklist

Before publishing, verify:

- [ ] **Version updated** in `pyproject.toml` and `__init__.py`
- [ ] **CHANGELOG.md** updated with release notes
- [ ] **README.md** is accurate and up-to-date
- [ ] **QUICKSTART.md** is included and working
- [ ] **Examples** run successfully (`python examples/quickstart.py`)
- [ ] **Tests pass** (`pytest tests/ -v`)
- [ ] **No sensitive data** in package (no credentials, tokens, etc.)
- [ ] **MANIFEST.in** includes all necessary files
- [ ] **Dependencies** are correctly listed in `pyproject.toml`
- [ ] **Package builds** without errors (`python -m build`)
- [ ] **Package validates** (`twine check dist/*`)

---

## Post-Publishing

### 1. Verify Installation

```bash
# Create fresh virtual environment
python -m venv test_env
source test_env/bin/activate  # or `test_env\Scripts\activate` on Windows

# Install from PyPI
pip install llm-security-firewall

# Test import
python -c "from llm_firewall import guard; print('✅ Success')"

# Run quickstart
python examples/quickstart.py
```

### 2. Announce Release

- **GitHub Release:** Create release tag and notes
- **Documentation:** Update installation instructions
- **Community:** Announce in GitHub Discussions (if enabled)

### 3. Monitor

- Check PyPI stats for downloads
- Monitor GitHub Issues for installation problems
- Track package health on PyPI

---

## Troubleshooting

### Build Errors

**Error: "No module named 'build'"**
```bash
pip install build
```

**Error: "Invalid distribution name"**
- Check `pyproject.toml` name field (must match PyPI naming rules)
- Use lowercase, hyphens only

### Upload Errors

**Error: "HTTP 401 Unauthorized"**
- Check `.pypirc` credentials
- Verify API token is correct
- Ensure token has proper scope

**Error: "File already exists"**
- Version already published
- Increment version number

**Error: "Repository not found"**
- Check repository URL in `.pypirc`
- Verify `--repository` flag matches configured server

### Installation Errors

**Error: "Package not found"**
- Wait 5-10 minutes after upload (PyPI indexing)
- Check package name spelling
- Verify package was uploaded successfully

**Error: "Dependencies not found"**
- Check `pyproject.toml` dependencies
- Verify all dependencies are on PyPI
- Test dependencies locally first

---

## Security Considerations

1. **API Tokens:** Never commit `.pypirc` to git (add to `.gitignore`)
2. **Credentials:** Use environment variables or secure storage
3. **Package Contents:** Review `MANIFEST.in` to ensure no secrets included
4. **Dependencies:** Audit dependencies for security vulnerabilities

---

## References

- **PyPI Documentation:** https://packaging.python.org/en/latest/guides/distributing-packages-using-setuptools/
- **Test PyPI:** https://test.pypi.org/
- **Production PyPI:** https://pypi.org/
- **Twine Documentation:** https://twine.readthedocs.io/

---

**Status:** Ready for Publishing
**Last Updated:** 2025-12-01
