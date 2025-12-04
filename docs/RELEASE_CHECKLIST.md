# Release Checklist - PyPI Publishing

**Target:** PyPI Release today
**Version:** 5.0.0rc1
**Date:** 2025-12-01

---

## Pre-Release (15 minutes)

### 1. Verify Package Contents

```bash
# Check what will be included
python -m build
twine check dist/*
```

**Verify:**
- [ ] README.md included
- [ ] QUICKSTART.md included
- [ ] LICENSE included
- [ ] Examples included
- [ ] No sensitive data (credentials, tokens)

### 2. Test Local Installation

```bash
# Build package
python -m build

# Install from local build
pip install dist/llm_security_firewall-5.0.0rc1-py3-none-any.whl

# Test import
python -c "from llm_firewall import guard; print('✅ Import OK')"

# Run quickstart
python examples/quickstart.py
```

**Verify:**
- [ ] Import works
- [ ] Quickstart runs
- [ ] Guard API works

---

## Test PyPI Upload (30 minutes)

### Step 1: Create Test PyPI Account (if needed)

1. Go to: https://test.pypi.org/account/register/
2. Create account
3. Get API token: Account Settings → API tokens → Create token
4. Copy token (starts with `pypi-`)

### Step 2: Configure Credentials

Create `~/.pypirc` (or `%USERPROFILE%\.pypirc` on Windows):

```ini
[distutils]
index-servers =
    testpypi

[testpypi]
repository = https://test.pypi.org/legacy/
username = __token__
password = pypi-<YOUR-TEST-TOKEN-HERE>
```

**Security:** `.pypirc` is already in `.gitignore` - never commit!

### Step 3: Upload to Test PyPI

```bash
# Clean previous builds
rm -rf dist/ build/ *.egg-info

# Build package
python -m build

# Validate
twine check dist/*

# Upload to Test PyPI
twine upload --repository testpypi dist/*
```

### Step 4: Test Installation from Test PyPI

```bash
# Install from Test PyPI
pip install --index-url https://test.pypi.org/simple/ llm-security-firewall

# Test import
python -c "from llm_firewall import guard; print('✅ Import OK')"

# Run quickstart
python examples/quickstart.py

# Test guard API
python -c "
from llm_firewall import guard
result = guard.check_input('Hello')
print(f'✅ Guard API works: {result.allowed}')
"
```

**Verify:**
- [ ] Package installs successfully
- [ ] All imports work
- [ ] Examples run
- [ ] Guard API works

---

## Production PyPI Upload (10 minutes)

**⚠️ ONLY if Test PyPI validation succeeded!**

### Step 1: Create Production PyPI Account (if needed)

1. Go to: https://pypi.org/account/register/
2. Create account
3. Get API token: Account Settings → API tokens → Create token
4. Copy token (starts with `pypi-`)

### Step 2: Update Credentials

Add to `~/.pypirc`:

```ini
[distutils]
index-servers =
    pypi
    testpypi

[pypi]
repository = https://upload.pypi.org/legacy/
username = __token__
password = pypi-<YOUR-PRODUCTION-TOKEN-HERE>

[testpypi]
repository = https://test.pypi.org/legacy/
username = __token__
password = pypi-<YOUR-TEST-TOKEN-HERE>
```

### Step 3: Upload to Production PyPI

```bash
# Build fresh package (important!)
rm -rf dist/ build/ *.egg-info
python -m build

# Validate
twine check dist/*

# Upload to Production PyPI
twine upload dist/*
```

### Step 4: Verify on PyPI

1. Check package page: https://pypi.org/project/llm-security-firewall/
2. Verify all files are present
3. Test installation from production PyPI:

```bash
# Wait 5-10 minutes for indexing
pip install llm-security-firewall

# Test
python -c "from llm_firewall import guard; print('✅ Success!')"
python examples/quickstart.py
```

---

## Post-Release (First 48 Hours)

### Hour 0-2: Immediate Actions

- [ ] Create GitHub Release with changelog
- [ ] Update README.md with PyPI badge
- [ ] Test installation from fresh virtual environment

### Hour 2-4: Community Launch

- [ ] Hacker News "Show HN" post
- [ ] Reddit: r/Python, r/MachineLearning
- [ ] Twitter/X post with code snippet

### Day 1-2: Engagement

- [ ] Monitor GitHub Issues
- [ ] Answer questions quickly
- [ ] Fix critical bugs immediately

### Day 2-3: Content

- [ ] Blog post (medium/dev.to)
- [ ] YouTube video (optional)
- [ ] External references

---

## Quick Command Reference

```bash
# Build package
python -m build

# Validate package
twine check dist/*

# Upload to Test PyPI
twine upload --repository testpypi dist/*

# Upload to Production PyPI
twine upload dist/*

# Test installation
pip install --index-url https://test.pypi.org/simple/ llm-security-firewall  # Test PyPI
pip install llm-security-firewall  # Production PyPI

# Test package
python -c "from llm_firewall import guard; print('OK')"
python examples/quickstart.py
```

---

## Troubleshooting

### "File already exists"
- Version already published
- Increment version in `pyproject.toml` and `__init__.py`

### "401 Unauthorized"
- Check `.pypirc` credentials
- Verify API token is correct
- Token must start with `pypi-`

### "Package not found" after upload
- Wait 5-10 minutes for PyPI indexing
- Check package name spelling
- Verify upload succeeded

### "ImportError" after installation
- Check package contents with `pip show llm-security-firewall`
- Verify `__init__.py` exports are correct
- Test in fresh virtual environment

---

**Status:** ✅ Ready for Release
**Last Updated:** 2025-12-01
