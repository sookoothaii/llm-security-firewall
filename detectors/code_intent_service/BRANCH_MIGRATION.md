# Feature-Branch Migration: Code Intent Detection Module

## Overview

This document describes the migration strategy for creating a feature branch for the Code Intent Detection module as a standalone experimental component.

**Branch:** `feature/code-intent-detection-standalone`  
**Parent Project:** LLM Security Firewall v2.5.0  
**Status:** Experimental standalone module

## Git Workflow

### Step 1: Create Feature Branch

```bash
# Ensure you're on main branch and up to date
git checkout main
git pull origin main

# Create and switch to feature branch
git checkout -b feature/code-intent-detection-standalone

# Push branch to remote
git push -u origin feature/code-intent-detection-standalone
```

### Step 2: Verify Branch Structure

```bash
# Verify branch was created
git branch -a

# Verify current branch
git status
```

### Step 3: Development Workflow

```bash
# Make changes to code_intent_service
# ... edit files ...

# Commit changes
git add detectors/code_intent_service/
git commit -m "feat: update code intent detection module"

# Push to feature branch
git push origin feature/code-intent-detection-standalone
```

### Step 4: Synchronization with Main

```bash
# Periodically sync with main branch
git checkout main
git pull origin main
git checkout feature/code-intent-detection-standalone
git merge main
# Resolve conflicts if any
git push origin feature/code-intent-detection-standalone
```

## Migration Checklist

### Code Organization

- [x] Code Intent Service located in `detectors/code_intent_service/`
- [x] Hexagonal architecture implemented
- [x] API layer (FastAPI) complete
- [x] Domain layer (entities, value objects, services)
- [x] Infrastructure layer (ML models, repositories, rule engines)
- [x] Application layer (services, use cases)

### Dependencies

- [x] `requirements.txt` in `detectors/code_intent_service/`
- [x] Core dependencies: fastapi, uvicorn, pydantic
- [x] Optional ML dependencies: transformers, torch (commented)
- [x] Metrics: prometheus-client (optional)

### Documentation

- [x] Architecture documentation (`ARCHITECTURE.md`)
- [x] API documentation (`README_API.md`)
- [x] Setup guides (`ENV_SETUP.md`, `START_SERVICE.md`)
- [x] Summary (`SUMMARY.md`)
- [x] Existing patterns (`EXISTING_PATTERNS.md`)

### Testing

- [x] Unit tests (`tests/unit/`)
- [x] Integration tests (`tests/integration/`)
- [x] Test scripts (`scripts/test_*.py`)

### Configuration

- [x] Environment setup scripts (`setup_env.py`, `setup_env_complete.py`)
- [x] Configuration settings (`infrastructure/config/settings.py`)
- [x] Composition root (`infrastructure/app/composition_root.py`)

## Future Evolution Options

This code may evolve in one of three ways:

1. **Merge back** into main LLM Security Firewall as an integrated module
2. **Split** into a separate repository (`llm-code-intent-detector`)
3. **Remain** as a long-lived branch with occasional synchronization

## Relationship to Parent Project

This module originated from the LLM Security Firewall as a specialized subsystem for detecting malicious code execution intents. While it shares architectural principles (hexagonal design, protocol-based adapters), it focuses specifically on:

- Hybrid ML/rule-based code intent detection
- 10 specialized benign validators
- CNN and CodeBERT model adapters
- Production REST API

## Installation (Experimental)

```bash
# Clone this specific branch
git clone -b feature/code-intent-detection-standalone https://github.com/sookoothaii/llm-security-firewall.git
cd llm-security-firewall/detectors/code_intent_service

# Install dependencies
pip install -r requirements.txt

# Setup environment
python setup_env_complete.py

# Start API server
python -m uvicorn api.main:app --reload --port 8000
```

## Notes

- This is an experimental branch and may be restructured in the future
- The module maintains compatibility with the parent project's architecture
- All dependencies are clearly documented in `requirements.txt`
- Configuration follows the same patterns as the parent project

