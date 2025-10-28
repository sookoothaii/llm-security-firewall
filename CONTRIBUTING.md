# Contributing to LLM Security Firewall

Thank you for your interest in contributing! This project follows scientific rigor and production quality standards.

## Development Principles

1. **100% Test Coverage** - All new code must include tests
2. **Persona/Epistemik Separation** - Personality affects tone only, never security thresholds
3. **Heritage Preservation** - Creator attribution required in all files
4. **Privacy-First** - No personal data in repository, users provide their own databases

## Getting Started

### Prerequisites

- Python >= 3.12
- PostgreSQL (for database tests)
- Git

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/sookoothaii/llm-security-firewall
cd llm-security-firewall

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
pytest -q --cov=llm_firewall --cov-report=xml
```

## Contribution Guidelines

### Code Style

- Follow PEP 8 conventions
- Use type hints for all functions
- Maximum line length: 100 characters
- Use Ruff for linting: `ruff check .`
- Use MyPy for type checking: `mypy src/llm_firewall`

### Testing Requirements

All contributions must include:

1. **Unit Tests** - Test individual functions/classes
2. **Integration Tests** - Test layer interactions
3. **Red Team Tests** - For new attack vectors, add corresponding defense tests
4. **Coverage** - Maintain 100% coverage for critical paths

Example test structure:

```python
def test_new_feature():
    # Arrange
    config = FirewallConfig(...)
    firewall = SecurityFirewall(config)
    
    # Act
    result = firewall.new_feature(input_data)
    
    # Assert
    assert result.is_safe
    assert result.confidence > 0.8
```

### Commit Messages

Follow conventional commits format:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Test additions/changes
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `chore`: Maintenance tasks

Example:
```
feat(evidence): add BLAKE3 hashing for content verification

Implements BLAKE3-based content hashing to replace SHA-256 for
improved performance in high-throughput scenarios.

Closes #123
```

### Pull Request Process

1. **Fork** the repository
2. **Create branch** from `main`: `git checkout -b feat/your-feature`
3. **Implement changes** with tests
4. **Run full test suite**: `pytest -q --cov=llm_firewall`
5. **Run linter**: `ruff check .`
6. **Run type checker**: `mypy src/llm_firewall`
7. **Update documentation** if needed
8. **Submit PR** with clear description

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Red team tests added (if applicable)
- [ ] All tests pass

## Checklist
- [ ] Code follows style guidelines
- [ ] 100% test coverage maintained
- [ ] Documentation updated
- [ ] Commit messages follow conventions
- [ ] Heritage attribution preserved
```

## Adding New Defense Layers

When adding a new defense layer:

1. **Create module** in appropriate package (e.g., `src/llm_firewall/trust/`)
2. **Implement layer logic** with clear interfaces
3. **Add configuration** in `config/*.yaml`
4. **Write comprehensive tests** (unit + integration + red team)
5. **Update documentation** (README.md, docs/)
6. **Add monitoring metrics** (Prometheus alerts if applicable)

Example layer structure:

```python
from llm_firewall.utils.types import ValidationResult

class NewDefenseLayer:
    """Brief description of defense mechanism.
    
    Scientific foundation: [Citation]
    Attack vectors addressed: [List]
    """
    
    def __init__(self, config: dict):
        self.threshold = config.get("threshold", 0.8)
    
    def validate(self, input_data: str) -> ValidationResult:
        """Validate input against defense criteria.
        
        Args:
            input_data: Text to validate
            
        Returns:
            ValidationResult with decision and confidence
        """
        # Implementation
        pass
```

## Adding New Attack Vectors

Red team tests are critical for validating defenses:

1. **Create test file** in `tests/red_team/`
2. **Implement attack** with clear documentation
3. **Test defense mechanisms** against attack
4. **Document expected behavior** in docstrings

Example red team test:

```python
def test_new_attack_vector():
    """Test defense against [Attack Name].
    
    Attack Description:
    [Detailed description of attack mechanism]
    
    Expected Defense:
    [Which layers should detect/block this attack]
    """
    firewall = SecurityFirewall(config)
    
    # Attempt attack
    result = firewall.validate_input(malicious_input)
    
    # Verify defense
    assert not result.is_safe
    assert "expected_reason" in result.reason
```

## Documentation

- Update README.md for user-facing changes
- Add docstrings for all public functions/classes
- Update CHANGELOG.md for notable changes
- Create/update docs/ for architectural changes

## Code of Conduct

Be respectful, constructive, and professional in all interactions. See CODE_OF_CONDUCT.md for details.

## Questions?

- Open a GitHub Discussion for general questions
- Open a GitHub Issue for bugs/feature requests
- Email security@sookoothaii.github.io for security concerns

## License

By contributing, you agree that your contributions will be licensed under the MIT License, with creator attribution required per project heritage policy.

---

**Heritage Attribution:**

This project was created by Joerg Bollwahn as part of the HAK/GAL research initiative. All contributions must preserve creator attribution in derivative works.

