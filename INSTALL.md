# Installation Guide

## For Users (pip install - when published)

```bash
pip install llm-security-firewall
```

## For Developers (from source)

### 1. Clone Repository

```bash
git clone https://github.com/yourusername/llm-security-firewall
cd llm-security-firewall
```

### 2. Install Dependencies

```bash
# Create virtual environment
python -m venv venv

# Activate (Windows)
.\venv\Scripts\Activate.ps1

# Activate (Linux/Mac)
source venv/bin/activate

# Install package in editable mode
pip install -e .

# Or install dependencies manually
pip install -r requirements.txt
```

### 3. Database Setup

#### PostgreSQL (Production)

```bash
# Create database
createdb llm_firewall

# Run migrations in order
psql -U your_user -d llm_firewall -f migrations/postgres/001_evidence_tables.sql
psql -U your_user -d llm_firewall -f migrations/postgres/002_caches.sql
psql -U your_user -d llm_firewall -f migrations/postgres/003_procedures.sql
psql -U your_user -d llm_firewall -f migrations/postgres/004_influence_budget.sql

# Verify
psql -U your_user -d llm_firewall -c "\dt"
```

#### SQLite (Development - coming in v1.1)

SQLite support planned for v1.1. For now, use PostgreSQL.

### 4. Configuration

```bash
# Copy example config
cp config/evidence_pipeline.yaml config/my_config.yaml

# Edit with your settings
# - Database URL
# - Thresholds
# - Domain lists
```

### 5. Verify Installation

```bash
# Run tests (if you copied them)
pytest tests/ -v

# Or run example
python examples/01_basic_usage.py

# Or use CLI
llm-firewall health-check
```

---

## Dependencies

### Required
- Python 3.12+
- numpy >= 1.24.0
- scipy >= 1.11.0
- pyyaml >= 6.0
- blake3 >= 0.3.0
- requests >= 2.31.0
- psycopg[binary] >= 3.1.0

### Optional
- prometheus-client >= 0.17.0 (for monitoring)
- pytest >= 7.4.0 (for development)

---

## Quick Test

```python
from llm_firewall import SecurityFirewall, FirewallConfig

config = FirewallConfig(config_dir="config")
firewall = SecurityFirewall(config)

# Should work!
is_safe, reason = firewall.validate_input("Hello, world!")
print(f"Safe: {is_safe}, Reason: {reason}")
```

---

## Troubleshooting

### "Module 'blake3' not found"
```bash
pip install blake3
```

### "Can't connect to database"
- Check PostgreSQL is running
- Verify connection string in config
- Test with: `psql -U user -d dbname`

### "Import errors"
- Ensure you're in virtual environment
- Run `pip install -e .` in repo root

---

## Support

- GitHub Issues: https://github.com/yourusername/llm-security-firewall/issues
- Documentation: `/docs`
- Examples: `/examples`


