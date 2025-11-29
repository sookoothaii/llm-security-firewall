# Docker Deployment Guide

**LLM Security Firewall** - Production deployment with Docker and PostgreSQL.

---

## Quick Start

### 1. Build Container

```bash
docker build -t llm-security-firewall:1.0.0 .
```text
### 2. Run with Docker Compose

```bash
# Set database password
export DB_PASSWORD="your-secure-password"

# Start all services (Firewall + PostgreSQL + Prometheus)
docker-compose up -d

# Check logs
docker-compose logs -f firewall

# Run health check
docker exec llm-security-firewall llm-firewall health-check
```text
### 3. Database Migrations

```bash
# Migrations run automatically on first start
# To manually run migrations:
docker exec -it llm-firewall-db psql -U firewall_user -d llm_firewall -f /docker-entrypoint-initdb.d/001_evidence_tables.sql
```text
---

## Services

### Firewall Container
- **Port:** Internal only (connects to PostgreSQL)
- **Command:** `llm-firewall health-check`
- **Config:** `/app/config` (mounted read-only)
- **Logs:** `/app/logs` (mounted for persistence)

### PostgreSQL
- **Port:** 5432 (exposed to host)
- **Database:** `llm_firewall`
- **Migrations:** Auto-run from `/docker-entrypoint-initdb.d`

### Prometheus
- **Port:** 9090
- **Config:** `monitoring/prometheus.yml`
- **Alerts:** `monitoring/alert_rules.yaml`

---

## Production Deployment

### Environment Variables

Create `.env` file:
```bash
DB_PASSWORD=<strong-password>
DB_HOST=postgres
DB_PORT=5432
DB_NAME=llm_firewall
DB_USER=firewall_user
```text
### Security Hardening

1. **Non-root user:** Container runs as `firewall` user (UID 1000)
2. **Read-only config:** Config mounted with `:ro` flag
3. **Network isolation:** Services in dedicated Docker network
4. **Secrets management:** Use Docker secrets for credentials

```bash
# Create secret
echo "my-secure-password" | docker secret create db_password -

# Update docker-compose.yml to use secrets
```text
### Resource Limits

```yaml
services:
  firewall:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '1.0'
          memory: 512M
```text
---

## Health Checks

### Container Health Check

```yaml
healthcheck:
  test: ["CMD", "llm-firewall", "health-check"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 40s
```text
### Manual Health Check

```bash
docker exec llm-security-firewall llm-firewall health-check
```text
---

## Monitoring

### Prometheus Metrics

Access Prometheus UI:
```bash
open http://localhost:9090
```text
Available metrics:
- `firewall_validation_total` - Total validations
- `firewall_block_rate` - Block/Gate rate
- `firewall_latency_ms` - Processing latency
- `firewall_canary_failures` - Drift detection

### Logs

```bash
# Follow logs
docker-compose logs -f firewall

# Export logs
docker logs llm-security-firewall > firewall.log 2>&1
```text
---

## CLI Commands in Container

```bash
# Validate input
docker exec llm-security-firewall llm-firewall validate "Test query"

# Check safety
docker exec llm-security-firewall llm-firewall check-safety "Query"

# Run canaries
docker exec llm-security-firewall llm-firewall run-canaries --sample-size 10

# Show alerts
docker exec llm-security-firewall llm-firewall show-alerts --domain SCIENCE
```text
---

## Troubleshooting

### Database Connection Issues

```bash
# Check PostgreSQL is running
docker-compose ps postgres

# Test connection
docker exec llm-firewall-db psql -U firewall_user -d llm_firewall -c "\dt"

# View PostgreSQL logs
docker-compose logs postgres
```text
### Performance Issues

```bash
# Check resource usage
docker stats llm-security-firewall

# Increase memory limit in docker-compose.yml
```text
### Migration Failures

```bash
# Re-run migrations manually
docker exec -it llm-firewall-db psql -U firewall_user -d llm_firewall
\i /docker-entrypoint-initdb.d/001_evidence_tables.sql
```text
---

## Scaling

### Horizontal Scaling

```yaml
services:
  firewall:
    deploy:
      replicas: 3
      update_config:
        parallelism: 1
        delay: 10s
```text
### Load Balancing

Use Nginx or Traefik as reverse proxy:
```nginx
upstream firewall_backend {
    server firewall:8080;
    server firewall:8081;
    server firewall:8082;
}
```text
---

## Backup & Recovery

### Database Backup

```bash
# Backup database
docker exec llm-firewall-db pg_dump -U firewall_user llm_firewall > backup.sql

# Restore database
docker exec -i llm-firewall-db psql -U firewall_user llm_firewall < backup.sql
```text
### Configuration Backup

```bash
# Backup configs
tar -czf config-backup.tar.gz config/ monitoring/

# Restore
tar -xzf config-backup.tar.gz
```text
---

## Production Checklist

- [ ] Set strong `DB_PASSWORD` in `.env`
- [ ] Enable container health checks
- [ ] Configure resource limits
- [ ] Setup log rotation
- [ ] Enable Prometheus monitoring
- [ ] Configure alert notifications
- [ ] Setup database backups (automated)
- [ ] Test kill-switch procedure
- [ ] Document rollback procedure
- [ ] Enable SSL/TLS for PostgreSQL

---

## Support

**Issues:** GitHub Issues
**Documentation:** `/docs`
**Examples:** `/examples`

**Creator:** Joerg Bollwahn
**License:** MIT
