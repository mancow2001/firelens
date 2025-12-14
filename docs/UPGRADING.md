# Upgrading FireLens

This guide covers upgrading FireLens to a new version while preserving your configuration and data.

## Overview

FireLens is designed for non-destructive upgrades:

| Component | Location | Persistence |
|-----------|----------|-------------|
| Configuration | `/etc/firelens/config.yaml` | File (bind mount) |
| Database | `/var/lib/firelens/data/metrics.db` | Docker volume |
| Logs | `/var/log/firelens/` | Docker volume |
| Certificates | `/opt/firelens/certs/` | File (bind mount) |

**Key Features:**
- Automatic database schema migrations on startup
- Configuration file preserved across upgrades
- Metrics data retained during schema changes
- Schema version tracking for audit

---

## Pre-Upgrade Checklist

Before upgrading, complete these steps:

### 1. Check Current Version

```bash
# Docker
docker exec firelens python -c "import firelens; print(firelens.__version__)"

# Non-Docker
python -c "import firelens; print(firelens.__version__)"
```

### 2. Review Release Notes

Check the [changelog](../CHANGELOG.md) for breaking changes between your current version and the target version.

### 3. Backup Configuration

```bash
# Docker
cp ./config.yaml ./config.yaml.backup-$(date +%Y%m%d)

# Non-Docker
cp /path/to/config.yaml /path/to/config.yaml.backup-$(date +%Y%m%d)
```

### 4. Backup Database

```bash
# Docker - backup the data volume
docker run --rm \
  -v firelens_data:/data \
  -v $(pwd):/backup \
  ubuntu tar czf /backup/firelens-data-$(date +%Y%m%d).tar.gz /data

# Non-Docker
cp ./data/metrics.db ./data/metrics.db.backup-$(date +%Y%m%d)
```

### 5. Verify Backup Integrity

```bash
# Test that backup archive is valid
tar -tzf firelens-data-*.tar.gz | head

# Test database backup is valid
sqlite3 ./data/metrics.db.backup-* "SELECT COUNT(*) FROM metrics;"
```

---

## Docker Upgrade Procedure

### Standard Upgrade

```bash
# 1. Stop the running container
docker-compose down

# 2. Pull/build new image
docker-compose pull
# Or if building locally:
docker-compose build --no-cache

# 3. Start with new version
docker-compose up -d

# 4. Monitor startup logs for migration messages
docker-compose logs -f firelens
```

### Watch for Migration Messages

On startup, you should see messages like:
```
INFO  Database schema upgrade: v0 → v1
INFO  Schema version updated to 1: Multi-vendor support...
INFO  Database schema upgrade complete: now at v1
```

### Verify Upgrade Success

```bash
# Check version
docker exec firelens python -c "import firelens; print(firelens.__version__)"

# Check database schema version
docker exec firelens sqlite3 /var/lib/firelens/data/metrics.db \
  "SELECT version, description, applied_at FROM schema_version ORDER BY version;"

# Check health endpoint
curl http://localhost:8080/api/health

# Verify firewalls are loaded
curl http://localhost:8080/api/firewalls | jq '.count'
```

---

## Non-Docker Upgrade Procedure

### Using pip

```bash
# 1. Stop the service
systemctl stop firelens  # or your service manager

# 2. Upgrade package
pip install --upgrade firelens-monitor

# 3. Restart service
systemctl start firelens

# 4. Check logs
journalctl -u firelens -f
```

### From Source

```bash
# 1. Stop the service
systemctl stop firelens

# 2. Update source code
cd /path/to/firelens
git fetch origin
git checkout v1.6.2  # or desired version

# 3. Reinstall
pip install -e .

# 4. Restart
systemctl start firelens
```

---

## Rollback Procedure

If the upgrade fails, rollback using your backups:

### Docker Rollback

```bash
# 1. Stop container
docker-compose down

# 2. Restore config
cp ./config.yaml.backup-YYYYMMDD ./config.yaml

# 3. Restore data volume
docker run --rm \
  -v firelens_data:/data \
  -v $(pwd):/backup \
  ubuntu bash -c "rm -rf /data/* && tar xzf /backup/firelens-data-YYYYMMDD.tar.gz -C /"

# 4. Use previous image version
# Edit docker-compose.yml to specify previous version tag

# 5. Start
docker-compose up -d
```

### Non-Docker Rollback

```bash
# 1. Stop service
systemctl stop firelens

# 2. Restore config
cp ./config.yaml.backup-YYYYMMDD ./config.yaml

# 3. Restore database
cp ./data/metrics.db.backup-YYYYMMDD ./data/metrics.db

# 4. Downgrade package
pip install firelens-monitor==1.5.0  # previous version

# 5. Restart
systemctl start firelens
```

---

## Version-Specific Notes

### Upgrading to v1.6.x

**New Features:**
- Multi-vendor support (Fortinet FortiGate, Cisco Firepower)
- Vendor-specific metrics tables
- Schema version tracking

**Schema Changes:**
- Added `schema_version` table
- Added `fortinet_metrics` table
- Added `palo_alto_metrics` table
- Added `cisco_firepower_metrics` table

**Migration:** Automatic. No manual steps required.

### Upgrading to v1.5.x

**New Features:**
- Interface-based bandwidth monitoring
- Session statistics

**Schema Changes:**
- Added `interface_metrics` table
- Added `session_statistics` table
- Removed obsolete session-based throughput columns

**Migration:** Automatic. Old metrics data is preserved.

---

## Troubleshooting

### Migration Fails on Startup

**Symptom:** Error messages about schema migration failure.

**Solution:**
1. Check logs for specific error
2. Verify database file permissions
3. Ensure sufficient disk space
4. Try manual migration:
   ```bash
   sqlite3 /var/lib/firelens/data/metrics.db ".schema"
   ```

### Configuration Not Loaded

**Symptom:** Firewalls missing after upgrade.

**Solution:**
1. Verify config.yaml exists and is readable
2. Check YAML syntax: `python -c "import yaml; yaml.safe_load(open('config.yaml'))"`
3. Check logs for config loading errors

### Web UI Shows Wrong Version

**Symptom:** Version in UI doesn't match installed version.

**Solution:**
1. Clear browser cache
2. Restart the container/service
3. Verify package version: `pip show firelens-monitor`

### Database Locked

**Symptom:** "database is locked" errors after upgrade.

**Solution:**
1. Stop all FireLens processes
2. Check for zombie processes: `ps aux | grep firelens`
3. Remove stale lock file if present
4. Restart service

---

## Best Practices

1. **Always backup before upgrading** - Both config and database
2. **Test in staging first** - If you have a test environment
3. **Read release notes** - Check for breaking changes
4. **Monitor logs during upgrade** - Watch for migration errors
5. **Verify after upgrade** - Check health endpoint and UI
6. **Keep backups for 30 days** - In case issues surface later

---

## Getting Help

- **Issues:** [GitHub Issues](https://github.com/mancow2001/FireLens/issues)
- **Discussions:** [GitHub Discussions](https://github.com/mancow2001/FireLens/discussions)
