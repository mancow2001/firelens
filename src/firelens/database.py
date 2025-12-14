#!/usr/bin/env python3
"""
FireLens Monitor - Database Management Module
Provides persistent storage for metrics data, interface monitoring, and session statistics
Includes automatic schema migration for interface and session data
"""

import logging
import re
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from queue import Empty, Queue
from typing import Any, Dict, List, Optional, Tuple

LOG = logging.getLogger("FireLens.database")


def parse_iso_datetime_python36(timestamp_str: str) -> datetime:
    """
    Parse ISO datetime string - Python 3.6 compatible version
    Python 3.6 doesn't have datetime.fromisoformat()
    """
    if not timestamp_str:
        return datetime.now(timezone.utc)

    # Remove 'Z' and replace with +00:00 for UTC
    if timestamp_str.endswith("Z"):
        timestamp_str = timestamp_str[:-1] + "+00:00"

    # Handle space instead of 'T' separator
    if " " in timestamp_str and "T" not in timestamp_str:
        timestamp_str = timestamp_str.replace(" ", "T", 1)

    # Try manual parsing for Python 3.6
    try:
        # Remove timezone for strptime, then add it back
        if "+" in timestamp_str:
            dt_part, tz_part = timestamp_str.rsplit("+", 1)
            sign = 1
        elif timestamp_str.count("-") > 2:  # Has timezone
            dt_part, tz_part = timestamp_str.rsplit("-", 1)
            sign = -1
        else:
            # No timezone, assume UTC
            try:
                dt = datetime.strptime(timestamp_str.replace("T", " "), "%Y-%m-%d %H:%M:%S.%f")
            except ValueError:
                dt = datetime.strptime(timestamp_str.replace("T", " "), "%Y-%m-%d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc)

        # Parse the datetime part
        try:
            dt = datetime.strptime(dt_part.replace("T", " "), "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            dt = datetime.strptime(dt_part.replace("T", " "), "%Y-%m-%d %H:%M:%S")

        # Parse timezone
        if ":" in tz_part:
            hours, minutes = map(int, tz_part.split(":"))
        else:
            hours = int(tz_part[:2])
            minutes = int(tz_part[2:]) if len(tz_part) > 2 else 0

        offset = timedelta(hours=sign * hours, minutes=sign * minutes)
        tz = timezone(offset)
        return dt.replace(tzinfo=tz)

    except Exception as e:
        LOG.debug(f"Manual parsing failed for '{timestamp_str}': {e}")

        # Last resort: try common formats without timezone, assume UTC
        formats = [
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d",
        ]

        for fmt in formats:
            try:
                dt = datetime.strptime(timestamp_str.split("+")[0].split("Z")[0], fmt)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue

    LOG.warning(f"Could not parse timestamp '{timestamp_str}', using current time")
    return datetime.now(timezone.utc)


# Use the Python 3.6 compatible function
parse_iso_datetime = parse_iso_datetime_python36


class EnhancedMetricsDatabase:
    """SQLite database for storing firewall metrics, interface data, and session statistics"""

    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Connection pooling to reduce overhead from creating/destroying connections
        # SQLite doesn't have true pooling, but we can reuse connections per thread
        self._connection_pool = Queue(maxsize=10)  # Pool of 10 reusable connections
        self._pool_lock = threading.Lock()
        self._thread_local = threading.local()

        LOG.info(f"🔧 Initializing database at: {self.db_path}")
        self._init_database()
        LOG.info(f"✅ Database ready with connection pooling at: {self.db_path}")

    def _init_database(self):
        """Initialize database schema with automatic migration"""
        with self._get_connection() as conn:
            # Create firewalls table FIRST (before metrics table due to foreign key)
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS firewalls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    host TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )
            LOG.info("✓ Firewalls table created/verified")

            # Create metrics table (common metrics only - vendor-specific go to vendor tables)
            # Note: New DBs get vendor-agnostic schema. Existing DBs migrated in _migrate_schema()
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    firewall_name TEXT NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (firewall_name) REFERENCES firewalls (name)
                )
            """
            )
            LOG.info("✓ Metrics table created/verified")

            # Create indexes for better query performance
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_metrics_firewall_timestamp
                ON metrics (firewall_name, timestamp)
            """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_metrics_timestamp
                ON metrics (timestamp)
            """
            )
            LOG.info("✓ Metrics indexes created/verified")

            # Create configuration table for storing runtime config
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS configuration (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )
            LOG.info("✓ Configuration table created/verified")

            # Create rename_tasks table for tracking background rename operations
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS rename_tasks (
                    id TEXT PRIMARY KEY,
                    old_name TEXT NOT NULL,
                    new_name TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    current_table TEXT,
                    total_rows INTEGER DEFAULT 0,
                    processed_rows INTEGER DEFAULT 0,
                    error_message TEXT,
                    started_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )
            LOG.debug("✓ Rename tasks table created/verified")

            # Create schema_version table for tracking database migrations
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    description TEXT
                )
            """
            )
            LOG.debug("✓ Schema version table created/verified")

            conn.commit()

            # Verify critical tables exist
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='firewalls'"
            )
            if not cursor.fetchone():
                LOG.error("❌ CRITICAL: Firewalls table was not created!")
                raise RuntimeError("Failed to create firewalls table")

            LOG.info("✅ Core database tables initialized")

        # Automatically migrate schema to add enhanced statistics and interface monitoring
        self._migrate_schema()

        LOG.info(f"Enhanced database initialized with interface monitoring: {self.db_path}")

    # Current schema version - increment when making schema changes
    SCHEMA_VERSION = 2

    def _get_schema_version(self, conn) -> int:
        """Get current schema version from database"""
        try:
            cursor = conn.execute("SELECT MAX(version) FROM schema_version")
            result = cursor.fetchone()
            return result[0] if result and result[0] else 0
        except sqlite3.OperationalError:
            # Table doesn't exist yet
            return 0

    def _set_schema_version(self, conn, version: int, description: str):
        """Record a schema version migration"""
        conn.execute(
            "INSERT OR REPLACE INTO schema_version (version, description) VALUES (?, ?)",
            (version, description),
        )
        LOG.info(f"📝 Schema version updated to {version}: {description}")

    def _migrate_schema(self):
        """Automatically detect schema changes and migrate database"""
        with self._get_connection() as conn:
            # Check current schema version
            current_version = self._get_schema_version(conn)
            target_version = self.SCHEMA_VERSION

            if current_version < target_version:
                LOG.info(f"🔄 Database schema upgrade: v{current_version} → v{target_version}")

            # === SCHEMA VERSION 2 MIGRATION ===
            # Move Palo Alto-specific columns out of main metrics table
            # CPU and pbuf metrics are now stored in vendor-specific tables
            if current_version < 2:
                cursor = conn.execute("PRAGMA table_info(metrics)")
                existing_columns = [row[1] for row in cursor.fetchall()]

                # Palo Alto-specific columns to remove from main metrics table
                pa_specific_columns = [
                    "cpu_user",
                    "cpu_system",
                    "cpu_idle",  # Generic CPU (not collected anymore)
                    "mgmt_cpu",
                    "data_plane_cpu",  # PA-specific
                    "data_plane_cpu_mean",
                    "data_plane_cpu_max",
                    "data_plane_cpu_p95",  # PA-specific
                    "pbuf_util_percent",  # PA-specific
                    "throughput_mbps_total",
                    "pps_total",  # Obsolete (moved to interface_metrics)
                ]

                # Check if any PA-specific columns exist in the metrics table
                columns_to_remove = [col for col in pa_specific_columns if col in existing_columns]

                if columns_to_remove:
                    col_count = len(columns_to_remove)
                    LOG.info(f"🔄 Schema v2 migration: Removing {col_count} vendor columns")
                    LOG.info(f"   Columns to remove: {', '.join(columns_to_remove)}")
                    LOG.info("   Note: Historical PA CPU/pbuf data will be dropped")
                    LOG.info("   Going forward, all vendor CPU data goes to vendor-specific tables")

                    try:
                        # Create new metrics table with only common fields
                        conn.execute(
                            """
                            CREATE TABLE metrics_v2 (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                firewall_name TEXT NOT NULL,
                                timestamp TIMESTAMP NOT NULL,
                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                FOREIGN KEY (firewall_name) REFERENCES firewalls (name)
                            )
                        """
                        )

                        # Copy only common data (timestamp, firewall_name, created_at)
                        conn.execute(
                            """
                            INSERT INTO metrics_v2 (firewall_name, timestamp, created_at)
                            SELECT firewall_name, timestamp, created_at FROM metrics
                        """
                        )

                        # Get row counts for logging
                        cursor = conn.execute("SELECT COUNT(*) FROM metrics")
                        old_count = cursor.fetchone()[0]
                        cursor = conn.execute("SELECT COUNT(*) FROM metrics_v2")
                        new_count = cursor.fetchone()[0]

                        # Drop old table
                        conn.execute("DROP TABLE metrics")

                        # Rename new table
                        conn.execute("ALTER TABLE metrics_v2 RENAME TO metrics")

                        # Recreate indexes
                        conn.execute(
                            """
                            CREATE INDEX IF NOT EXISTS idx_metrics_firewall_timestamp
                            ON metrics (firewall_name, timestamp)
                        """
                        )
                        conn.execute(
                            """
                            CREATE INDEX IF NOT EXISTS idx_metrics_timestamp
                            ON metrics (timestamp)
                        """
                        )

                        conn.commit()

                        LOG.info("✅ Schema v2 migration successful")
                        LOG.info(f"   Migrated {new_count} of {old_count} metric records")
                        LOG.info(f"   Removed columns: {', '.join(columns_to_remove)}")
                        LOG.info("   PA CPU data now stored in palo_alto_metrics table")
                        LOG.info("   Fortinet CPU data stored in fortinet_metrics table")

                    except Exception as e:
                        LOG.error(f"❌ Schema v2 migration failed: {e}")
                        conn.rollback()
                        LOG.warning("   Database rolled back to previous state")
                        raise

            # Check what columns currently exist in metrics table
            cursor = conn.execute("PRAGMA table_info(metrics)")
            existing_columns = [row[1] for row in cursor.fetchall()]

            # Define columns that should be REMOVED (no longer collected)
            obsolete_columns = [
                "throughput_mbps_total",  # Session-based throughput (replaced by interface metrics)
                "throughput_mbps_max",  # Session-based throughput max
                "throughput_mbps_min",  # Session-based throughput min
                "throughput_mbps_p95",  # Session-based throughput p95
                "pps_total",  # Session-based PPS (replaced by interface metrics)
                "pps_max",  # Session-based PPS max
                "pps_min",  # Session-based PPS min
                "pps_p95",  # Session-based PPS p95
                "session_sample_count",  # Session sampling metadata
                "session_success_rate",  # Session sampling metadata
                "session_sampling_period",  # Session sampling metadata
            ]

            # Check if any obsolete columns exist
            columns_to_remove = [col for col in obsolete_columns if col in existing_columns]

            if columns_to_remove:
                col_count = len(columns_to_remove)
                LOG.info(f"🔍 Schema migration: Detected {col_count} obsolete columns")
                LOG.info("   Removing session-based throughput columns (now interface-based)")

                # SQLite doesn't support DROP COLUMN easily, so we need to recreate the table
                # Get the columns we want to keep
                columns_to_keep = [col for col in existing_columns if col not in obsolete_columns]

                # Build the new table schema with only columns we want
                new_columns_def = []
                cursor = conn.execute("PRAGMA table_info(metrics)")
                for row in cursor.fetchall():
                    col_name = row[1]
                    if col_name in columns_to_keep:
                        col_type = row[2]
                        not_null = " NOT NULL" if row[3] else ""
                        default = f" DEFAULT {row[4]}" if row[4] is not None else ""
                        pk = " PRIMARY KEY AUTOINCREMENT" if row[5] else ""
                        new_columns_def.append(f"{col_name} {col_type}{not_null}{default}{pk}")

                # Add foreign key constraint
                if "firewall_name" in columns_to_keep:
                    new_columns_def.append(
                        "FOREIGN KEY (firewall_name) REFERENCES firewalls (name)"
                    )

                try:
                    # Create new table with updated schema
                    conn.execute(
                        f"""
                        CREATE TABLE metrics_new (
                            {", ".join(new_columns_def)}
                        )
                    """
                    )

                    # Copy data from old table to new table
                    columns_str = ", ".join(columns_to_keep)
                    conn.execute(
                        f"""
                        INSERT INTO metrics_new ({columns_str})
                        SELECT {columns_str} FROM metrics
                    """
                    )

                    # Drop old table
                    conn.execute("DROP TABLE metrics")

                    # Rename new table
                    conn.execute("ALTER TABLE metrics_new RENAME TO metrics")

                    # Recreate indexes
                    conn.execute(
                        """
                        CREATE INDEX IF NOT EXISTS idx_metrics_firewall_timestamp
                        ON metrics (firewall_name, timestamp)
                    """
                    )

                    conn.execute(
                        """
                        CREATE INDEX IF NOT EXISTS idx_metrics_timestamp
                        ON metrics (timestamp)
                    """
                    )

                    conn.commit()

                    col_count = len(columns_to_remove)
                    LOG.info(f"✅ Schema migration: Removed {col_count} obsolete columns")
                    for col in columns_to_remove:
                        LOG.info(f"   ✓ Removed: {col}")
                    LOG.info("📈 Throughput now tracked via interface_metrics table")

                except Exception as e:
                    LOG.error(f"❌ Schema migration failed: {e}")
                    conn.rollback()
                    LOG.warning("   Database rolled back to previous state")
                    LOG.warning("   Obsolete columns will remain but won't receive new data")
            else:
                LOG.debug("✅ Schema is up-to-date: No obsolete columns found")

            # Migrate firewalls table to add hardware info columns
            cursor = conn.execute("PRAGMA table_info(firewalls)")
            firewall_columns = [row[1] for row in cursor.fetchall()]

            hardware_columns = {
                "model": "TEXT",
                "family": "TEXT",
                "platform_family": "TEXT",
                "serial": "TEXT",
                "hostname": "TEXT",
                "sw_version": "TEXT",
            }

            for col_name, col_type in hardware_columns.items():
                if col_name not in firewall_columns:
                    try:
                        conn.execute(f"ALTER TABLE firewalls ADD COLUMN {col_name} {col_type}")
                        LOG.info(f"✅ Added {col_name} column to firewalls table")
                    except Exception as e:
                        LOG.warning(f"Could not add {col_name} column: {e}")

            conn.commit()

            # Create interface metrics table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS interface_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    firewall_name TEXT NOT NULL,
                    interface_name TEXT NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    rx_mbps REAL NOT NULL,
                    tx_mbps REAL NOT NULL,
                    total_mbps REAL NOT NULL,
                    rx_pps REAL NOT NULL,
                    tx_pps REAL NOT NULL,
                    interval_seconds REAL NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (firewall_name) REFERENCES firewalls (name)
                )
            """
            )

            # Create session statistics table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS session_statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    firewall_name TEXT NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    active_sessions INTEGER NOT NULL,
                    max_sessions INTEGER NOT NULL,
                    tcp_sessions INTEGER DEFAULT 0,
                    udp_sessions INTEGER DEFAULT 0,
                    icmp_sessions INTEGER DEFAULT 0,
                    session_rate REAL DEFAULT 0.0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (firewall_name) REFERENCES firewalls (name)
                )
            """
            )

            # Create indexes for interface metrics
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_interface_metrics_firewall_interface_timestamp
                ON interface_metrics (firewall_name, interface_name, timestamp)
            """
            )

            # Additional optimized indexes for common query patterns
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_interface_metrics_firewall_timestamp
                ON interface_metrics (firewall_name, timestamp DESC)
            """
            )

            # Note: Partial indexes with datetime() are not supported in all SQLite versions
            # Removed partial indexes to ensure compatibility

            # Create indexes for session statistics
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_session_statistics_firewall_timestamp
                ON session_statistics (firewall_name, timestamp)
            """
            )

            # Create vendor-specific metrics tables for modular schema evolution

            # Fortinet-specific metrics table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS fortinet_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    firewall_name TEXT NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    cpu_usage REAL,
                    memory_usage_percent REAL,
                    session_setup_rate REAL,
                    npu_sessions INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (firewall_name) REFERENCES firewalls (name)
                )
            """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_fortinet_metrics_fw_ts
                ON fortinet_metrics (firewall_name, timestamp)
            """
            )

            # Palo Alto-specific metrics table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS palo_alto_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    firewall_name TEXT NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    mgmt_cpu REAL,
                    data_plane_cpu_mean REAL,
                    data_plane_cpu_max REAL,
                    data_plane_cpu_p95 REAL,
                    pbuf_util_percent REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (firewall_name) REFERENCES firewalls (name)
                )
            """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_palo_alto_metrics_fw_ts
                ON palo_alto_metrics (firewall_name, timestamp)
            """
            )

            # Cisco Firepower-specific metrics table (placeholder for future)
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cisco_firepower_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    firewall_name TEXT NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (firewall_name) REFERENCES firewalls (name)
                )
            """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_cisco_firepower_metrics_fw_ts
                ON cisco_firepower_metrics (firewall_name, timestamp)
            """
            )

            # Migrate vendor tables - add missing columns to existing tables
            # This handles upgrades from older versions that didn't have all columns

            # Check fortinet_metrics for cpu_usage column (added in v1.6.12)
            cursor = conn.execute("PRAGMA table_info(fortinet_metrics)")
            fortinet_columns = [row[1] for row in cursor.fetchall()]
            if "cpu_usage" not in fortinet_columns:
                try:
                    conn.execute("ALTER TABLE fortinet_metrics ADD COLUMN cpu_usage REAL")
                    LOG.info("✅ Added cpu_usage column to fortinet_metrics table")
                except Exception as e:
                    LOG.warning(f"Could not add cpu_usage column to fortinet_metrics: {e}")

            # Commit all changes
            conn.commit()

            # Check if new tables were created
            cursor = conn.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type='table'
                AND name IN ('interface_metrics', 'session_statistics',
                            'fortinet_metrics', 'palo_alto_metrics', 'cisco_firepower_metrics')
            """
            )
            new_tables = [row[0] for row in cursor.fetchall()]

            if new_tables:
                LOG.info(f"📊 Monitoring tables ready: {', '.join(new_tables)}")
            else:
                LOG.debug("✅ All monitoring tables already exist")

            # Record schema version if migrations were applied
            current_version = self._get_schema_version(conn)
            if current_version < self.SCHEMA_VERSION:
                self._set_schema_version(
                    conn,
                    self.SCHEMA_VERSION,
                    "Vendor-agnostic metrics table - CPU/pbuf moved to vendor-specific tables",
                )
                conn.commit()
                LOG.info(f"✅ Database schema upgrade complete: now at v{self.SCHEMA_VERSION}")
            else:
                LOG.debug(f"✅ Database schema is current (v{current_version})")

    @contextmanager
    def _get_connection(self):
        """
        Context manager for database connections with pooling
        Reuses connections from pool to reduce overhead
        """
        conn = None
        from_pool = False

        try:
            # Try to get connection from pool (non-blocking)
            try:
                conn = self._connection_pool.get_nowait()
                from_pool = True
                LOG.debug(
                    f"Reusing connection from pool (pool size: {self._connection_pool.qsize()})"
                )
            except Empty:
                # Pool is empty, create new connection
                conn = sqlite3.connect(str(self.db_path), timeout=30.0, check_same_thread=False)
                conn.row_factory = sqlite3.Row
                LOG.debug("Created new database connection")

            yield conn

        finally:
            if conn:
                try:
                    # Return connection to pool if possible (and it's healthy)
                    if from_pool or self._connection_pool.qsize() < 10:
                        # Reset any uncommitted transactions
                        try:
                            conn.rollback()
                        except Exception:
                            pass
                        # Try to return to pool
                        try:
                            self._connection_pool.put_nowait(conn)
                            pool_size = self._connection_pool.qsize()
                            LOG.debug(f"Returned connection to pool (pool size: {pool_size})")
                        except Exception:
                            # Pool is full, close this connection
                            conn.close()
                            LOG.debug("Pool full, closed excess connection")
                    else:
                        # Pool is full, close connection
                        conn.close()
                        LOG.debug("Closed database connection (pool full)")
                except Exception as e:
                    LOG.debug(f"Error managing connection: {e}")
                    try:
                        conn.close()
                    except Exception:
                        pass

    def register_firewall(
        self, name: str, host: str, hardware_info: Optional[Dict[str, str]] = None
    ) -> bool:
        """
        Register a firewall in the database with optional hardware information

        Args:
            name: Firewall name
            host: Firewall host/IP
            hardware_info: Optional dict with model, family, serial, etc.
        """
        try:
            with self._get_connection() as conn:
                if hardware_info:
                    # Store hardware info if provided
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO firewalls
                        (name, host, model, family, platform_family,
                         serial, hostname, sw_version, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """,
                        (
                            name,
                            host,
                            hardware_info.get("model"),
                            hardware_info.get("family"),
                            hardware_info.get("platform_family"),
                            hardware_info.get("serial"),
                            hardware_info.get("hostname"),
                            hardware_info.get("sw_version"),
                        ),
                    )
                    model_info = (
                        f" [Model: {hardware_info.get('model', 'unknown')}]"
                        if hardware_info.get("model")
                        else ""
                    )
                    LOG.info(f"Registered firewall: {name} ({host}){model_info}")
                else:
                    # Just update name and host
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO firewalls (name, host, updated_at)
                        VALUES (?, ?, CURRENT_TIMESTAMP)
                    """,
                        (name, host),
                    )
                    LOG.info(f"Registered firewall: {name} ({host})")
                conn.commit()
                return True
        except Exception as e:
            LOG.error(f"Failed to register firewall {name}: {e}")
            return False

    def unregister_firewall(self, name: str, delete_metrics: bool = True) -> bool:
        """
        Unregister a firewall from the database

        Args:
            name: Firewall name to remove
            delete_metrics: If True, also delete all metrics data for this firewall

        Returns:
            True if successful, False otherwise
        """
        try:
            with self._get_connection() as conn:
                if delete_metrics:
                    # Delete metrics data first (foreign key relationships)
                    # Use IF EXISTS pattern to handle tables that may not exist
                    conn.execute("DELETE FROM metrics WHERE firewall_name = ?", (name,))
                    try:
                        conn.execute(
                            "DELETE FROM interface_metrics WHERE firewall_name = ?", (name,)
                        )
                    except Exception:
                        pass  # Table may not exist
                    try:
                        conn.execute("DELETE FROM session_stats WHERE firewall_name = ?", (name,))
                    except Exception:
                        pass  # Table may not exist
                    LOG.info(f"Deleted all metrics for firewall: {name}")

                # Delete from firewalls table
                cursor = conn.execute("DELETE FROM firewalls WHERE name = ?", (name,))
                conn.commit()

                if cursor.rowcount > 0:
                    LOG.info(f"Unregistered firewall: {name}")
                    return True
                else:
                    LOG.warning(f"Firewall not found in database: {name}")
                    return False
        except Exception as e:
            LOG.error(f"Failed to unregister firewall {name}: {e}")
            return False

    def rename_firewall(self, old_name: str, new_name: str) -> tuple:
        """
        Rename a firewall and cascade the change to all related tables.

        This method atomically updates the firewall name across all tables:
        - firewalls
        - metrics
        - interface_metrics
        - session_statistics

        Args:
            old_name: Current firewall name
            new_name: New firewall name

        Returns:
            Tuple of (success: bool, message: str)
        """
        if old_name == new_name:
            return True, "Names are identical, no change needed"

        # Validate new name format
        import re

        if not re.match(r"^[a-zA-Z0-9_]+$", new_name):
            return False, "New name must contain only letters, numbers, and underscores"

        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                # Check old name exists
                cursor.execute("SELECT id FROM firewalls WHERE name = ?", (old_name,))
                if not cursor.fetchone():
                    return False, f"Firewall '{old_name}' not found"

                # Check new name doesn't conflict
                cursor.execute("SELECT id FROM firewalls WHERE name = ?", (new_name,))
                if cursor.fetchone():
                    return False, f"Firewall '{new_name}' already exists"

                # Cascade updates to all related tables
                # Update metrics table
                cursor.execute(
                    "UPDATE metrics SET firewall_name = ? WHERE firewall_name = ?",
                    (new_name, old_name),
                )
                metrics_count = cursor.rowcount

                # Update interface_metrics table (may not exist in older schemas)
                interface_count = 0
                try:
                    cursor.execute(
                        "UPDATE interface_metrics SET firewall_name = ? WHERE firewall_name = ?",
                        (new_name, old_name),
                    )
                    interface_count = cursor.rowcount
                except Exception:
                    pass  # Table may not exist

                # Update session_statistics table (may not exist in older schemas)
                session_count = 0
                try:
                    cursor.execute(
                        "UPDATE session_statistics SET firewall_name = ? WHERE firewall_name = ?",
                        (new_name, old_name),
                    )
                    session_count = cursor.rowcount
                except Exception:
                    pass  # Table may not exist

                # Update vendor-specific metrics tables
                fortinet_count = 0
                palo_alto_count = 0
                cisco_count = 0
                try:
                    cursor.execute(
                        "UPDATE fortinet_metrics SET firewall_name = ? WHERE firewall_name = ?",
                        (new_name, old_name),
                    )
                    fortinet_count = cursor.rowcount
                except Exception:
                    pass  # Table may not exist

                try:
                    cursor.execute(
                        "UPDATE palo_alto_metrics SET firewall_name = ? WHERE firewall_name = ?",
                        (new_name, old_name),
                    )
                    palo_alto_count = cursor.rowcount
                except Exception:
                    pass  # Table may not exist

                try:
                    sql = (
                        "UPDATE cisco_firepower_metrics "
                        "SET firewall_name = ? WHERE firewall_name = ?"
                    )
                    cursor.execute(sql, (new_name, old_name))
                    cisco_count = cursor.rowcount
                except Exception:
                    pass  # Table may not exist

                # Update the firewall record itself
                cursor.execute(
                    "UPDATE firewalls SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE name = ?",
                    (new_name, old_name),
                )

                conn.commit()

                vendor_counts = fortinet_count + palo_alto_count + cisco_count
                LOG.info(
                    f"Renamed firewall '{old_name}' to '{new_name}' "
                    f"(updated {metrics_count} metrics, {interface_count} interface records, "
                    f"{session_count} session records, {vendor_counts} vendor-specific records)"
                )

                return True, f"Successfully renamed '{old_name}' to '{new_name}'"

        except Exception as e:
            LOG.error(f"Error renaming firewall '{old_name}' to '{new_name}': {e}")
            return False, f"Error renaming firewall: {str(e)}"

    def count_firewall_references(self, firewall_name: str) -> Dict[str, int]:
        """
        Count rows referencing a firewall across all tables.
        Used to estimate rename task duration.

        Args:
            firewall_name: Name of the firewall

        Returns:
            Dict with counts per table: {'metrics': N, 'interface_metrics': N, ...}
        """
        counts = {"metrics": 0, "interface_metrics": 0, "session_statistics": 0}

        try:
            with self._get_connection() as conn:
                # Count metrics
                cursor = conn.execute(
                    "SELECT COUNT(*) FROM metrics WHERE firewall_name = ?", (firewall_name,)
                )
                counts["metrics"] = cursor.fetchone()[0]

                # Count interface_metrics
                try:
                    cursor = conn.execute(
                        "SELECT COUNT(*) FROM interface_metrics WHERE firewall_name = ?",
                        (firewall_name,),
                    )
                    counts["interface_metrics"] = cursor.fetchone()[0]
                except Exception:
                    pass  # Table may not exist

                # Count session_statistics
                try:
                    cursor = conn.execute(
                        "SELECT COUNT(*) FROM session_statistics WHERE firewall_name = ?",
                        (firewall_name,),
                    )
                    counts["session_statistics"] = cursor.fetchone()[0]
                except Exception:
                    pass  # Table may not exist

        except Exception as e:
            LOG.error(f"Error counting firewall references for '{firewall_name}': {e}")

        return counts

    def start_rename_task(
        self, old_name: str, new_name: str
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Start a background rename task.

        Args:
            old_name: Current firewall name
            new_name: New firewall name

        Returns:
            Tuple of (task_id, error_message) - task_id is None if validation fails
        """
        # Validation
        if old_name == new_name:
            return None, "Names are identical"

        if not re.match(r"^[a-zA-Z0-9_]+$", new_name):
            return None, "Invalid name format. Use only letters, numbers, and underscores."

        # Check names exist/don't exist
        with self._get_connection() as conn:
            if not conn.execute("SELECT 1 FROM firewalls WHERE name = ?", (old_name,)).fetchone():
                return None, f"Firewall '{old_name}' not found"
            if conn.execute("SELECT 1 FROM firewalls WHERE name = ?", (new_name,)).fetchone():
                return None, f"Firewall '{new_name}' already exists"

            # Check for pending/running rename tasks for this firewall
            sql = (
                "SELECT id, status FROM rename_tasks "
                "WHERE old_name = ? AND status IN ('pending', 'running')"
            )
            existing = conn.execute(sql, (old_name,)).fetchone()
            if existing:
                status = existing[1]
                task_id = existing[0]
                return (None, f"Rename task already {status} for firewall (task {task_id})")

        # Count total rows
        counts = self.count_firewall_references(old_name)
        total_rows = sum(counts.values())

        # Create task record
        task_id = str(uuid.uuid4())[:8]
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO rename_tasks (id, old_name, new_name, status, total_rows)
                VALUES (?, ?, ?, 'pending', ?)
            """,
                (task_id, old_name, new_name, total_rows),
            )
            conn.commit()

        # Start background thread
        thread = threading.Thread(target=self._execute_rename_task, args=(task_id,), daemon=True)
        thread.start()

        LOG.info(f"Started rename task {task_id}: '{old_name}' -> '{new_name}' ({total_rows} rows)")
        return task_id, None

    def _execute_rename_task(self, task_id: str):
        """Execute the rename in a background thread with batched updates"""
        BATCH_SIZE = 10000

        try:
            # Get task details
            with self._get_connection() as conn:
                task = conn.execute(
                    "SELECT old_name, new_name FROM rename_tasks WHERE id = ?", (task_id,)
                ).fetchone()
                if not task:
                    return

                old_name, new_name = task

                # Update status to running
                conn.execute(
                    """
                    UPDATE rename_tasks
                    SET status = 'running', started_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """,
                    (task_id,),
                )
                conn.commit()

            # Process each table
            tables = ["metrics", "interface_metrics", "session_statistics"]
            processed = 0

            for table in tables:
                self._update_task_progress(task_id, processed, table)

                while True:
                    with self._get_connection() as conn:
                        # Use rowid for efficient batching
                        cursor = conn.execute(
                            f"""
                            UPDATE {table}
                            SET firewall_name = ?
                            WHERE rowid IN (
                                SELECT rowid FROM {table}
                                WHERE firewall_name = ?
                                LIMIT {BATCH_SIZE}
                            )
                        """,
                            (new_name, old_name),
                        )

                        updated = cursor.rowcount
                        conn.commit()

                        processed += updated
                        self._update_task_progress(task_id, processed, table)

                        if updated < BATCH_SIZE:
                            break

            # Update the firewall record itself
            with self._get_connection() as conn:
                conn.execute(
                    "UPDATE firewalls SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE name = ?",
                    (new_name, old_name),
                )
                conn.commit()

            # Mark complete
            with self._get_connection() as conn:
                conn.execute(
                    """
                    UPDATE rename_tasks
                    SET status = 'completed', completed_at = CURRENT_TIMESTAMP, processed_rows = ?
                    WHERE id = ?
                """,
                    (processed, task_id),
                )
                conn.commit()

            LOG.info(
                f"Rename task {task_id} completed: '{old_name}' -> '{new_name}' ({processed} rows)"
            )

        except Exception as e:
            LOG.error(f"Rename task {task_id} failed: {e}")
            with self._get_connection() as conn:
                conn.execute(
                    """
                    UPDATE rename_tasks
                    SET status = 'failed', error_message = ?, completed_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """,
                    (str(e), task_id),
                )
                conn.commit()

    def _update_task_progress(self, task_id: str, processed: int, current_table: str):
        """Update task progress in database"""
        with self._get_connection() as conn:
            conn.execute(
                """
                UPDATE rename_tasks
                SET processed_rows = ?, current_table = ?
                WHERE id = ?
            """,
                (processed, current_table, task_id),
            )
            conn.commit()

    def get_rename_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """
        Get status of a rename task.

        Args:
            task_id: The task ID

        Returns:
            Dict with task status or None if not found
        """
        with self._get_connection() as conn:
            row = conn.execute(
                """
                SELECT id, old_name, new_name, status, current_table,
                       total_rows, processed_rows, error_message,
                       started_at, completed_at
                FROM rename_tasks WHERE id = ?
            """,
                (task_id,),
            ).fetchone()

            if not row:
                return None

            total_rows = row[5] or 0
            processed_rows = row[6] or 0

            return {
                "task_id": row[0],
                "old_name": row[1],
                "new_name": row[2],
                "status": row[3],
                "current_table": row[4],
                "total_rows": total_rows,
                "processed_rows": processed_rows,
                "progress_percent": (
                    round(processed_rows / total_rows * 100, 1) if total_rows > 0 else 100
                ),
                "error_message": row[7],
                "started_at": row[8],
                "completed_at": row[9],
            }

    def insert_metrics(
        self, firewall_name: str, metrics: Dict[str, Any], vendor_type: str = None
    ) -> bool:
        """
        Insert metrics data for a firewall.

        The main metrics table only stores common data (timestamp, firewall_name).
        Vendor-specific metrics are automatically routed to vendor tables:
        - palo_alto: mgmt_cpu, data_plane_cpu_*, pbuf_util_percent
        - fortinet: cpu_usage, memory_usage_percent, session_setup_rate, npu_sessions

        Args:
            firewall_name: Name of the firewall
            metrics: Dict containing metric values
            vendor_type: 'palo_alto', 'fortinet', or 'cisco_firepower' (optional)

        Returns:
            True if successful, False otherwise
        """
        try:
            # Auto-register firewall if metrics include host information
            if "firewall_host" in metrics:
                self.register_firewall(firewall_name, metrics["firewall_host"])

            with self._get_connection() as conn:
                # Convert timestamp string to datetime if needed
                timestamp = metrics.get("timestamp")
                if isinstance(timestamp, str):
                    timestamp = parse_iso_datetime(timestamp)
                elif timestamp is None:
                    timestamp = datetime.now(timezone.utc)
                elif isinstance(timestamp, datetime) and timestamp.tzinfo is None:
                    # Add UTC timezone if missing
                    timestamp = timestamp.replace(tzinfo=timezone.utc)

                # Insert into main metrics table (common fields only)
                conn.execute(
                    """
                    INSERT INTO metrics (firewall_name, timestamp)
                    VALUES (?, ?)
                """,
                    (firewall_name, timestamp),
                )
                conn.commit()

            # Route vendor-specific data to vendor tables
            if vendor_type == "palo_alto":
                # Extract Palo Alto-specific metrics
                pa_metrics = {
                    "timestamp": timestamp,
                    "mgmt_cpu": metrics.get("mgmt_cpu"),
                    "data_plane_cpu_mean": metrics.get("data_plane_cpu_mean"),
                    "data_plane_cpu_max": metrics.get("data_plane_cpu_max"),
                    "data_plane_cpu_p95": metrics.get("data_plane_cpu_p95"),
                    "pbuf_util_percent": metrics.get("pbuf_util_percent"),
                }
                self.insert_palo_alto_metrics(firewall_name, pa_metrics)

            elif vendor_type == "fortinet":
                # Extract Fortinet-specific metrics
                fortinet_metrics = {
                    "timestamp": timestamp,
                    "cpu_usage": metrics.get("cpu_usage"),
                    "memory_usage_percent": metrics.get("memory_usage_percent"),
                    "session_setup_rate": metrics.get("session_setup_rate"),
                    "npu_sessions": metrics.get("npu_sessions"),
                }
                self.insert_fortinet_metrics(firewall_name, fortinet_metrics)

            return True
        except Exception as e:
            LOG.error(f"Failed to insert metrics for {firewall_name}: {e}")
            return False

    def insert_interface_metrics(
        self, firewall_name: str, interface_metrics: Dict[str, Any]
    ) -> bool:
        """Insert interface metrics data"""
        try:
            # Auto-register firewall if metrics include host information
            if "firewall_host" in interface_metrics:
                self.register_firewall(firewall_name, interface_metrics["firewall_host"])

            with self._get_connection() as conn:
                timestamp = interface_metrics.get("timestamp")
                if isinstance(timestamp, str):
                    timestamp = parse_iso_datetime(timestamp)
                elif timestamp is None:
                    timestamp = datetime.now(timezone.utc)
                elif isinstance(timestamp, datetime) and timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)

                conn.execute(
                    """
                    INSERT INTO interface_metrics (
                        firewall_name, interface_name, timestamp, rx_mbps, tx_mbps,
                        total_mbps, rx_pps, tx_pps, interval_seconds
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        firewall_name,
                        interface_metrics.get("interface_name"),
                        timestamp,
                        interface_metrics.get("rx_mbps", 0),
                        interface_metrics.get("tx_mbps", 0),
                        interface_metrics.get("total_mbps", 0),
                        interface_metrics.get("rx_pps", 0),
                        interface_metrics.get("tx_pps", 0),
                        interface_metrics.get("interval_seconds", 0),
                    ),
                )
                conn.commit()
                return True
        except Exception as e:
            LOG.error(f"Failed to insert interface metrics for {firewall_name}: {e}")
            return False

    def insert_session_statistics(self, firewall_name: str, session_stats: Dict[str, Any]) -> bool:
        """Insert session statistics data"""
        try:
            # Auto-register firewall if metrics include host information
            if "firewall_host" in session_stats:
                self.register_firewall(firewall_name, session_stats["firewall_host"])

            with self._get_connection() as conn:
                timestamp = session_stats.get("timestamp")
                if isinstance(timestamp, str):
                    timestamp = parse_iso_datetime(timestamp)
                elif timestamp is None:
                    timestamp = datetime.now(timezone.utc)
                elif isinstance(timestamp, datetime) and timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)

                conn.execute(
                    """
                    INSERT INTO session_statistics (
                        firewall_name, timestamp, active_sessions, max_sessions,
                        tcp_sessions, udp_sessions, icmp_sessions, session_rate
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        firewall_name,
                        timestamp,
                        session_stats.get("active_sessions", 0),
                        session_stats.get("max_sessions", 0),
                        session_stats.get("tcp_sessions", 0),
                        session_stats.get("udp_sessions", 0),
                        session_stats.get("icmp_sessions", 0),
                        session_stats.get("session_rate", 0.0),
                    ),
                )
                conn.commit()
                return True
        except Exception as e:
            LOG.error(f"Failed to insert session statistics for {firewall_name}: {e}")
            return False

    def insert_fortinet_metrics(self, firewall_name: str, metrics: Dict[str, Any]) -> bool:
        """Insert Fortinet-specific metrics data"""
        try:
            with self._get_connection() as conn:
                timestamp = metrics.get("timestamp")
                if isinstance(timestamp, str):
                    timestamp = parse_iso_datetime(timestamp)
                elif timestamp is None:
                    timestamp = datetime.now(timezone.utc)
                elif isinstance(timestamp, datetime) and timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)

                conn.execute(
                    """
                    INSERT INTO fortinet_metrics (
                        firewall_name, timestamp, cpu_usage, memory_usage_percent,
                        session_setup_rate, npu_sessions
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                    (
                        firewall_name,
                        timestamp,
                        metrics.get("cpu_usage"),
                        metrics.get("memory_usage_percent"),
                        metrics.get("session_setup_rate"),
                        metrics.get("npu_sessions"),
                    ),
                )
                conn.commit()
                return True
        except Exception as e:
            LOG.error(f"Failed to insert Fortinet metrics for {firewall_name}: {e}")
            return False

    def insert_palo_alto_metrics(self, firewall_name: str, metrics: Dict[str, Any]) -> bool:
        """Insert Palo Alto-specific metrics data"""
        try:
            with self._get_connection() as conn:
                timestamp = metrics.get("timestamp")
                if isinstance(timestamp, str):
                    timestamp = parse_iso_datetime(timestamp)
                elif timestamp is None:
                    timestamp = datetime.now(timezone.utc)
                elif isinstance(timestamp, datetime) and timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)

                conn.execute(
                    """
                    INSERT INTO palo_alto_metrics (
                        firewall_name, timestamp, mgmt_cpu,
                        data_plane_cpu_mean, data_plane_cpu_max,
                        data_plane_cpu_p95, pbuf_util_percent
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        firewall_name,
                        timestamp,
                        metrics.get("mgmt_cpu"),
                        metrics.get("data_plane_cpu_mean"),
                        metrics.get("data_plane_cpu_max"),
                        metrics.get("data_plane_cpu_p95"),
                        metrics.get("pbuf_util_percent"),
                    ),
                )
                conn.commit()
                return True
        except Exception as e:
            LOG.error(f"Failed to insert Palo Alto metrics for {firewall_name}: {e}")
            return False

    def get_fortinet_metrics(
        self,
        firewall_name: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Get Fortinet-specific metrics for a firewall"""
        try:
            with self._get_connection() as conn:
                query = """
                    SELECT * FROM fortinet_metrics
                    WHERE firewall_name = ?
                """
                params = [firewall_name]

                if start_time:
                    query += " AND timestamp >= ?"
                    params.append(start_time)

                if end_time:
                    query += " AND timestamp <= ?"
                    params.append(end_time)

                query += " ORDER BY timestamp DESC"

                if limit:
                    query += " LIMIT ?"
                    params.append(limit)

                cursor = conn.execute(query, params)
                rows = cursor.fetchall()

                return [dict(row) for row in rows]
        except Exception as e:
            LOG.error(f"Failed to get Fortinet metrics for {firewall_name}: {e}")
            return []

    def get_palo_alto_metrics(
        self,
        firewall_name: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Get Palo Alto-specific metrics for a firewall"""
        try:
            with self._get_connection() as conn:
                query = """
                    SELECT * FROM palo_alto_metrics
                    WHERE firewall_name = ?
                """
                params = [firewall_name]

                if start_time:
                    query += " AND timestamp >= ?"
                    params.append(start_time)

                if end_time:
                    query += " AND timestamp <= ?"
                    params.append(end_time)

                query += " ORDER BY timestamp DESC"

                if limit:
                    query += " LIMIT ?"
                    params.append(limit)

                cursor = conn.execute(query, params)
                rows = cursor.fetchall()

                return [dict(row) for row in rows]
        except Exception as e:
            LOG.error(f"Failed to get Palo Alto metrics for {firewall_name}: {e}")
            return []

    def get_vendor_metrics(
        self,
        firewall_name: str,
        vendor_type: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get vendor-specific metrics for a firewall.

        Args:
            firewall_name: Name of the firewall
            vendor_type: 'fortinet', 'palo_alto', or 'cisco_firepower'
            start_time: Optional start time filter
            end_time: Optional end time filter
            limit: Optional max number of records

        Returns:
            List of vendor-specific metrics
        """
        if vendor_type == "fortinet":
            return self.get_fortinet_metrics(firewall_name, start_time, end_time, limit)
        elif vendor_type == "palo_alto":
            return self.get_palo_alto_metrics(firewall_name, start_time, end_time, limit)
        elif vendor_type == "cisco_firepower":
            # Placeholder - return empty list until Cisco is implemented
            return []
        else:
            LOG.warning(f"Unknown vendor type: {vendor_type}")
            return []

    def get_interface_metrics(
        self,
        firewall_name: str,
        interface_name: str = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Get interface metrics for a firewall"""
        try:
            with self._get_connection() as conn:
                query = """
                    SELECT * FROM interface_metrics
                    WHERE firewall_name = ?
                """
                params = [firewall_name]

                if interface_name:
                    query += " AND interface_name = ?"
                    params.append(interface_name)

                if start_time:
                    query += " AND timestamp >= ?"
                    params.append(start_time)

                if end_time:
                    query += " AND timestamp <= ?"
                    params.append(end_time)

                query += " ORDER BY timestamp DESC"

                if limit:
                    query += " LIMIT ?"
                    params.append(limit)

                cursor = conn.execute(query, params)
                rows = cursor.fetchall()

                return [dict(row) for row in rows]
        except Exception as e:
            LOG.error(f"Failed to get interface metrics for {firewall_name}: {e}")
            return []

    def get_interface_metrics_batch(
        self,
        firewall_name: str,
        interface_names: List[str],
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get interface metrics for multiple interfaces in a single query (fixes N+1 problem)
        Returns dict mapping interface_name to list of metrics
        """
        if not interface_names:
            return {}

        try:
            with self._get_connection() as conn:
                # Build query with IN clause for multiple interfaces
                placeholders = ",".join("?" * len(interface_names))
                query = f"""
                    SELECT * FROM interface_metrics
                    WHERE firewall_name = ?
                    AND interface_name IN ({placeholders})
                """
                params = [firewall_name] + list(interface_names)

                if start_time:
                    query += " AND timestamp >= ?"
                    params.append(start_time)

                if end_time:
                    query += " AND timestamp <= ?"
                    params.append(end_time)

                # FIXED: Apply limit PER interface, not globally
                # Strategy: Fetch all matching rows, then limit per interface in Python
                # This ensures each interface gets up to 'limit' data points

                query += " ORDER BY interface_name, timestamp DESC"

                cursor = conn.execute(query, params)
                rows = cursor.fetchall()

                # Group results by interface_name and apply per-interface limit
                result = {}
                for row in rows:
                    row_dict = dict(row)
                    iface = row_dict["interface_name"]
                    if iface not in result:
                        result[iface] = []

                    # Apply limit PER interface (e.g., 500 points per interface, not 500 total)
                    if limit is None or len(result[iface]) < limit:
                        result[iface].append(row_dict)

                iface_count = len(result)
                max_pts = limit or "all"
                LOG.info(f"Batch query: {iface_count} interfaces (up to {max_pts} pts)")
                if limit:
                    total_points = sum(len(points) for points in result.values())
                    LOG.debug(f"Returned {total_points} points across {iface_count} interfaces")

                return result

        except Exception as e:
            LOG.error(f"Failed to get interface metrics batch for {firewall_name}: {e}")
            return {}

    def get_session_statistics(
        self,
        firewall_name: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Get session statistics for a firewall"""
        try:
            with self._get_connection() as conn:
                query = """
                    SELECT * FROM session_statistics
                    WHERE firewall_name = ?
                """
                params = [firewall_name]

                if start_time:
                    query += " AND timestamp >= ?"
                    params.append(start_time)

                if end_time:
                    query += " AND timestamp <= ?"
                    params.append(end_time)

                query += " ORDER BY timestamp DESC"

                if limit:
                    query += " LIMIT ?"
                    params.append(limit)

                cursor = conn.execute(query, params)
                rows = cursor.fetchall()

                return [dict(row) for row in rows]
        except Exception as e:
            LOG.error(f"Failed to get session statistics for {firewall_name}: {e}")
            return []

    def get_available_interfaces(self, firewall_name: str) -> List[str]:
        """Get list of available interfaces for a firewall"""
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    """
                    SELECT DISTINCT interface_name
                    FROM interface_metrics
                    WHERE firewall_name = ?
                    ORDER BY interface_name
                """,
                    (firewall_name,),
                )

                return [row[0] for row in cursor.fetchall()]
        except Exception as e:
            LOG.error(f"Failed to get available interfaces for {firewall_name}: {e}")
            return []

    def get_latest_interface_summary(
        self, firewall_name: str, interface_names: List[str]
    ) -> Dict[str, Dict[str, Any]]:
        """
        Get latest metrics for multiple interfaces in a single query.
        Returns dict mapping interface_name to latest metrics
        """
        if not interface_names:
            return {}

        try:
            with self._get_connection() as conn:
                # Build query with IN clause and get latest record per interface
                placeholders = ",".join("?" * len(interface_names))
                query = f"""
                    SELECT im.*
                    FROM interface_metrics im
                    INNER JOIN (
                        SELECT interface_name, MAX(timestamp) as max_timestamp
                        FROM interface_metrics
                        WHERE firewall_name = ? AND interface_name IN ({placeholders})
                        GROUP BY interface_name
                    ) latest ON im.interface_name = latest.interface_name
                              AND im.timestamp = latest.max_timestamp
                    WHERE im.firewall_name = ?
                """
                params = [firewall_name] + list(interface_names) + [firewall_name]

                cursor = conn.execute(query, params)
                rows = cursor.fetchall()

                # Map interface_name to metrics
                result = {}
                for row in rows:
                    row_dict = dict(row)
                    result[row_dict["interface_name"]] = row_dict

                LOG.debug(f"Fetched latest metrics for {len(result)} interfaces in single query")
                return result

        except Exception as e:
            LOG.error(f"Failed to get latest interface summary for {firewall_name}: {e}")
            return {}

    # Include all original methods from the base database class
    def get_metrics(
        self,
        firewall_name: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve metrics for a firewall within time range"""
        try:
            with self._get_connection() as conn:
                query = """
                    SELECT * FROM metrics
                    WHERE firewall_name = ?
                """
                params = [firewall_name]

                if start_time:
                    query += " AND timestamp >= ?"
                    params.append(start_time)

                if end_time:
                    query += " AND timestamp <= ?"
                    params.append(end_time)

                query += " ORDER BY timestamp DESC"

                if limit:
                    query += " LIMIT ?"
                    params.append(limit)

                cursor = conn.execute(query, params)
                rows = cursor.fetchall()

                return [dict(row) for row in rows]
        except Exception as e:
            LOG.error(f"Failed to retrieve metrics for {firewall_name}: {e}")
            return []

    def get_latest_metrics(self, firewall_name: str, count: int = 100) -> List[Dict[str, Any]]:
        """Get the latest N metrics for a firewall"""
        return self.get_metrics(firewall_name, limit=count)

    def get_all_firewalls(self) -> List[Dict[str, Any]]:
        """Get list of all registered firewalls with hardware info"""
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    """
                    SELECT f.name, f.host, f.created_at, f.updated_at,
                           f.model, f.family, f.platform_family, f.serial,
                           f.hostname, f.sw_version,
                           COUNT(m.id) as metric_count,
                           MAX(m.timestamp) as last_metric_time
                    FROM firewalls f
                    LEFT JOIN metrics m ON f.name = m.firewall_name
                    GROUP BY f.name, f.host, f.created_at, f.updated_at,
                             f.model, f.family, f.platform_family, f.serial,
                             f.hostname, f.sw_version
                    ORDER BY f.name
                """
                )
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            LOG.error(f"Failed to retrieve firewalls: {e}")
            return []

    def get_database_stats(self) -> Dict[str, Any]:
        """Get enhanced database statistics including interface data"""
        try:
            with self._get_connection() as conn:
                # Get total metrics count
                cursor = conn.execute("SELECT COUNT(*) as total_metrics FROM metrics")
                total_metrics = cursor.fetchone()["total_metrics"]

                # Get metrics per firewall
                cursor = conn.execute(
                    """
                    SELECT firewall_name, COUNT(*) as count
                    FROM metrics
                    GROUP BY firewall_name
                """
                )
                firewall_counts = {row["firewall_name"]: row["count"] for row in cursor.fetchall()}

                # Get date range
                cursor = conn.execute(
                    """
                    SELECT MIN(timestamp) as earliest, MAX(timestamp) as latest
                    FROM metrics
                """
                )
                date_range = cursor.fetchone()

                # Get interface metrics count
                cursor = conn.execute("SELECT COUNT(*) as interface_metrics FROM interface_metrics")
                interface_metrics_count = cursor.fetchone()["interface_metrics"]

                # Get session statistics count
                cursor = conn.execute("SELECT COUNT(*) as session_stats FROM session_statistics")
                session_stats_count = cursor.fetchone()["session_stats"]

                # Get database file size
                db_size = self.db_path.stat().st_size if self.db_path.exists() else 0

                stats = {
                    "total_metrics": total_metrics,
                    "interface_metrics_count": interface_metrics_count,
                    "session_statistics_count": session_stats_count,
                    "firewall_counts": firewall_counts,
                    "earliest_metric": date_range["earliest"],
                    "latest_metric": date_range["latest"],
                    "database_size_bytes": db_size,
                    "database_size_mb": round(db_size / (1024 * 1024), 2),
                    "enhanced_monitoring_available": True,
                }

                return stats
        except Exception as e:
            LOG.error(f"Failed to get enhanced database stats: {e}")
            return {}

    def cleanup_old_metrics(self, days_to_keep: int = 30) -> int:
        """Remove metrics older than specified days from all tables"""
        try:
            cutoff_time = datetime.now(timezone.utc) - timedelta(days=days_to_keep)
            total_deleted = 0

            with self._get_connection() as conn:
                # Clean main metrics
                cursor = conn.execute("DELETE FROM metrics WHERE timestamp < ?", (cutoff_time,))
                deleted_metrics = cursor.rowcount

                # Clean interface metrics
                cursor = conn.execute(
                    "DELETE FROM interface_metrics WHERE timestamp < ?", (cutoff_time,)
                )
                deleted_interface = cursor.rowcount

                # Clean session statistics
                cursor = conn.execute(
                    "DELETE FROM session_statistics WHERE timestamp < ?", (cutoff_time,)
                )
                deleted_sessions = cursor.rowcount

                # Clean vendor-specific metrics tables
                deleted_fortinet = 0
                deleted_palo_alto = 0
                deleted_cisco = 0
                try:
                    cursor = conn.execute(
                        "DELETE FROM fortinet_metrics WHERE timestamp < ?", (cutoff_time,)
                    )
                    deleted_fortinet = cursor.rowcount
                except Exception:
                    pass  # Table may not exist

                try:
                    cursor = conn.execute(
                        "DELETE FROM palo_alto_metrics WHERE timestamp < ?", (cutoff_time,)
                    )
                    deleted_palo_alto = cursor.rowcount
                except Exception:
                    pass  # Table may not exist

                try:
                    cursor = conn.execute(
                        "DELETE FROM cisco_firepower_metrics WHERE timestamp < ?", (cutoff_time,)
                    )
                    deleted_cisco = cursor.rowcount
                except Exception:
                    pass  # Table may not exist

                conn.commit()

                total_deleted = (
                    deleted_metrics
                    + deleted_interface
                    + deleted_sessions
                    + deleted_fortinet
                    + deleted_palo_alto
                    + deleted_cisco
                )

                if total_deleted > 0:
                    LOG.info(
                        f"Cleaned up {deleted_metrics} metrics, {deleted_interface} interface, "
                        f"{deleted_sessions} session, {deleted_fortinet} Fortinet, "
                        f"{deleted_palo_alto} PA records (>{days_to_keep} days old)"
                    )

                return total_deleted
        except Exception as e:
            LOG.error(f"Failed to cleanup old data: {e}")
            return 0

    def export_metrics_to_dict(
        self,
        firewall_name: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Export enhanced metrics to dictionary format suitable for pandas/CSV"""
        metrics = self.get_metrics(firewall_name, start_time, end_time)

        # Convert timestamps to ISO format strings for export
        for metric in metrics:
            if "timestamp" in metric and metric["timestamp"]:
                if isinstance(metric["timestamp"], str):
                    # Already a string, ensure it's ISO format
                    try:
                        dt = parse_iso_datetime(metric["timestamp"])
                        metric["timestamp"] = dt.isoformat()
                    except Exception:
                        pass  # Keep original if parsing fails
                else:
                    # Convert datetime to ISO string
                    metric["timestamp"] = metric["timestamp"].isoformat()

        return metrics


# Maintain backward compatibility
class MetricsDatabase(EnhancedMetricsDatabase):
    """Backward compatibility alias for the enhanced database"""

    pass
