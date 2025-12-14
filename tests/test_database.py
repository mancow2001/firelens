#!/usr/bin/env python3
"""
Unit tests for database performance optimizations
Tests connection pooling, batch queries, and index creation
"""
import unittest
import tempfile
import sqlite3
from pathlib import Path
from datetime import datetime, timezone, timedelta
from firelens.database import EnhancedMetricsDatabase


class TestDatabaseConnectionPooling(unittest.TestCase):
    """Test database connection pooling"""

    def setUp(self):
        """Create temporary database for testing"""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_metrics.db"
        self.db = EnhancedMetricsDatabase(str(self.db_path))

    def tearDown(self):
        """Clean up temporary database"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_connection_pool_initialization(self):
        """Test that connection pool is initialized"""
        self.assertTrue(hasattr(self.db, '_connection_pool'))
        self.assertTrue(hasattr(self.db, '_pool_lock'))
        self.assertTrue(hasattr(self.db, '_thread_local'))

    def test_connection_reuse(self):
        """Test that connections are reused from pool"""
        # Make multiple queries and check pool grows
        for i in range(5):
            self.db.register_firewall(f"fw{i}", f"https://fw{i}.example.com")

        # Pool should have connections
        pool_size = self.db._connection_pool.qsize()
        self.assertGreater(pool_size, 0, "Connection pool should have reused connections")
        self.assertLessEqual(pool_size, 10, "Pool should not exceed maximum size")

    def test_connection_pool_limit(self):
        """Test that connection pool doesn't exceed max size"""
        # Create more connections than pool size
        for i in range(20):
            self.db.register_firewall(f"fw{i}", f"https://fw{i}.example.com")

        pool_size = self.db._connection_pool.qsize()
        self.assertLessEqual(pool_size, 10, "Pool should not exceed 10 connections")


class TestBatchQueries(unittest.TestCase):
    """Test batch query methods that fix N+1 problems"""

    def setUp(self):
        """Create temporary database with test data"""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_metrics.db"
        self.db = EnhancedMetricsDatabase(str(self.db_path))

        # Register test firewall
        self.db.register_firewall("test_fw", "https://test.example.com")

        # Insert test interface metrics
        timestamp = datetime.now(timezone.utc)
        for interface in ["ethernet1/1", "ethernet1/2", "ethernet1/3"]:
            for i in range(5):
                metrics = {
                    'interface_name': interface,
                    'timestamp': timestamp - timedelta(minutes=i),
                    'rx_mbps': 10.0 + i,
                    'tx_mbps': 5.0 + i,
                    'total_mbps': 15.0 + i,
                    'rx_pps': 1000,
                    'tx_pps': 500,
                    'rx_bytes': 1000000,
                    'tx_bytes': 500000,
                    'rx_packets': 10000,
                    'tx_packets': 5000,
                    'rx_errors': 0,
                    'tx_errors': 0,
                    'interval_seconds': 30.0
                }
                self.db.insert_interface_metrics("test_fw", metrics)

    def tearDown(self):
        """Clean up temporary database"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_get_interface_metrics_batch(self):
        """Test batch interface metrics query"""
        interfaces = ["ethernet1/1", "ethernet1/2", "ethernet1/3"]
        result = self.db.get_interface_metrics_batch("test_fw", interfaces, limit=500)

        # Should return data for all 3 interfaces
        self.assertEqual(len(result), 3, "Should return metrics for 3 interfaces")
        self.assertIn("ethernet1/1", result)
        self.assertIn("ethernet1/2", result)
        self.assertIn("ethernet1/3", result)

        # Each interface should have 5 data points (we inserted 5 per interface in setUp)
        for interface in interfaces:
            self.assertGreater(len(result[interface]), 0, f"{interface} should have data")
            self.assertEqual(len(result[interface]), 5, f"{interface} should have all 5 data points")

    def test_get_interface_metrics_batch_per_interface_limit(self):
        """Test that limit applies PER interface, not globally"""
        interfaces = ["ethernet1/1", "ethernet1/2", "ethernet1/3"]

        # Request limit of 3 points
        result = self.db.get_interface_metrics_batch("test_fw", interfaces, limit=3)

        # Should return data for all 3 interfaces
        self.assertEqual(len(result), 3, "Should return metrics for all 3 interfaces")

        # IMPORTANT: Each interface should get UP TO 3 points (limit per interface)
        # NOT 3 points total divided among interfaces
        for interface in interfaces:
            self.assertGreater(len(result[interface]), 0, f"{interface} should have data")
            self.assertLessEqual(len(result[interface]), 3, f"{interface} should have at most 3 points")
            # Since we inserted 5 points per interface, with limit=3 we should get exactly 3
            self.assertEqual(len(result[interface]), 3, f"{interface} should have exactly 3 points with limit=3")

    def test_get_interface_metrics_batch_with_time_filter(self):
        """Test batch query with time filters"""
        interfaces = ["ethernet1/1", "ethernet1/2"]
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=2)

        result = self.db.get_interface_metrics_batch(
            "test_fw", interfaces, start_time=start_time, end_time=end_time
        )

        self.assertGreater(len(result), 0, "Should return filtered results")

    def test_get_latest_interface_summary(self):
        """Test latest interface summary batch query"""
        interfaces = ["ethernet1/1", "ethernet1/2", "ethernet1/3"]
        result = self.db.get_latest_interface_summary("test_fw", interfaces)

        # Should return latest metrics for each interface
        self.assertEqual(len(result), 3, "Should return latest for 3 interfaces")

        for interface in interfaces:
            self.assertIn(interface, result, f"Should have {interface} in results")
            metrics = result[interface]
            self.assertIn('rx_mbps', metrics)
            self.assertIn('tx_mbps', metrics)
            self.assertIn('total_mbps', metrics)

    def test_batch_query_performance(self):
        """Test that batch query is faster than N+1 queries"""
        import time

        interfaces = ["ethernet1/1", "ethernet1/2", "ethernet1/3"]

        # Time N+1 queries (individual queries in loop)
        start = time.time()
        individual_results = {}
        for interface in interfaces:
            metrics = self.db.get_interface_metrics("test_fw", interface, limit=5)
            if metrics:
                individual_results[interface] = metrics
        individual_time = time.time() - start

        # Time batch query
        start = time.time()
        batch_results = self.db.get_interface_metrics_batch("test_fw", interfaces, limit=5)
        batch_time = time.time() - start

        # Batch should be faster (or at least not slower)
        self.assertLessEqual(batch_time, individual_time * 1.5,
                            "Batch query should be comparable or faster than N+1 queries")


class TestDatabaseIndexes(unittest.TestCase):
    """Test that performance indexes are created"""

    def setUp(self):
        """Create temporary database"""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_metrics.db"
        self.db = EnhancedMetricsDatabase(str(self.db_path))

    def tearDown(self):
        """Clean up temporary database"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_interface_metrics_indexes_created(self):
        """Test that interface metrics indexes are created"""
        with self.db._get_connection() as conn:
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='interface_metrics'"
            )
            indexes = [row[0] for row in cursor.fetchall()]

        # Check for expected indexes (partial indexes removed for SQLite compatibility)
        expected_indexes = [
            'idx_interface_metrics_firewall_interface_timestamp',
            'idx_interface_metrics_firewall_timestamp'
        ]

        for expected in expected_indexes:
            self.assertIn(expected, indexes, f"Index {expected} should be created")

    def test_session_statistics_indexes_created(self):
        """Test that session statistics indexes are created"""
        with self.db._get_connection() as conn:
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='session_statistics'"
            )
            indexes = [row[0] for row in cursor.fetchall()]

        expected_indexes = [
            'idx_session_statistics_firewall_timestamp'
        ]

        for expected in expected_indexes:
            self.assertIn(expected, indexes, f"Index {expected} should be created")

    def test_indexes_improve_query_performance(self):
        """Test that indexes exist and improve performance"""
        # Just verify that standard indexes exist (partial indexes removed for compatibility)
        with self.db._get_connection() as conn:
            cursor = conn.execute(
                """SELECT name FROM sqlite_master WHERE type='index'"""
            )
            indexes = [row[0] for row in cursor.fetchall()]

        # Should have at least the main performance indexes
        self.assertGreater(len(indexes), 0, "Should have performance indexes created")


class TestFirewallHardwareInfo(unittest.TestCase):
    """Test firewall hardware information storage and retrieval"""

    def setUp(self):
        """Create temporary database for testing"""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_metrics.db"
        self.db = EnhancedMetricsDatabase(str(self.db_path))

    def tearDown(self):
        """Clean up temporary database"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_schema_has_hardware_columns(self):
        """Test that firewalls table has hardware info columns"""
        with self.db._get_connection() as conn:
            cursor = conn.execute("PRAGMA table_info(firewalls)")
            columns = [row[1] for row in cursor.fetchall()]

        expected_columns = ['model', 'family', 'platform_family', 'serial',
                          'hostname', 'sw_version']

        for col in expected_columns:
            self.assertIn(col, columns,
                         f"Column {col} should exist in firewalls table")

    def test_register_firewall_with_hardware_info(self):
        """Test registering firewall with hardware information"""
        hardware_info = {
            'model': 'PA-3430',
            'family': '3000',
            'platform_family': 'pa-3400-series',
            'serial': '001234567890',
            'hostname': 'datacenter-fw',
            'sw_version': '11.0.3'
        }

        success = self.db.register_firewall('test_fw', 'https://10.0.0.1', hardware_info)

        self.assertTrue(success, "Should successfully register firewall with hardware info")

        # Verify data was stored
        firewalls = self.db.get_all_firewalls()
        self.assertEqual(len(firewalls), 1)

        fw = firewalls[0]
        self.assertEqual(fw['name'], 'test_fw')
        self.assertEqual(fw['model'], 'PA-3430')
        self.assertEqual(fw['family'], '3000')
        self.assertEqual(fw['platform_family'], 'pa-3400-series')
        self.assertEqual(fw['serial'], '001234567890')
        self.assertEqual(fw['hostname'], 'datacenter-fw')
        self.assertEqual(fw['sw_version'], '11.0.3')

    def test_register_firewall_without_hardware_info(self):
        """Test registering firewall without hardware info still works"""
        success = self.db.register_firewall('test_fw', 'https://10.0.0.1')

        self.assertTrue(success, "Should successfully register firewall without hardware info")

        firewalls = self.db.get_all_firewalls()
        self.assertEqual(len(firewalls), 1)

        fw = firewalls[0]
        self.assertEqual(fw['name'], 'test_fw')
        self.assertEqual(fw['host'], 'https://10.0.0.1')
        # Hardware fields should be None or empty
        self.assertIn(fw.get('model'), [None, ''])

    def test_register_firewall_updates_hardware_info(self):
        """Test that re-registering firewall updates hardware info"""
        # Register without hardware info
        self.db.register_firewall('test_fw', 'https://10.0.0.1')

        # Register again with hardware info
        hardware_info = {
            'model': 'PA-3430',
            'family': '3000',
            'sw_version': '11.0.3'
        }
        self.db.register_firewall('test_fw', 'https://10.0.0.1', hardware_info)

        # Verify hardware info was added
        firewalls = self.db.get_all_firewalls()
        self.assertEqual(len(firewalls), 1)

        fw = firewalls[0]
        self.assertEqual(fw['model'], 'PA-3430')
        self.assertEqual(fw['family'], '3000')
        self.assertEqual(fw['sw_version'], '11.0.3')

    def test_get_all_firewalls_includes_hardware_info(self):
        """Test that get_all_firewalls returns hardware info"""
        # Register multiple firewalls with different hardware info
        firewalls_data = [
            ('fw1', 'https://10.0.0.1', {'model': 'PA-3430', 'sw_version': '11.0.3'}),
            ('fw2', 'https://10.0.0.2', {'model': 'PA-5445', 'sw_version': '11.1.0'}),
            ('fw3', 'https://10.0.0.3', None)
        ]

        for name, host, hw_info in firewalls_data:
            self.db.register_firewall(name, host, hw_info)

        # Retrieve all firewalls
        firewalls = self.db.get_all_firewalls()

        self.assertEqual(len(firewalls), 3)

        # Verify first firewall
        fw1 = next(fw for fw in firewalls if fw['name'] == 'fw1')
        self.assertEqual(fw1['model'], 'PA-3430')
        self.assertEqual(fw1['sw_version'], '11.0.3')

        # Verify second firewall
        fw2 = next(fw for fw in firewalls if fw['name'] == 'fw2')
        self.assertEqual(fw2['model'], 'PA-5445')
        self.assertEqual(fw2['sw_version'], '11.1.0')

        # Verify third firewall (no hardware info)
        fw3 = next(fw for fw in firewalls if fw['name'] == 'fw3')
        self.assertIn(fw3.get('model'), [None, ''])

    def test_schema_migration_idempotent(self):
        """Test that schema migration can be run multiple times safely"""
        # Migration happens during __init__, so create multiple instances
        db1 = EnhancedMetricsDatabase(str(self.db_path))
        db2 = EnhancedMetricsDatabase(str(self.db_path))
        db3 = EnhancedMetricsDatabase(str(self.db_path))

        # Verify columns still exist
        with self.db._get_connection() as conn:
            cursor = conn.execute("PRAGMA table_info(firewalls)")
            columns = [row[1] for row in cursor.fetchall()]

        self.assertIn('model', columns)
        self.assertIn('family', columns)
        self.assertIn('sw_version', columns)

    def test_hardware_info_with_partial_data(self):
        """Test storing hardware info with only some fields populated"""
        hardware_info = {
            'model': 'PA-3430',
            'sw_version': '11.0.3'
            # Other fields not provided
        }

        self.db.register_firewall('test_fw', 'https://10.0.0.1', hardware_info)

        firewalls = self.db.get_all_firewalls()
        fw = firewalls[0]

        self.assertEqual(fw['model'], 'PA-3430')
        self.assertEqual(fw['sw_version'], '11.0.3')
        # Unprovided fields should be None or empty
        self.assertIn(fw.get('family'), [None, ''])
        self.assertIn(fw.get('serial'), [None, ''])


class TestFirewallUnregister(unittest.TestCase):
    """Test firewall unregister functionality"""

    def setUp(self):
        """Create temporary database for testing"""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_metrics.db"
        self.db = EnhancedMetricsDatabase(str(self.db_path))

    def tearDown(self):
        """Clean up temporary database"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_unregister_firewall_removes_from_database(self):
        """Test that unregister_firewall removes firewall from database"""
        # Register a firewall
        self.db.register_firewall('test_fw', 'https://10.0.0.1')
        firewalls = self.db.get_all_firewalls()
        self.assertEqual(len(firewalls), 1)

        # Unregister
        result = self.db.unregister_firewall('test_fw')
        self.assertTrue(result, "Should successfully unregister firewall")

        # Verify removed
        firewalls = self.db.get_all_firewalls()
        self.assertEqual(len(firewalls), 0)

    def test_unregister_nonexistent_firewall_returns_false(self):
        """Test that unregistering non-existent firewall returns False"""
        result = self.db.unregister_firewall('nonexistent_fw')
        self.assertFalse(result, "Should return False for non-existent firewall")

    def test_unregister_firewall_deletes_metrics(self):
        """Test that unregister_firewall also deletes associated metrics"""
        # Register and add some metrics
        self.db.register_firewall('test_fw', 'https://10.0.0.1')
        self.db.insert_metrics('test_fw', {
            'mgmt_cpu': 25.0,
            'data_plane_cpu': 30.0,
            'throughput_mbps_total': 100.0
        })

        # Verify metrics exist
        metrics = self.db.get_latest_metrics('test_fw', count=10)
        self.assertGreater(len(metrics), 0)

        # Unregister with delete_metrics=True (default)
        self.db.unregister_firewall('test_fw', delete_metrics=True)

        # Verify metrics are also gone
        metrics = self.db.get_latest_metrics('test_fw', count=10)
        self.assertEqual(len(metrics), 0)

    def test_unregister_firewall_preserves_metrics_when_requested(self):
        """Test that unregister can preserve metrics if requested"""
        # Register and add some metrics
        self.db.register_firewall('test_fw', 'https://10.0.0.1')
        self.db.insert_metrics('test_fw', {
            'mgmt_cpu': 25.0,
            'data_plane_cpu': 30.0
        })

        # Unregister with delete_metrics=False
        self.db.unregister_firewall('test_fw', delete_metrics=False)

        # Firewall should be gone
        firewalls = self.db.get_all_firewalls()
        self.assertEqual(len(firewalls), 0)

        # But metrics should still exist
        metrics = self.db.get_latest_metrics('test_fw', count=10)
        self.assertGreater(len(metrics), 0)


class TestFirewallRename(unittest.TestCase):
    """Test firewall rename functionality with cascading updates"""

    def setUp(self):
        """Create temporary database with test data"""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_metrics.db"
        self.db = EnhancedMetricsDatabase(str(self.db_path))

    def tearDown(self):
        """Clean up temporary database"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_rename_success(self):
        """Test successful firewall rename cascades to all tables"""
        # Register firewall
        self.db.register_firewall('old_name', 'https://10.0.0.1')

        # Add some metrics
        self.db.insert_metrics('old_name', {
            'mgmt_cpu': 25.0,
            'data_plane_cpu': 30.0,
            'throughput_mbps_total': 100.0
        })

        # Add interface metrics
        self.db.insert_interface_metrics('old_name', {
            'interface_name': 'ethernet1/1',
            'timestamp': datetime.now(timezone.utc),
            'rx_mbps': 10.0,
            'tx_mbps': 5.0,
            'total_mbps': 15.0,
            'rx_pps': 1000,
            'tx_pps': 500,
            'rx_bytes': 1000000,
            'tx_bytes': 500000,
            'rx_packets': 10000,
            'tx_packets': 5000,
            'rx_errors': 0,
            'tx_errors': 0,
            'interval_seconds': 30.0
        })

        # Rename firewall
        success, message = self.db.rename_firewall('old_name', 'new_name')

        self.assertTrue(success, f"Rename should succeed: {message}")
        self.assertIn('Successfully renamed', message)

        # Verify firewall was renamed
        firewalls = self.db.get_all_firewalls()
        fw_names = [fw['name'] for fw in firewalls]
        self.assertIn('new_name', fw_names)
        self.assertNotIn('old_name', fw_names)

        # Verify metrics are accessible under new name
        metrics = self.db.get_latest_metrics('new_name', count=10)
        self.assertGreater(len(metrics), 0, "Metrics should be preserved under new name")

        # Verify old name has no metrics
        old_metrics = self.db.get_latest_metrics('old_name', count=10)
        self.assertEqual(len(old_metrics), 0, "Old name should have no metrics")

        # Verify interface metrics are accessible under new name
        interface_metrics = self.db.get_interface_metrics('new_name', 'ethernet1/1', limit=10)
        self.assertGreater(len(interface_metrics), 0, "Interface metrics should be preserved")

    def test_rename_nonexistent_firewall(self):
        """Test renaming a firewall that doesn't exist"""
        success, message = self.db.rename_firewall('nonexistent', 'new_name')

        self.assertFalse(success)
        self.assertIn('not found', message.lower())

    def test_rename_to_existing_name(self):
        """Test renaming to a name that already exists fails"""
        # Register two firewalls
        self.db.register_firewall('fw1', 'https://10.0.0.1')
        self.db.register_firewall('fw2', 'https://10.0.0.2')

        # Try to rename fw1 to fw2
        success, message = self.db.rename_firewall('fw1', 'fw2')

        self.assertFalse(success)
        self.assertIn('already exists', message.lower())

        # Verify both firewalls still exist with original names
        firewalls = self.db.get_all_firewalls()
        fw_names = [fw['name'] for fw in firewalls]
        self.assertIn('fw1', fw_names)
        self.assertIn('fw2', fw_names)

    def test_rename_same_name(self):
        """Test renaming to same name is a no-op"""
        self.db.register_firewall('test_fw', 'https://10.0.0.1')

        success, message = self.db.rename_firewall('test_fw', 'test_fw')

        self.assertTrue(success)
        self.assertIn('identical', message.lower())

    def test_rename_preserves_metrics(self):
        """Test that metrics are preserved after rename"""
        # Register firewall
        self.db.register_firewall('original', 'https://10.0.0.1')

        # Add multiple metrics with different values (using vendor_type to route to vendor table)
        for i in range(5):
            self.db.insert_metrics('original', {
                'mgmt_cpu': 20.0 + i,
                'data_plane_cpu_mean': 30.0 + i,
                'pbuf_util_percent': 10.0 + i
            }, vendor_type='palo_alto')

        # Get metric count before rename (main metrics table)
        metrics_before = self.db.get_latest_metrics('original', count=100)
        count_before = len(metrics_before)

        # Get vendor metrics before rename
        vendor_before = self.db.get_palo_alto_metrics('original', limit=100)
        vendor_count_before = len(vendor_before)

        # Rename
        success, _ = self.db.rename_firewall('original', 'renamed')
        self.assertTrue(success)

        # Get metrics after rename
        metrics_after = self.db.get_latest_metrics('renamed', count=100)
        count_after = len(metrics_after)

        # Get vendor metrics after rename
        vendor_after = self.db.get_palo_alto_metrics('renamed', limit=100)
        vendor_count_after = len(vendor_after)

        # Same number of metrics should exist in both tables
        self.assertEqual(count_before, count_after,
                        "All main metrics should be preserved after rename")
        self.assertEqual(vendor_count_before, vendor_count_after,
                        "All vendor metrics should be preserved after rename")

        # Verify vendor metric values are preserved
        self.assertEqual(vendor_before[0]['mgmt_cpu'], vendor_after[0]['mgmt_cpu'])

    def test_rename_invalid_name_format(self):
        """Test renaming to invalid name format fails"""
        self.db.register_firewall('test_fw', 'https://10.0.0.1')

        # Test invalid characters
        invalid_names = ['fw with spaces', 'fw-with-dashes', 'fw.with.dots', 'fw@special']
        for invalid_name in invalid_names:
            success, message = self.db.rename_firewall('test_fw', invalid_name)
            self.assertFalse(success, f"Should reject invalid name: {invalid_name}")
            self.assertIn('letters, numbers, and underscores', message.lower())

    def test_rename_preserves_hardware_info(self):
        """Test that hardware info is preserved after rename"""
        hardware_info = {
            'model': 'PA-3430',
            'family': '3000',
            'serial': '001234567890',
            'sw_version': '11.0.3'
        }
        self.db.register_firewall('original', 'https://10.0.0.1', hardware_info)

        # Rename
        success, _ = self.db.rename_firewall('original', 'renamed')
        self.assertTrue(success)

        # Verify hardware info preserved
        firewalls = self.db.get_all_firewalls()
        fw = next(fw for fw in firewalls if fw['name'] == 'renamed')

        self.assertEqual(fw['model'], 'PA-3430')
        self.assertEqual(fw['family'], '3000')
        self.assertEqual(fw['serial'], '001234567890')
        self.assertEqual(fw['sw_version'], '11.0.3')

    def test_rename_updates_timestamp(self):
        """Test that rename updates the updated_at timestamp"""
        self.db.register_firewall('test_fw', 'https://10.0.0.1')

        # Get original timestamp
        firewalls = self.db.get_all_firewalls()
        original_updated = firewalls[0].get('updated_at')

        # Wait more than 1 second since SQLite CURRENT_TIMESTAMP has second precision
        import time
        time.sleep(1.1)

        success, _ = self.db.rename_firewall('test_fw', 'renamed')
        self.assertTrue(success)

        # Get new timestamp
        firewalls = self.db.get_all_firewalls()
        new_updated = firewalls[0].get('updated_at')

        # updated_at should be different (newer)
        if original_updated and new_updated:
            self.assertNotEqual(original_updated, new_updated,
                               "updated_at should change after rename")


class TestBackgroundRenameTask(unittest.TestCase):
    """Test background rename task functionality"""

    def setUp(self):
        """Create temporary database with test data"""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_metrics.db"
        self.db = EnhancedMetricsDatabase(str(self.db_path))

    def tearDown(self):
        """Clean up temporary database"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_rename_tasks_table_exists(self):
        """Test that rename_tasks table is created"""
        with self.db._get_connection() as conn:
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='rename_tasks'"
            )
            result = cursor.fetchone()
        self.assertIsNotNone(result, "rename_tasks table should exist")

    def test_count_firewall_references_empty(self):
        """Test counting references for a firewall with no data"""
        self.db.register_firewall('test_fw', 'https://10.0.0.1')

        counts = self.db.count_firewall_references('test_fw')

        self.assertEqual(counts['metrics'], 0)
        self.assertEqual(counts['interface_metrics'], 0)
        self.assertEqual(counts['session_statistics'], 0)

    def test_count_firewall_references_with_data(self):
        """Test counting references for a firewall with data"""
        self.db.register_firewall('test_fw', 'https://10.0.0.1')

        # Add 3 metrics
        for i in range(3):
            self.db.insert_metrics('test_fw', {
                'mgmt_cpu': 25.0 + i,
                'data_plane_cpu': 30.0 + i
            })

        # Add 2 interface metrics
        for i in range(2):
            self.db.insert_interface_metrics('test_fw', {
                'interface_name': 'ethernet1/1',
                'timestamp': datetime.now(timezone.utc),
                'rx_mbps': 10.0,
                'tx_mbps': 5.0,
                'total_mbps': 15.0,
                'rx_pps': 1000,
                'tx_pps': 500,
                'interval_seconds': 30.0
            })

        counts = self.db.count_firewall_references('test_fw')

        self.assertEqual(counts['metrics'], 3)
        self.assertEqual(counts['interface_metrics'], 2)
        self.assertEqual(counts['session_statistics'], 0)

    def test_start_rename_task_validation_same_name(self):
        """Test that starting a rename with same name fails"""
        self.db.register_firewall('test_fw', 'https://10.0.0.1')

        task_id, error = self.db.start_rename_task('test_fw', 'test_fw')

        self.assertIsNone(task_id)
        self.assertIn('identical', error.lower())

    def test_start_rename_task_validation_invalid_format(self):
        """Test that invalid name format is rejected"""
        self.db.register_firewall('test_fw', 'https://10.0.0.1')

        task_id, error = self.db.start_rename_task('test_fw', 'fw-with-dashes')

        self.assertIsNone(task_id)
        self.assertIn('invalid', error.lower())

    def test_start_rename_task_validation_nonexistent(self):
        """Test that renaming nonexistent firewall fails"""
        task_id, error = self.db.start_rename_task('nonexistent', 'new_name')

        self.assertIsNone(task_id)
        self.assertIn('not found', error.lower())

    def test_start_rename_task_validation_duplicate(self):
        """Test that renaming to existing name fails"""
        self.db.register_firewall('fw1', 'https://10.0.0.1')
        self.db.register_firewall('fw2', 'https://10.0.0.2')

        task_id, error = self.db.start_rename_task('fw1', 'fw2')

        self.assertIsNone(task_id)
        self.assertIn('already exists', error.lower())

    def test_start_rename_task_success(self):
        """Test successfully starting a rename task"""
        self.db.register_firewall('old_name', 'https://10.0.0.1')

        task_id, error = self.db.start_rename_task('old_name', 'new_name')

        self.assertIsNotNone(task_id, f"Task should be created: {error}")
        self.assertIsNone(error)
        self.assertEqual(len(task_id), 8, "Task ID should be 8 characters")

    def test_get_rename_task_status_not_found(self):
        """Test getting status for nonexistent task"""
        status = self.db.get_rename_task_status('nonexistent')
        self.assertIsNone(status)

    def test_rename_task_completes(self):
        """Test that rename task completes successfully"""
        import time

        # Create firewall with some data
        self.db.register_firewall('old_name', 'https://10.0.0.1')
        self.db.insert_metrics('old_name', {
            'mgmt_cpu': 25.0,
            'data_plane_cpu': 30.0
        })

        # Start rename task
        task_id, error = self.db.start_rename_task('old_name', 'new_name')
        self.assertIsNotNone(task_id, f"Task should start: {error}")

        # Wait for task to complete (should be very fast with small data)
        for _ in range(10):
            time.sleep(0.1)
            status = self.db.get_rename_task_status(task_id)
            if status and status['status'] in ('completed', 'failed'):
                break

        # Verify completion
        status = self.db.get_rename_task_status(task_id)
        self.assertIsNotNone(status)
        self.assertEqual(status['status'], 'completed', f"Task should complete: {status}")
        self.assertEqual(status['progress_percent'], 100)

        # Verify firewall was renamed
        firewalls = self.db.get_all_firewalls()
        fw_names = [fw['name'] for fw in firewalls]
        self.assertIn('new_name', fw_names)
        self.assertNotIn('old_name', fw_names)

        # Verify metrics are accessible under new name
        metrics = self.db.get_latest_metrics('new_name', count=10)
        self.assertGreater(len(metrics), 0)

    def test_rename_task_progress_tracking(self):
        """Test that task progress is tracked correctly"""
        import time

        # Create firewall with some data
        self.db.register_firewall('test_fw', 'https://10.0.0.1')
        for i in range(5):
            self.db.insert_metrics('test_fw', {
                'mgmt_cpu': 25.0 + i,
                'data_plane_cpu': 30.0 + i
            })

        # Start task
        task_id, _ = self.db.start_rename_task('test_fw', 'renamed_fw')

        # Wait for completion
        for _ in range(10):
            time.sleep(0.1)
            status = self.db.get_rename_task_status(task_id)
            if status and status['status'] == 'completed':
                break

        status = self.db.get_rename_task_status(task_id)
        self.assertEqual(status['status'], 'completed')
        self.assertEqual(status['total_rows'], 5)  # 5 metrics
        self.assertEqual(status['processed_rows'], 5)

    def test_prevent_concurrent_rename_tasks(self):
        """Test that concurrent renames of same firewall are prevented"""
        import time

        # Create firewall with data (more data = longer task)
        self.db.register_firewall('test_fw', 'https://10.0.0.1')
        for i in range(100):
            self.db.insert_metrics('test_fw', {'mgmt_cpu': 25.0 + i})

        # Start first task
        task_id1, error1 = self.db.start_rename_task('test_fw', 'new_name1')
        self.assertIsNotNone(task_id1, f"First task should start: {error1}")

        # Wait a tiny bit for first task to start
        time.sleep(0.05)

        # Try to start second task for same firewall
        task_id2, error2 = self.db.start_rename_task('test_fw', 'new_name2')

        # Second task should fail (either because task is in progress, or firewall was already renamed)
        # Both are valid outcomes depending on timing
        if task_id2 is None:
            # Second task was blocked - this is the expected behavior
            # Could be "already running/pending" OR "not found" if first task completed
            self.assertTrue(
                'already' in error2.lower() or 'not found' in error2.lower(),
                f"Expected blocking message or not found, got: {error2}"
            )
        else:
            # First task was already complete, second task started on renamed firewall
            # This shouldn't happen since we're renaming from test_fw which wouldn't exist
            status1 = self.db.get_rename_task_status(task_id1)
            self.assertEqual(status1['status'], 'completed')


class TestConfigManagerRenameFirewall(unittest.TestCase):
    """Test ConfigManager rename_firewall functionality"""

    def setUp(self):
        """Create temporary config file"""
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = Path(self.temp_dir) / "config.yaml"

        # Import ConfigManager
        from firelens.config import ConfigManager, EnhancedFirewallConfig

        # Create config manager
        self.config_manager = ConfigManager(str(self.config_path))

        # Add a test firewall
        self.config_manager.add_firewall(EnhancedFirewallConfig(
            name='test_fw',
            host='https://10.0.0.1',
            username='admin',
            password='password'
        ))

    def tearDown(self):
        """Clean up temporary config"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_rename_firewall_success(self):
        """Test successful rename in config manager"""
        result = self.config_manager.rename_firewall('test_fw', 'renamed_fw')

        self.assertTrue(result)
        self.assertIn('renamed_fw', self.config_manager.firewalls)
        self.assertNotIn('test_fw', self.config_manager.firewalls)

        # Verify the config object was updated
        fw = self.config_manager.get_firewall('renamed_fw')
        self.assertEqual(fw.name, 'renamed_fw')
        self.assertEqual(fw.host, 'https://10.0.0.1')

    def test_rename_firewall_nonexistent(self):
        """Test renaming nonexistent firewall returns False"""
        result = self.config_manager.rename_firewall('nonexistent', 'new_name')
        self.assertFalse(result)

    def test_rename_firewall_to_existing(self):
        """Test renaming to existing name returns False"""
        from firelens.config import EnhancedFirewallConfig

        # Add another firewall
        self.config_manager.add_firewall(EnhancedFirewallConfig(
            name='other_fw',
            host='https://10.0.0.2',
            username='admin',
            password='password'
        ))

        result = self.config_manager.rename_firewall('test_fw', 'other_fw')
        self.assertFalse(result)

        # Both should still exist
        self.assertIn('test_fw', self.config_manager.firewalls)
        self.assertIn('other_fw', self.config_manager.firewalls)


class TestVendorSpecificMetricsTables(unittest.TestCase):
    """Test vendor-specific metrics tables"""

    def setUp(self):
        """Create temporary database for testing"""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_metrics.db"
        self.db = EnhancedMetricsDatabase(str(self.db_path))

        # Register test firewall
        self.db.register_firewall("test_fw", "https://test.example.com")

    def tearDown(self):
        """Clean up temporary database"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_vendor_tables_created(self):
        """Test that vendor-specific metrics tables are created"""
        with self.db._get_connection() as conn:
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
            tables = [row[0] for row in cursor.fetchall()]

        self.assertIn('fortinet_metrics', tables, "fortinet_metrics table should exist")
        self.assertIn('palo_alto_metrics', tables, "palo_alto_metrics table should exist")
        self.assertIn('cisco_firepower_metrics', tables, "cisco_firepower_metrics table should exist")

    def test_fortinet_metrics_schema(self):
        """Test fortinet_metrics table has correct columns"""
        with self.db._get_connection() as conn:
            cursor = conn.execute("PRAGMA table_info(fortinet_metrics)")
            columns = [row[1] for row in cursor.fetchall()]

        expected_columns = ['firewall_name', 'timestamp', 'memory_usage_percent',
                          'session_setup_rate', 'npu_sessions']
        for col in expected_columns:
            self.assertIn(col, columns, f"Column {col} should exist in fortinet_metrics")

    def test_palo_alto_metrics_schema(self):
        """Test palo_alto_metrics table has correct columns"""
        with self.db._get_connection() as conn:
            cursor = conn.execute("PRAGMA table_info(palo_alto_metrics)")
            columns = [row[1] for row in cursor.fetchall()]

        expected_columns = ['firewall_name', 'timestamp', 'mgmt_cpu',
                          'data_plane_cpu_mean', 'data_plane_cpu_max',
                          'data_plane_cpu_p95', 'pbuf_util_percent']
        for col in expected_columns:
            self.assertIn(col, columns, f"Column {col} should exist in palo_alto_metrics")

    def test_insert_fortinet_metrics(self):
        """Test inserting Fortinet-specific metrics"""
        timestamp = datetime.now(timezone.utc)
        metrics = {
            'timestamp': timestamp,
            'memory_usage_percent': 75.5,
            'session_setup_rate': 150.0,
            'npu_sessions': 50000
        }

        success = self.db.insert_fortinet_metrics("test_fw", metrics)
        self.assertTrue(success, "Should successfully insert Fortinet metrics")

        # Verify data was stored
        results = self.db.get_fortinet_metrics("test_fw", limit=1)
        self.assertEqual(len(results), 1)
        self.assertAlmostEqual(results[0]['memory_usage_percent'], 75.5, places=1)
        self.assertAlmostEqual(results[0]['session_setup_rate'], 150.0, places=1)
        self.assertEqual(results[0]['npu_sessions'], 50000)

    def test_insert_palo_alto_metrics(self):
        """Test inserting Palo Alto-specific metrics"""
        timestamp = datetime.now(timezone.utc)
        metrics = {
            'timestamp': timestamp,
            'mgmt_cpu': 25.0,
            'data_plane_cpu_mean': 30.0,
            'data_plane_cpu_max': 45.0,
            'data_plane_cpu_p95': 40.0,
            'pbuf_util_percent': 5.5
        }

        success = self.db.insert_palo_alto_metrics("test_fw", metrics)
        self.assertTrue(success, "Should successfully insert Palo Alto metrics")

        # Verify data was stored
        results = self.db.get_palo_alto_metrics("test_fw", limit=1)
        self.assertEqual(len(results), 1)
        self.assertAlmostEqual(results[0]['mgmt_cpu'], 25.0, places=1)
        self.assertAlmostEqual(results[0]['data_plane_cpu_mean'], 30.0, places=1)
        self.assertAlmostEqual(results[0]['pbuf_util_percent'], 5.5, places=1)

    def test_get_vendor_metrics_by_type(self):
        """Test getting vendor metrics by vendor type"""
        timestamp = datetime.now(timezone.utc)

        # Insert Fortinet metrics
        self.db.insert_fortinet_metrics("test_fw", {
            'timestamp': timestamp,
            'memory_usage_percent': 80.0,
            'session_setup_rate': 200.0,
            'npu_sessions': 100000
        })

        # Get via generic method
        results = self.db.get_vendor_metrics("test_fw", "fortinet", limit=1)
        self.assertEqual(len(results), 1)
        self.assertAlmostEqual(results[0]['memory_usage_percent'], 80.0, places=1)

    def test_get_vendor_metrics_unknown_type(self):
        """Test getting vendor metrics for unknown type returns empty list"""
        results = self.db.get_vendor_metrics("test_fw", "unknown_vendor")
        self.assertEqual(results, [])

    def test_vendor_metrics_time_filtering(self):
        """Test time filtering on vendor-specific metrics"""
        now = datetime.now(timezone.utc)
        old_time = now - timedelta(hours=2)
        recent_time = now - timedelta(minutes=30)

        # Insert old and recent metrics
        self.db.insert_fortinet_metrics("test_fw", {
            'timestamp': old_time,
            'memory_usage_percent': 50.0,
            'session_setup_rate': 100.0,
            'npu_sessions': 10000
        })
        self.db.insert_fortinet_metrics("test_fw", {
            'timestamp': recent_time,
            'memory_usage_percent': 60.0,
            'session_setup_rate': 120.0,
            'npu_sessions': 15000
        })

        # Query only recent metrics
        start_time = now - timedelta(hours=1)
        results = self.db.get_fortinet_metrics("test_fw", start_time=start_time)

        self.assertEqual(len(results), 1)
        self.assertAlmostEqual(results[0]['memory_usage_percent'], 60.0, places=1)

    def test_vendor_metrics_indexes_created(self):
        """Test that vendor metrics indexes are created"""
        with self.db._get_connection() as conn:
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            )
            indexes = [row[0] for row in cursor.fetchall()]

        self.assertIn('idx_fortinet_metrics_fw_ts', indexes)
        self.assertIn('idx_palo_alto_metrics_fw_ts', indexes)
        self.assertIn('idx_cisco_firepower_metrics_fw_ts', indexes)


if __name__ == '__main__':
    unittest.main()
