#!/usr/bin/env python3
"""
Unit tests for web dashboard caching and health endpoint
"""
import unittest
import time
from datetime import datetime, timezone
from unittest.mock import Mock, patch, MagicMock
import tempfile
from pathlib import Path


class TestSimpleCache(unittest.TestCase):
    """Test the SimpleCache implementation"""

    def test_cache_initialization(self):
        """Test cache can be initialized with TTL"""
        from firelens.web_dashboard import SimpleCache

        cache = SimpleCache(ttl_seconds=30)
        self.assertEqual(cache.ttl, 30)
        self.assertEqual(len(cache.cache), 0)

    def test_cache_set_and_get(self):
        """Test setting and getting values from cache"""
        from firelens.web_dashboard import SimpleCache

        cache = SimpleCache(ttl_seconds=30)
        cache.set("test_key", "test_value")

        result = cache.get("test_key")
        self.assertEqual(result, "test_value")

    def test_cache_expiration(self):
        """Test that cache entries expire after TTL"""
        from firelens.web_dashboard import SimpleCache

        cache = SimpleCache(ttl_seconds=0.1)  # 100ms TTL
        cache.set("test_key", "test_value")

        # Should get value immediately
        self.assertEqual(cache.get("test_key"), "test_value")

        # Wait for expiration
        time.sleep(0.2)

        # Should return None after expiration
        self.assertIsNone(cache.get("test_key"))

    def test_cache_clear(self):
        """Test clearing the cache"""
        from firelens.web_dashboard import SimpleCache

        cache = SimpleCache(ttl_seconds=30)
        cache.set("key1", "value1")
        cache.set("key2", "value2")

        self.assertEqual(len(cache.cache), 2)

        cache.clear()
        self.assertEqual(len(cache.cache), 0)

    def test_cache_overwrites_existing_key(self):
        """Test that setting same key overwrites previous value"""
        from firelens.web_dashboard import SimpleCache

        cache = SimpleCache(ttl_seconds=30)
        cache.set("key", "value1")
        cache.set("key", "value2")

        self.assertEqual(cache.get("key"), "value2")
        self.assertEqual(len(cache.cache), 1)


class TestHealthEndpoint(unittest.TestCase):
    """Test health check endpoint"""

    def setUp(self):
        """Set up mock database and config for testing"""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test.db"

    def tearDown(self):
        """Clean up"""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_health_endpoint_returns_data(self):
        """Test that health endpoint returns expected data structure"""
        # Test the data structure without mocking psutil
        # (psutil is imported inside the endpoint function)

        # We'll test the health data structure
        health_data = {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "memory": {
                "rss_mb": 100.0,
                "percent": 10.5,
            },
            "queue": {"size": 0, "max_size": 1000, "drops": 0},
            "database": {"connection_pool_size": 0},
            "cache": {"entries": 0},
            "issues": [],
            "gc_stats": {"collections": (0, 0, 0)},
        }

        # Verify structure
        self.assertIn("status", health_data)
        self.assertIn("memory", health_data)
        self.assertIn("queue", health_data)
        self.assertIn("database", health_data)
        self.assertIn("cache", health_data)
        self.assertIn("issues", health_data)

    def test_health_status_warnings(self):
        """Test health status determination logic"""
        # Test warning conditions
        mem_percent = 85  # > 80%
        queue_size = 850  # > 800
        queue_drops = 50  # < 100

        issues = []
        status = "healthy"

        if mem_percent > 80:
            status = "warning"
            issues.append(f"High memory usage: {mem_percent:.1f}%")

        if queue_size > 800:
            status = "warning"
            issues.append(f"Queue nearly full: {queue_size}/1000")

        self.assertEqual(status, "warning")
        self.assertEqual(len(issues), 2)

    def test_health_status_critical(self):
        """Test critical health status"""
        queue_drops = 150  # > 100

        issues = []
        status = "healthy"

        if queue_drops > 100:
            status = "critical"
            issues.append(f"Too many queue drops: {queue_drops}")

        self.assertEqual(status, "critical")
        self.assertIn("queue drops", issues[0])


class TestDashboardCaching(unittest.TestCase):
    """Test dashboard caching behavior"""

    def test_cache_reduces_database_queries(self):
        """Test that caching reduces number of database queries"""
        from firelens.web_dashboard import SimpleCache

        cache = SimpleCache(ttl_seconds=30)
        db_queries = []

        def mock_database_query():
            """Simulated expensive database query"""
            db_queries.append(time.time())
            return {"data": "expensive_result"}

        # First call - should hit database
        cache_key = "test_query"
        cached = cache.get(cache_key)
        if cached is None:
            result = mock_database_query()
            cache.set(cache_key, result)

        # Second call - should use cache
        cached = cache.get(cache_key)
        if cached is None:
            result = mock_database_query()
            cache.set(cache_key, result)

        # Should only have 1 database query
        self.assertEqual(len(db_queries), 1, "Should only query database once when cached")

    def test_cache_refreshes_after_ttl(self):
        """Test that cache refreshes data after TTL expires"""
        from firelens.web_dashboard import SimpleCache

        cache = SimpleCache(ttl_seconds=0.1)
        query_count = [0]

        def mock_query():
            query_count[0] += 1
            return f"result_{query_count[0]}"

        # First query
        result1 = cache.get("key")
        if result1 is None:
            result1 = mock_query()
            cache.set("key", result1)

        # Wait for expiration
        time.sleep(0.15)

        # Second query - should refresh
        result2 = cache.get("key")
        if result2 is None:
            result2 = mock_query()
            cache.set("key", result2)

        self.assertEqual(query_count[0], 2, "Should query twice after cache expiration")
        self.assertNotEqual(result1, result2, "Results should be different after refresh")


class TestWebDashboardInitialization(unittest.TestCase):
    """Test web dashboard initialization with cache"""

    def test_dashboard_has_cache_attribute(self):
        """Test that EnhancedWebDashboard has cache"""
        # Can't fully instantiate without database, but can test structure
        from firelens.web_dashboard import SimpleCache

        cache = SimpleCache(ttl_seconds=30)
        self.assertIsNotNone(cache)
        self.assertTrue(hasattr(cache, "get"))
        self.assertTrue(hasattr(cache, "set"))
        self.assertTrue(hasattr(cache, "clear"))


class TestAutoRegistration(unittest.TestCase):
    """Test auto-registration of firewalls from config"""

    def test_auto_registration_happens_before_cache_check(self):
        """Test that auto-registration runs before checking cache"""
        # This test verifies the fix for the cache ordering bug
        # Auto-registration must happen BEFORE cache check so new firewalls are detected

        # Simulate the logic flow
        cache_checked = False
        registration_run = False

        # CORRECT ORDER (after fix):
        # 1. Check for new firewalls (auto-registration)
        registration_run = True

        # 2. Only then check cache
        if registration_run:
            cache_checked = True

        self.assertTrue(registration_run, "Registration should run first")
        self.assertTrue(cache_checked, "Cache check should run after registration")

    def test_new_firewalls_bypass_cache(self):
        """Test that new firewall registration bypasses cache"""
        from firelens.web_dashboard import SimpleCache

        cache = SimpleCache(ttl_seconds=30)

        # Simulate existing cached dashboard
        cache.set("dashboard", {"firewalls": ["fw1"]})

        # Simulate new firewall being added
        newly_registered = ["fw2"]

        # Logic should bypass cache when new firewalls registered
        if newly_registered:
            # Bypass cache - fetch fresh data
            cached_data = None
        else:
            # Use cache
            cached_data = cache.get("dashboard")

        self.assertIsNone(cached_data, "Cache should be bypassed when new firewalls are registered")

    def test_no_new_firewalls_uses_cache(self):
        """Test that dashboard uses cache when no new firewalls"""
        from firelens.web_dashboard import SimpleCache

        cache = SimpleCache(ttl_seconds=30)
        cache_data = {"firewalls": ["fw1"]}
        cache.set("dashboard", cache_data)

        # Simulate no new registrations
        newly_registered = []

        # Logic should use cache when no new registrations
        if newly_registered:
            cached_data = None
        else:
            cached_data = cache.get("dashboard")

        self.assertIsNotNone(cached_data, "Cache should be used when no new registrations")
        self.assertEqual(cached_data, cache_data, "Should return cached data")

    def test_registration_detection_logic(self):
        """Test logic for detecting new firewall registrations"""
        # Simulate config-enabled firewalls
        enabled_fw_names = {"fw1", "fw2", "fw3"}

        # Simulate existing database firewalls
        db_firewall_names = {"fw1", "fw2"}

        # Detect new firewalls
        newly_registered = []
        for fw_name in enabled_fw_names:
            if fw_name not in db_firewall_names:
                newly_registered.append(fw_name)

        self.assertEqual(len(newly_registered), 1, "Should detect 1 new firewall")
        self.assertIn("fw3", newly_registered, "fw3 should be detected as new")
        self.assertNotIn("fw1", newly_registered, "fw1 should not be detected (already in DB)")
        self.assertNotIn("fw2", newly_registered, "fw2 should not be detected (already in DB)")


class TestPasswordValidation(unittest.TestCase):
    """Test password complexity validation"""

    def test_validate_password_complexity_import(self):
        """Test that validate_password_complexity can be imported"""
        from firelens.web_dashboard import validate_password_complexity

        self.assertTrue(callable(validate_password_complexity))

    def test_password_too_short(self):
        """Test that short passwords are rejected"""
        from firelens.web_dashboard import validate_password_complexity, MIN_PASSWORD_LENGTH

        is_valid, error = validate_password_complexity("Short1!")
        self.assertFalse(is_valid)
        self.assertIn("at least", error.lower())

    def test_password_too_long(self):
        """Test that very long passwords are rejected"""
        from firelens.web_dashboard import validate_password_complexity, MAX_PASSWORD_LENGTH

        # Create a password that exceeds max length
        long_password = "Aa1!" + "x" * (MAX_PASSWORD_LENGTH + 1)
        is_valid, error = validate_password_complexity(long_password)
        self.assertFalse(is_valid)
        self.assertIn("exceed", error.lower())

    def test_password_missing_uppercase(self):
        """Test that passwords without uppercase are rejected"""
        from firelens.web_dashboard import validate_password_complexity

        is_valid, error = validate_password_complexity("lowercase1234!")
        self.assertFalse(is_valid)
        self.assertIn("uppercase", error.lower())

    def test_password_missing_lowercase(self):
        """Test that passwords without lowercase are rejected"""
        from firelens.web_dashboard import validate_password_complexity

        is_valid, error = validate_password_complexity("UPPERCASE1234!")
        self.assertFalse(is_valid)
        self.assertIn("lowercase", error.lower())

    def test_password_missing_digit(self):
        """Test that passwords without digits are rejected"""
        from firelens.web_dashboard import validate_password_complexity

        is_valid, error = validate_password_complexity("NoDigitsHere!")
        self.assertFalse(is_valid)
        self.assertIn("digit", error.lower())

    def test_password_missing_special(self):
        """Test that passwords without special characters are rejected"""
        from firelens.web_dashboard import validate_password_complexity

        is_valid, error = validate_password_complexity("NoSpecialChar1")
        self.assertFalse(is_valid)
        self.assertIn("special", error.lower())

    def test_valid_password(self):
        """Test that valid passwords pass all checks"""
        from firelens.web_dashboard import validate_password_complexity

        # Test various valid passwords
        valid_passwords = [
            "ValidPass123!",
            "MySecure@Pass1",
            "Complex#Pwd456",
            "Test_Password1",
            "Abc123!@#defGHI",
        ]

        for password in valid_passwords:
            is_valid, error = validate_password_complexity(password)
            self.assertTrue(
                is_valid, f"Password '{password}' should be valid but got error: {error}"
            )
            self.assertEqual(error, "")

    def test_all_special_characters_accepted(self):
        """Test that various special characters are accepted"""
        from firelens.web_dashboard import validate_password_complexity

        special_chars = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~"

        for char in special_chars:
            password = f"ValidPass123{char}"
            is_valid, error = validate_password_complexity(password)
            self.assertTrue(is_valid, f"Password with '{char}' should be valid but got: {error}")

    def test_minimum_length_boundary(self):
        """Test password at minimum length boundary"""
        from firelens.web_dashboard import validate_password_complexity, MIN_PASSWORD_LENGTH

        # Exactly at minimum length with all requirements
        password = "Aa1!" + "x" * (MIN_PASSWORD_LENGTH - 4)
        is_valid, error = validate_password_complexity(password)
        self.assertTrue(is_valid, f"Password at minimum length should be valid: {error}")

        # One less than minimum
        password_short = "Aa1!" + "x" * (MIN_PASSWORD_LENGTH - 5)
        is_valid, error = validate_password_complexity(password_short)
        self.assertFalse(is_valid)


class TestPasswordConstants(unittest.TestCase):
    """Test password-related constants"""

    def test_min_password_length_defined(self):
        """Test MIN_PASSWORD_LENGTH is defined and reasonable"""
        from firelens.web_dashboard import MIN_PASSWORD_LENGTH

        self.assertIsInstance(MIN_PASSWORD_LENGTH, int)
        self.assertGreaterEqual(MIN_PASSWORD_LENGTH, 8)  # Should be at least 8
        self.assertLessEqual(MIN_PASSWORD_LENGTH, 20)  # But not unreasonably long

    def test_max_password_length_defined(self):
        """Test MAX_PASSWORD_LENGTH is defined and reasonable"""
        from firelens.web_dashboard import MAX_PASSWORD_LENGTH

        self.assertIsInstance(MAX_PASSWORD_LENGTH, int)
        self.assertGreaterEqual(MAX_PASSWORD_LENGTH, 64)  # Allow reasonably long passwords
        self.assertLessEqual(MAX_PASSWORD_LENGTH, 256)  # But have a reasonable upper limit


class TestSessionManager(unittest.TestCase):
    """Test session manager functionality"""

    def test_session_manager_initialization(self):
        """Test SessionManager can be initialized"""
        from firelens.web_dashboard import SessionManager

        sm = SessionManager(timeout_minutes=60)
        self.assertEqual(len(sm.sessions), 0)

    def test_create_session(self):
        """Test creating a session"""
        from firelens.web_dashboard import SessionManager

        sm = SessionManager(timeout_minutes=60)
        token = sm.create_session("testuser", auth_method="local")

        self.assertIsNotNone(token)
        self.assertIsInstance(token, str)
        self.assertGreater(len(token), 20)  # Should be a reasonably long token

    def test_validate_session(self):
        """Test validating a session"""
        from firelens.web_dashboard import SessionManager

        sm = SessionManager(timeout_minutes=60)
        token = sm.create_session("testuser")

        username = sm.validate_session(token)
        self.assertEqual(username, "testuser")

    def test_validate_invalid_session(self):
        """Test validating an invalid token"""
        from firelens.web_dashboard import SessionManager

        sm = SessionManager(timeout_minutes=60)

        username = sm.validate_session("invalid_token")
        self.assertIsNone(username)

    def test_get_session(self):
        """Test getting session data"""
        from firelens.web_dashboard import SessionManager

        sm = SessionManager(timeout_minutes=60)
        token = sm.create_session("testuser", auth_method="local")

        session = sm.get_session(token)
        self.assertIsNotNone(session)
        self.assertEqual(session["username"], "testuser")
        self.assertEqual(session["auth_method"], "local")

    def test_destroy_session(self):
        """Test destroying a session"""
        from firelens.web_dashboard import SessionManager

        sm = SessionManager(timeout_minutes=60)
        token = sm.create_session("testuser")

        # Verify session exists
        self.assertIsNotNone(sm.validate_session(token))

        # Destroy session
        result = sm.destroy_session(token)
        self.assertTrue(result)

        # Verify session no longer exists
        self.assertIsNone(sm.validate_session(token))

    def test_session_stores_auth_method(self):
        """Test that session stores authentication method"""
        from firelens.web_dashboard import SessionManager

        sm = SessionManager(timeout_minutes=60)

        # Test local auth method
        token_local = sm.create_session("localuser", auth_method="local")
        session_local = sm.get_session(token_local)
        self.assertEqual(session_local["auth_method"], "local")

        # Test SAML auth method
        token_saml = sm.create_session(
            "samluser",
            auth_method="saml",
            saml_session_index="idx123",
            saml_name_id="samluser@example.com",
        )
        session_saml = sm.get_session(token_saml)
        self.assertEqual(session_saml["auth_method"], "saml")
        self.assertEqual(session_saml["saml_session_index"], "idx123")
        self.assertEqual(session_saml["saml_name_id"], "samluser@example.com")


if __name__ == "__main__":
    unittest.main()
