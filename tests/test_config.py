"""Tests for configuration management"""
import pytest
import tempfile
import os
from pathlib import Path

from firelens.config import EnhancedConfigManager, EnhancedFirewallConfig, EnhancedGlobalConfig


class TestConfigSaveLoad:
    """Test configuration save and load round-trips"""

    def test_firewall_config_save_load_roundtrip(self, tmp_path):
        """Test that firewall configs survive save/load cycle without duplicate name error"""
        config_file = tmp_path / "config.yaml"

        # Create initial config manager
        manager = EnhancedConfigManager(config_file=config_file)

        # Add a firewall
        fw_config = EnhancedFirewallConfig(
            name="TEST_FW",
            host="https://10.0.0.1",
            username="admin",
            password="secret123",
            type="palo_alto",
            enabled=True,
            poll_interval=30
        )
        manager.add_firewall(fw_config)

        # Verify it was saved
        assert config_file.exists()
        assert "TEST_FW" in manager.firewalls

        # Create a NEW config manager that loads from the same file
        # This simulates a service restart
        manager2 = EnhancedConfigManager(config_file=config_file)

        # Should load without "multiple values for keyword argument 'name'" error
        assert "TEST_FW" in manager2.firewalls
        loaded_fw = manager2.firewalls["TEST_FW"]
        assert loaded_fw.name == "TEST_FW"
        assert loaded_fw.host == "https://10.0.0.1"
        assert loaded_fw.username == "admin"
        assert loaded_fw.poll_interval == 30

    def test_multiple_firewalls_save_load(self, tmp_path):
        """Test multiple firewalls survive save/load cycle"""
        config_file = tmp_path / "config.yaml"

        manager = EnhancedConfigManager(config_file=config_file)

        # Remove default example firewall if present
        if "example_fw" in manager.firewalls:
            manager.remove_firewall("example_fw")

        # Add multiple firewalls
        for i in range(3):
            fw_config = EnhancedFirewallConfig(
                name=f"FW_{i}",
                host=f"https://10.0.0.{i}",
                username="admin",
                password="secret",
                type="palo_alto"
            )
            manager.add_firewall(fw_config)

        # Reload and verify all firewalls
        manager2 = EnhancedConfigManager(config_file=config_file)
        assert len(manager2.firewalls) == 3
        for i in range(3):
            assert f"FW_{i}" in manager2.firewalls

    def test_firewall_with_interface_configs_save_load(self, tmp_path):
        """Test firewall with interface configs survives save/load"""
        config_file = tmp_path / "config.yaml"

        manager = EnhancedConfigManager(config_file=config_file)

        fw_config = EnhancedFirewallConfig(
            name="FW_WITH_INTERFACES",
            host="https://10.0.0.1",
            username="admin",
            password="secret",
            type="palo_alto",
            interface_monitoring=True,
            auto_discover_interfaces=True,
            exclude_interfaces=["loopback", "vlan.1"]
        )
        manager.add_firewall(fw_config)

        # Reload and verify
        manager2 = EnhancedConfigManager(config_file=config_file)
        loaded_fw = manager2.firewalls["FW_WITH_INTERFACES"]
        assert loaded_fw.interface_monitoring is True
        assert loaded_fw.auto_discover_interfaces is True
        assert "loopback" in loaded_fw.exclude_interfaces

    def test_admin_config_save_load(self, tmp_path):
        """Test admin config survives save/load"""
        config_file = tmp_path / "config.yaml"

        manager = EnhancedConfigManager(config_file=config_file)

        # Modify admin config
        manager.global_config.admin.username = "customAdmin"
        manager.global_config.admin.password = "customPass123"
        manager.global_config.admin.session_timeout_minutes = 120
        manager.save_enhanced_config()

        # Reload and verify
        manager2 = EnhancedConfigManager(config_file=config_file)
        assert manager2.global_config.admin.username == "customAdmin"
        assert manager2.global_config.admin.password == "customPass123"
        assert manager2.global_config.admin.session_timeout_minutes == 120


class TestConfigValidation:
    """Test configuration validation"""

    def test_firewall_requires_name(self):
        """Test that firewall config requires a name"""
        with pytest.raises(TypeError):
            EnhancedFirewallConfig(
                host="https://10.0.0.1",
                username="admin",
                password="secret"
            )

    def test_firewall_requires_host(self):
        """Test that firewall config requires a host"""
        with pytest.raises(TypeError):
            EnhancedFirewallConfig(
                name="TEST",
                username="admin",
                password="secret"
            )

    def test_firewall_defaults(self):
        """Test firewall config default values"""
        fw = EnhancedFirewallConfig(
            name="TEST",
            host="https://10.0.0.1",
            username="admin",
            password="secret"
        )
        assert fw.type == "palo_alto"
        assert fw.enabled is True
        assert fw.poll_interval == 60
        assert fw.verify_ssl is True
