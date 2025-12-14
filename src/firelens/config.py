#!/usr/bin/env python3
"""
FireLens Monitor - Configuration Management Module
Adds interface monitoring configuration support
"""

import logging
import os
import secrets
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional

import yaml

try:
    import bcrypt

    BCRYPT_OK = True
except ImportError:
    BCRYPT_OK = False

try:
    from dotenv import load_dotenv

    DOTENV_OK = True
except ImportError:
    DOTENV_OK = False

LOG = logging.getLogger("FireLens.config")


# Password hashing utilities
def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    if not BCRYPT_OK:
        LOG.warning("bcrypt not available, storing password in plaintext (INSECURE)")
        return password
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its hash."""
    if not BCRYPT_OK:
        # Fallback to plaintext comparison if bcrypt not available
        return password == password_hash

    # Check if the stored value is a bcrypt hash (starts with $2)
    if password_hash.startswith("$2"):
        try:
            return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
        except Exception as e:
            LOG.error(f"Password verification failed: {e}")
            return False
    else:
        # Legacy plaintext password - compare directly
        # This allows migration from old configs
        return password == password_hash


def generate_secure_password(length: int = 16) -> str:
    """Generate a cryptographically secure random password."""
    # Use URL-safe characters for easy copy/paste
    return secrets.token_urlsafe(length)


@dataclass
class InterfaceConfig:
    """Configuration for monitoring a specific interface"""

    name: str
    display_name: str
    enabled: bool = True
    description: str = ""


@dataclass
class SAMLConfig:
    """Configuration for SAML 2.0 authentication"""

    enabled: bool = False

    # Identity Provider (IdP) Configuration
    idp_entity_id: str = ""
    idp_sso_url: str = ""
    idp_slo_url: str = ""
    idp_x509_cert: str = ""

    # Service Provider (SP) Configuration
    sp_entity_id: str = ""
    sp_acs_url: str = ""
    sp_slo_url: str = ""

    # Security Options
    want_assertions_signed: bool = True
    want_response_signed: bool = False

    # Attribute Mapping
    username_attribute: str = "email"


@dataclass
class AdminConfig:
    """Configuration for administrative web interface"""

    enabled: bool = True
    username: str = "fireAdmin"
    password: str = ""  # Plaintext password (deprecated, for migration only)
    password_hash: str = ""  # Bcrypt hashed password
    password_reset_required: bool = True  # Force password reset on first login
    session_timeout_minutes: int = 60
    secure_cookies: bool = True  # Set secure flag on cookies (disable for dev without HTTPS)
    saml: Optional[SAMLConfig] = None

    def __post_init__(self):
        """Handle password migration and initialization."""
        # If we have a plaintext password but no hash, this is a legacy config
        # or first-time setup - we'll handle hashing at save time
        pass

    def set_password(self, new_password: str):
        """Set a new password (will be hashed)."""
        self.password_hash = hash_password(new_password)
        self.password = ""  # Clear plaintext
        self.password_reset_required = False

    def check_password(self, password: str) -> bool:
        """Verify a password against stored hash or legacy plaintext."""
        # First try the hash
        if self.password_hash:
            return verify_password(password, self.password_hash)
        # Fall back to legacy plaintext password
        if self.password:
            return verify_password(password, self.password)
        return False

    def needs_password_reset(self) -> bool:
        """Check if user needs to reset their password."""
        return self.password_reset_required or (not self.password_hash and not self.password)


@dataclass
class WebSSLConfig:
    """Configuration for SSL/TLS on the web dashboard"""

    enabled: bool = True  # SSL enabled by default
    cert_file: str = ""  # Path to certificate file (PEM)
    key_file: str = ""  # Path to private key file (PEM)
    auto_generate: bool = True  # Auto-generate self-signed cert if none exists
    https_port: int = 8443  # HTTPS port
    http_port: int = 8080  # HTTP port (for redirect)
    redirect_http_to_https: bool = True  # Redirect HTTP to HTTPS
    min_tls_version: str = "TLSv1.2"  # Minimum TLS version


# Supported vendor types
SUPPORTED_VENDOR_TYPES = ["palo_alto", "fortinet", "cisco_firepower"]


@dataclass
class EnhancedFirewallConfig:
    """Enhanced configuration for a single firewall with interface monitoring"""

    name: str
    host: str
    username: str
    password: str
    type: str = "palo_alto"  # Vendor type: palo_alto, fortinet, cisco_firepower
    verify_ssl: bool = True
    enabled: bool = True
    poll_interval: int = 60
    dp_aggregation: str = "mean"  # mean, max, p95
    vdom: str = "root"  # FortiGate VDOM (Virtual Domain), defaults to "root"

    # NEW: Interface monitoring configuration
    interface_monitoring: bool = True

    # Multiple ways to specify interfaces for monitoring
    interface_configs: List[InterfaceConfig] = None  # Detailed interface configs
    monitor_interfaces: List[str] = None  # Simple list of interface names
    auto_discover_interfaces: bool = True  # Auto-discover and monitor all interfaces
    exclude_interfaces: List[str] = None  # Interfaces to exclude from monitoring

    def __post_init__(self):
        """Initialize interface monitoring configuration"""
        # Initialize exclude list if not provided
        if self.exclude_interfaces is None:
            self.exclude_interfaces = ["mgmt", "loopback", "tunnel", "ha1", "ha2"]

        # If no specific interface configuration provided, use defaults
        if self.interface_configs is None and self.monitor_interfaces is None:
            if self.auto_discover_interfaces:
                # Will auto-discover interfaces at runtime
                self.interface_configs = []
            else:
                # Provide common default interfaces
                self.interface_configs = [
                    InterfaceConfig(
                        name="ethernet1/1",
                        display_name="Internet/WAN",
                        description="Primary internet connection",
                    ),
                    InterfaceConfig(
                        name="ethernet1/2",
                        display_name="LAN/Internal",
                        description="Internal network connection",
                    ),
                    InterfaceConfig(
                        name="ethernet1/3", display_name="DMZ", description="DMZ network connection"
                    ),
                    InterfaceConfig(
                        name="ae1",
                        display_name="Aggregate 1",
                        description="Link aggregation group 1",
                        enabled=False,  # Disabled by default since not all FWs have aggregates
                    ),
                    InterfaceConfig(
                        name="ae2",
                        display_name="Aggregate 2",
                        description="Link aggregation group 2",
                        enabled=False,  # Disabled by default
                    ),
                ]

        # Convert simple interface list to interface configs if provided
        if self.monitor_interfaces and not self.interface_configs:
            self.interface_configs = []
            for interface_name in self.monitor_interfaces:
                # Create display name from interface name
                display_name = self._generate_display_name(interface_name)
                self.interface_configs.append(
                    InterfaceConfig(
                        name=interface_name,
                        display_name=display_name,
                        enabled=True,
                        description=f"Monitored interface {interface_name}",
                    )
                )

    def _generate_display_name(self, interface_name: str) -> str:
        """Generate a user-friendly display name from interface name"""
        name = interface_name.lower()

        # Common interface type mappings
        if name.startswith("ethernet1/1"):
            return "WAN/Internet"
        elif name.startswith("ethernet1/2"):
            return "LAN/Internal"
        elif name.startswith("ethernet1/3"):
            return "DMZ"
        elif name.startswith("ethernet"):
            # Extract port number
            port = name.replace("ethernet", "").replace("1/", "Port ")
            return f"Port {port}"
        elif name.startswith("ae"):
            # Aggregate interface
            agg_num = name.replace("ae", "")
            return f"Aggregate {agg_num}"
        elif name.startswith("vlan"):
            # VLAN interface
            vlan_num = name.replace("vlan", "")
            return f"VLAN {vlan_num}"
        elif name.startswith("tunnel"):
            return f"Tunnel {name.replace('tunnel.', '')}"
        else:
            # Capitalize first letter for unknown interfaces
            return interface_name.capitalize()

    def get_enabled_interfaces(self) -> List[str]:
        """Get list of interface names that should be monitored"""
        if not self.interface_monitoring:
            return []

        enabled_interfaces = []

        if self.interface_configs:
            # Use configured interfaces
            enabled_interfaces = [ic.name for ic in self.interface_configs if ic.enabled]
        elif self.monitor_interfaces:
            # Use simple interface list
            enabled_interfaces = self.monitor_interfaces[:]

        # Apply exclusions
        if self.exclude_interfaces:
            enabled_interfaces = [
                iface
                for iface in enabled_interfaces
                if not any(exclude in iface.lower() for exclude in self.exclude_interfaces)
            ]

        return enabled_interfaces

    def should_monitor_interface(self, interface_name: str) -> bool:
        """Check if a specific interface should be monitored"""
        if not self.interface_monitoring:
            return False

        # Check exclusions first
        if self.exclude_interfaces:
            if any(exclude in interface_name.lower() for exclude in self.exclude_interfaces):
                return False

        # If auto-discovery is enabled and no specific configs, monitor everything not excluded
        if (
            self.auto_discover_interfaces
            and not self.interface_configs
            and not self.monitor_interfaces
        ):
            return True

        # Check if explicitly configured
        enabled_interfaces = self.get_enabled_interfaces()
        return interface_name in enabled_interfaces

    def add_discovered_interface(self, interface_name: str, description: str = "") -> bool:
        """Add a newly discovered interface to the configuration"""
        if not self.auto_discover_interfaces:
            return False

        # Check if already configured
        if self.interface_configs:
            existing_names = [ic.name for ic in self.interface_configs]
            if interface_name in existing_names:
                return False

        # Create new interface config
        display_name = self._generate_display_name(interface_name)
        new_interface = InterfaceConfig(
            name=interface_name,
            display_name=display_name,
            enabled=True,
            description=description or f"Auto-discovered interface {interface_name}",
        )

        if self.interface_configs is None:
            self.interface_configs = []

        self.interface_configs.append(new_interface)
        return True


@dataclass
class EnhancedGlobalConfig:
    """Enhanced global configuration settings"""

    output_dir: str = "./output"
    web_dashboard: bool = True
    web_port: int = 8080
    database_path: str = "./data/metrics.db"
    log_level: str = "INFO"

    # NEW: Enhanced monitoring settings
    interface_monitoring_enabled: bool = True
    session_statistics_enabled: bool = True
    enhanced_dashboard: bool = True

    # Admin interface configuration
    admin: AdminConfig = None

    # Certificate configuration
    certs_directory: str = "./certs"

    # SSL/TLS configuration
    web_ssl: WebSSLConfig = None

    def __post_init__(self):
        """Initialize admin config if not provided"""
        if self.admin is None:
            self.admin = AdminConfig()
        if self.web_ssl is None:
            self.web_ssl = WebSSLConfig()


class EnhancedConfigManager:
    """Enhanced configuration manager with interface monitoring support"""

    def __init__(self, config_file: str = "config.yaml"):
        self.config_file = Path(config_file)
        self.global_config = EnhancedGlobalConfig()
        self.firewalls: Dict[str, EnhancedFirewallConfig] = {}

        # Load environment variables if available
        if DOTENV_OK:
            load_dotenv()

        self._load_config()

    def _load_config(self):
        """Load enhanced configuration from file or environment variables"""
        if self.config_file.exists():
            self._load_from_yaml()
        else:
            self._load_from_env()
            self._create_default_enhanced_config()

    def _load_from_yaml(self):
        """Load enhanced configuration from YAML file"""
        try:
            with open(self.config_file, "r") as f:
                data = yaml.safe_load(f) or {}

            # Load global config
            global_data = data.get("global", {})

            # Handle admin config separately (nested object)
            if "admin" in global_data:
                admin_data = global_data.pop("admin")
                if isinstance(admin_data, dict):
                    # Handle nested SAML config
                    saml_config = None
                    if "saml" in admin_data:
                        saml_data = admin_data.pop("saml")
                        if isinstance(saml_data, dict):
                            saml_config = SAMLConfig(**saml_data)
                    self.global_config.admin = AdminConfig(**admin_data, saml=saml_config)

                # Parse web_ssl config
                if "web_ssl" in global_data:
                    ssl_data = global_data.pop("web_ssl")
                    if isinstance(ssl_data, dict):
                        self.global_config.web_ssl = WebSSLConfig(**ssl_data)

            for key, value in global_data.items():
                if hasattr(self.global_config, key):
                    setattr(self.global_config, key, value)

            # Load firewall configs with interface monitoring
            firewalls_data = data.get("firewalls", {})
            for name, fw_data in firewalls_data.items():
                # Handle interface configs
                interface_configs = None
                if "interface_configs" in fw_data:
                    interface_configs = []
                    for if_data in fw_data["interface_configs"]:
                        interface_configs.append(InterfaceConfig(**if_data))
                    del fw_data["interface_configs"]  # Remove from fw_data to avoid duplicate

                # Remove 'name' from fw_data if present (it's already the dict key)
                fw_data.pop("name", None)

                # Create enhanced firewall config
                fw_config = EnhancedFirewallConfig(name=name, **fw_data)
                if interface_configs:
                    fw_config.interface_configs = interface_configs

                self.firewalls[name] = fw_config

            fw_count = len(self.firewalls)
            LOG.info(f"Loaded config for {fw_count} firewalls from {self.config_file}")

        except Exception as e:
            LOG.error(f"Failed to load enhanced config from {self.config_file}: {e}")
            self._load_from_env()

    def _load_from_env(self):
        """Load configuration from environment variables (legacy support)"""
        # Global config from env
        self.global_config.output_dir = os.getenv("OUTPUT_DIR", self.global_config.output_dir)
        self.global_config.web_dashboard = self._env_bool(
            "WEB_DASHBOARD", self.global_config.web_dashboard
        )
        self.global_config.web_port = int(os.getenv("WEB_PORT", str(self.global_config.web_port)))
        self.global_config.database_path = os.getenv(
            "DATABASE_PATH", self.global_config.database_path
        )
        self.global_config.log_level = os.getenv("LOG_LEVEL", self.global_config.log_level)

        # NEW: Enhanced monitoring settings
        self.global_config.interface_monitoring_enabled = self._env_bool(
            "INTERFACE_MONITORING", True
        )
        self.global_config.session_statistics_enabled = self._env_bool("SESSION_STATISTICS", True)
        self.global_config.enhanced_dashboard = self._env_bool("ENHANCED_DASHBOARD", True)

        # Single firewall from env (legacy)
        host = os.getenv("PAN_HOST")
        username = os.getenv("PAN_USERNAME")
        password = os.getenv("PAN_PASSWORD")

        if host and username and password:
            fw_name = "legacy_firewall"
            self.firewalls[fw_name] = EnhancedFirewallConfig(
                name=fw_name,
                host=host,
                username=username,
                password=password,
                verify_ssl=self._env_bool("VERIFY_SSL", True),
                poll_interval=int(os.getenv("POLL_INTERVAL", "60")),
                dp_aggregation=os.getenv("DP_AGGREGATION", "mean"),
                interface_monitoring=self._env_bool("INTERFACE_MONITORING", True),
            )
            LOG.info("Loaded legacy firewall config from environment variables")

    def _env_bool(self, key: str, default: bool) -> bool:
        """Convert environment variable to boolean"""
        val = os.getenv(key)
        if val is None:
            return default
        return str(val).strip().lower() in {"1", "true", "yes", "y"}

    def _create_default_enhanced_config(self):
        """Create a default enhanced configuration file"""
        if not self.firewalls:
            # Create example firewall with interface monitoring
            self.firewalls["example_fw"] = EnhancedFirewallConfig(
                name="example_fw",
                host="https://192.168.1.1",
                username="admin",
                password="password",
                enabled=False,  # Disabled by default
            )

        self.save_enhanced_config()
        LOG.info(f"Created default enhanced configuration file: {self.config_file}")

    def save_enhanced_config(self):
        """
        Save current enhanced configuration to YAML file.

        Creates a backup before saving and restores it on failure.
        This ensures configuration is not lost if save fails mid-write.
        """
        import shutil

        data = {"global": asdict(self.global_config), "firewalls": {}}

        # Convert enhanced firewall configs to dict format
        for name, fw in self.firewalls.items():
            fw_dict = asdict(fw)
            # Convert interface configs to list of dicts
            if fw_dict.get("interface_configs"):
                fw_dict["interface_configs"] = [asdict(ic) for ic in fw.interface_configs]
            data["firewalls"][name] = fw_dict

        # Ensure config directory exists
        self.config_file.parent.mkdir(parents=True, exist_ok=True)

        # Create backup of existing config if it exists
        backup_file = self.config_file.with_suffix(".yaml.bak")
        config_existed = self.config_file.exists()

        try:
            if config_existed:
                shutil.copy2(self.config_file, backup_file)
                LOG.debug(f"Created config backup: {backup_file}")

            # Write new config
            with open(self.config_file, "w") as f:
                yaml.dump(data, f, default_flow_style=False, indent=2)

            # Verify the file was written correctly by reading it back
            with open(self.config_file, "r") as f:
                yaml.safe_load(f)  # Validate YAML is parseable

            LOG.info(f"Enhanced configuration saved to {self.config_file}")

            # Remove backup on successful save
            if backup_file.exists():
                backup_file.unlink()

        except Exception as e:
            LOG.error(f"Failed to save configuration: {e}")

            # Restore from backup if available
            if config_existed and backup_file.exists():
                try:
                    shutil.copy2(backup_file, self.config_file)
                    LOG.warning(f"Restored configuration from backup: {backup_file}")
                except Exception as restore_error:
                    LOG.error(f"Failed to restore backup: {restore_error}")

            raise RuntimeError(f"Configuration save failed: {e}") from e

    def add_firewall(self, config: EnhancedFirewallConfig) -> bool:
        """Add a new enhanced firewall configuration"""
        if config.name in self.firewalls:
            LOG.warning(f"Firewall {config.name} already exists, updating configuration")

        self.firewalls[config.name] = config
        self.save_enhanced_config()
        return True

    def remove_firewall(self, name: str) -> bool:
        """Remove a firewall configuration"""
        if name in self.firewalls:
            del self.firewalls[name]
            self.save_enhanced_config()
            LOG.info(f"Removed firewall configuration: {name}")
            return True
        return False

    def rename_firewall(self, old_name: str, new_name: str) -> bool:
        """
        Rename a firewall in the configuration.

        Args:
            old_name: Current firewall name
            new_name: New firewall name

        Returns:
            True if successful, False otherwise
        """
        if old_name not in self.firewalls:
            LOG.warning(f"Cannot rename: firewall '{old_name}' not found")
            return False

        if new_name in self.firewalls:
            LOG.warning(f"Cannot rename: firewall '{new_name}' already exists")
            return False

        # Get the config and update its name
        config = self.firewalls[old_name]
        config.name = new_name

        # Remove old entry and add new one
        del self.firewalls[old_name]
        self.firewalls[new_name] = config

        self.save_enhanced_config()
        LOG.info(f"Renamed firewall configuration: '{old_name}' -> '{new_name}'")
        return True

    def get_enabled_firewalls(self) -> Dict[str, EnhancedFirewallConfig]:
        """Get all enabled firewall configurations"""
        return {name: fw for name, fw in self.firewalls.items() if fw.enabled}

    def get_firewall(self, name: str) -> Optional[EnhancedFirewallConfig]:
        """Get specific firewall configuration"""
        return self.firewalls.get(name)

    def list_firewalls(self) -> List[str]:
        """List all firewall names"""
        return list(self.firewalls.keys())

    def validate_enhanced_config(self) -> List[str]:
        """Validate enhanced configuration and return list of errors"""
        errors = []

        # Validate global config
        if self.global_config.web_port < 1 or self.global_config.web_port > 65535:
            errors.append("Invalid web_port: must be between 1-65535")

        # Validate firewall configs
        for name, fw in self.firewalls.items():
            if not fw.host:
                errors.append(f"Firewall {name}: host is required")

            # Vendor-specific credential validation
            # Fortinet uses API token only (password field), username is ignored
            if fw.type == "fortinet":
                if not fw.password:
                    errors.append(f"Firewall {name}: API token (password) is required for Fortinet")
            else:
                # Palo Alto, Cisco, and others require both username and password
                if not fw.username or not fw.password:
                    errors.append(f"Firewall {name}: username and password are required")

            if fw.poll_interval < 1:
                errors.append(f"Firewall {name}: poll_interval must be >= 1")

            if fw.dp_aggregation not in ["mean", "max", "p95"]:
                errors.append(f"Firewall {name}: dp_aggregation must be mean, max, or p95")

            # Validate vendor type
            if fw.type not in SUPPORTED_VENDOR_TYPES:
                errors.append(
                    f"Firewall {name}: unsupported vendor type '{fw.type}'. "
                    f"Supported types: {SUPPORTED_VENDOR_TYPES}"
                )

            # Validate interface configs
            if fw.interface_monitoring:
                # Check for conflicting interface configuration methods
                config_methods = 0
                if fw.interface_configs:
                    config_methods += 1
                if fw.monitor_interfaces:
                    config_methods += 1
                if (
                    fw.auto_discover_interfaces
                    and not fw.interface_configs
                    and not fw.monitor_interfaces
                ):
                    config_methods += 1

                if config_methods == 0:
                    errors.append(
                        f"Firewall {name}: interface_monitoring enabled but no interfaces specified"
                    )

                # Validate interface_configs if provided
                if fw.interface_configs:
                    interface_names = [ic.name for ic in fw.interface_configs]
                    if len(interface_names) != len(set(interface_names)):
                        errors.append(
                            f"Firewall {name}: duplicate interface names in interface_configs"
                        )

                # Validate monitor_interfaces if provided
                if fw.monitor_interfaces:
                    if len(fw.monitor_interfaces) != len(set(fw.monitor_interfaces)):
                        errors.append(
                            f"Firewall {name}: duplicate interface names in monitor_interfaces"
                        )

                    for interface_name in fw.monitor_interfaces:
                        if not interface_name or not isinstance(interface_name, str):
                            errors.append(
                                f"Firewall {name}: invalid interface name in monitor_interfaces"
                            )

                # Validate exclude_interfaces if provided
                if fw.exclude_interfaces:
                    for exclude_pattern in fw.exclude_interfaces:
                        if not exclude_pattern or not isinstance(exclude_pattern, str):
                            errors.append(
                                f"Firewall {name}: invalid exclude pattern in exclude_interfaces"
                            )

        return errors

    # Backward compatibility methods
    def validate_config(self) -> List[str]:
        """Backward compatibility for validate_config"""
        return self.validate_enhanced_config()

    def save_config(self):
        """Backward compatibility for save_config"""
        return self.save_enhanced_config()


# Maintain backward compatibility
class FirewallConfig(EnhancedFirewallConfig):
    """Backward compatibility alias"""

    pass


class GlobalConfig(EnhancedGlobalConfig):
    """Backward compatibility alias"""

    pass


class ConfigManager(EnhancedConfigManager):
    """Backward compatibility alias"""

    pass


def create_enhanced_example_config() -> str:
    """Create an enhanced example configuration file"""
    example_config = """# FireLens Monitor Configuration
# Includes flexible interface monitoring with multiple configuration methods

global:
  output_dir: "./output"
  web_dashboard: true
  web_port: 8080
  database_path: "./data/metrics.db"
  log_level: "INFO"

  # Enhanced monitoring settings
  interface_monitoring_enabled: true
  session_statistics_enabled: true
  enhanced_dashboard: true

firewalls:
  # Method 1: Detailed interface configuration with custom display names
  datacenter_fw:
    host: "https://10.100.192.3"
    username: "admin"
    password: "YourPassword"
    verify_ssl: false
    enabled: true
    poll_interval: 30  # Recommended for interface monitoring
    dp_aggregation: "mean"  # mean, max, p95

    interface_monitoring: true
    auto_discover_interfaces: false  # Use specific configuration
    interface_configs:
      - name: "ethernet1/1"
        display_name: "Internet/WAN"
        enabled: true
        description: "Primary internet connection"
      - name: "ethernet1/2"
        display_name: "LAN/Internal"
        enabled: true
        description: "Internal network connection"
      - name: "ethernet1/3"
        display_name: "DMZ"
        enabled: true
        description: "DMZ network connection"
      - name: "ethernet1/4"
        display_name: "Guest Network"
        enabled: false  # Disabled, won't be monitored
        description: "Guest network connection"
      - name: "ae1"
        display_name: "Aggregate 1"
        enabled: true
        description: "Link aggregation group 1"
      - name: "ae2"
        display_name: "Aggregate 2"
        enabled: false  # Only monitor ae1
        description: "Link aggregation group 2"

  # Method 2: Simple list of interface names to monitor
  branch_fw_simple:
    host: "https://192.168.1.1"
    username: "admin"
    password: "YourPassword"
    verify_ssl: false
    enabled: true
    poll_interval: 30
    dp_aggregation: "max"

    interface_monitoring: true
    auto_discover_interfaces: false
    # Simple list - display names will be auto-generated
    monitor_interfaces:
      - "ethernet1/1"
      - "ethernet1/2"
      - "ethernet1/5"
      - "vlan.100"
      - "vlan.200"
    exclude_interfaces:
      - "mgmt"
      - "loopback"
      - "tunnel"

  # Method 3: Auto-discovery with exclusions
  branch_fw_auto:
    host: "https://192.168.2.1"
    username: "admin"
    password: "YourPassword"
    verify_ssl: false
    enabled: true
    poll_interval: 30
    dp_aggregation: "mean"

    interface_monitoring: true
    auto_discover_interfaces: true  # Monitor all discovered interfaces
    # Will monitor all interfaces except those in exclude list
    exclude_interfaces:
      - "mgmt"           # Exclude management interfaces
      - "loopback"       # Exclude loopback interfaces
      - "tunnel"         # Exclude tunnel interfaces
      - "ha1"            # Exclude HA interfaces
      - "ha2"
      - "ethernet1/8"    # Exclude specific interface

  # Legacy method: No interface monitoring (backward compatibility)
  legacy_fw:
    host: "https://192.168.4.1"
    username: "admin"
    password: "YourPassword"
    verify_ssl: false
    enabled: true
    poll_interval: 60
    dp_aggregation: "mean"
    interface_monitoring: false  # Only session-based monitoring

  disabled_fw:
    host: "https://192.168.5.1"
    username: "admin"
    password: "YourPassword"
    verify_ssl: false
    enabled: false  # This firewall will not be monitored at all
    poll_interval: 60
    dp_aggregation: "mean"
    interface_monitoring: false

# Configuration Method Summary:
# 1. interface_configs: Detailed configuration with custom display names
# 2. monitor_interfaces: Simple list of interface names to monitor
# 3. auto_discover_interfaces: Automatically find and monitor all interfaces
# 4. exclude_interfaces: Patterns to exclude from monitoring (applies to all methods)
# 5. Mix and match: Use auto_discover + interface_configs for hybrid approach
"""
    return example_config


# Backward compatibility function
def create_example_config() -> str:
    """Backward compatibility for create_example_config"""
    return create_enhanced_example_config()
