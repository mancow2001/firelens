#!/usr/bin/env python3
"""
FireLens Monitor - Fortinet FortiGate Vendor Implementation
REST API client for FortiGate firewalls using API token authentication.

API Documentation: https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/
REST API Guide: https://fndn.fortinet.net/ (requires FNDN account)
"""
import logging
import requests
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

from .base import (
    VendorAdapter,
    VendorClient,
    InterfaceSample,
    SessionStats,
    HardwareInfo,
    SystemMetrics,
)
from . import register_vendor

LOG = logging.getLogger("FireLens.vendors.fortinet")


class FortinetClient(VendorClient):
    """
    Fortinet FortiGate REST API client.

    Authentication:
    ---------------
    Uses API Token authentication (Bearer header).
    - Create token in System > Administrators > REST API Admin
    - Pass the token as the 'password' parameter to authenticate()
    - The 'username' parameter is ignored for token auth

    Base URL: https://<host>/api/v2/

    VDOM Support:
    -------------
    All API calls include ?vdom=<name> parameter.
    Default VDOM is "root". Configure via set_vdom() after authentication.
    """

    VENDOR_NAME = "Fortinet FortiGate"
    VENDOR_TYPE = "fortinet"

    def __init__(self, host: str, verify_ssl: bool = True, ca_bundle_path: Optional[str] = None):
        """
        Initialize FortiGate client.

        Args:
            host: Firewall IP/hostname (https:// prefix optional)
            verify_ssl: Verify SSL certificates (False for self-signed)
            ca_bundle_path: Optional path to custom CA bundle for SSL verification
        """
        self._host = host.rstrip('/')
        if not self._host.startswith('http'):
            self._host = f"https://{self._host}"
        self._base_url = f"{self._host}/api/v2"
        self._verify_ssl = verify_ssl
        self._ca_bundle_path = ca_bundle_path
        self._api_token: Optional[str] = None
        self._session: Optional[requests.Session] = None
        self._authenticated = False
        self._hardware_info: Optional[HardwareInfo] = None
        self._vdom = "root"  # Default VDOM

        LOG.info(f"FortiGate client initialized for {self._host} with verify_ssl={self._verify_ssl}")

    @property
    def vendor_name(self) -> str:
        return self.VENDOR_NAME

    @property
    def vendor_type(self) -> str:
        return self.VENDOR_TYPE

    def set_vdom(self, vdom: str) -> None:
        """
        Set the VDOM for API calls.

        Args:
            vdom: Virtual domain name (e.g., "root", "customer1")
        """
        self._vdom = vdom
        LOG.debug(f"VDOM set to: {vdom}")

    def _get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Make a GET request to the FortiGate API.

        Args:
            endpoint: API endpoint (e.g., "/monitor/system/status")
            params: Optional query parameters

        Returns:
            JSON response as dictionary

        Raises:
            requests.HTTPError: On API error
            ValueError: If not authenticated
        """
        if not self._session:
            raise ValueError("Not authenticated. Call authenticate() first.")

        if params is None:
            params = {}
        params['vdom'] = self._vdom

        url = f"{self._base_url}{endpoint}"

        # Determine SSL verification setting
        # verify_ssl=False takes precedence (disable verification entirely)
        # If verify_ssl=True, use custom CA bundle if available, else system default
        if not self._verify_ssl:
            verify = False
        elif self._ca_bundle_path:
            verify = self._ca_bundle_path
        else:
            verify = True
        LOG.debug(f"FortiGate API request to {endpoint} with verify={verify}")

        response = self._session.get(url, params=params, verify=verify)
        response.raise_for_status()
        return response.json()

    def authenticate(self, username: str, password: str) -> bool:
        """
        Authenticate with FortiGate API using API token.

        For FortiGate, 'password' should be the API token, not user password.
        The 'username' parameter is ignored for token-based auth.

        Args:
            username: Ignored for token auth (kept for interface compatibility)
            password: API token from FortiGate REST API Admin

        Returns:
            True if authentication successful
        """
        try:
            self._api_token = password
            self._session = requests.Session()
            self._session.headers.update({
                "Authorization": f"Bearer {self._api_token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            })

            # Test authentication by fetching system status
            data = self._get("/monitor/system/status")

            # Cache hardware info from response
            # Note: Some fields are in 'results', others at top level
            results = data.get("results", {})

            # Model info is in results
            model_name = results.get("model_name", "FortiGate")
            model_number = results.get("model_number", "")
            if model_number:
                model_name = f"{model_name}-{model_number}"

            # Serial, version, build are at top level in FortiOS 7.x
            serial = data.get("serial", results.get("serial", ""))
            version = data.get("version", results.get("version", "Unknown"))
            build = data.get("build", results.get("build", "Unknown"))
            hostname = results.get("hostname", "")

            self._hardware_info = HardwareInfo(
                vendor=self.VENDOR_NAME,
                model=model_name,
                serial=serial,
                hostname=hostname,
                sw_version=f"{version} build {build}",
                vendor_specific={
                    "build": build,
                    "vdom": self._vdom,
                }
            )

            self._authenticated = True
            LOG.info(f"Authenticated to FortiGate {self._hardware_info.hostname} ({self._hardware_info.model})")
            return True

        except requests.HTTPError as e:
            LOG.error(f"FortiGate authentication failed: {e}")
            self._authenticated = False
            return False
        except Exception as e:
            LOG.error(f"FortiGate authentication error: {e}")
            self._authenticated = False
            return False

    def is_authenticated(self) -> bool:
        """Check if client is currently authenticated."""
        return self._authenticated and self._api_token is not None

    def collect_system_metrics(self) -> SystemMetrics:
        """
        Collect CPU and memory metrics from FortiGate.

        Endpoints:
        - GET /api/v2/monitor/system/resource/usage (CPU, session rate, NPU)
        - GET /api/v2/monitor/system/performance/status (accurate memory)

        Returns:
            SystemMetrics with CPU and memory usage, plus vendor-specific metrics
        """
        timestamp = datetime.now(timezone.utc)
        vendor_metrics: Dict[str, Any] = {}

        try:
            # Get resource usage (CPU, session rates, NPU sessions)
            data = self._get("/monitor/system/resource/usage")
            results = data.get("results", {})

            # Parse CPU usage
            cpu_data = results.get("cpu", [])
            if cpu_data and isinstance(cpu_data, list) and len(cpu_data) > 0:
                cpu_usage = float(cpu_data[0].get("current", 0))
            else:
                # Try alternative format where cpu is a direct value
                cpu_usage = float(results.get("cpu", 0))

            vendor_metrics["cpu_usage"] = cpu_usage

            # Parse session setup rate (Fortinet-specific)
            setuprate_data = results.get("setuprate", [])
            if setuprate_data and isinstance(setuprate_data, list) and len(setuprate_data) > 0:
                vendor_metrics["session_setup_rate"] = float(setuprate_data[0].get("current", 0))
            else:
                vendor_metrics["session_setup_rate"] = 0.0

            # Parse NPU sessions (hardware-accelerated sessions)
            npu_session_data = results.get("npu_session", [])
            if npu_session_data and isinstance(npu_session_data, list) and len(npu_session_data) > 0:
                vendor_metrics["npu_sessions"] = int(npu_session_data[0].get("current", 0))
            else:
                vendor_metrics["npu_sessions"] = 0

            # Parse disk usage if available
            disk_data = results.get("disk", [])
            if disk_data and isinstance(disk_data, list) and len(disk_data) > 0:
                disk = disk_data[0]
                used = disk.get("used", 0)
                total = disk.get("total", 1)
                if total > 0:
                    vendor_metrics["disk_usage"] = (used / total) * 100
                vendor_metrics["disk_used_mb"] = used
                vendor_metrics["disk_total_mb"] = total

            # Get accurate memory from performance/status endpoint
            memory_usage = None
            try:
                perf_data = self._get("/monitor/system/performance/status")
                perf_results = perf_data.get("results", {})
                mem_info = perf_results.get("mem", {})

                if mem_info:
                    mem_total = mem_info.get("total", 0)
                    mem_used = mem_info.get("used", 0)
                    if mem_total > 0:
                        memory_usage = (mem_used / mem_total) * 100
                        vendor_metrics["memory_usage_percent"] = memory_usage
                        vendor_metrics["memory_used_bytes"] = mem_used
                        vendor_metrics["memory_total_bytes"] = mem_total
                        vendor_metrics["memory_free_bytes"] = mem_info.get("free", 0)
            except Exception as mem_err:
                LOG.debug(f"Could not get memory from performance/status: {mem_err}")
                # Fallback to resource/usage memory data
                memory_data = results.get("mem", results.get("memory", []))
                if memory_data and isinstance(memory_data, list) and len(memory_data) > 0:
                    mem = memory_data[0]
                    used = mem.get("used", 0)
                    total = mem.get("total", 1)
                    if total > 0:
                        memory_usage = (used / total) * 100
                        vendor_metrics["memory_usage_percent"] = memory_usage

            LOG.debug(f"FortiGate metrics: CPU={cpu_usage}%, Memory={memory_usage}%, "
                     f"SetupRate={vendor_metrics.get('session_setup_rate', 0)}/s, "
                     f"NPU={vendor_metrics.get('npu_sessions', 0)}")

            return SystemMetrics(
                timestamp=timestamp,
                cpu_usage=cpu_usage,
                memory_usage=memory_usage,
                vendor_metrics=vendor_metrics
            )

        except Exception as e:
            LOG.error(f"Failed to collect FortiGate system metrics: {e}")
            return SystemMetrics(
                timestamp=timestamp,
                cpu_usage=0.0,
                memory_usage=None,
                vendor_metrics={"error": str(e)}
            )

    def collect_interface_stats(self, interfaces: Optional[List[str]] = None) -> Dict[str, InterfaceSample]:
        """
        Collect interface statistics from FortiGate.

        Endpoint: GET /api/v2/monitor/system/interface?include_vlan=true

        Args:
            interfaces: Specific interfaces to collect, or None for all

        Returns:
            Dictionary mapping interface names to InterfaceSample
        """
        result: Dict[str, InterfaceSample] = {}
        timestamp = datetime.now(timezone.utc)

        try:
            data = self._get("/monitor/system/interface", params={"include_vlan": "true"})
            results = data.get("results", {})

            # Results can be a dict (keyed by interface name) or a list
            if isinstance(results, dict):
                interface_items = results.items()
            elif isinstance(results, list):
                interface_items = [(iface.get("name", ""), iface) for iface in results]
            else:
                LOG.warning(f"Unexpected interface results format: {type(results)}")
                return result

            for name, iface in interface_items:
                if not name:
                    continue

                # Filter if specific interfaces requested
                if interfaces and name not in interfaces:
                    continue

                result[name] = InterfaceSample(
                    timestamp=timestamp,
                    interface_name=name,
                    rx_bytes=int(iface.get("rx_bytes", 0)),
                    tx_bytes=int(iface.get("tx_bytes", 0)),
                    rx_packets=int(iface.get("rx_packets", 0)),
                    tx_packets=int(iface.get("tx_packets", 0)),
                    rx_errors=int(iface.get("rx_errors", 0)),
                    tx_errors=int(iface.get("tx_errors", 0)),
                    success=True
                )

            LOG.debug(f"Collected stats for {len(result)} FortiGate interfaces")
            return result

        except Exception as e:
            LOG.error(f"Failed to collect FortiGate interface stats: {e}")
            return result

    def collect_session_stats(self) -> SessionStats:
        """
        Collect session statistics from FortiGate.

        Endpoint: GET /api/v2/monitor/system/resource/usage
        Session data is in results.session[0].current

        Returns:
            SessionStats with active session counts
        """
        timestamp = datetime.now(timezone.utc)

        try:
            # Get session data from resource usage endpoint
            # This returns current sessions and historical data
            data = self._get("/monitor/system/resource/usage")
            results = data.get("results", {})

            total_sessions = 0
            max_sessions = 0

            # Session data is in a list format: results.session[0]
            session_data = results.get("session", [])
            if session_data and len(session_data) > 0:
                session_info = session_data[0]
                total_sessions = int(session_info.get("current", 0))

                # Get max from 24-hour historical data
                historical = session_info.get("historical", {})
                day_data = historical.get("24-hour", {})
                max_sessions = int(day_data.get("max", total_sessions))

            LOG.debug(f"FortiGate sessions: {total_sessions} active, {max_sessions} max (24h)")

            return SessionStats(
                timestamp=timestamp,
                active_sessions=total_sessions,
                max_sessions=max_sessions,
                tcp_sessions=0,  # Not directly available without parsing full session table
                udp_sessions=0,
                icmp_sessions=0,
                session_rate=0.0
            )

        except Exception as e:
            LOG.error(f"Failed to collect FortiGate session stats: {e}")
            return SessionStats(
                timestamp=timestamp,
                active_sessions=0,
                max_sessions=0
            )

    def get_hardware_info(self) -> HardwareInfo:
        """
        Get hardware information from FortiGate.

        Returns:
            HardwareInfo with device details
        """
        if self._hardware_info:
            return self._hardware_info

        # Fetch if not cached (should already be cached from authenticate)
        try:
            data = self._get("/monitor/system/status")
            results = data.get("results", {})

            # Model info is in results
            model_name = results.get("model_name", "FortiGate")
            model_number = results.get("model_number", "")
            if model_number:
                model_name = f"{model_name}-{model_number}"

            # Serial, version, build are at top level in FortiOS 7.x
            serial = data.get("serial", results.get("serial", ""))
            version = data.get("version", results.get("version", "Unknown"))
            build = data.get("build", results.get("build", "Unknown"))
            hostname = results.get("hostname", "")

            self._hardware_info = HardwareInfo(
                vendor=self.VENDOR_NAME,
                model=model_name,
                serial=serial,
                hostname=hostname,
                sw_version=f"{version} build {build}",
                vendor_specific={
                    "build": build,
                    "vdom": self._vdom,
                }
            )
            return self._hardware_info

        except Exception as e:
            LOG.error(f"Failed to get FortiGate hardware info: {e}")
            return HardwareInfo(
                vendor=self.VENDOR_NAME,
                model="Unknown",
                serial="",
                hostname="",
                sw_version=""
            )

    def discover_interfaces(self) -> List[str]:
        """
        Discover available interfaces on FortiGate.

        Returns:
            List of interface names
        """
        try:
            data = self._get("/monitor/system/interface", params={"include_vlan": "true"})
            results = data.get("results", {})

            # Results can be a dict (keyed by interface name) or a list
            if isinstance(results, dict):
                names = list(results.keys())
            elif isinstance(results, list):
                names = [iface.get("name", "") for iface in results if iface.get("name")]
            else:
                LOG.warning(f"Unexpected interface results format: {type(results)}")
                return []

            LOG.debug(f"Discovered {len(names)} FortiGate interfaces")
            return names

        except Exception as e:
            LOG.error(f"Failed to discover FortiGate interfaces: {e}")
            return []

    def close(self) -> None:
        """Close the API client and cleanup resources."""
        if self._session:
            self._session.close()
            self._session = None
        self._authenticated = False
        self._api_token = None
        LOG.debug("FortiGate client closed")


class FortinetAdapter(VendorAdapter):
    """
    Fortinet FortiGate vendor adapter.

    Factory for creating FortiGate clients and providing
    vendor-specific configuration.

    Supported Models:
    - FortiGate 40F, 60F, 80F (Entry-level)
    - FortiGate 100F, 200F, 400F (Mid-range)
    - FortiGate 600F, 1000F, 1800F (High-end)
    - FortiGate 2600F, 3600F (Data center)
    - FortiGate VM (Virtual appliances)

    All models use the same REST API interface.
    """

    VENDOR_NAME = "Fortinet FortiGate"
    VENDOR_TYPE = "fortinet"

    @property
    def vendor_name(self) -> str:
        return self.VENDOR_NAME

    @property
    def vendor_type(self) -> str:
        return self.VENDOR_TYPE

    def create_client(self, host: str, verify_ssl: bool = True, ca_bundle_path: Optional[str] = None) -> FortinetClient:
        """
        Create a new FortiGate API client.

        Args:
            host: Firewall IP/hostname
            verify_ssl: Verify SSL certificates
            ca_bundle_path: Optional path to custom CA bundle for SSL verification

        Returns:
            Configured FortinetClient instance
        """
        return FortinetClient(host, verify_ssl, ca_bundle_path)

    def get_supported_metrics(self) -> List[str]:
        """
        Get list of metrics supported by FortiGate firewalls.

        Note: FortiGate has simpler metric structure than Palo Alto.
        No separate management/data plane CPU metrics.

        Returns:
            List of metric names
        """
        return [
            'cpu_usage',
            'memory_usage',
            'disk_usage',
            'active_sessions',
            'max_sessions',
            'session_rate',
        ]

    def get_hardware_fields(self) -> List[str]:
        """
        Get list of hardware info fields for FortiGate firewalls.

        Returns:
            List of field names
        """
        return [
            'model',
            'serial',
            'hostname',
            'sw_version',
            'build',
        ]

    def get_default_exclude_interfaces(self) -> List[str]:
        """
        Get default interface exclusion patterns for FortiGate.

        FortiGate interface naming:
        - Physical: port1, port2, wan1, wan2, internal
        - VLAN: vlan100, port1.100
        - VPN: ssl.root, ipsec tunnels
        - Management: mgmt, fortilink
        - HA: ha1, ha2, hasync

        Returns:
            List of patterns to exclude
        """
        return [
            'mgmt',
            'fortilink',
            'ha1',
            'ha2',
            'hasync',
            'ssl.root',  # SSL VPN interface
            'npu0_vlink',  # NPU internal links
            'root',  # Root VDOM interface
        ]


# Register this vendor
register_vendor(FortinetAdapter.VENDOR_TYPE, FortinetAdapter)
LOG.debug("Registered Fortinet FortiGate vendor adapter")
