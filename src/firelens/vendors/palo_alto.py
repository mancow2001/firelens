#!/usr/bin/env python3
"""
FireLens Monitor - Palo Alto Networks Vendor Implementation
Wraps existing PAN-OS API client and parsing functions
"""
import logging
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

LOG = logging.getLogger("FireLens.vendors.palo_alto")

# Lazy imports to avoid circular dependency with collectors.py
# These are imported on first use rather than at module load time
_collectors_imported = False
_PanOSAPIClient = None


def _ensure_collectors_imported():
    """Lazy import of collectors module to avoid circular imports."""
    global _collectors_imported, _PanOSAPIClient
    global FIREWALL_CORE_ARCHITECTURE, is_affected_by_dp_core_issue, get_core_architecture
    global parse_dp_cpu_from_rm_your_panos11, parse_pbuf_live_from_rm_your_panos11
    global parse_cpu_from_debug_status, parse_cpu_from_system_info, parse_cpu_from_top
    global parse_system_info_hardware, parse_mgmt_cpu_from_load_average
    global parse_management_cpu_from_system_resources, _aggregate, calculate_percentile
    global parse_interface_statistics_your_panos11, parse_session_statistics_your_panos11
    global discover_interfaces_panos11, _InterfaceSample

    if _collectors_imported:
        return True

    try:
        from ..collectors import (
            FireLensClient as _PanOSAPIClientImport,
            FIREWALL_CORE_ARCHITECTURE as _FIREWALL_CORE_ARCHITECTURE,
            is_affected_by_dp_core_issue as _is_affected_by_dp_core_issue,
            get_core_architecture as _get_core_architecture,
            parse_dp_cpu_from_rm_your_panos11 as _parse_dp_cpu_from_rm_your_panos11,
            parse_pbuf_live_from_rm_your_panos11 as _parse_pbuf_live_from_rm_your_panos11,
            parse_cpu_from_debug_status as _parse_cpu_from_debug_status,
            parse_cpu_from_system_info as _parse_cpu_from_system_info,
            parse_cpu_from_top as _parse_cpu_from_top,
            parse_system_info_hardware as _parse_system_info_hardware,
            parse_mgmt_cpu_from_load_average as _parse_mgmt_cpu_from_load_average,
            parse_management_cpu_from_system_resources as _parse_management_cpu_from_system_resources,
            _aggregate as __aggregate,
            calculate_percentile as _calculate_percentile,
        )
        from ..interface_monitor import (
            parse_interface_statistics_your_panos11 as _parse_interface_statistics_your_panos11,
            parse_session_statistics_your_panos11 as _parse_session_statistics_your_panos11,
            discover_interfaces_panos11 as _discover_interfaces_panos11,
            InterfaceSample as _InterfaceSampleImport,
        )

        # Assign to globals
        _PanOSAPIClient = _PanOSAPIClientImport
        FIREWALL_CORE_ARCHITECTURE = _FIREWALL_CORE_ARCHITECTURE
        is_affected_by_dp_core_issue = _is_affected_by_dp_core_issue
        get_core_architecture = _get_core_architecture
        parse_dp_cpu_from_rm_your_panos11 = _parse_dp_cpu_from_rm_your_panos11
        parse_pbuf_live_from_rm_your_panos11 = _parse_pbuf_live_from_rm_your_panos11
        parse_cpu_from_debug_status = _parse_cpu_from_debug_status
        parse_cpu_from_system_info = _parse_cpu_from_system_info
        parse_cpu_from_top = _parse_cpu_from_top
        parse_system_info_hardware = _parse_system_info_hardware
        parse_mgmt_cpu_from_load_average = _parse_mgmt_cpu_from_load_average
        parse_management_cpu_from_system_resources = _parse_management_cpu_from_system_resources
        _aggregate = __aggregate
        calculate_percentile = _calculate_percentile
        parse_interface_statistics_your_panos11 = _parse_interface_statistics_your_panos11
        parse_session_statistics_your_panos11 = _parse_session_statistics_your_panos11
        discover_interfaces_panos11 = _discover_interfaces_panos11
        _InterfaceSample = _InterfaceSampleImport

        _collectors_imported = True
        return True

    except ImportError as e:
        LOG.warning(f"Failed to import Palo Alto dependencies: {e}")
        return False


# For backward compatibility, expose PALO_ALTO_AVAILABLE as a property
PALO_ALTO_AVAILABLE = True  # Will be checked at runtime


class PaloAltoClient(VendorClient):
    """
    Palo Alto Networks PAN-OS API client.

    Wraps the existing FireLensClient implementation to provide
    the VendorClient interface for multi-vendor support.

    Supports:
    - PA-VM, PA-200/220, PA-800, PA-3000, PA-5000 series
    - PA-400, PA-1400, PA-3400, PA-5400 series (with DP core handling)
    - PAN-OS 9.x, 10.x, 11.x

    API: XML-based REST API with API key authentication
    """

    VENDOR_NAME = "Palo Alto Networks"
    VENDOR_TYPE = "palo_alto"

    def __init__(self, host: str, verify_ssl: bool = True, ca_bundle_path: Optional[str] = None):
        """
        Initialize Palo Alto client.

        Args:
            host: Firewall IP/hostname (https:// prefix optional)
            verify_ssl: Verify SSL certificates (False for self-signed)
            ca_bundle_path: Optional path to custom CA bundle for SSL verification
        """
        # Lazy import collectors module to avoid circular imports
        if not _ensure_collectors_imported():
            raise ImportError("Palo Alto dependencies not available")

        self._client = _PanOSAPIClient(host, verify_ssl, ca_bundle_path)
        self._authenticated = False
        self._hardware_info: Optional[HardwareInfo] = None
        self._model: str = ""
        self._is_affected_model: bool = False

    @property
    def vendor_name(self) -> str:
        return self.VENDOR_NAME

    @property
    def vendor_type(self) -> str:
        return self.VENDOR_TYPE

    def authenticate(self, username: str, password: str) -> bool:
        """
        Authenticate with PAN-OS API using keygen.

        Args:
            username: Admin username
            password: Admin password

        Returns:
            True if authentication successful
        """
        success = self._client.keygen(username, password)
        if success:
            self._authenticated = True
            # Detect hardware after authentication
            self._detect_hardware()
        return success

    def is_authenticated(self) -> bool:
        return self._authenticated and self._client.api_key is not None

    def _detect_hardware(self) -> None:
        """Detect firewall model and hardware info after authentication."""
        xml = self._client.op("<show><system><info/></system></show>")
        if xml:
            hw_info, _ = parse_system_info_hardware(xml)
            if hw_info:
                self._model = hw_info.get('model', '')
                self._is_affected_model = is_affected_by_dp_core_issue(self._model)
                self._hardware_info = HardwareInfo(
                    vendor=self.VENDOR_NAME,
                    model=hw_info.get('model', ''),
                    serial=hw_info.get('serial', ''),
                    hostname=hw_info.get('hostname', ''),
                    sw_version=hw_info.get('sw_version', ''),
                    vendor_specific={
                        'family': hw_info.get('family', ''),
                        'platform_family': hw_info.get('platform_family', ''),
                    }
                )
                LOG.info(f"Detected Palo Alto {self._model} (affected model: {self._is_affected_model})")

    def collect_system_metrics(self) -> SystemMetrics:
        """
        Collect CPU and system metrics from Palo Alto firewall.

        Uses multiple methods for management CPU based on model type:
        - Affected models (PA-400/1400/3400/5400): Load average method
        - Other models: Debug status -> System info -> Top parsing

        Returns:
            SystemMetrics with CPU usage and vendor-specific metrics
        """
        timestamp = datetime.now(timezone.utc)
        vendor_metrics: Dict[str, Any] = {}

        # Collect management CPU
        mgmt_cpu = 0.0
        if self._is_affected_model:
            # Use load average method for affected models
            xml = self._client.op("<show><system><resources/></system></show>")
            if xml:
                metrics, msg = parse_mgmt_cpu_from_load_average(xml, self._model)
                mgmt_cpu = metrics.get('mgmt_cpu', 0.0)
                vendor_metrics.update(metrics)
                LOG.debug(f"Mgmt CPU (load avg): {msg}")
        else:
            # Try multiple methods for non-affected models
            # Method 1: Debug status (most accurate)
            xml = self._client.request("<request><s><debug><status/></debug></s></request>")
            if xml:
                metrics, msg = parse_cpu_from_debug_status(xml)
                if metrics.get('mgmt_cpu_debug'):
                    mgmt_cpu = metrics['mgmt_cpu_debug']
                    vendor_metrics.update(metrics)
                    LOG.debug(f"Mgmt CPU (debug): {msg}")

            # Method 2: System info (fallback)
            if not mgmt_cpu:
                xml = self._client.op("<show><system><info/></system></show>")
                if xml:
                    metrics, msg = parse_cpu_from_system_info(xml)
                    if metrics.get('mgmt_cpu_load_avg'):
                        mgmt_cpu = metrics['mgmt_cpu_load_avg']
                        vendor_metrics.update(metrics)
                        LOG.debug(f"Mgmt CPU (system info): {msg}")

            # Method 3: Top parsing (last resort)
            if not mgmt_cpu:
                xml = self._client.op("<show><system><resources/></system></show>")
                if xml:
                    metrics, msg = parse_cpu_from_top(xml)
                    if metrics.get('mgmt_cpu'):
                        mgmt_cpu = metrics['mgmt_cpu']
                        vendor_metrics.update(metrics)
                        LOG.debug(f"Mgmt CPU (top): {msg}")

        # Collect data plane CPU and packet buffer
        xml = self._client.op(
            "<show><running><resource-monitor><minute></minute></resource-monitor></running></show>"
        )
        if xml:
            # Data plane CPU
            dp_metrics, dp_msg = parse_dp_cpu_from_rm_your_panos11(xml)
            vendor_metrics.update(dp_metrics)
            LOG.debug(f"DP CPU: {dp_msg}")

            # Packet buffer
            pbuf_metrics, pbuf_msg = parse_pbuf_live_from_rm_your_panos11(xml)
            vendor_metrics.update(pbuf_metrics)
            LOG.debug(f"Packet buffer: {pbuf_msg}")

        # Set primary CPU metric
        vendor_metrics['mgmt_cpu'] = mgmt_cpu

        return SystemMetrics(
            timestamp=timestamp,
            cpu_usage=mgmt_cpu,  # Use management CPU as primary
            vendor_metrics=vendor_metrics
        )

    def collect_interface_stats(self, interfaces: Optional[List[str]] = None) -> Dict[str, InterfaceSample]:
        """
        Collect interface statistics from Palo Alto firewall.

        Uses two-stage collection:
        1. Discover interfaces if not specified
        2. Query each interface for detailed counters

        Args:
            interfaces: Specific interfaces to collect, or None for all

        Returns:
            Dictionary mapping interface names to InterfaceSample
        """
        result: Dict[str, InterfaceSample] = {}
        timestamp = datetime.now(timezone.utc)

        # Use existing parsing function
        samples = parse_interface_statistics_your_panos11(self._client)

        if interfaces:
            # Filter to requested interfaces
            samples = {k: v for k, v in samples.items() if k in interfaces}

        # Convert to our InterfaceSample format
        for name, sample in samples.items():
            if sample and sample.success:
                result[name] = InterfaceSample(
                    timestamp=timestamp,
                    interface_name=name,
                    rx_bytes=sample.rx_bytes,
                    tx_bytes=sample.tx_bytes,
                    rx_packets=sample.rx_packets,
                    tx_packets=sample.tx_packets,
                    rx_errors=sample.rx_errors,
                    tx_errors=sample.tx_errors,
                    success=True
                )

        return result

    def collect_session_stats(self) -> SessionStats:
        """
        Collect session statistics from Palo Alto firewall.

        Returns:
            SessionStats with active sessions, max sessions, and breakdown
        """
        timestamp = datetime.now(timezone.utc)

        stats = parse_session_statistics_your_panos11(self._client)

        return SessionStats(
            timestamp=timestamp,
            active_sessions=stats.get('active_sessions', 0),
            max_sessions=stats.get('max_sessions', 0),
            tcp_sessions=stats.get('tcp_sessions', 0),
            udp_sessions=stats.get('udp_sessions', 0),
            icmp_sessions=stats.get('icmp_sessions', 0),
            session_rate=stats.get('session_rate', 0.0)
        )

    def get_hardware_info(self) -> HardwareInfo:
        """
        Get hardware information from Palo Alto firewall.

        Returns:
            HardwareInfo with model, serial, version, etc.
        """
        if self._hardware_info:
            return self._hardware_info

        # Fetch if not cached
        self._detect_hardware()

        if self._hardware_info:
            return self._hardware_info

        # Return empty info if detection failed
        return HardwareInfo(
            vendor=self.VENDOR_NAME,
            model="Unknown",
            serial="",
            hostname="",
            sw_version=""
        )

    def discover_interfaces(self) -> List[str]:
        """
        Discover available interfaces on Palo Alto firewall.

        Returns:
            List of interface names (e.g., ['ethernet1/1', 'ethernet1/2'])
        """
        xml = self._client.op("<show><interface>all</interface></show>")
        if xml:
            return discover_interfaces_panos11(xml)
        return []

    def close(self) -> None:
        """Close the API client and cleanup resources."""
        if self._client:
            self._client.close()
            self._authenticated = False


class PaloAltoAdapter(VendorAdapter):
    """
    Palo Alto Networks vendor adapter.

    Factory for creating Palo Alto clients and providing
    vendor-specific configuration.
    """

    VENDOR_NAME = "Palo Alto Networks"
    VENDOR_TYPE = "palo_alto"

    @property
    def vendor_name(self) -> str:
        return self.VENDOR_NAME

    @property
    def vendor_type(self) -> str:
        return self.VENDOR_TYPE

    def create_client(self, host: str, verify_ssl: bool = True, ca_bundle_path: Optional[str] = None) -> PaloAltoClient:
        """
        Create a new Palo Alto API client.

        Args:
            host: Firewall IP/hostname
            verify_ssl: Verify SSL certificates
            ca_bundle_path: Optional path to custom CA bundle for SSL verification

        Returns:
            Configured PaloAltoClient instance
        """
        return PaloAltoClient(host, verify_ssl, ca_bundle_path)

    def get_supported_metrics(self) -> List[str]:
        """
        Get list of metrics supported by Palo Alto firewalls.

        Returns:
            List of metric names
        """
        return [
            'cpu_usage',
            'mgmt_cpu',
            'mgmt_cpu_debug',
            'mgmt_cpu_load_avg',
            'data_plane_cpu',
            'data_plane_cpu_mean',
            'data_plane_cpu_max',
            'data_plane_cpu_p95',
            'pbuf_util_percent',
            'active_sessions',
            'max_sessions',
            'session_rate',
        ]

    def get_hardware_fields(self) -> List[str]:
        """
        Get list of hardware info fields for Palo Alto firewalls.

        Returns:
            List of field names
        """
        return [
            'model',
            'serial',
            'hostname',
            'sw_version',
            'family',
            'platform_family',
        ]

    def get_default_exclude_interfaces(self) -> List[str]:
        """
        Get default interface exclusion patterns for Palo Alto.

        Returns:
            List of patterns to exclude (management, loopback, HA, tunnels)
        """
        return [
            'mgmt',
            'loopback',
            'tunnel',
            'ha1',
            'ha2',
            'ha1-a',
            'ha1-b',
            'ha2-a',
            'ha2-b',
            'vlan',  # Often excludes VLAN interfaces by default
        ]


# Register this vendor
if PALO_ALTO_AVAILABLE:
    register_vendor(PaloAltoAdapter.VENDOR_TYPE, PaloAltoAdapter)
    LOG.debug("Registered Palo Alto Networks vendor adapter")
