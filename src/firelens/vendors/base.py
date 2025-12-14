#!/usr/bin/env python3
"""
FireLens Monitor - Vendor Abstraction Layer
Abstract base classes for multi-vendor firewall support
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class InterfaceSample:
    """Raw interface counters at one point in time - vendor agnostic"""

    timestamp: datetime
    interface_name: str
    rx_bytes: int
    tx_bytes: int
    rx_packets: int
    tx_packets: int
    rx_errors: int = 0
    tx_errors: int = 0
    success: bool = True
    error: Optional[str] = None


@dataclass
class SessionStats:
    """Session statistics - vendor agnostic"""

    timestamp: datetime
    active_sessions: int
    max_sessions: int
    tcp_sessions: int = 0
    udp_sessions: int = 0
    icmp_sessions: int = 0
    session_rate: float = 0.0  # Sessions per second


@dataclass
class HardwareInfo:
    """Hardware information - vendor agnostic with optional vendor-specific fields"""

    vendor: str
    model: str
    serial: str
    hostname: str
    sw_version: str
    # Vendor-specific fields stored as dict
    vendor_specific: Dict[str, Any] = None

    def __post_init__(self):
        if self.vendor_specific is None:
            self.vendor_specific = {}


@dataclass
class SystemMetrics:
    """System metrics - vendor agnostic"""

    timestamp: datetime
    cpu_usage: float  # Overall CPU percentage
    memory_usage: Optional[float] = None  # Memory percentage if available
    # Vendor-specific metrics (e.g., mgmt_cpu, data_plane_cpu for Palo Alto)
    vendor_metrics: Dict[str, Any] = None

    def __post_init__(self):
        if self.vendor_metrics is None:
            self.vendor_metrics = {}


class VendorClient(ABC):
    """
    Abstract API client for firewall communication.

    Each vendor implementation handles:
    - Authentication (API key, OAuth, session-based, etc.)
    - API calls (REST, XML, SSH, etc.)
    - Response parsing
    - Error handling
    """

    @property
    @abstractmethod
    def vendor_name(self) -> str:
        """Human-readable vendor name (e.g., 'Palo Alto Networks')"""
        pass

    @property
    @abstractmethod
    def vendor_type(self) -> str:
        """Vendor type identifier (e.g., 'palo_alto')"""
        pass

    @abstractmethod
    def authenticate(self, username: str, password: str) -> bool:
        """
        Authenticate with the firewall.

        Args:
            username: Authentication username
            password: Authentication password or API token

        Returns:
            True if authentication successful, False otherwise
        """
        pass

    @abstractmethod
    def is_authenticated(self) -> bool:
        """Check if client is currently authenticated"""
        pass

    @abstractmethod
    def collect_system_metrics(self) -> SystemMetrics:
        """
        Collect system-level metrics (CPU, memory, etc.)

        Returns:
            SystemMetrics dataclass with collected metrics
        """
        pass

    @abstractmethod
    def collect_interface_stats(
        self, interfaces: Optional[List[str]] = None
    ) -> Dict[str, InterfaceSample]:
        """
        Collect interface statistics.

        Args:
            interfaces: Optional list of specific interfaces to collect.
                       If None, collect all available interfaces.

        Returns:
            Dictionary mapping interface names to InterfaceSample
        """
        pass

    @abstractmethod
    def collect_session_stats(self) -> SessionStats:
        """
        Collect session/connection statistics.

        Returns:
            SessionStats dataclass with session information
        """
        pass

    @abstractmethod
    def get_hardware_info(self) -> HardwareInfo:
        """
        Get hardware and software information.

        Returns:
            HardwareInfo dataclass with device information
        """
        pass

    @abstractmethod
    def discover_interfaces(self) -> List[str]:
        """
        Discover available interfaces on the firewall.

        Returns:
            List of interface names
        """
        pass

    @abstractmethod
    def close(self) -> None:
        """Close the client connection and cleanup resources"""
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


class VendorAdapter(ABC):
    """
    Abstract factory for creating vendor-specific components.

    Each vendor provides an adapter that creates properly configured
    clients and collectors for that vendor's firewalls.
    """

    @property
    @abstractmethod
    def vendor_name(self) -> str:
        """Human-readable vendor name"""
        pass

    @property
    @abstractmethod
    def vendor_type(self) -> str:
        """Vendor type identifier used in configuration"""
        pass

    @abstractmethod
    def create_client(
        self, host: str, verify_ssl: bool = True, ca_bundle_path: Optional[str] = None
    ) -> VendorClient:
        """
        Create a new API client for this vendor.

        Args:
            host: Firewall hostname or IP address
            verify_ssl: Whether to verify SSL certificates
            ca_bundle_path: Optional path to custom CA bundle for SSL verification

        Returns:
            Configured VendorClient instance
        """
        pass

    @abstractmethod
    def get_supported_metrics(self) -> List[str]:
        """
        Get list of metrics supported by this vendor.

        Returns:
            List of metric names (e.g., ['cpu_usage', 'mgmt_cpu', 'data_plane_cpu'])
        """
        pass

    @abstractmethod
    def get_hardware_fields(self) -> List[str]:
        """
        Get list of hardware info fields supported by this vendor.

        Returns:
            List of field names (e.g., ['model', 'serial', 'platform_family'])
        """
        pass

    def get_default_exclude_interfaces(self) -> List[str]:
        """
        Get default interface name patterns to exclude from monitoring.

        Override in vendor implementations for vendor-specific defaults.

        Returns:
            List of interface name patterns to exclude
        """
        return ["mgmt", "management", "loopback", "lo"]


# Type alias for vendor registry
VendorRegistry = Dict[str, type]
