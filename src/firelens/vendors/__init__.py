#!/usr/bin/env python3
"""
FireLens Monitor - Vendor Module
Multi-vendor firewall support with pluggable adapters
"""
import logging
from typing import Dict, Type, Optional

from .base import (
    VendorAdapter,
    VendorClient,
    InterfaceSample,
    SessionStats,
    HardwareInfo,
    SystemMetrics,
)

LOG = logging.getLogger("FireLens.vendors")

# Vendor registry - maps vendor type strings to adapter classes
_VENDOR_REGISTRY: Dict[str, Type[VendorAdapter]] = {}

# Supported vendor types
SUPPORTED_VENDORS = ['palo_alto', 'fortinet', 'cisco_firepower']


def register_vendor(vendor_type: str, adapter_class: Type[VendorAdapter]) -> None:
    """
    Register a vendor adapter in the registry.

    Args:
        vendor_type: Vendor type identifier (e.g., 'palo_alto')
        adapter_class: VendorAdapter subclass to register
    """
    if vendor_type in _VENDOR_REGISTRY:
        LOG.warning(f"Overwriting existing vendor registration for '{vendor_type}'")
    _VENDOR_REGISTRY[vendor_type] = adapter_class
    LOG.debug(f"Registered vendor adapter: {vendor_type} -> {adapter_class.__name__}")


def get_vendor_adapter(vendor_type: str) -> VendorAdapter:
    """
    Get a vendor adapter instance by type.

    Args:
        vendor_type: Vendor type identifier (e.g., 'palo_alto')

    Returns:
        Configured VendorAdapter instance

    Raises:
        ValueError: If vendor type is not registered
    """
    if vendor_type not in _VENDOR_REGISTRY:
        available = list(_VENDOR_REGISTRY.keys())
        raise ValueError(
            f"Unknown vendor type: '{vendor_type}'. "
            f"Available vendors: {available}"
        )
    return _VENDOR_REGISTRY[vendor_type]()


def get_available_vendors() -> Dict[str, str]:
    """
    Get dictionary of available vendors.

    Returns:
        Dictionary mapping vendor_type to vendor_name
    """
    return {
        vendor_type: adapter_class().vendor_name
        for vendor_type, adapter_class in _VENDOR_REGISTRY.items()
    }


def is_vendor_supported(vendor_type: str) -> bool:
    """
    Check if a vendor type is supported.

    Args:
        vendor_type: Vendor type identifier

    Returns:
        True if vendor is registered and available
    """
    return vendor_type in _VENDOR_REGISTRY


# Import vendor implementations to trigger registration
# Each vendor module registers itself when imported
try:
    from . import palo_alto
except ImportError as e:
    LOG.warning(f"Failed to load Palo Alto vendor module: {e}")

try:
    from . import fortinet
except ImportError as e:
    LOG.debug(f"Fortinet vendor module not available: {e}")

try:
    from . import cisco_firepower
except ImportError as e:
    LOG.debug(f"Cisco Firepower vendor module not available: {e}")


# Public API
__all__ = [
    # Base classes
    'VendorAdapter',
    'VendorClient',
    'InterfaceSample',
    'SessionStats',
    'HardwareInfo',
    'SystemMetrics',
    # Registry functions
    'register_vendor',
    'get_vendor_adapter',
    'get_available_vendors',
    'is_vendor_supported',
    'SUPPORTED_VENDORS',
]
