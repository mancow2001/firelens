"""
FireLens Monitor - Multi-vendor Firewall Monitoring Solution

A production-ready, multi-vendor firewall monitoring solution that collects
real-time CPU, throughput, packet buffer, interface bandwidth, and session
statistics from multiple firewalls simultaneously.
"""

__version__ = "1.0.30"
__author__ = "FireLens Team"
__license__ = "MIT"

# Package-level imports for convenience
from .app import FireLensApp
from .config import ConfigManager, FirewallConfig, GlobalConfig
from .database import MetricsDatabase

__all__ = [
    "__version__",
    "FireLensApp",
    "ConfigManager",
    "FirewallConfig",
    "GlobalConfig",
    "MetricsDatabase",
]
