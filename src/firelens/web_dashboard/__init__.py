"""
FireLens Monitor - Web Dashboard Package
Provides web interface for monitoring firewall metrics, interface bandwidth, and session statistics
"""

from .app import EnhancedWebDashboard, WebDashboard
from .cache import SimpleCache
from .helpers import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    get_admin_user,
    get_csrf_token,
    is_admin_enabled,
    is_saml_available,
    validate_csrf,
    validate_password_complexity,
)
from .middleware import CacheControlMiddleware, setup_middleware
from .session import SessionManager

__all__ = [
    # Main classes
    "EnhancedWebDashboard",
    "WebDashboard",
    "SimpleCache",
    "SessionManager",
    "CacheControlMiddleware",
    # Helper functions
    "validate_password_complexity",
    "get_admin_user",
    "get_csrf_token",
    "validate_csrf",
    "is_admin_enabled",
    "is_saml_available",
    "setup_middleware",
    # Constants
    "MIN_PASSWORD_LENGTH",
    "MAX_PASSWORD_LENGTH",
]
