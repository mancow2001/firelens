"""
FireLens Monitor - Routes Package
FastAPI route modules for the web dashboard
"""

from .admin import router as admin_router
from .auth import router as auth_router
from .certificates import router as certificates_router
from .dashboard import router as dashboard_router
from .saml import router as saml_router
from .ssl import router as ssl_router

__all__ = [
    "dashboard_router",
    "auth_router",
    "saml_router",
    "admin_router",
    "certificates_router",
    "ssl_router",
]
