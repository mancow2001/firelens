#!/usr/bin/env python3
"""
FireLens Monitor - Web Dashboard Module
Provides web interface for monitoring firewall metrics, interface bandwidth, and session statistics
"""

import asyncio
import logging
import threading
from pathlib import Path
from typing import Optional

try:
    import uvicorn
    from fastapi import FastAPI
    from fastapi.staticfiles import StaticFiles
    from fastapi.templating import Jinja2Templates

    FASTAPI_OK = True
except ImportError:
    FASTAPI_OK = False

# Rate limiting support
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.errors import RateLimitExceeded
    from slowapi.util import get_remote_address

    SLOWAPI_OK = True
except ImportError:
    SLOWAPI_OK = False

# Import from extracted modules
from .cache import SimpleCache
from .middleware import setup_middleware

# Import route modules
from .routes import (
    admin_router,
    auth_router,
    certificates_router,
    dashboard_router,
    saml_router,
    ssl_router,
)
from .session import SessionManager

LOG = logging.getLogger("FireLens.web")


class EnhancedWebDashboard:
    """Enhanced web dashboard with interface monitoring capabilities"""

    def __init__(self, database, config_manager, collector_manager=None):
        if not FASTAPI_OK:
            raise RuntimeError(
                "FastAPI not available - install with: pip install fastapi uvicorn jinja2"
            )

        self.database = database
        self.config_manager = config_manager
        self.collector_manager = collector_manager
        self.app = FastAPI(title="FireLens Monitor")
        self.server_thread = None
        self.should_stop = False

        # Set up rate limiting
        if SLOWAPI_OK:
            self.limiter = Limiter(key_func=get_remote_address)
            self.app.state.limiter = self.limiter
            self.app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
            LOG.info("Rate limiting initialized with slowapi")
        else:
            self.limiter = None
            LOG.warning("slowapi not available - rate limiting disabled")

        # Add cache control middleware for static files
        setup_middleware(self.app)

        # Add caching to reduce database load
        self.cache = SimpleCache(ttl_seconds=30)  # Cache for 30 seconds
        LOG.info("Dashboard cache initialized with 30s TTL")

        # Initialize admin session manager
        admin_timeout = 60  # Default timeout
        if hasattr(config_manager.global_config, "admin") and config_manager.global_config.admin:
            admin_timeout = config_manager.global_config.admin.session_timeout_minutes
        self.session_manager = SessionManager(timeout_minutes=admin_timeout)
        LOG.info(f"Admin session manager initialized with {admin_timeout}min timeout")

        # Initialize SAML handler if configured
        self.saml_handler = None
        try:
            from ..saml_auth import SAMLAuthHandler

            if (
                hasattr(config_manager.global_config, "admin")
                and config_manager.global_config.admin
                and config_manager.global_config.admin.saml
            ):
                self.saml_handler = SAMLAuthHandler(config_manager.global_config.admin.saml)
                if self.saml_handler.is_available():
                    LOG.info("SAML authentication handler initialized")
                else:
                    LOG.info("SAML configured but not fully available (check configuration)")
        except ImportError:
            LOG.debug("SAML authentication not available (python3-saml not installed)")

        # Store shared state on app.state for route handlers
        self.app.state.database = self.database
        self.app.state.config_manager = self.config_manager
        self.app.state.collector_manager = self.collector_manager
        self.app.state.session_manager = self.session_manager
        self.app.state.saml_handler = self.saml_handler
        self.app.state.cache = self.cache

        # Setup static files directory (in parent since we're in web_dashboard/)
        self.static_dir = Path(__file__).parent.parent / "static"
        if self.static_dir.exists():
            self.app.mount("/static", StaticFiles(directory=str(self.static_dir)), name="static")
            LOG.info(f"Static files directory mounted: {self.static_dir}")
        else:
            LOG.warning(f"Static files directory not found: {self.static_dir}")

        # Setup templates directory (in parent since we're in web_dashboard/)
        self.templates_dir = Path(__file__).parent.parent / "templates"
        self.templates_dir.mkdir(exist_ok=True)
        self.templates = Jinja2Templates(directory=str(self.templates_dir))
        self.app.state.templates = self.templates

        # Verify required templates exist
        self._verify_templates()

        # Register route modules
        self._register_routers()

    def _verify_templates(self):
        """Verify HTML templates exist in the templates directory"""
        # Check if templates exist
        dashboard_path = self.templates_dir / "dashboard.html"
        detail_path = self.templates_dir / "firewall_detail.html"

        if not dashboard_path.exists():
            LOG.error(f"Dashboard template not found at {dashboard_path}")
            LOG.error("Please ensure dashboard.html exists in the templates directory")
            raise FileNotFoundError(f"Required template not found: {dashboard_path}")
        else:
            LOG.info(f"Using dashboard template: {dashboard_path}")

        if not detail_path.exists():
            LOG.error(f"Firewall detail template not found at {detail_path}")
            LOG.error("Please ensure firewall_detail.html exists in the templates directory")
            raise FileNotFoundError(f"Required template not found: {detail_path}")
        else:
            LOG.info(f"Using firewall detail template: {detail_path}")

        LOG.info(f"Templates directory: {self.templates_dir}")
        LOG.info("All required templates found successfully")

    def _register_routers(self):
        """Register all route modules with the FastAPI app"""
        # Dashboard routes (public - no prefix)
        self.app.include_router(dashboard_router)
        LOG.debug("Registered dashboard routes")

        # Auth routes (/admin/login, /admin/logout, /admin/password)
        self.app.include_router(auth_router)
        LOG.debug("Registered auth routes")

        # SAML routes (/admin/saml/*)
        self.app.include_router(saml_router)
        LOG.debug("Registered SAML routes")

        # Admin routes (/admin, /admin/firewall/*, /admin/api/firewalls/*)
        self.app.include_router(admin_router)
        LOG.debug("Registered admin routes")

        # Certificate routes (/admin/certificates, /admin/api/certificates/*)
        self.app.include_router(certificates_router)
        LOG.debug("Registered certificate routes")

        # SSL routes (/admin/ssl, /admin/api/ssl/*)
        self.app.include_router(ssl_router)
        LOG.debug("Registered SSL routes")

        LOG.info("All route modules registered successfully")

    def start_server(
        self,
        host: str = "0.0.0.0",
        port: int = 8080,
        ssl_certfile: Optional[str] = None,
        ssl_keyfile: Optional[str] = None,
    ):
        """Start the enhanced web server in a thread with optional SSL support"""
        if self.server_thread and self.server_thread.is_alive():
            LOG.warning("Enhanced web server already running")
            return self.server_thread

        def run_server():
            """Run enhanced server in thread with new event loop"""
            try:
                # Create new event loop for this thread
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

                # Create and configure server
                config = uvicorn.Config(
                    self.app,
                    host=host,
                    port=port,
                    log_level="warning",
                    access_log=False,
                    loop=loop,
                    ssl_certfile=ssl_certfile,
                    ssl_keyfile=ssl_keyfile,
                )

                server = uvicorn.Server(config)

                # Run server
                protocol = "https" if ssl_certfile else "http"
                LOG.info(f"Starting enhanced web server on {protocol}://{host}:{port}")
                loop.run_until_complete(server.serve())

            except Exception as e:
                LOG.error(f"Enhanced web server failed: {e}")
            finally:
                # Clean up
                try:
                    loop.close()
                except Exception:
                    pass

        # Start server thread
        self.server_thread = threading.Thread(
            target=run_server, name="enhanced-web-server", daemon=True
        )
        self.server_thread.start()

        LOG.info(f"Enhanced web dashboard started at http://{host}:{port}")
        return self.server_thread

    def stop_server(self):
        """Stop the enhanced web server"""
        self.should_stop = True
        if self.server_thread and self.server_thread.is_alive():
            LOG.info("Stopping enhanced web server...")

    def start_http_redirect_server(
        self, http_port: int = 8080, https_port: int = 8443, host: str = "0.0.0.0"
    ):
        """
        Start a lightweight HTTP server that redirects all requests to HTTPS.
        This is useful for dual-port operation where HTTP redirects to HTTPS.
        """
        from fastapi import FastAPI
        from starlette.requests import Request
        from starlette.responses import RedirectResponse

        redirect_app = FastAPI(title="HTTP to HTTPS Redirect")

        @redirect_app.api_route(
            "/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
        )
        async def redirect_to_https(request: Request, path: str = ""):
            """Redirect all HTTP requests to HTTPS"""
            # Build the HTTPS URL
            # Get the host from the request, replace port if present
            request_host = request.headers.get("host", "localhost")
            if ":" in request_host:
                request_host = request_host.split(":")[0]

            # Construct HTTPS URL with proper port
            https_url = f"https://{request_host}:{https_port}/{path}"

            # Include query string if present
            if request.url.query:
                https_url = f"{https_url}?{request.url.query}"

            return RedirectResponse(url=https_url, status_code=301)

        def run_redirect_server():
            """Run redirect server in thread"""
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

                config = uvicorn.Config(
                    redirect_app,
                    host=host,
                    port=http_port,
                    log_level="warning",
                    access_log=False,
                    loop=loop,
                )

                server = uvicorn.Server(config)
                LOG.info(
                    f"Starting HTTP redirect server on http://{host}:{http_port} -> https://...:{https_port}"
                )
                loop.run_until_complete(server.serve())

            except Exception as e:
                LOG.error(f"HTTP redirect server failed: {e}")
            finally:
                try:
                    loop.close()
                except Exception:
                    pass

        # Start redirect server thread
        redirect_thread = threading.Thread(
            target=run_redirect_server, name="http-redirect-server", daemon=True
        )
        redirect_thread.start()

        LOG.info(
            f"HTTP redirect server started: http://{host}:{http_port} -> https://...:{https_port}"
        )
        return redirect_thread


# Maintain backward compatibility
class WebDashboard(EnhancedWebDashboard):
    """Backward compatibility alias for the enhanced web dashboard"""

    pass
