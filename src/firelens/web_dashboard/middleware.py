"""
FireLens Monitor - Middleware Module
HTTP middleware for caching, security headers, and other request/response processing
"""

import logging

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

LOG = logging.getLogger("FireLens.web")


class CacheControlMiddleware(BaseHTTPMiddleware):
    """Middleware to add Cache-Control and security headers"""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        path = request.url.path

        # Static files caching
        if path.startswith("/static/"):
            # Third-party libraries - cache for 8 hours
            if "/js/chart" in path or "/js/chartjs-adapter" in path:
                response.headers["Cache-Control"] = "public, max-age=28800"
            # App CSS and JS - cache for 1 hour, revalidate
            elif path.endswith((".css", ".js")):
                response.headers["Cache-Control"] = "public, max-age=3600, must-revalidate"
            # Images - cache for 1 week
            elif path.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico")):
                response.headers["Cache-Control"] = "public, max-age=604800"
            # Other static files - cache for 1 hour
            else:
                response.headers["Cache-Control"] = "public, max-age=3600"
        # API responses - no caching
        elif path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
            response.headers["Pragma"] = "no-cache"
        # HTML pages - no caching to ensure fresh content
        elif response.headers.get("content-type", "").startswith("text/html"):
            response.headers["Cache-Control"] = "no-cache, must-revalidate"

        # Security headers for all responses
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # CSP: Allow scripts from self, inline scripts (needed for Chart.js), and inline styles
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )

        return response


def setup_middleware(app):
    """Add all middleware to the FastAPI app"""
    app.add_middleware(CacheControlMiddleware)
    LOG.info("Cache-Control middleware configured")
