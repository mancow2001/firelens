"""
FireLens Monitor - SSL/TLS Management Routes
SSL certificate generation, upload, and management routes
"""

import logging
import socket

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from ..helpers import get_admin_user, get_csrf_token, validate_csrf

LOG = logging.getLogger("FireLens.web")

router = APIRouter(prefix="/admin")


def _get_ssl_manager(request: Request):
    """Get SSL manager instance"""
    try:
        from ...ssl_manager import SSLManager

        config_manager = request.app.state.config_manager
        certs_dir = getattr(config_manager.global_config, "certs_directory", "./certs")
        return SSLManager(certs_dir)
    except ImportError:
        return None


@router.get("/ssl", response_class=HTMLResponse)
async def admin_ssl_page(request: Request):
    """SSL/TLS management page"""
    user = get_admin_user(request)
    if not user:
        return RedirectResponse(url="/admin/login", status_code=302)

    templates = request.app.state.templates
    config_manager = request.app.state.config_manager

    ssl_manager = _get_ssl_manager(request)
    ssl_config = config_manager.global_config.web_ssl

    cert_info = None
    if ssl_manager:
        cert_info = ssl_manager.get_certificate_info()

    return templates.TemplateResponse(
        "admin_ssl.html",
        {
            "request": request,
            "user": user,
            "ssl_enabled": ssl_config.enabled if ssl_config else False,
            "https_port": ssl_config.https_port if ssl_config else 8443,
            "http_port": ssl_config.http_port if ssl_config else 8080,
            "cert_info": cert_info,
            "csrf_token": get_csrf_token(request),
        },
    )


@router.get("/api/ssl/status")
async def admin_api_ssl_status(request: Request):
    """API: Get SSL status and certificate info"""
    user = get_admin_user(request)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    config_manager = request.app.state.config_manager

    ssl_manager = _get_ssl_manager(request)
    ssl_config = config_manager.global_config.web_ssl

    cert_info = None
    if ssl_manager:
        cert_info = ssl_manager.get_certificate_info()

    return JSONResponse(
        {
            "ssl_enabled": ssl_config.enabled if ssl_config else False,
            "https_port": ssl_config.https_port if ssl_config else 8443,
            "http_port": ssl_config.http_port if ssl_config else 8080,
            "has_certificate": ssl_manager.has_valid_certificate() if ssl_manager else False,
            "certificate": cert_info,
        }
    )


@router.post("/api/ssl/generate")
async def admin_api_ssl_generate(request: Request):
    """API: Generate a new self-signed certificate"""
    user = get_admin_user(request)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    try:
        data = await request.json()
    except Exception:
        data = {}

    # Validate CSRF token
    csrf_token = data.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not validate_csrf(request, csrf_token):
        return JSONResponse({"success": False, "message": "Invalid CSRF token"}, status_code=403)

    ssl_manager = _get_ssl_manager(request)
    if not ssl_manager:
        return JSONResponse(
            {"success": False, "message": "SSL manager not available"}, status_code=500
        )

    try:
        hostname = socket.gethostname()
        cert_path, key_path = ssl_manager.generate_self_signed_cert(
            hostname=hostname, valid_days=365
        )
        return JSONResponse(
            {
                "success": True,
                "message": "Self-signed certificate generated. Restart service to apply.",
            }
        )
    except Exception as e:
        LOG.error(f"Error generating self-signed certificate: {e}")
        return JSONResponse(
            {"success": False, "message": f"Error generating certificate: {str(e)}"},
            status_code=500,
        )


@router.post("/api/ssl/upload")
async def admin_api_ssl_upload(request: Request):
    """API: Upload a new certificate and private key"""
    user = get_admin_user(request)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"success": False, "message": "Invalid request data"}, status_code=400)

    # Validate CSRF token
    csrf_token = data.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not validate_csrf(request, csrf_token):
        return JSONResponse({"success": False, "message": "Invalid CSRF token"}, status_code=403)

    certificate = data.get("certificate", "").strip()
    private_key = data.get("private_key", "").strip()

    if not certificate or not private_key:
        return JSONResponse(
            {"success": False, "message": "Both certificate and private key are required"},
            status_code=400,
        )

    ssl_manager = _get_ssl_manager(request)
    if not ssl_manager:
        return JSONResponse(
            {"success": False, "message": "SSL manager not available"}, status_code=500
        )

    success, message = ssl_manager.install_certificate(certificate, private_key)
    return JSONResponse(
        {
            "success": success,
            "message": message + " Restart the service to apply changes." if success else message,
        },
        status_code=200 if success else 400,
    )


@router.delete("/api/ssl/certificate")
async def admin_api_ssl_delete(request: Request):
    """API: Delete the current SSL certificate"""
    user = get_admin_user(request)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    # Validate CSRF token from header
    csrf_token = request.headers.get("X-CSRF-Token")
    if not validate_csrf(request, csrf_token):
        return JSONResponse({"success": False, "message": "Invalid CSRF token"}, status_code=403)

    ssl_manager = _get_ssl_manager(request)
    if not ssl_manager:
        return JSONResponse(
            {"success": False, "message": "SSL manager not available"}, status_code=500
        )

    success, message = ssl_manager.delete_certificate()
    return JSONResponse(
        {"success": success, "message": message}, status_code=200 if success else 400
    )
