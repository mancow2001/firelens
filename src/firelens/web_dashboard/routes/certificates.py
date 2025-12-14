"""
FireLens Monitor - Certificate Management Routes
CA certificate upload, viewing, and management routes
"""
import logging

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from ..helpers import get_admin_user, get_csrf_token, validate_csrf

LOG = logging.getLogger("FireLens.web")

router = APIRouter(prefix="/admin")


def _get_cert_manager(request: Request):
    """Get certificate manager instance"""
    from ...cert_manager import CertificateManager
    config_manager = request.app.state.config_manager
    certs_dir = getattr(config_manager.global_config, 'certs_directory', './certs')
    return CertificateManager(certs_dir)


@router.get("/certificates", response_class=HTMLResponse)
async def admin_certificates_page(request: Request):
    """Certificate management page"""
    user = get_admin_user(request)
    if not user:
        return RedirectResponse(url="/admin/login", status_code=302)

    templates = request.app.state.templates
    cert_manager = _get_cert_manager(request)
    certificates = cert_manager.list_certificates()
    stats = cert_manager.get_certificate_stats()

    return templates.TemplateResponse("admin_certificates.html", {
        "request": request,
        "user": user,
        "certificates": certificates,
        "stats": stats,
        "csrf_token": get_csrf_token(request)
    })


@router.get("/api/certificates")
async def admin_api_list_certificates(request: Request):
    """API: List all uploaded CA certificates"""
    user = get_admin_user(request)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    cert_manager = _get_cert_manager(request)
    certificates = cert_manager.list_certificates()

    return JSONResponse([cert.to_dict() for cert in certificates])


@router.post("/api/certificates")
async def admin_api_upload_certificate(request: Request):
    """API: Upload new CA certificate(s)"""
    user = get_admin_user(request)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    # Parse multipart form data
    form = await request.form()

    # Validate CSRF token from form or header
    csrf_token = form.get('csrf_token') or request.headers.get('X-CSRF-Token')
    if not validate_csrf(request, csrf_token):
        return JSONResponse({"error": "Invalid or missing CSRF token"}, status_code=403)

    file = form.get("file")

    if not file:
        return JSONResponse({
            "status": "error",
            "message": "No file provided"
        }, status_code=400)

    # Read file contents
    contents = await file.read()
    filename = file.filename

    cert_manager = _get_cert_manager(request)
    result = cert_manager.add_certificate(contents, filename)

    if result.success:
        LOG.info(f"Admin {user} uploaded {result.certs_added} certificate(s)")
        return JSONResponse({
            "status": "ok",
            "message": f"Added {result.certs_added} certificate(s)",
            "certs_added": result.certs_added,
            "certificates": [cert.to_dict() for cert in result.certificates],
            "warning": result.error  # May contain "already exists" warnings
        })
    else:
        return JSONResponse({
            "status": "error",
            "message": result.error
        }, status_code=400)


@router.delete("/api/certificates/{cert_id}")
async def admin_api_delete_certificate(request: Request, cert_id: str):
    """API: Delete a CA certificate"""
    user = get_admin_user(request)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    # Validate CSRF token from header (DELETE requests typically don't have body)
    csrf_token = request.headers.get('X-CSRF-Token')
    if not validate_csrf(request, csrf_token):
        return JSONResponse({"error": "Invalid or missing CSRF token"}, status_code=403)

    cert_manager = _get_cert_manager(request)
    success, message = cert_manager.delete_certificate(cert_id)

    if success:
        LOG.info(f"Admin {user} deleted certificate {cert_id}")
        return JSONResponse({
            "status": "ok",
            "message": message
        })
    else:
        return JSONResponse({
            "status": "error",
            "message": message
        }, status_code=404)


@router.get("/api/certificates/{cert_id}")
async def admin_api_get_certificate(request: Request, cert_id: str):
    """API: Get certificate details"""
    user = get_admin_user(request)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    cert_manager = _get_cert_manager(request)
    cert = cert_manager.get_certificate(cert_id)

    if cert:
        return JSONResponse(cert.to_dict())
    else:
        return JSONResponse({
            "status": "error",
            "message": "Certificate not found"
        }, status_code=404)


@router.get("/api/certificates/{cert_id}/download")
async def admin_api_download_certificate(request: Request, cert_id: str):
    """API: Download certificate as PEM file"""
    user = get_admin_user(request)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    cert_manager = _get_cert_manager(request)
    cert_info = cert_manager.get_certificate(cert_id)
    pem_data = cert_manager.get_certificate_pem(cert_id)

    if pem_data and cert_info:
        return Response(
            content=pem_data,
            media_type="application/x-pem-file",
            headers={
                "Content-Disposition": f"attachment; filename={cert_info.filename}"
            }
        )
    else:
        return JSONResponse({
            "status": "error",
            "message": "Certificate not found"
        }, status_code=404)


@router.get("/api/certificates/stats")
async def admin_api_certificate_stats(request: Request):
    """API: Get certificate statistics"""
    user = get_admin_user(request)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    cert_manager = _get_cert_manager(request)
    stats = cert_manager.get_certificate_stats()
    return JSONResponse(stats)
