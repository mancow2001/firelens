"""
FireLens Monitor - SAML Authentication Routes
SAML/SSO login, logout, ACS, SLO, and metadata routes
"""

import logging
import urllib.parse

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from ..helpers import get_admin_user, get_csrf_token, validate_csrf

LOG = logging.getLogger("FireLens.web")

router = APIRouter(prefix="/admin/saml")


def _prepare_saml_request(request: Request) -> dict:
    """Prepare request data for SAML handler"""
    return {
        "https": request.url.scheme == "https",
        "http_host": request.url.hostname,
        "server_port": request.url.port or (443 if request.url.scheme == "https" else 80),
        "script_name": str(request.url.path),
        "get_data": dict(request.query_params),
        "post_data": {},
    }


def _is_saml_available(request: Request) -> bool:
    """Check if SAML authentication is available"""
    saml_handler = request.app.state.saml_handler
    return saml_handler is not None and saml_handler.is_available()


@router.get("/login")
async def saml_login(request: Request):
    """Initiate SAML SSO login"""
    if not _is_saml_available(request):
        return HTMLResponse("<h1>SAML authentication is not configured</h1>", status_code=503)

    templates = request.app.state.templates
    saml_handler = request.app.state.saml_handler

    try:
        request_data = _prepare_saml_request(request)
        redirect_url = saml_handler.initiate_login(request_data, return_to="/admin")
        return RedirectResponse(url=redirect_url, status_code=302)
    except Exception as e:
        LOG.exception(f"SAML login initiation error: {e}")
        return templates.TemplateResponse(
            "admin_saml_error.html",
            {"request": request, "error": f"Failed to initiate SAML login: {str(e)}"},
            status_code=500,
        )


@router.post("/acs")
async def saml_acs(request: Request):
    """SAML Assertion Consumer Service - receives SAML Response from IdP"""
    if not _is_saml_available(request):
        return HTMLResponse("<h1>SAML authentication is not configured</h1>", status_code=503)

    templates = request.app.state.templates
    config_manager = request.app.state.config_manager
    session_manager = request.app.state.session_manager
    saml_handler = request.app.state.saml_handler

    try:
        # Get POST data
        form_data = await request.form()
        post_data = {key: value for key, value in form_data.items()}

        request_data = _prepare_saml_request(request)
        request_data["post_data"] = post_data

        success, username, session_index, error = saml_handler.process_response(request_data)

        if success and username:
            # Create local session with SAML info
            admin_config = config_manager.global_config.admin
            token = session_manager.create_session(
                username=username,
                auth_method="saml",
                saml_session_index=session_index,
                saml_name_id=username,
            )

            response = RedirectResponse(url="/admin", status_code=302)
            response.set_cookie(
                key="firelens_admin_session",
                value=token,
                httponly=True,
                samesite="strict",
                secure=admin_config.secure_cookies,
                path="/admin",
                max_age=admin_config.session_timeout_minutes * 60,
            )
            LOG.info(f"SAML login successful for user: {username}")
            return response
        else:
            LOG.warning(f"SAML authentication failed: {error}")
            return templates.TemplateResponse(
                "admin_saml_error.html",
                {"request": request, "error": error or "Authentication failed"},
                status_code=401,
            )

    except Exception as e:
        LOG.exception(f"SAML ACS error: {e}")
        return templates.TemplateResponse(
            "admin_saml_error.html",
            {"request": request, "error": f"SAML processing error: {str(e)}"},
            status_code=500,
        )


@router.get("/slo")
@router.post("/slo")
async def saml_slo(request: Request):
    """SAML Single Logout endpoint - handles both GET and POST"""
    if not _is_saml_available(request):
        return RedirectResponse(url="/admin/login", status_code=302)

    session_manager = request.app.state.session_manager
    saml_handler = request.app.state.saml_handler

    try:
        # Get data from either GET or POST
        if request.method == "POST":
            form_data = await request.form()
            data = {key: value for key, value in form_data.items()}
        else:
            data = dict(request.query_params)

        request_data = _prepare_saml_request(request)
        request_data["get_data"] = data if request.method == "GET" else {}
        request_data["post_data"] = data if request.method == "POST" else {}

        def delete_session_callback():
            # Try to find and destroy the session
            token = request.cookies.get("firelens_admin_session")
            if token:
                session_manager.destroy_session(token)

        success, redirect_url, error = saml_handler.process_logout(
            request_data, delete_session_callback=delete_session_callback
        )

        if success:
            if redirect_url:
                response = RedirectResponse(url=redirect_url, status_code=302)
            else:
                response = RedirectResponse(url="/admin/login", status_code=302)
            response.delete_cookie("firelens_admin_session", path="/admin")
            return response
        else:
            LOG.warning(f"SAML SLO failed: {error}")
            # On error, still clear local session and redirect to login
            token = request.cookies.get("firelens_admin_session")
            if token:
                session_manager.destroy_session(token)
            response = RedirectResponse(url="/admin/login", status_code=302)
            response.delete_cookie("firelens_admin_session", path="/admin")
            return response

    except Exception as e:
        LOG.exception(f"SAML SLO error: {e}")
        # On error, clear session and redirect to login
        response = RedirectResponse(url="/admin/login", status_code=302)
        response.delete_cookie("firelens_admin_session", path="/admin")
        return response


@router.get("/metadata")
async def saml_metadata(request: Request):
    """Return SP metadata XML for IdP configuration"""
    saml_handler = request.app.state.saml_handler
    if not saml_handler:
        return HTMLResponse("<!-- SAML not configured -->", status_code=503)

    metadata = saml_handler.get_metadata()
    return HTMLResponse(content=metadata, media_type="application/xml")


# ============================================
# SAML Admin Configuration Page & API
# ============================================


@router.get("", response_class=HTMLResponse)
async def admin_saml_page(request: Request):
    """SAML/SSO configuration page"""
    user = get_admin_user(request)
    if not user:
        return RedirectResponse(url="/admin/login", status_code=302)

    templates = request.app.state.templates
    config_manager = request.app.state.config_manager
    saml_handler = request.app.state.saml_handler

    # Get current SAML config
    saml_config = None
    saml_enabled = False
    if (
        hasattr(config_manager.global_config, "admin")
        and config_manager.global_config.admin
        and config_manager.global_config.admin.saml
    ):
        saml_config = config_manager.global_config.admin.saml
        saml_enabled = saml_handler is not None and saml_handler.is_available()

    # Build metadata URL
    host = request.headers.get("host", "localhost:8080")
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    metadata_url = f"{scheme}://{host}/admin/saml/metadata"

    # Create config object for template
    config_dict = {
        "enabled": saml_config.enabled if saml_config else False,
        "idp_entity_id": saml_config.idp_entity_id if saml_config else "",
        "idp_sso_url": saml_config.idp_sso_url if saml_config else "",
        "idp_slo_url": saml_config.idp_slo_url if saml_config else "",
        "idp_x509_cert": saml_config.idp_x509_cert if saml_config else "",
        "sp_entity_id": saml_config.sp_entity_id if saml_config else "",
        "sp_acs_url": saml_config.sp_acs_url if saml_config else "",
        "sp_slo_url": saml_config.sp_slo_url if saml_config else "",
        "username_attribute": saml_config.username_attribute if saml_config else "email",
        "want_assertions_signed": saml_config.want_assertions_signed if saml_config else True,
        "want_response_signed": saml_config.want_response_signed if saml_config else False,
    }

    # Convert to object-like access for template
    class ConfigObj:
        def __init__(self, d):
            for k, v in d.items():
                setattr(self, k, v)

    return templates.TemplateResponse(
        "admin_saml.html",
        {
            "request": request,
            "user": user,
            "config": ConfigObj(config_dict),
            "saml_enabled": saml_enabled,
            "metadata_url": metadata_url,
            "csrf_token": get_csrf_token(request),
        },
    )


@router.post("/config")
async def admin_api_save_saml_config(request: Request):
    """API: Save SAML configuration"""
    user = get_admin_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    config_manager = request.app.state.config_manager

    try:
        data = await request.json()

        # Validate CSRF token
        csrf_token = data.get("csrf_token") or request.headers.get("X-CSRF-Token")
        if not validate_csrf(request, csrf_token):
            raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")

        # Update config in memory
        from ...config import SAMLConfig

        saml_config = SAMLConfig(
            enabled=data.get("enabled", False),
            idp_entity_id=data.get("idp_entity_id", ""),
            idp_sso_url=data.get("idp_sso_url", ""),
            idp_slo_url=data.get("idp_slo_url", ""),
            idp_x509_cert=data.get("idp_x509_cert", ""),
            sp_entity_id=data.get("sp_entity_id", ""),
            sp_acs_url=data.get("sp_acs_url", ""),
            sp_slo_url=data.get("sp_slo_url", ""),
            username_attribute=data.get("username_attribute", "email"),
            want_assertions_signed=data.get("want_assertions_signed", True),
            want_response_signed=data.get("want_response_signed", False),
        )

        # Update in-memory config
        if (
            not hasattr(config_manager.global_config, "admin")
            or not config_manager.global_config.admin
        ):
            from ...config import AdminConfig

            config_manager.global_config.admin = AdminConfig()

        config_manager.global_config.admin.saml = saml_config

        # Save to config file
        config_manager.save_config()

        # Reinitialize SAML handler and store on app state
        try:
            from ...saml_auth import SAMLAuthHandler

            saml_handler = SAMLAuthHandler(saml_config)
            request.app.state.saml_handler = saml_handler
            if saml_handler.is_available():
                LOG.info("SAML handler reinitialized successfully")
            else:
                LOG.info("SAML config saved but not fully configured")
        except Exception as e:
            LOG.warning(f"Could not reinitialize SAML handler: {e}")

        return JSONResponse({"status": "success", "message": "SAML configuration saved"})

    except Exception as e:
        LOG.exception(f"Error saving SAML config: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/test")
async def admin_api_test_saml_config(request: Request):
    """API: Test SAML configuration validity"""
    user = get_admin_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        data = await request.json()

        # Validate required fields
        errors = []
        if data.get("enabled"):
            if not data.get("idp_entity_id"):
                errors.append("IdP Entity ID is required")
            if not data.get("idp_sso_url"):
                errors.append("IdP SSO URL is required")
            if not data.get("idp_x509_cert"):
                errors.append("IdP X.509 Certificate is required")
            if not data.get("sp_entity_id"):
                errors.append("SP Entity ID is required")
            if not data.get("sp_acs_url"):
                errors.append("SP ACS URL is required")

            # Validate certificate format
            cert = data.get("idp_x509_cert", "")
            if cert and "-----BEGIN CERTIFICATE-----" not in cert:
                errors.append(
                    "IdP Certificate should be in PEM format (-----BEGIN CERTIFICATE-----)"
                )

            # Validate URLs
            for field, name in [("idp_sso_url", "IdP SSO URL"), ("sp_acs_url", "SP ACS URL")]:
                url = data.get(field, "")
                if url:
                    parsed = urllib.parse.urlparse(url)
                    if not parsed.scheme or not parsed.netloc:
                        errors.append(f"{name} must be a valid URL")

        if errors:
            return JSONResponse({"valid": False, "message": "; ".join(errors)}, status_code=400)

        # Try to create a SAML handler with this config to validate
        if data.get("enabled"):
            try:
                from ...config import SAMLConfig
                from ...saml_auth import SAMLAuthHandler

                test_config = SAMLConfig(
                    enabled=True,
                    idp_entity_id=data.get("idp_entity_id", ""),
                    idp_sso_url=data.get("idp_sso_url", ""),
                    idp_slo_url=data.get("idp_slo_url", ""),
                    idp_x509_cert=data.get("idp_x509_cert", ""),
                    sp_entity_id=data.get("sp_entity_id", ""),
                    sp_acs_url=data.get("sp_acs_url", ""),
                    sp_slo_url=data.get("sp_slo_url", ""),
                    username_attribute=data.get("username_attribute", "email"),
                    want_assertions_signed=data.get("want_assertions_signed", True),
                    want_response_signed=data.get("want_response_signed", False),
                )

                handler = SAMLAuthHandler(test_config)
                if handler.is_available():
                    return JSONResponse(
                        {"valid": True, "message": "Configuration is valid and ready to use"}
                    )
                else:
                    return JSONResponse(
                        {
                            "valid": False,
                            "message": "Configuration incomplete - check all required fields",
                        },
                        status_code=400,
                    )

            except Exception as e:
                return JSONResponse(
                    {"valid": False, "message": f"Configuration error: {str(e)}"}, status_code=400
                )

        return JSONResponse({"valid": True, "message": "Configuration valid (SAML disabled)"})

    except Exception as e:
        LOG.exception(f"Error testing SAML config: {e}")
        raise HTTPException(status_code=500, detail=str(e))
