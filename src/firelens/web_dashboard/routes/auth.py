"""
FireLens Monitor - Authentication Routes
Login, logout, and password change routes
"""
import logging
from typing import Optional

from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from ..helpers import (
    get_admin_user, get_csrf_token, validate_csrf,
    is_admin_enabled, validate_password_complexity,
    MIN_PASSWORD_LENGTH,
)

LOG = logging.getLogger("FireLens.web")

router = APIRouter(prefix="/admin")


def _prepare_saml_request(request: Request) -> dict:
    """Prepare request data for SAML handler"""
    return {
        'https': request.url.scheme == 'https',
        'http_host': request.url.hostname,
        'server_port': request.url.port or (443 if request.url.scheme == 'https' else 80),
        'script_name': str(request.url.path),
        'get_data': dict(request.query_params),
        'post_data': {}
    }


@router.get("/login", response_class=HTMLResponse)
async def admin_login_page(request: Request, error: Optional[str] = None):
    """Admin login page"""
    if not is_admin_enabled(request):
        return HTMLResponse("<h1>Admin interface is disabled</h1>", status_code=403)

    # Check if already logged in
    user = get_admin_user(request)
    if user:
        return RedirectResponse(url="/admin", status_code=302)

    templates = request.app.state.templates
    config_manager = request.app.state.config_manager
    saml_handler = request.app.state.saml_handler
    saml_available = saml_handler is not None and saml_handler.is_available()

    # Check if initial password setup is required
    admin_config = config_manager.global_config.admin
    password_reset_required = admin_config.needs_password_reset()

    return templates.TemplateResponse("admin_login.html", {
        "request": request,
        "error": error,
        "saml_enabled": saml_available,
        "password_reset_required": password_reset_required
    })


@router.post("/login")
async def admin_login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    """Process admin login"""
    if not is_admin_enabled(request):
        return HTMLResponse("<h1>Admin interface is disabled</h1>", status_code=403)

    templates = request.app.state.templates
    config_manager = request.app.state.config_manager
    session_manager = request.app.state.session_manager
    saml_handler = request.app.state.saml_handler
    saml_available = saml_handler is not None and saml_handler.is_available()

    # Get admin credentials from config
    admin_config = config_manager.global_config.admin

    # Check if password reset is required (first-time setup)
    if admin_config.needs_password_reset():
        LOG.info("Password reset required - redirecting to setup")
        return templates.TemplateResponse("admin_login.html", {
            "request": request,
            "error": "Initial password setup required. Please set a new password.",
            "password_reset_required": True,
            "saml_enabled": saml_available
        }, status_code=401)

    # Verify credentials using secure password check
    if username == admin_config.username and admin_config.check_password(password):
        # Create session
        token = session_manager.create_session(username)

        # Redirect to admin dashboard with session cookie
        response = RedirectResponse(url="/admin", status_code=302)
        response.set_cookie(
            key="firelens_admin_session",
            value=token,
            httponly=True,
            samesite="strict",
            secure=admin_config.secure_cookies,
            path="/admin",
            max_age=admin_config.session_timeout_minutes * 60
        )
        LOG.info(f"Admin login successful for user: {username}")
        return response
    else:
        LOG.warning(f"Failed admin login attempt for user: {username}")
        return templates.TemplateResponse("admin_login.html", {
            "request": request,
            "error": "Invalid username or password",
            "saml_enabled": saml_available
        }, status_code=401)


@router.post("/logout")
async def admin_logout(request: Request):
    """Admin logout - handles both local and SAML sessions"""
    session_manager = request.app.state.session_manager
    saml_handler = request.app.state.saml_handler

    token = request.cookies.get("firelens_admin_session")

    if token:
        session = session_manager.get_session(token)

        # Check if this was a SAML session that needs SLO
        if (session and session.get('auth_method') == 'saml' and
            saml_handler and saml_handler.is_available()):

            # Prepare request data for SAML SLO
            request_data = _prepare_saml_request(request)
            name_id = session.get('saml_name_id')
            session_index = session.get('saml_session_index')

            if name_id:
                # Initiate SAML logout
                redirect_url = saml_handler.initiate_logout(
                    request_data,
                    name_id=name_id,
                    session_index=session_index,
                    return_to="/admin/login"
                )

                if redirect_url:
                    # Destroy local session first
                    session_manager.destroy_session(token)
                    response = RedirectResponse(url=redirect_url, status_code=302)
                    response.delete_cookie("firelens_admin_session", path="/admin")
                    return response

        # Local session or SAML SLO not configured - just destroy local session
        session_manager.destroy_session(token)

    response = RedirectResponse(url="/admin/login", status_code=302)
    response.delete_cookie("firelens_admin_session", path="/admin")
    return response


# ============================================
# Initial Password Setup Route
# ============================================

@router.post("/setup-password")
async def admin_setup_password(
    request: Request,
    new_password: str = Form(...),
    confirm_password: str = Form(...)
):
    """Initial password setup for first-time login"""
    if not is_admin_enabled(request):
        return HTMLResponse("<h1>Admin interface is disabled</h1>", status_code=403)

    templates = request.app.state.templates
    config_manager = request.app.state.config_manager
    session_manager = request.app.state.session_manager
    admin_config = config_manager.global_config.admin

    # Only allow if password reset is actually required
    if not admin_config.needs_password_reset():
        return RedirectResponse(url="/admin/login", status_code=302)

    # Validate passwords match
    if new_password != confirm_password:
        return templates.TemplateResponse("admin_login.html", {
            "request": request,
            "error": "Passwords do not match",
            "password_reset_required": True,
            "saml_enabled": False
        }, status_code=400)

    # Validate password complexity
    is_valid, message = validate_password_complexity(new_password)
    if not is_valid:
        return templates.TemplateResponse("admin_login.html", {
            "request": request,
            "error": message,
            "password_reset_required": True,
            "saml_enabled": False
        }, status_code=400)

    # Set the new password
    admin_config.set_password(new_password)

    # Save config to persist the password
    config_manager.save_config()

    LOG.info(f"Initial admin password set for user: {admin_config.username}")

    # Auto-login after setting password
    token = session_manager.create_session(admin_config.username)
    response = RedirectResponse(url="/admin", status_code=302)
    response.set_cookie(
        key="firelens_admin_session",
        value=token,
        httponly=True,
        samesite="strict",
        secure=admin_config.secure_cookies,
        path="/admin",
        max_age=admin_config.session_timeout_minutes * 60
    )
    return response


# ============================================
# Password Change Routes
# ============================================

@router.get("/password", response_class=HTMLResponse)
async def admin_password_page(request: Request):
    """Password change page"""
    user = get_admin_user(request)
    if not user:
        return RedirectResponse(url="/admin/login", status_code=302)

    templates = request.app.state.templates
    session_manager = request.app.state.session_manager

    # Get session info to check auth method
    token = request.cookies.get("firelens_admin_session")
    session = session_manager.get_session(token) if token else None
    auth_method = session.get('auth_method', 'local') if session else 'local'

    # SAML users cannot change password (managed by IdP)
    if auth_method == 'saml':
        return templates.TemplateResponse("admin_password.html", {
            "request": request,
            "user": user,
            "auth_method": auth_method,
            "saml_user": True,
            "min_length": MIN_PASSWORD_LENGTH,
            "csrf_token": get_csrf_token(request)
        })

    return templates.TemplateResponse("admin_password.html", {
        "request": request,
        "user": user,
        "auth_method": auth_method,
        "saml_user": False,
        "min_length": MIN_PASSWORD_LENGTH,
        "csrf_token": get_csrf_token(request)
    })


@router.post("/api/password/change")
async def admin_api_change_password(request: Request):
    """API: Change admin password"""
    user = get_admin_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    session_manager = request.app.state.session_manager
    config_manager = request.app.state.config_manager

    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # Validate CSRF token
    csrf_token = data.get('csrf_token') or request.headers.get('X-CSRF-Token')
    if not validate_csrf(request, csrf_token):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")

    # Get session info to check auth method
    token = request.cookies.get("firelens_admin_session")
    session = session_manager.get_session(token) if token else None
    auth_method = session.get('auth_method', 'local') if session else 'local'

    # SAML users cannot change password
    if auth_method == 'saml':
        raise HTTPException(
            status_code=403,
            detail="SAML users cannot change password. Password is managed by your Identity Provider."
        )

    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')
    confirm_password = data.get('confirm_password', '')

    # Validate required fields
    if not current_password:
        raise HTTPException(status_code=400, detail="Current password is required")
    if not new_password:
        raise HTTPException(status_code=400, detail="New password is required")
    if not confirm_password:
        raise HTTPException(status_code=400, detail="Password confirmation is required")

    # Verify current password using secure check
    admin_config = config_manager.global_config.admin
    if not admin_config.check_password(current_password):
        LOG.warning(f"Password change failed for user {user}: incorrect current password")
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    # Check passwords match
    if new_password != confirm_password:
        raise HTTPException(status_code=400, detail="New passwords do not match")

    # Validate password complexity
    is_valid, error_msg = validate_password_complexity(new_password)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error_msg)

    # Update password with hashing
    admin_config.set_password(new_password)
    config_manager.save_config()

    LOG.info(f"Admin user {user} changed their password successfully")

    return JSONResponse({
        "status": "ok",
        "message": "Password changed successfully"
    })
