"""
FireLens Monitor - Shared Helper Functions
Authentication, validation, and utility functions used across routes
"""

from typing import Optional, Tuple

from fastapi import Request

# Password complexity requirements
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128


def validate_password_complexity(password: str) -> Tuple[bool, str]:
    """
    Validate password meets complexity requirements.
    Returns (is_valid, error_message).

    Requirements:
    - Minimum 12 characters
    - Maximum 128 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters long"

    if len(password) > MAX_PASSWORD_LENGTH:
        return False, f"Password must not exceed {MAX_PASSWORD_LENGTH} characters"

    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"

    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"

    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"

    special_chars = set("!@#$%^&*()_+-=[]{}|;':\",./<>?`~")
    if not any(c in special_chars for c in password):
        return (
            False,
            "Password must contain at least one special character (!@#$%^&*()_+-=[]{})",
        )

    return True, ""


def get_admin_user(request: Request) -> Optional[str]:
    """
    Get authenticated admin username from session cookie.
    Returns None if not authenticated.
    """
    session_token = request.cookies.get("firelens_admin_session")
    if session_token:
        return request.app.state.session_manager.validate_session(session_token)
    return None


def get_csrf_token(request: Request) -> Optional[str]:
    """Get CSRF token for current session"""
    session_token = request.cookies.get("firelens_admin_session")
    if session_token:
        return request.app.state.session_manager.get_csrf_token(session_token)
    return None


def validate_csrf(request: Request, csrf_token: Optional[str]) -> bool:
    """Validate CSRF token from form/header against session"""
    session_token = request.cookies.get("firelens_admin_session")
    if not session_token or not csrf_token:
        return False
    return request.app.state.session_manager.validate_csrf_token(session_token, csrf_token)


def is_admin_enabled(request: Request) -> bool:
    """Check if admin interface is enabled"""
    config = request.app.state.config_manager.global_config
    admin_config = getattr(config, "admin", None)
    if admin_config is None:
        return True  # Default to enabled if not configured
    return getattr(admin_config, "enabled", True)


def is_saml_available(request: Request) -> bool:
    """Check if SAML/SSO is available and enabled"""
    saml_handler = request.app.state.saml_handler
    if saml_handler is None:
        return False
    config = request.app.state.config_manager.global_config
    saml_config = getattr(config, "saml", None)
    if saml_config is None:
        return False
    return getattr(saml_config, "enabled", False)
