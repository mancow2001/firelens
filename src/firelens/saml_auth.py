#!/usr/bin/env python3
"""
FireLens Monitor - SAML 2.0 Authentication Module
Provides SAML authentication support for Okta, Azure AD, and other SAML 2.0 IdPs
"""

import logging
from typing import Any, Dict, Optional, Tuple

try:
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    from onelogin.saml2.settings import OneLogin_Saml2_Settings
    from onelogin.saml2.utils import OneLogin_Saml2_Utils

    SAML_AVAILABLE = True
except ImportError:
    SAML_AVAILABLE = False
    OneLogin_Saml2_Auth = None
    OneLogin_Saml2_Settings = None
    OneLogin_Saml2_Utils = None

from .config import SAMLConfig

LOG = logging.getLogger("FireLens.saml")


class SAMLAuthHandler:
    """
    Handles SAML 2.0 authentication flows including:
    - SP-initiated SSO login
    - IdP-initiated SSO login
    - SP-initiated Single Logout (SLO)
    - IdP-initiated Single Logout (SLO)
    - SP Metadata generation
    """

    def __init__(self, config: SAMLConfig):
        """
        Initialize the SAML auth handler with configuration.

        Args:
            config: SAMLConfig dataclass with IdP and SP settings
        """
        self.config = config
        self._validate_config()

    def _validate_config(self) -> None:
        """Validate that required SAML configuration is present."""
        if not SAML_AVAILABLE:
            LOG.warning("python3-saml library not installed. SAML authentication unavailable.")
            return

        if not self.config.enabled:
            return

        required_fields = [
            ("idp_entity_id", "IdP Entity ID"),
            ("idp_sso_url", "IdP SSO URL"),
            ("idp_x509_cert", "IdP X.509 Certificate"),
            ("sp_entity_id", "SP Entity ID"),
            ("sp_acs_url", "SP ACS URL"),
        ]

        missing = []
        for field, name in required_fields:
            if not getattr(self.config, field, None):
                missing.append(name)

        if missing:
            LOG.error(f"SAML configuration incomplete. Missing: {', '.join(missing)}")

    def is_available(self) -> bool:
        """Check if SAML authentication is available and properly configured."""
        if not SAML_AVAILABLE:
            return False
        if not self.config.enabled:
            return False
        # Check minimum required config
        return bool(
            self.config.idp_entity_id
            and self.config.idp_sso_url
            and self.config.idp_x509_cert
            and self.config.sp_entity_id
            and self.config.sp_acs_url
        )

    def _get_saml_settings(self) -> Dict[str, Any]:
        """
        Generate the settings dictionary for python3-saml.

        Returns:
            Settings dictionary compatible with OneLogin_Saml2_Auth
        """
        settings = {
            "strict": True,
            "debug": False,
            "sp": {
                "entityId": self.config.sp_entity_id,
                "assertionConsumerService": {
                    "url": self.config.sp_acs_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                },
                "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            },
            "idp": {
                "entityId": self.config.idp_entity_id,
                "singleSignOnService": {
                    "url": self.config.idp_sso_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                },
                "x509cert": self.config.idp_x509_cert.strip(),
            },
            "security": {
                "nameIdEncrypted": False,
                "authnRequestsSigned": False,
                "logoutRequestSigned": False,
                "logoutResponseSigned": False,
                "signMetadata": False,
                "wantMessagesSigned": self.config.want_response_signed,
                "wantAssertionsSigned": self.config.want_assertions_signed,
                "wantAssertionsEncrypted": False,
                "wantNameIdEncrypted": False,
                "requestedAuthnContext": False,
                "wantAttributeStatement": False,
            },
        }

        # Add SLO configuration if provided
        if self.config.sp_slo_url:
            settings["sp"]["singleLogoutService"] = {
                "url": self.config.sp_slo_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            }

        if self.config.idp_slo_url:
            settings["idp"]["singleLogoutService"] = {
                "url": self.config.idp_slo_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            }

        return settings

    def _prepare_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare request data in the format expected by python3-saml.

        Args:
            request_data: Dictionary with http_host, script_name, get_data, post_data

        Returns:
            Formatted request dictionary
        """
        return {
            "https": "on" if request_data.get("https", True) else "off",
            "http_host": request_data.get("http_host", ""),
            "server_port": request_data.get("server_port", 443),
            "script_name": request_data.get("script_name", ""),
            "get_data": request_data.get("get_data", {}),
            "post_data": request_data.get("post_data", {}),
        }

    def initiate_login(self, request_data: Dict[str, Any], return_to: str = "/admin") -> str:
        """
        Initiate SAML SSO login by generating AuthnRequest.

        Args:
            request_data: HTTP request information
            return_to: URL to redirect to after successful login

        Returns:
            Redirect URL to IdP SSO endpoint

        Raises:
            RuntimeError: If SAML is not available or configured
        """
        if not self.is_available():
            raise RuntimeError("SAML authentication is not available")

        req = self._prepare_request(request_data)
        settings = self._get_saml_settings()

        auth = OneLogin_Saml2_Auth(req, settings)
        redirect_url = auth.login(return_to=return_to)

        LOG.info("SAML login initiated, redirecting to IdP")
        return redirect_url

    def process_response(
        self, request_data: Dict[str, Any]
    ) -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:
        """
        Process SAML Response from IdP (ACS endpoint).

        Args:
            request_data: HTTP request information including POST data with SAMLResponse

        Returns:
            Tuple of (success, username, session_index, error_message)
            - success: True if authentication successful
            - username: Extracted username from assertion (based on username_attribute)
            - session_index: SAML session index for SLO
            - error_message: Error description if authentication failed
        """
        if not self.is_available():
            return False, None, None, "SAML authentication is not available"

        req = self._prepare_request(request_data)
        settings = self._get_saml_settings()

        try:
            auth = OneLogin_Saml2_Auth(req, settings)
            auth.process_response()

            errors = auth.get_errors()
            if errors:
                error_reason = auth.get_last_error_reason()
                LOG.error(f"SAML authentication failed: {errors}, Reason: {error_reason}")
                return False, None, None, f"SAML Error: {error_reason or ', '.join(errors)}"

            if not auth.is_authenticated():
                LOG.warning("SAML response processed but user not authenticated")
                return False, None, None, "Authentication failed"

            # Extract username from attributes
            attributes = auth.get_attributes()
            name_id = auth.get_nameid()
            session_index = auth.get_session_index()

            # Try to get username from configured attribute, fall back to NameID
            username = None
            attr_name = self.config.username_attribute

            if attr_name in attributes and attributes[attr_name]:
                username = attributes[attr_name][0]
            elif name_id:
                username = name_id

            if not username:
                attr_keys = list(attributes.keys())
                LOG.error(f"Could not extract username. Attrs: {attr_keys}, NameID: {name_id}")
                return False, None, None, f"Could not extract username from '{attr_name}'"

            LOG.info(f"SAML authentication successful for user: {username}")
            return True, username, session_index, None

        except Exception as e:
            LOG.exception(f"SAML response processing error: {e}")
            return False, None, None, f"SAML processing error: {str(e)}"

    def initiate_logout(
        self,
        request_data: Dict[str, Any],
        name_id: str,
        session_index: Optional[str] = None,
        return_to: str = "/admin/login",
    ) -> Optional[str]:
        """
        Initiate SAML Single Logout (SLO).

        Args:
            request_data: HTTP request information
            name_id: User's NameID from original assertion
            session_index: SAML session index from original assertion
            return_to: URL to redirect to after logout

        Returns:
            Redirect URL to IdP SLO endpoint, or None if SLO not configured
        """
        if not self.is_available():
            return None

        if not self.config.idp_slo_url:
            LOG.info("IdP SLO URL not configured, skipping SAML logout")
            return None

        req = self._prepare_request(request_data)
        settings = self._get_saml_settings()

        try:
            auth = OneLogin_Saml2_Auth(req, settings)
            redirect_url = auth.logout(
                name_id=name_id, session_index=session_index, return_to=return_to
            )
            LOG.info(f"SAML logout initiated for user: {name_id}")
            return redirect_url
        except Exception as e:
            LOG.exception(f"SAML logout initiation error: {e}")
            return None

    def process_logout(
        self, request_data: Dict[str, Any], delete_session_callback=None
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Process SAML Logout Request or Response (SLO endpoint).

        Args:
            request_data: HTTP request information
            delete_session_callback: Optional callback to delete local session

        Returns:
            Tuple of (success, redirect_url, error_message)
            - success: True if logout processed successfully
            - redirect_url: URL to redirect to (for LogoutResponse) or None
            - error_message: Error description if processing failed
        """
        if not self.is_available():
            return False, None, "SAML authentication is not available"

        req = self._prepare_request(request_data)
        settings = self._get_saml_settings()

        try:
            auth = OneLogin_Saml2_Auth(req, settings)

            # Check if this is a logout request or response
            get_data = request_data.get("get_data", {})
            post_data = request_data.get("post_data", {})

            if "SAMLResponse" in get_data or "SAMLResponse" in post_data:
                # This is a LogoutResponse from IdP
                auth.process_slo()
                errors = auth.get_errors()
                if errors:
                    LOG.error(f"SAML SLO response error: {errors}")
                    return False, None, f"SLO Error: {', '.join(errors)}"

                LOG.info("SAML logout response processed successfully")
                return True, "/admin/login", None

            elif "SAMLRequest" in get_data or "SAMLRequest" in post_data:
                # This is a LogoutRequest from IdP (IdP-initiated logout)
                def callback():
                    if delete_session_callback:
                        delete_session_callback()

                redirect_url = auth.process_slo(
                    delete_session_cb=callback, keep_local_session=False
                )
                errors = auth.get_errors()
                if errors:
                    LOG.error(f"SAML SLO request error: {errors}")
                    return False, None, f"SLO Error: {', '.join(errors)}"

                LOG.info("SAML logout request processed, sending response")
                return True, redirect_url, None

            else:
                return False, None, "Invalid SLO request - no SAMLRequest or SAMLResponse"

        except Exception as e:
            LOG.exception(f"SAML SLO processing error: {e}")
            return False, None, f"SLO processing error: {str(e)}"

    def get_metadata(self) -> str:
        """
        Generate SP metadata XML for IdP configuration.

        Returns:
            SP metadata XML string
        """
        if not SAML_AVAILABLE:
            return "<!-- SAML library not available -->"

        settings = self._get_saml_settings()

        try:
            saml_settings = OneLogin_Saml2_Settings(settings, sp_validation_only=True)
            metadata = saml_settings.get_sp_metadata()
            errors = saml_settings.validate_metadata(metadata)

            if errors:
                LOG.warning(f"Metadata validation warnings: {errors}")

            return metadata
        except Exception as e:
            LOG.exception(f"Error generating SP metadata: {e}")
            return f"<!-- Error generating metadata: {e} -->"
