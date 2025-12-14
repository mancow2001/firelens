"""
FireLens Monitor - Session Manager Module
Admin authentication and CSRF protection
"""
import logging
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional

LOG = logging.getLogger("FireLens.web")


class SessionManager:
    """Session management for admin authentication"""

    def __init__(self, timeout_minutes: int = 60, absolute_timeout_hours: int = 8):
        self.sessions: Dict[str, dict] = {}
        self.timeout = timedelta(minutes=timeout_minutes)
        self.absolute_timeout = timedelta(hours=absolute_timeout_hours)

    def create_session(self, username: str, auth_method: str = 'local',
                       saml_session_index: Optional[str] = None,
                       saml_name_id: Optional[str] = None) -> str:
        """Create a new session and return the token"""
        token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        self.sessions[token] = {
            'username': username,
            'created_at': datetime.utcnow(),
            'last_activity': datetime.utcnow(),
            'auth_method': auth_method,
            'saml_session_index': saml_session_index,
            'saml_name_id': saml_name_id,
            'csrf_token': csrf_token
        }
        LOG.info(f"Created admin session for user: {username} (auth: {auth_method})")
        return token

    def validate_session(self, token: str) -> Optional[str]:
        """
        Validate session token and return username if valid.
        Returns None if invalid or expired.
        """
        if not token or token not in self.sessions:
            return None

        session = self.sessions[token]
        now = datetime.utcnow()

        # Check absolute timeout (max session lifetime regardless of activity)
        if now - session['created_at'] > self.absolute_timeout:
            LOG.info(f"Session absolute timeout for user: {session['username']}")
            self.destroy_session(token)
            return None

        # Check idle timeout
        if now - session['last_activity'] > self.timeout:
            LOG.info(f"Session idle timeout for user: {session['username']}")
            self.destroy_session(token)
            return None

        # Update last activity
        session['last_activity'] = now
        return session['username']

    def get_session(self, token: str) -> Optional[dict]:
        """Get full session data for a token"""
        if not token or token not in self.sessions:
            return None
        return self.sessions.get(token)

    def get_csrf_token(self, session_token: str) -> Optional[str]:
        """Get CSRF token for a session"""
        session = self.get_session(session_token)
        if session:
            return session.get('csrf_token')
        return None

    def validate_csrf_token(self, session_token: str, csrf_token: str) -> bool:
        """Validate CSRF token against session"""
        if not session_token or not csrf_token:
            return False
        session = self.get_session(session_token)
        if not session:
            return False
        return secrets.compare_digest(session.get('csrf_token', ''), csrf_token)

    def destroy_session(self, token: str) -> bool:
        """Destroy a session"""
        if token in self.sessions:
            username = self.sessions[token]['username']
            del self.sessions[token]
            LOG.info(f"Destroyed admin session for user: {username}")
            return True
        return False

    def destroy_session_by_index(self, session_index: str) -> bool:
        """Destroy session by SAML session index (for IdP-initiated logout)"""
        for token, session in list(self.sessions.items()):
            if session.get('saml_session_index') == session_index:
                self.destroy_session(token)
                return True
        return False

    def cleanup_expired(self):
        """Remove all expired sessions"""
        now = datetime.utcnow()
        expired = [
            token for token, session in self.sessions.items()
            if now - session['last_activity'] > self.timeout
        ]
        for token in expired:
            self.destroy_session(token)
        if expired:
            LOG.info(f"Cleaned up {len(expired)} expired sessions")
