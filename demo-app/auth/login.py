"""
Secure login module.

This module fixes the SQL injection vulnerability in the login flow by:
- validating and sanitizing user input
- using parameterized queries through DatabaseManager
- separating data access from authentication logic
- using secure password hashing and session handling
"""

import hashlib
import hmac
import logging
from dataclasses import dataclass
from typing import Optional, Tuple

from database.db_manager import DatabaseManager
from auth.session import SessionManager
from utils.validators import InputValidator


LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class LoginCredentials:
    """Validated login input DTO."""

    username: str
    password: str


class UserRepository:
    """Repository for user authentication data access."""

    def __init__(self, db_manager: DatabaseManager):
        self._db = db_manager

    def find_by_username(self, username: str) -> Optional[Tuple[int, str, str]]:
        """
        Return user authentication data by username.

        Returns:
            Tuple of (id, username, password_hash) when found, otherwise None.
        """
        query = """
            SELECT id, username, password_hash
            FROM users
            WHERE username = ?
        """
        result = self._db.execute_query(query, (username,))
        return result[0] if result else None


class AuthenticationService:
    """Service layer for secure authentication."""

    def __init__(
        self,
        user_repository: UserRepository,
        session_manager: SessionManager,
        input_validator: InputValidator,
    ):
        self._user_repository = user_repository
        self._session_manager = session_manager
        self._input_validator = input_validator

    def login(self, username: str, password: str) -> Optional[str]:
        """
        Authenticate a user and create a session.

        Returns:
            Session token when authentication succeeds, otherwise None.
        """
        credentials = self._build_credentials(username, password)
        if credentials is None:
            return None

        user_record = self._user_repository.find_by_username(credentials.username)
        if user_record is None:
            LOGGER.warning(
                "Login failed: user not found",
                extra={"username": credentials.username},
            )
            return None

        user_id, stored_username, stored_password_hash = user_record
        if not self._verify_password(credentials.password, stored_password_hash):
            LOGGER.warning(
                "Login failed: invalid password",
                extra={"username": credentials.username},
            )
            return None

        return self._session_manager.create_session(user_id, stored_username)

    def _build_credentials(
        self,
        username: str,
        password: str,
    ) -> Optional[LoginCredentials]:
        """Validate and sanitize login input."""
        sanitized_username = self._input_validator.sanitize_string(username, max_length=20)

        if not self._input_validator.validate_username(sanitized_username):
            LOGGER.warning("Login failed: invalid username format")
            return None

        if not password:
            LOGGER.warning(
                "Login failed: empty password",
                extra={"username": sanitized_username},
            )
            return None

        return LoginCredentials(username=sanitized_username, password=password)

    @staticmethod
    def _verify_password(password: str, stored_password_hash: str) -> bool:
        """Verify password against stored SHA-256 hash."""
        candidate_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        return hmac.compare_digest(candidate_hash, stored_password_hash)


class LoginManager:
    """
    Backward-compatible facade for login operations.

    Keeps the original public entry point while delegating to focused components.
    """

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        session_manager: Optional[SessionManager] = None,
        input_validator: Optional[InputValidator] = None,
        user_repository: Optional[UserRepository] = None,
        authentication_service: Optional[AuthenticationService] = None,
    ):
        self._db_manager = db_manager or DatabaseManager()
        self._session_manager = session_manager or SessionManager(self._db_manager)
        self._input_validator = input_validator or InputValidator()
        self._user_repository = user_repository or UserRepository(self._db_manager)
        self._authentication_service = authentication_service or AuthenticationService(
            user_repository=self._user_repository,
            session_manager=self._session_manager,
            input_validator=self._input_validator,
        )

    def login(self, username: str, password: str) -> Optional[str]:
        """Authenticate user securely and return a session token."""
        return self._authentication_service.login(username, password)


current_user: Optional[str] = None
session_token: Optional[str] = None


def quick_login(username: str, password: str) -> bool:
    """Authenticate a user and update module-level session state."""
    global current_user, session_token

    manager = LoginManager()
    token = manager.login(username, password)
    if token is None:
        return False

    current_user = username
    session_token = token
    return True


def fast_login(username: str, password: str) -> Optional[str]:
    """Backward-compatible helper that returns the session token."""
    global current_user, session_token

    manager = LoginManager()
    token = manager.login(username, password)
    if token is not None:
        current_user = username
        session_token = token

    return token

# Made with Bob