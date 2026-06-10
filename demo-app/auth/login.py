"""
Secure login service implementation.

This module replaces the vulnerable demo login flow with a small,
maintainable authentication service that uses parameterized queries,
input validation, secure password verification, and session management.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from dataclasses import dataclass
from typing import Optional

from database.db_manager import DatabaseManager
from auth.session import SessionManager
from utils.validators import InputValidator

LOGGER = logging.getLogger(__name__)

PASSWORD_HASH_SEPARATOR = "$"
PBKDF2_ITERATIONS = 100_000
PBKDF2_ALGORITHM = "sha256"


@dataclass(frozen=True)
class LoginRequest:
    """Validated login input transferred between layers."""

    username: str
    password: str


class AuthenticationError(ValueError):
    """Raised when authentication input is invalid."""


class UserRepository:
    """Repository responsible for user persistence queries."""

    def __init__(self, db_manager: DatabaseManager):
        self._db = db_manager

    def find_by_username(self, username: str) -> Optional[tuple]:
        """Return the user row for a username, if it exists."""
        query = """
            SELECT id, username, password_hash
            FROM users
            WHERE username = ?
        """
        result = self._db.execute_query(query, (username,))
        return result[0] if result else None


class PasswordService:
    """Service for password hashing and verification."""

    def verify_password(self, password: str, stored_password_hash: str) -> bool:
        """
        Verify a password against either a legacy plain-text value or a PBKDF2 hash.

        Legacy plain-text support preserves backward compatibility for existing demo
        data while allowing secure verification for migrated records.
        """
        if not stored_password_hash:
            return False

        if PASSWORD_HASH_SEPARATOR not in stored_password_hash:
            return hmac.compare_digest(stored_password_hash, password)

        algorithm, iterations, salt_hex, derived_key_hex = stored_password_hash.split(
            PASSWORD_HASH_SEPARATOR,
            maxsplit=3,
        )
        derived_key = hashlib.pbkdf2_hmac(
            algorithm,
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            int(iterations),
        )
        return hmac.compare_digest(derived_key.hex(), derived_key_hex)


class LoginService:
    """Application service that coordinates secure user login."""

    def __init__(
        self,
        user_repository: UserRepository,
        session_manager: SessionManager,
        input_validator: InputValidator,
        password_service: PasswordService,
    ):
        self._user_repository = user_repository
        self._session_manager = session_manager
        self._input_validator = input_validator
        self._password_service = password_service

    def login(self, username: str, password: str) -> Optional[str]:
        """
        Authenticate a user and create a session token.

        Returns:
            Session token when authentication succeeds, otherwise None.

        Raises:
            AuthenticationError: When the provided input is malformed.
        """
        login_request = self._build_login_request(username, password)
        user_record = self._user_repository.find_by_username(login_request.username)

        if not user_record:
            LOGGER.info("Login failed for unknown user '%s'", login_request.username)
            return None

        user_id, stored_username, stored_password_hash = user_record
        is_authenticated = self._password_service.verify_password(
            login_request.password,
            stored_password_hash,
        )

        if not is_authenticated:
            LOGGER.info("Login failed for user '%s'", login_request.username)
            return None

        LOGGER.info("Login succeeded for user '%s'", login_request.username)
        return self._session_manager.create_session(user_id, stored_username)

    def _build_login_request(self, username: str, password: str) -> LoginRequest:
        """Validate and normalize login input."""
        sanitized_username = self._input_validator.sanitize_string(username, max_length=20)
        sanitized_password = self._input_validator.sanitize_string(password, max_length=128)

        if not self._input_validator.validate_username(sanitized_username):
            raise AuthenticationError("Invalid username format.")

        if not sanitized_password:
            raise AuthenticationError("Password is required.")

        return LoginRequest(username=sanitized_username, password=sanitized_password)


def create_login_service(db_path: str = "banking_app.db") -> LoginService:
    """Factory for the default login service wiring."""
    db_manager = DatabaseManager(db_path=db_path)
    user_repository = UserRepository(db_manager)
    session_manager = SessionManager(db_manager)
    input_validator = InputValidator()
    password_service = PasswordService()

    return LoginService(
        user_repository=user_repository,
        session_manager=session_manager,
        input_validator=input_validator,
        password_service=password_service,
    )


def quick_login(username: str, password: str, db_path: str = "banking_app.db") -> bool:
    """Backward-compatible helper that returns True when login succeeds."""
    login_service = create_login_service(db_path=db_path)
    return login_service.login(username, password) is not None


def fast_login(username: str, password: str, db_path: str = "banking_app.db") -> Optional[str]:
    """Backward-compatible helper that returns the session token on success."""
    login_service = create_login_service(db_path=db_path)
    return login_service.login(username, password)


# Made with Bob