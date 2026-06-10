"""
Authentication Module - Secure login and session management

This module provides secure authentication functionality following OWASP guidelines:
- Parameterized queries to prevent SQL injection
- bcrypt for password hashing
- Secure session token generation
- Input validation
- Rate limiting for failed login attempts
- No sensitive data in logs
"""

import os
import secrets
import bcrypt
from datetime import datetime, timedelta
from typing import Optional, Tuple
from dataclasses import dataclass

from ..database.db_manager import DatabaseManager
from ..utils.validators import InputValidator


# Configuration constants
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15
SESSION_DURATION_HOURS = 24


@dataclass
class AuthResult:
    """Data Transfer Object for authentication results"""
    success: bool
    token: Optional[str] = None
    user_id: Optional[int] = None
    error_message: Optional[str] = None


@dataclass
class User:
    """Data Transfer Object for user data"""
    id: int
    username: str
    password_hash: str
    created_at: str


class PasswordHasher:
    """
    Handles secure password hashing using bcrypt.
    
    Follows OWASP password storage guidelines.
    """
    
    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash a password using bcrypt.
        
        Args:
            password: Plain text password
            
        Returns:
            Hashed password as string
        """
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """
        Verify a password against its hash.
        
        Args:
            password: Plain text password to verify
            password_hash: Stored password hash
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            return bcrypt.checkpw(
                password.encode('utf-8'),
                password_hash.encode('utf-8')
            )
        except Exception:
            return False


class SessionManager:
    """
    Manages user sessions securely.
    
    Uses cryptographically secure tokens and implements session expiration.
    """
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize session manager.
        
        Args:
            db_manager: Database manager instance
        """
        self.db = db_manager
    
    def create_session(self, user_id: int) -> str:
        """
        Create a new session for a user.
        
        Args:
            user_id: User ID to create session for
            
        Returns:
            Secure session token
        """
        # Generate cryptographically secure token
        token = secrets.token_urlsafe(32)
        
        # Calculate expiration time
        expires_at = datetime.now() + timedelta(hours=SESSION_DURATION_HOURS)
        
        # Store session in database using parameterized query
        query = """
            INSERT INTO sessions (token, user_id, expires_at)
            VALUES (?, ?, ?)
        """
        self.db.execute_query(query, (token, user_id, expires_at.isoformat()))
        
        return token
    
    def validate_session(self, token: str) -> Optional[int]:
        """
        Validate a session token and return user ID if valid.
        
        Args:
            token: Session token to validate
            
        Returns:
            User ID if session is valid, None otherwise
        """
        # Use parameterized query to prevent SQL injection
        query = """
            SELECT user_id, expires_at
            FROM sessions
            WHERE token = ?
        """
        results = self.db.execute_query(query, (token,))
        
        if not results:
            return None
        
        user_id, expires_at_str = results[0]
        expires_at = datetime.fromisoformat(expires_at_str)
        
        # Check if session has expired
        if datetime.now() > expires_at:
            self.delete_session(token)
            return None
        
        return user_id
    
    def delete_session(self, token: str) -> None:
        """
        Delete a session (logout).
        
        Args:
            token: Session token to delete
        """
        # Use parameterized query to prevent SQL injection
        query = "DELETE FROM sessions WHERE token = ?"
        self.db.execute_query(query, (token,))
    
    def cleanup_expired_sessions(self) -> None:
        """Remove all expired sessions from database"""
        query = "DELETE FROM sessions WHERE expires_at < ?"
        self.db.execute_query(query, (datetime.now().isoformat(),))


class LoginAttemptTracker:
    """
    Tracks failed login attempts to prevent brute force attacks.
    
    Implements account lockout after multiple failed attempts.
    """
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize login attempt tracker.
        
        Args:
            db_manager: Database manager instance
        """
        self.db = db_manager
    
    def record_failed_attempt(self, username: str) -> None:
        """
        Record a failed login attempt.
        
        Args:
            username: Username that failed to login
        """
        query = """
            INSERT INTO login_attempts (username, failed_attempts, last_failed_attempt)
            VALUES (?, 1, ?)
            ON CONFLICT(username) DO UPDATE SET
                failed_attempts = failed_attempts + 1,
                last_failed_attempt = ?
        """
        now = datetime.now().isoformat()
        self.db.execute_query(query, (username, now, now))
    
    def reset_attempts(self, username: str) -> None:
        """
        Reset failed login attempts after successful login.
        
        Args:
            username: Username to reset attempts for
        """
        query = "DELETE FROM login_attempts WHERE username = ?"
        self.db.execute_query(query, (username,))
    
    def is_locked_out(self, username: str) -> bool:
        """
        Check if an account is locked out due to failed attempts.
        
        Args:
            username: Username to check
            
        Returns:
            True if account is locked out, False otherwise
        """
        query = """
            SELECT failed_attempts, last_failed_attempt
            FROM login_attempts
            WHERE username = ?
        """
        results = self.db.execute_query(query, (username,))
        
        if not results:
            return False
        
        failed_attempts, last_failed_str = results[0]
        
        if failed_attempts < MAX_FAILED_ATTEMPTS:
            return False
        
        # Check if lockout period has expired
        last_failed = datetime.fromisoformat(last_failed_str)
        lockout_expires = last_failed + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
        
        if datetime.now() > lockout_expires:
            # Lockout expired, reset attempts
            self.reset_attempts(username)
            return False
        
        return True


class UserRepository:
    """
    Repository for user data access.
    
    Implements the Repository pattern to abstract database operations.
    """
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize user repository.
        
        Args:
            db_manager: Database manager instance
        """
        self.db = db_manager
    
    def find_by_username(self, username: str) -> Optional[User]:
        """
        Find a user by username.
        
        Args:
            username: Username to search for
            
        Returns:
            User object if found, None otherwise
        """
        # Use parameterized query to prevent SQL injection
        query = """
            SELECT id, username, password_hash, created_at
            FROM users
            WHERE username = ?
        """
        results = self.db.execute_query(query, (username,))
        
        if not results:
            return None
        
        row = results[0]
        return User(
            id=row[0],
            username=row[1],
            password_hash=row[2],
            created_at=row[3]
        )
    
    def create_user(self, username: str, password_hash: str) -> int:
        """
        Create a new user.
        
        Args:
            username: Username for new user
            password_hash: Hashed password
            
        Returns:
            ID of created user
        """
        # Use parameterized query to prevent SQL injection
        query = """
            INSERT INTO users (username, password_hash)
            VALUES (?, ?)
        """
        self.db.execute_query(query, (username, password_hash))
        
        # Get the created user's ID
        user = self.find_by_username(username)
        return user.id if user else 0


class AuthenticationService:
    """
    Main authentication service.
    
    Orchestrates login, logout, and registration operations.
    Follows Single Responsibility Principle by delegating to specialized classes.
    """
    
    def __init__(
        self,
        db_manager: DatabaseManager,
        validator: InputValidator,
        password_hasher: PasswordHasher,
        session_manager: SessionManager,
        attempt_tracker: LoginAttemptTracker,
        user_repository: UserRepository
    ):
        """
        Initialize authentication service with dependencies.
        
        Args:
            db_manager: Database manager
            validator: Input validator
            password_hasher: Password hasher
            session_manager: Session manager
            attempt_tracker: Login attempt tracker
            user_repository: User repository
        """
        self.db = db_manager
        self.validator = validator
        self.password_hasher = password_hasher
        self.session_manager = session_manager
        self.attempt_tracker = attempt_tracker
        self.user_repository = user_repository
    
    def login(self, username: str, password: str) -> AuthResult:
        """
        Authenticate a user and create a session.
        
        Args:
            username: Username to authenticate
            password: Password to verify
            
        Returns:
            AuthResult with success status and token if successful
        """
        # Validate input format
        if not self.validator.validate_username(username):
            return AuthResult(
                success=False,
                error_message="Invalid username format"
            )
        
        # Check if account is locked out
        if self.attempt_tracker.is_locked_out(username):
            return AuthResult(
                success=False,
                error_message=f"Account locked due to multiple failed attempts. Try again in {LOCKOUT_DURATION_MINUTES} minutes."
            )
        
        # Find user in database
        user = self.user_repository.find_by_username(username)
        
        if not user:
            # Record failed attempt (timing attack mitigation: always hash even if user doesn't exist)
            self.password_hasher.verify_password(password, "$2b$12$dummy.hash.to.prevent.timing.attack")
            self.attempt_tracker.record_failed_attempt(username)
            return AuthResult(
                success=False,
                error_message="Invalid username or password"
            )
        
        # Verify password
        if not self.password_hasher.verify_password(password, user.password_hash):
            self.attempt_tracker.record_failed_attempt(username)
            return AuthResult(
                success=False,
                error_message="Invalid username or password"
            )
        
        # Successful login - reset failed attempts
        self.attempt_tracker.reset_attempts(username)
        
        # Create session
        token = self.session_manager.create_session(user.id)
        
        return AuthResult(
            success=True,
            token=token,
            user_id=user.id
        )
    
    def logout(self, token: str) -> bool:
        """
        Logout a user by invalidating their session.
        
        Args:
            token: Session token to invalidate
            
        Returns:
            True if logout successful
        """
        self.session_manager.delete_session(token)
        return True
    
    def register(self, username: str, password: str) -> AuthResult:
        """
        Register a new user.
        
        Args:
            username: Desired username
            password: Desired password
            
        Returns:
            AuthResult with success status
        """
        # Validate username format
        if not self.validator.validate_username(username):
            return AuthResult(
                success=False,
                error_message="Invalid username format. Use 3-20 alphanumeric characters or underscore."
            )
        
        # Validate password strength
        if not self.validator.validate_password_strength(password):
            return AuthResult(
                success=False,
                error_message="Password must be 8-128 characters with uppercase, lowercase, digit, and special character."
            )
        
        # Check if username already exists
        existing_user = self.user_repository.find_by_username(username)
        if existing_user:
            return AuthResult(
                success=False,
                error_message="Username already exists"
            )
        
        # Hash password
        password_hash = self.password_hasher.hash_password(password)
        
        # Create user
        user_id = self.user_repository.create_user(username, password_hash)
        
        return AuthResult(
            success=True,
            user_id=user_id
        )
    
    def validate_session(self, token: str) -> Optional[int]:
        """
        Validate a session token.
        
        Args:
            token: Session token to validate
            
        Returns:
            User ID if session is valid, None otherwise
        """
        return self.session_manager.validate_session(token)


# Factory function for creating authentication service with all dependencies
def create_auth_service(db_path: str = "banking_app.db") -> AuthenticationService:
    """
    Factory function to create an authentication service with all dependencies.
    
    Args:
        db_path: Path to database file
        
    Returns:
        Configured AuthenticationService instance
    """
    db_manager = DatabaseManager(db_path)
    validator = InputValidator()
    password_hasher = PasswordHasher()
    session_manager = SessionManager(db_manager)
    attempt_tracker = LoginAttemptTracker(db_manager)
    user_repository = UserRepository(db_manager)
    
    return AuthenticationService(
        db_manager=db_manager,
        validator=validator,
        password_hasher=password_hasher,
        session_manager=session_manager,
        attempt_tracker=attempt_tracker,
        user_repository=user_repository
    )


# Made with Bob