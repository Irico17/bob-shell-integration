"""
Authentication Service - Business logic for user authentication
Implements secure authentication with bcrypt password hashing and parameterized queries
"""

import secrets
import logging
from typing import Optional
import bcrypt

from demo_app.auth.user_repository import UserRepository, User
from demo_app.auth.session_repository import SessionRepository, Session
from demo_app.auth.validators import InputValidator


logger = logging.getLogger(__name__)


class AuthenticationError(Exception):
    """Base exception for authentication errors"""
    pass


class InvalidCredentialsError(AuthenticationError):
    """Raised when credentials are invalid"""
    pass


class AccountLockedError(AuthenticationError):
    """Raised when account is locked due to too many failed attempts"""
    pass


class AuthenticationService:
    """
    Service for user authentication operations.
    
    Follows Single Responsibility Principle - only handles authentication logic.
    Uses Dependency Injection for repositories.
    All database operations use parameterized queries via repositories.
    """
    
    # Maximum failed login attempts before account lockout
    MAX_FAILED_ATTEMPTS = 5
    
    # Minimum password length
    MIN_PASSWORD_LENGTH = 8
    
    def __init__(
        self,
        user_repository: UserRepository,
        session_repository: SessionRepository,
        validator: InputValidator
    ):
        """
        Initialize authentication service with dependencies.
        
        Args:
            user_repository: Repository for user data access
            session_repository: Repository for session data access
            validator: Input validator for sanitization
        """
        self.user_repo = user_repository
        self.session_repo = session_repository
        self.validator = validator
    
    def login(self, username: str, password: str) -> str:
        """
        Authenticate user and create session.
        
        Args:
            username: Username to authenticate
            password: Plain text password
            
        Returns:
            Session token for authenticated user
            
        Raises:
            InvalidCredentialsError: If credentials are invalid
            AccountLockedError: If account is locked
            ValueError: If input validation fails
        """
        # Validate input
        username = self.validator.validate_username(username)
        self.validator.validate_password_format(password)
        
        # Check for account lockout
        failed_attempts = self.user_repo.get_failed_login_count(username)
        if failed_attempts >= self.MAX_FAILED_ATTEMPTS:
            logger.warning(f"Account locked due to too many failed attempts: {username}")
            raise AccountLockedError(
                f"Account locked. Too many failed login attempts."
            )
        
        # Find user by username (uses parameterized query)
        user = self.user_repo.find_by_username(username)
        
        if not user:
            # Record failed attempt even if user doesn't exist (prevent user enumeration)
            self.user_repo.record_failed_login(username)
            logger.warning(f"Login attempt for non-existent user: {username}")
            raise InvalidCredentialsError("Invalid username or password")
        
        # Verify password using bcrypt
        if not self._verify_password(password, user.password_hash):
            # Record failed attempt
            self.user_repo.record_failed_login(username)
            logger.warning(f"Failed login attempt for user: {username}")
            raise InvalidCredentialsError("Invalid username or password")
        
        # Reset failed login attempts on successful login
        self.user_repo.reset_failed_logins(username)
        
        # Generate secure session token
        token = self._generate_secure_token()
        
        # Create session (uses parameterized query)
        self.session_repo.create(token, user.id)
        
        logger.info(f"User logged in successfully: {username}")
        
        return token
    
    def logout(self, token: str) -> bool:
        """
        Logout user by invalidating session.
        
        Args:
            token: Session token to invalidate
            
        Returns:
            True if logout successful, False otherwise
        """
        # Validate token format
        if not token or len(token) < 32:
            return False
        
        # Delete session (uses parameterized query)
        success = self.session_repo.delete(token)
        
        if success:
            logger.info(f"User logged out successfully")
        
        return success
    
    def validate_session(self, token: str) -> Optional[User]:
        """
        Validate session token and return associated user.
        
        Args:
            token: Session token to validate
            
        Returns:
            User instance if session is valid, None otherwise
        """
        # Validate token format
        if not token or len(token) < 32:
            return None
        
        # Find session (uses parameterized query)
        session = self.session_repo.find_by_token(token)
        
        if not session:
            return None
        
        # Get user for this session (uses parameterized query)
        user = self.user_repo.find_by_id(session.user_id)
        
        return user
    
    def register(self, username: str, password: str) -> User:
        """
        Register new user with secure password hashing.
        
        Args:
            username: Username for new user
            password: Plain text password
            
        Returns:
            Created User instance
            
        Raises:
            ValueError: If validation fails or user already exists
        """
        # Validate input
        username = self.validator.validate_username(username)
        self.validator.validate_password_strength(password)
        
        # Check if user already exists (uses parameterized query)
        existing_user = self.user_repo.find_by_username(username)
        if existing_user:
            raise ValueError(f"Username already exists: {username}")
        
        # Hash password using bcrypt
        password_hash = self._hash_password(password)
        
        # Create user (uses parameterized query)
        user = self.user_repo.create(username, password_hash)
        
        logger.info(f"User registered successfully: {username}")
        
        return user
    
    def change_password(
        self,
        user_id: int,
        old_password: str,
        new_password: str
    ) -> bool:
        """
        Change user password after verifying old password.
        
        Args:
            user_id: ID of user changing password
            old_password: Current password for verification
            new_password: New password to set
            
        Returns:
            True if password changed successfully
            
        Raises:
            ValueError: If validation fails
            InvalidCredentialsError: If old password is incorrect
        """
        # Validate new password
        self.validator.validate_password_strength(new_password)
        
        # Get user (uses parameterized query)
        user = self.user_repo.find_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        
        # Verify old password
        if not self._verify_password(old_password, user.password_hash):
            raise InvalidCredentialsError("Current password is incorrect")
        
        # Hash new password
        new_password_hash = self._hash_password(new_password)
        
        # Update password (uses parameterized query)
        success = self.user_repo.update_password(user_id, new_password_hash)
        
        if success:
            # Invalidate all existing sessions for security
            self.session_repo.delete_all_for_user(user_id)
            logger.info(f"Password changed for user ID: {user_id}")
        
        return success
    
    def _hash_password(self, password: str) -> str:
        """
        Hash password using bcrypt.
        
        Args:
            password: Plain text password
            
        Returns:
            Bcrypt hashed password
        """
        # Generate salt and hash password
        salt = bcrypt.gensalt(rounds=12)
        password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
        return password_hash.decode('utf-8')
    
    def _verify_password(self, password: str, password_hash: str) -> bool:
        """
        Verify password against bcrypt hash.
        
        Args:
            password: Plain text password to verify
            password_hash: Bcrypt hash to verify against
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            return bcrypt.checkpw(
                password.encode('utf-8'),
                password_hash.encode('utf-8')
            )
        except Exception as e:
            logger.error(f"Error verifying password: {e}")
            return False
    
    def _generate_secure_token(self) -> str:
        """
        Generate cryptographically secure random token.
        
        Returns:
            URL-safe random token
        """
        # Use secrets module for cryptographically secure random generation
        return secrets.token_urlsafe(32)


# Made with Bob
