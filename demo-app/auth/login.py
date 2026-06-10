"""
Secure Login Module - Refactored with SOLID principles and security best practices

This module provides secure authentication functionality:
- SQL injection prevention through parameterized queries
- Secure password hashing
- Input validation
- Session management
- Rate limiting
- Proper separation of concerns

All security vulnerabilities from the previous version have been fixed.
"""

import os
from typing import Optional, Tuple
from .authentication_service import AuthenticationService
from .user_repository import UserRepository, User
from .password_service import PasswordValidator, PasswordHasher
from .session_manager import SessionManager
from .input_validator import InputValidator
from ..database.db_manager import DatabaseManager


class LoginManager:
    """
    Manages user authentication operations.
    
    SOLID Principles Applied:
    - Single Responsibility: Only coordinates authentication operations
    - Open/Closed: Extensible through dependency injection
    - Liskov Substitution: Can be replaced with any auth manager
    - Interface Segregation: Focused interface
    - Dependency Inversion: Depends on abstractions
    
    Security Features:
    - No SQL injection vulnerabilities (all queries parameterized)
    - No hardcoded credentials
    - Secure password hashing
    - Input validation
    - Rate limiting
    - Secure session tokens
    - No sensitive data logging
    """
    
    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize login manager with all dependencies.
        
        Uses Dependency Injection pattern for testability and flexibility.
        
        Args:
            db_path: Optional path to database file
        """
        # Get database path from environment or use default
        if db_path is None:
            db_path = os.getenv('DB_PATH', 'banking_app.db')
        
        # Initialize dependencies
        self.db_manager = DatabaseManager(db_path)
        self.user_repository = UserRepository(self.db_manager)
        self.session_manager = SessionManager(self.db_manager)
        self.password_hasher = PasswordHasher()
        self.password_validator = PasswordValidator()
        self.input_validator = InputValidator()
        
        # Initialize authentication service with all dependencies
        self.auth_service = AuthenticationService(
            user_repository=self.user_repository,
            session_manager=self.session_manager,
            password_hasher=self.password_hasher,
            password_validator=self.password_validator,
            input_validator=self.input_validator
        )
    
    def login(self, username: str, password: str) -> Tuple[bool, Optional[str], str]:
        """
        Authenticate user and create session.
        
        SECURE: Uses parameterized queries to prevent SQL injection.
        SECURE: Validates input before processing.
        SECURE: Implements rate limiting.
        SECURE: Does not log sensitive data.
        
        Args:
            username: Username to authenticate
            password: Password to verify
            
        Returns:
            Tuple of (success, session_token, message)
            
        Example:
            >>> manager = LoginManager()
            >>> success, token, msg = manager.login("john_doe", "SecurePass123!")
            >>> if success:
            ...     print(f"Login successful. Token: {token}")
        """
        return self.auth_service.login(username, password)
    
    def register(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Register a new user.
        
        SECURE: Uses parameterized queries to prevent SQL injection.
        SECURE: Validates username and password strength.
        SECURE: Hashes password securely before storage.
        
        Args:
            username: Username for new user
            password: Password for new user
            
        Returns:
            Tuple of (success, message)
            
        Example:
            >>> manager = LoginManager()
            >>> success, msg = manager.register("john_doe", "SecurePass123!")
            >>> print(msg)
        """
        return self.auth_service.register(username, password)
    
    def logout(self, session_token: str) -> Tuple[bool, str]:
        """
        Logout user by invalidating session.
        
        SECURE: Uses parameterized query to delete session.
        
        Args:
            session_token: Session token to invalidate
            
        Returns:
            Tuple of (success, message)
            
        Example:
            >>> manager = LoginManager()
            >>> success, msg = manager.logout(token)
            >>> print(msg)
        """
        return self.auth_service.logout(session_token)
    
    def validate_session(self, session_token: str) -> Tuple[bool, Optional[User]]:
        """
        Validate session and return user if valid.
        
        SECURE: Uses parameterized query to validate session.
        
        Args:
            session_token: Session token to validate
            
        Returns:
            Tuple of (is_valid, user)
            
        Example:
            >>> manager = LoginManager()
            >>> is_valid, user = manager.validate_session(token)
            >>> if is_valid:
            ...     print(f"Valid session for user: {user.username}")
        """
        return self.auth_service.validate_session(session_token)
    
    def get_user(self, username: str) -> Optional[User]:
        """
        Get user by username.
        
        SECURE: Uses parameterized query.
        SECURE: Validates input.
        
        Args:
            username: Username to search for
            
        Returns:
            User object if found, None otherwise
            
        Example:
            >>> manager = LoginManager()
            >>> user = manager.get_user("john_doe")
            >>> if user:
            ...     print(f"User found: {user.username}")
        """
        return self.auth_service.get_user_by_username(username)
    
    def cleanup_expired_sessions(self) -> None:
        """
        Remove expired sessions from database.
        
        Should be called periodically for maintenance.
        
        Example:
            >>> manager = LoginManager()
            >>> manager.cleanup_expired_sessions()
        """
        self.session_manager.cleanup_expired_sessions()


# Convenience functions for backward compatibility
# These maintain a simple API while using secure implementations

def create_login_manager(db_path: Optional[str] = None) -> LoginManager:
    """
    Factory function to create a LoginManager instance.
    
    Args:
        db_path: Optional path to database file
        
    Returns:
        Configured LoginManager instance
    """
    return LoginManager(db_path)


def quick_login(username: str, password: str, db_path: Optional[str] = None) -> Tuple[bool, Optional[str], str]:
    """
    Quick login function for simple use cases.
    
    SECURE: Uses the secure LoginManager implementation.
    
    Args:
        username: Username to authenticate
        password: Password to verify
        db_path: Optional path to database file
        
    Returns:
        Tuple of (success, session_token, message)
    """
    manager = LoginManager(db_path)
    return manager.login(username, password)


# Made with Bob