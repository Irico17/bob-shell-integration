"""
Secure Authentication Module - Fixed SQL Injection Vulnerabilities
This module provides secure authentication using parameterized queries and bcrypt password hashing
"""

import os
import logging
from typing import Optional

from demo_app.database.db_manager import DatabaseManager
from demo_app.auth.user_repository import UserRepository, User
from demo_app.auth.session_repository import SessionRepository
from demo_app.auth.authentication_service import (
    AuthenticationService,
    InvalidCredentialsError,
    AccountLockedError
)
from demo_app.auth.validators import InputValidator, ValidationError


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SecureLoginManager:
    """
    Secure login manager that uses dependency injection and follows SOLID principles.
    
    SECURITY FIXES:
    - All SQL queries use parameterized statements (prevents SQL injection)
    - Passwords hashed with bcrypt (secure password storage)
    - No hardcoded credentials (uses environment variables)
    - Input validation on all user inputs
    - Secure session token generation using secrets module
    - Account lockout after failed attempts
    - No sensitive data in logs
    
    ARCHITECTURE IMPROVEMENTS:
    - Follows Single Responsibility Principle (separated concerns)
    - Uses Dependency Injection (testable and flexible)
    - Repository pattern for data access
    - Service layer for business logic
    - Clear separation of concerns
    """
    
    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize secure login manager with dependency injection.
        
        Args:
            db_path: Optional path to database file. Uses environment variable or default.
        """
        # Get database path from environment or use default
        if db_path is None:
            db_path = os.getenv('DB_PATH', 'banking_app.db')
        
        # Initialize dependencies
        self.db_manager = DatabaseManager(db_path)
        self.user_repo = UserRepository(self.db_manager)
        self.session_repo = SessionRepository(self.db_manager)
        self.validator = InputValidator()
        self.auth_service = AuthenticationService(
            self.user_repo,
            self.session_repo,
            self.validator
        )
    
    def login(self, username: str, password: str) -> Optional[str]:
        """
        Authenticate user with secure parameterized queries.
        
        SECURITY: All database queries use parameterized statements.
        SECURITY: Passwords verified using bcrypt.
        SECURITY: No sensitive data logged.
        
        Args:
            username: Username to authenticate
            password: Plain text password (will be verified against bcrypt hash)
            
        Returns:
            Session token if authentication successful, None otherwise
        """
        try:
            # Authentication service handles all security checks
            # Uses parameterized queries internally
            token = self.auth_service.login(username, password)
            
            # Log successful login (no sensitive data)
            logger.info(f"Successful login for user: {username}")
            
            return token
            
        except ValidationError as e:
            logger.warning(f"Login validation failed: {e}")
            return None
            
        except InvalidCredentialsError as e:
            logger.warning(f"Invalid credentials for user: {username}")
            return None
            
        except AccountLockedError as e:
            logger.warning(f"Account locked for user: {username}")
            return None
            
        except Exception as e:
            logger.error(f"Unexpected error during login: {e}")
            return None
    
    def logout(self, token: str) -> bool:
        """
        Logout user by invalidating session.
        
        SECURITY: Uses parameterized query to delete session.
        
        Args:
            token: Session token to invalidate
            
        Returns:
            True if logout successful, False otherwise
        """
        try:
            return self.auth_service.logout(token)
            
        except Exception as e:
            logger.error(f"Error during logout: {e}")
            return False
    
    def validate_session(self, token: str) -> Optional[User]:
        """
        Validate session token and return user.
        
        SECURITY: Uses parameterized queries to check session.
        
        Args:
            token: Session token to validate
            
        Returns:
            User instance if session valid, None otherwise
        """
        try:
            return self.auth_service.validate_session(token)
            
        except Exception as e:
            logger.error(f"Error validating session: {e}")
            return None
    
    def register(self, username: str, password: str) -> Optional[User]:
        """
        Register new user with secure password hashing.
        
        SECURITY: Password hashed with bcrypt before storage.
        SECURITY: Input validation prevents injection attacks.
        SECURITY: Uses parameterized queries for database operations.
        
        Args:
            username: Username for new user
            password: Plain text password (will be hashed with bcrypt)
            
        Returns:
            User instance if registration successful, None otherwise
        """
        try:
            user = self.auth_service.register(username, password)
            
            # Log registration (no sensitive data)
            logger.info(f"New user registered: {username}")
            
            return user
            
        except ValidationError as e:
            logger.warning(f"Registration validation failed: {e}")
            return None
            
        except ValueError as e:
            logger.warning(f"Registration failed: {e}")
            return None
            
        except Exception as e:
            logger.error(f"Unexpected error during registration: {e}")
            return None
    
    def change_password(
        self,
        user_id: int,
        old_password: str,
        new_password: str
    ) -> bool:
        """
        Change user password securely.
        
        SECURITY: Verifies old password before allowing change.
        SECURITY: New password hashed with bcrypt.
        SECURITY: Invalidates all existing sessions after password change.
        
        Args:
            user_id: ID of user changing password
            old_password: Current password for verification
            new_password: New password to set
            
        Returns:
            True if password changed successfully, False otherwise
        """
        try:
            return self.auth_service.change_password(
                user_id,
                old_password,
                new_password
            )
            
        except ValidationError as e:
            logger.warning(f"Password change validation failed: {e}")
            return False
            
        except InvalidCredentialsError as e:
            logger.warning(f"Password change failed - invalid credentials")
            return False
            
        except Exception as e:
            logger.error(f"Error changing password: {e}")
            return False


# Convenience function for backward compatibility
def create_login_manager(db_path: Optional[str] = None) -> SecureLoginManager:
    """
    Factory function to create SecureLoginManager instance.
    
    Args:
        db_path: Optional path to database file
        
    Returns:
        SecureLoginManager instance
    """
    return SecureLoginManager(db_path)


# Example usage demonstrating secure authentication
if __name__ == "__main__":
    # Create secure login manager
    login_manager = create_login_manager()
    
    # Example: Register a new user
    print("Registering new user...")
    user = login_manager.register("testuser", "SecurePass123!")
    
    if user:
        print(f"User registered successfully: {user.username}")
        
        # Example: Login
        print("\nLogging in...")
        token = login_manager.login("testuser", "SecurePass123!")
        
        if token:
            print(f"Login successful! Session token: {token[:16]}...")
            
            # Example: Validate session
            print("\nValidating session...")
            validated_user = login_manager.validate_session(token)
            
            if validated_user:
                print(f"Session valid for user: {validated_user.username}")
            
            # Example: Logout
            print("\nLogging out...")
            if login_manager.logout(token):
                print("Logout successful!")
        else:
            print("Login failed!")
    else:
        print("Registration failed!")


# Made with Bob