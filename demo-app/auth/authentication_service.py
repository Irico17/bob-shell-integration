"""
Authentication Service - Secure user authentication
"""

import logging
from typing import Optional, Tuple
from .user_repository import UserRepository, User
from .password_service import PasswordValidator, PasswordHasher
from .session_manager import SessionManager
from .input_validator import InputValidator


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AuthenticationError(Exception):
    """Custom exception for authentication errors"""
    pass


class AuthenticationService:
    """
    Handles user authentication securely.
    
    Follows SOLID Principles:
    - Single Responsibility: Only handles authentication logic
    - Open/Closed: Extensible through dependency injection
    - Liskov Substitution: Can be replaced with any auth implementation
    - Interface Segregation: Focused interface for authentication
    - Dependency Inversion: Depends on abstractions (repositories, managers)
    
    Security Features:
    - Prevents SQL injection through parameterized queries
    - Secure password hashing
    - Input validation
    - Rate limiting through failed login tracking
    - Secure session token generation
    - No sensitive data logging
    """
    
    MAX_FAILED_ATTEMPTS = 5
    
    def __init__(
        self,
        user_repository: UserRepository,
        session_manager: SessionManager,
        password_hasher: PasswordHasher,
        password_validator: PasswordValidator,
        input_validator: InputValidator
    ):
        """
        Initialize authentication service with dependencies.
        
        Args:
            user_repository: Repository for user data access
            session_manager: Manager for session operations
            password_hasher: Service for password hashing
            password_validator: Service for password validation
            input_validator: Service for input validation
        """
        self.user_repository = user_repository
        self.session_manager = session_manager
        self.password_hasher = password_hasher
        self.password_validator = password_validator
        self.input_validator = input_validator
    
    def login(self, username: str, password: str) -> Tuple[bool, Optional[str], str]:
        """
        Authenticate user and create session.
        
        SECURE: All database queries use parameterized statements.
        SECURE: No sensitive data is logged.
        SECURE: Implements rate limiting.
        
        Args:
            username: Username to authenticate
            password: Password to verify
            
        Returns:
            Tuple of (success, session_token, message)
        """
        try:
            # Validate input
            is_valid, error_msg = self.input_validator.validate_username(username)
            if not is_valid:
                logger.warning(f"Login attempt with invalid username format")
                return False, None, error_msg
            
            if not password:
                logger.warning(f"Login attempt with empty password")
                return False, None, "Password cannot be empty"
            
            # Check for account lockout
            failed_attempts = self.user_repository.get_failed_login_count(username)
            if failed_attempts >= self.MAX_FAILED_ATTEMPTS:
                logger.warning(f"Account locked due to too many failed attempts: {username}")
                return False, None, "Account locked due to too many failed login attempts"
            
            # Find user (uses parameterized query)
            user = self.user_repository.find_by_username(username)
            if not user:
                # Record failed attempt even if user doesn't exist (prevent user enumeration)
                self.user_repository.record_failed_login(username)
                logger.info(f"Failed login attempt for non-existent user")
                return False, None, "Invalid username or password"
            
            # Verify password
            if not self.password_hasher.verify_password(password, user.password_hash):
                self.user_repository.record_failed_login(username)
                logger.info(f"Failed login attempt for user: {username}")
                return False, None, "Invalid username or password"
            
            # Reset failed attempts on successful login
            self.user_repository.reset_failed_logins(username)
            
            # Create session
            session_token = self.session_manager.create_session(user.id)
            
            logger.info(f"Successful login for user: {username}")
            return True, session_token, "Login successful"
            
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            return False, None, "An error occurred during login"
    
    def register(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Register a new user.
        
        SECURE: All database queries use parameterized statements.
        SECURE: Password is validated and securely hashed.
        SECURE: Input is validated before processing.
        
        Args:
            username: Username for new user
            password: Password for new user
            
        Returns:
            Tuple of (success, message)
        """
        try:
            # Validate username
            is_valid, error_msg = self.input_validator.validate_username(username)
            if not is_valid:
                return False, error_msg
            
            # Validate password
            is_valid, error_msg = self.password_validator.validate(password)
            if not is_valid:
                return False, error_msg
            
            # Check if username already exists (uses parameterized query)
            if self.user_repository.username_exists(username):
                logger.info(f"Registration attempt with existing username: {username}")
                return False, "Username already exists"
            
            # Hash password
            password_hash = self.password_hasher.hash_password(password)
            
            # Create user (uses parameterized query)
            user = self.user_repository.create(username, password_hash)
            
            logger.info(f"New user registered: {username}")
            return True, "Registration successful"
            
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            return False, "An error occurred during registration"
    
    def logout(self, session_token: str) -> Tuple[bool, str]:
        """
        Logout user by invalidating session.
        
        SECURE: Uses parameterized query to delete session.
        
        Args:
            session_token: Session token to invalidate
            
        Returns:
            Tuple of (success, message)
        """
        try:
            if not session_token:
                return False, "Invalid session token"
            
            self.session_manager.delete_session(session_token)
            logger.info("User logged out successfully")
            return True, "Logout successful"
            
        except Exception as e:
            logger.error(f"Logout error: {str(e)}")
            return False, "An error occurred during logout"
    
    def validate_session(self, session_token: str) -> Tuple[bool, Optional[User]]:
        """
        Validate session and return user if valid.
        
        SECURE: Uses parameterized query to validate session.
        
        Args:
            session_token: Session token to validate
            
        Returns:
            Tuple of (is_valid, user)
        """
        try:
            is_valid, user_id = self.session_manager.validate_session(session_token)
            
            if not is_valid or user_id is None:
                return False, None
            
            # Get user details (uses parameterized query)
            user = self.user_repository.find_by_id(user_id)
            return True, user
            
        except Exception as e:
            logger.error(f"Session validation error: {str(e)}")
            return False, None
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        """
        Get user by username.
        
        SECURE: Uses parameterized query.
        
        Args:
            username: Username to search for
            
        Returns:
            User object if found, None otherwise
        """
        try:
            # Validate input
            is_valid, _ = self.input_validator.validate_username(username)
            if not is_valid:
                return None
            
            return self.user_repository.find_by_username(username)
            
        except Exception as e:
            logger.error(f"Error getting user: {str(e)}")
            return None


# Made with Bob
