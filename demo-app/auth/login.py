"""
SECURE LOGIN IMPLEMENTATION
Fixed SQL injection vulnerabilities and improved security practices
"""

import hashlib
import sqlite3
import secrets
import re
from typing import Optional, Tuple
from abc import ABC, abstractmethod


# Configuration - should be loaded from environment variables in production
DB_PATH = "banking.db"


class PasswordHasher:
    """Handles secure password hashing using SHA-256 (should use bcrypt in production)"""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using SHA-256 with salt"""
        # In production, use bcrypt or argon2
        salt = secrets.token_hex(16)
        hashed = hashlib.sha256((password + salt).encode()).hexdigest()
        return f"{salt}${hashed}"
    
    @staticmethod
    def verify_password(password: str, stored_hash: str) -> bool:
        """Verify password against stored hash"""
        try:
            salt, hashed = stored_hash.split('$')
            new_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            return new_hash == hashed
        except (ValueError, AttributeError):
            return False


class InputValidator:
    """Validates user input to prevent injection attacks and ensure data quality"""
    
    # Username: alphanumeric, underscore, hyphen, 3-50 chars
    USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{3,50}$')
    # Email: basic email validation
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    
    MIN_PASSWORD_LENGTH = 8
    MIN_USERNAME_LENGTH = 3
    MAX_USERNAME_LENGTH = 50
    
    @classmethod
    def validate_username(cls, username: str) -> bool:
        """Validate username format"""
        if not username or not isinstance(username, str):
            return False
        return bool(cls.USERNAME_PATTERN.match(username))
    
    @classmethod
    def validate_password(cls, password: str) -> bool:
        """Validate password strength"""
        if not password or not isinstance(password, str):
            return False
        if len(password) < cls.MIN_PASSWORD_LENGTH:
            return False
        # Should have at least one uppercase, lowercase, digit, and special char
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        return has_upper and has_lower and has_digit
    
    @classmethod
    def validate_email(cls, email: str) -> bool:
        """Validate email format"""
        if not email or not isinstance(email, str):
            return False
        return bool(cls.EMAIL_PATTERN.match(email))


class SessionTokenGenerator:
    """Generates cryptographically secure session tokens"""
    
    @staticmethod
    def generate_token() -> str:
        """Generate a secure random token"""
        return secrets.token_urlsafe(32)


class DatabaseConnection:
    """Manages database connections with proper resource handling"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None
    
    def connect(self) -> sqlite3.Connection:
        """Establish database connection"""
        if not self.conn:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
        return self.conn
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            self.conn = None
    
    def __enter__(self):
        return self.connect()
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class IUserRepository(ABC):
    """Interface for user data access"""
    
    @abstractmethod
    def find_by_username(self, username: str) -> Optional[dict]:
        """Find user by username"""
        pass
    
    @abstractmethod
    def find_by_username_and_role(self, username: str, role: str) -> Optional[dict]:
        """Find user by username and role"""
        pass
    
    @abstractmethod
    def create_user(self, username: str, password_hash: str, email: str, 
                   phone: str, address: str, city: str, country: str, zipcode: str) -> bool:
        """Create new user"""
        pass
    
    @abstractmethod
    def update_user_contact(self, username: str, email: str, phone: str) -> bool:
        """Update user contact information"""
        pass


class UserRepository(IUserRepository):
    """Repository for user data access with parameterized queries"""
    
    def __init__(self, db_connection: DatabaseConnection):
        self.db = db_connection
    
    def find_by_username(self, username: str) -> Optional[dict]:
        """
        Find user by username using parameterized query
        SECURE: Uses ? placeholder to prevent SQL injection
        """
        conn = self.db.connect()
        cursor = conn.cursor()
        
        # SECURE: Parameterized query prevents SQL injection
        query = "SELECT * FROM users WHERE username = ?"
        cursor.execute(query, (username,))
        
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    
    def find_by_username_and_role(self, username: str, role: str) -> Optional[dict]:
        """
        Find user by username and role using parameterized query
        SECURE: Uses ? placeholders to prevent SQL injection
        """
        conn = self.db.connect()
        cursor = conn.cursor()
        
        # SECURE: Parameterized query prevents SQL injection
        query = "SELECT * FROM users WHERE username = ? AND role = ?"
        cursor.execute(query, (username, role))
        
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    
    def create_user(self, username: str, password_hash: str, email: str,
                   phone: str, address: str, city: str, country: str, zipcode: str) -> bool:
        """
        Create new user using parameterized query
        SECURE: Uses ? placeholders to prevent SQL injection
        """
        conn = self.db.connect()
        cursor = conn.cursor()
        
        try:
            # SECURE: Parameterized query prevents SQL injection
            query = """
                INSERT INTO users (username, password, email, phone, address, city, country, zipcode)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """
            cursor.execute(query, (username, password_hash, email, phone, address, city, country, zipcode))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            # User already exists
            return False
        except Exception as e:
            # Log error without exposing details
            print(f"Database error occurred during user creation")
            return False
    
    def update_user_contact(self, username: str, email: str, phone: str) -> bool:
        """
        Update user contact information using parameterized query
        SECURE: Uses ? placeholders to prevent SQL injection
        """
        conn = self.db.connect()
        cursor = conn.cursor()
        
        try:
            # SECURE: Parameterized query prevents SQL injection
            query = "UPDATE users SET email = ?, phone = ? WHERE username = ?"
            cursor.execute(query, (email, phone, username))
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            print(f"Database error occurred during user update")
            return False


class ISessionRepository(ABC):
    """Interface for session data access"""
    
    @abstractmethod
    def create_session(self, token: str, username: str) -> bool:
        """Create new session"""
        pass
    
    @abstractmethod
    def find_session(self, token: str) -> Optional[dict]:
        """Find session by token"""
        pass
    
    @abstractmethod
    def delete_session(self, token: str) -> bool:
        """Delete session"""
        pass


class SessionRepository(ISessionRepository):
    """Repository for session data access with parameterized queries"""
    
    def __init__(self, db_connection: DatabaseConnection):
        self.db = db_connection
    
    def create_session(self, token: str, username: str) -> bool:
        """
        Create new session using parameterized query
        SECURE: Uses ? placeholders to prevent SQL injection
        """
        conn = self.db.connect()
        cursor = conn.cursor()
        
        try:
            # SECURE: Parameterized query prevents SQL injection
            query = "INSERT INTO sessions (token, username) VALUES (?, ?)"
            cursor.execute(query, (token, username))
            conn.commit()
            return True
        except Exception as e:
            print(f"Database error occurred during session creation")
            return False
    
    def find_session(self, token: str) -> Optional[dict]:
        """
        Find session by token using parameterized query
        SECURE: Uses ? placeholder to prevent SQL injection
        """
        conn = self.db.connect()
        cursor = conn.cursor()
        
        # SECURE: Parameterized query prevents SQL injection
        query = "SELECT * FROM sessions WHERE token = ?"
        cursor.execute(query, (token,))
        
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    
    def delete_session(self, token: str) -> bool:
        """
        Delete session using parameterized query
        SECURE: Uses ? placeholder to prevent SQL injection
        """
        conn = self.db.connect()
        cursor = conn.cursor()
        
        try:
            # SECURE: Parameterized query prevents SQL injection
            query = "DELETE FROM sessions WHERE token = ?"
            cursor.execute(query, (token,))
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            print(f"Database error occurred during session deletion")
            return False


class AuthenticationService:
    """
    Service layer for authentication logic
    Follows Single Responsibility Principle - only handles authentication
    """
    
    def __init__(self, user_repo: IUserRepository, session_repo: ISessionRepository,
                 password_hasher: PasswordHasher, token_generator: SessionTokenGenerator):
        self.user_repo = user_repo
        self.session_repo = session_repo
        self.password_hasher = password_hasher
        self.token_generator = token_generator
    
    def login(self, username: str, password: str) -> Optional[str]:
        """
        Authenticate user and create session
        Returns session token on success, None on failure
        """
        # Validate input
        if not InputValidator.validate_username(username):
            print(f"Login attempt with invalid username format")
            return None
        
        if not password:
            print(f"Login attempt with empty password")
            return None
        
        # Find user
        user = self.user_repo.find_by_username(username)
        if not user:
            print(f"Login attempt for non-existent user: {username}")
            return None
        
        # Verify password
        if not self.password_hasher.verify_password(password, user['password']):
            print(f"Failed login attempt for user: {username}")
            return None
        
        # Generate secure session token
        token = self.token_generator.generate_token()
        
        # Create session
        if self.session_repo.create_session(token, username):
            print(f"Successful login for user: {username}")
            return token
        
        return None
    
    def validate_session(self, token: str) -> bool:
        """Validate if session token is valid"""
        if not token:
            return False
        
        session = self.session_repo.find_session(token)
        return session is not None
    
    def logout(self, token: str) -> bool:
        """Logout user by deleting session"""
        if not token:
            return False
        
        return self.session_repo.delete_session(token)
    
    def admin_login(self, username: str, password: str) -> bool:
        """
        Authenticate admin user
        Returns True if user is admin and credentials are valid
        """
        # Validate input
        if not InputValidator.validate_username(username):
            return False
        
        if not password:
            return False
        
        # Find admin user
        user = self.user_repo.find_by_username_and_role(username, 'admin')
        if not user:
            return False
        
        # Verify password
        return self.password_hasher.verify_password(password, user['password'])


class UserService:
    """
    Service layer for user management
    Follows Single Responsibility Principle - only handles user operations
    """
    
    def __init__(self, user_repo: IUserRepository, password_hasher: PasswordHasher):
        self.user_repo = user_repo
        self.password_hasher = password_hasher
    
    def register_user(self, username: str, password: str, email: str,
                     phone: str, address: str, city: str, country: str, zipcode: str) -> bool:
        """
        Register new user with validation
        Returns True on success, False on failure
        """
        # Validate username
        if not InputValidator.validate_username(username):
            print(f"Registration failed: Invalid username format")
            return False
        
        # Validate password
        if not InputValidator.validate_password(password):
            print(f"Registration failed: Password does not meet requirements")
            return False
        
        # Validate email
        if not InputValidator.validate_email(email):
            print(f"Registration failed: Invalid email format")
            return False
        
        # Hash password
        password_hash = self.password_hasher.hash_password(password)
        
        # Create user
        success = self.user_repo.create_user(
            username, password_hash, email, phone, address, city, country, zipcode
        )
        
        if success:
            print(f"User registered successfully: {username}")
        else:
            print(f"Registration failed: User may already exist")
        
        return success
    
    def update_user_contact(self, username: str, email: str, phone: str) -> bool:
        """Update user contact information"""
        # Validate email
        if not InputValidator.validate_email(email):
            print(f"Update failed: Invalid email format")
            return False
        
        return self.user_repo.update_user_contact(username, email, phone)
    
    def get_user(self, username: str) -> Optional[dict]:
        """Get user information (without sensitive data)"""
        user = self.user_repo.find_by_username(username)
        if user:
            # Remove sensitive data before returning
            safe_user = {
                'username': user['username'],
                'email': user['email'],
                'phone': user.get('phone', ''),
            }
            return safe_user
        return None


class LoginManager:
    """
    Facade for authentication and user management
    Provides backward compatibility with legacy code
    """
    
    def __init__(self):
        self.db_connection = DatabaseConnection(DB_PATH)
        self.user_repo = UserRepository(self.db_connection)
        self.session_repo = SessionRepository(self.db_connection)
        self.password_hasher = PasswordHasher()
        self.token_generator = SessionTokenGenerator()
        
        self.auth_service = AuthenticationService(
            self.user_repo, self.session_repo, 
            self.password_hasher, self.token_generator
        )
        self.user_service = UserService(self.user_repo, self.password_hasher)
    
    def login(self, username: str, password: str) -> Optional[str]:
        """Authenticate user and return session token"""
        return self.auth_service.login(username, password)
    
    def validate_session(self, token: str) -> bool:
        """Validate session token"""
        return self.auth_service.validate_session(token)
    
    def logout(self, token: str) -> bool:
        """Logout user"""
        return self.auth_service.logout(token)
    
    def admin_login(self, username: str, password: str) -> bool:
        """Authenticate admin user"""
        return self.auth_service.admin_login(username, password)
    
    def register_user(self, username: str, password: str, email: str,
                     phone: str = '', address: str = '', city: str = '', 
                     country: str = '', zipcode: str = '') -> bool:
        """Register new user"""
        return self.user_service.register_user(
            username, password, email, phone, address, city, country, zipcode
        )
    
    def get_user_data(self, username: str) -> Optional[dict]:
        """Get user data (without sensitive information)"""
        return self.user_service.get_user(username)
    
    def update_user_contact(self, username: str, email: str, phone: str) -> bool:
        """Update user contact information"""
        return self.user_service.update_user_contact(username, email, phone)
    
    def close(self):
        """Close database connection"""
        self.db_connection.close()


# Made with Bob