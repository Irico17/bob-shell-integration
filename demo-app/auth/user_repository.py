"""
User Repository - Data access layer for user operations
"""

from typing import Optional, Tuple
from datetime import datetime
from ..database.db_manager import DatabaseManager


class User:
    """
    User domain model.
    
    Represents a user entity with its properties.
    """
    
    def __init__(
        self,
        user_id: int,
        username: str,
        password_hash: str,
        created_at: str
    ):
        self.id = user_id
        self.username = username
        self.password_hash = password_hash
        self.created_at = created_at
    
    def to_dict(self) -> dict:
        """
        Convert user to dictionary (without sensitive data).
        
        Returns:
            Dictionary with safe user data
        """
        return {
            'id': self.id,
            'username': self.username,
            'created_at': self.created_at
        }


class UserRepository:
    """
    Repository for user data access.
    
    Follows Repository Pattern - abstracts data access.
    Uses parameterized queries to prevent SQL injection.
    Follows Dependency Inversion Principle - depends on DatabaseManager abstraction.
    """
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize user repository.
        
        Args:
            db_manager: Database manager instance for dependency injection
        """
        self.db_manager = db_manager
    
    def find_by_username(self, username: str) -> Optional[User]:
        """
        Find user by username using parameterized query.
        
        SECURE: Uses ? placeholder to prevent SQL injection.
        
        Args:
            username: Username to search for
            
        Returns:
            User object if found, None otherwise
        """
        query = "SELECT id, username, password_hash, created_at FROM users WHERE username = ?"
        results = self.db_manager.execute_query(query, (username,))
        
        if not results:
            return None
        
        user_data = results[0]
        return User(
            user_id=user_data[0],
            username=user_data[1],
            password_hash=user_data[2],
            created_at=user_data[3]
        )
    
    def find_by_id(self, user_id: int) -> Optional[User]:
        """
        Find user by ID using parameterized query.
        
        SECURE: Uses ? placeholder to prevent SQL injection.
        
        Args:
            user_id: User ID to search for
            
        Returns:
            User object if found, None otherwise
        """
        query = "SELECT id, username, password_hash, created_at FROM users WHERE id = ?"
        results = self.db_manager.execute_query(query, (user_id,))
        
        if not results:
            return None
        
        user_data = results[0]
        return User(
            user_id=user_data[0],
            username=user_data[1],
            password_hash=user_data[2],
            created_at=user_data[3]
        )
    
    def create(self, username: str, password_hash: str) -> User:
        """
        Create new user using parameterized query.
        
        SECURE: Uses ? placeholders to prevent SQL injection.
        
        Args:
            username: Username for new user
            password_hash: Hashed password
            
        Returns:
            Created User object
            
        Raises:
            Exception: If username already exists
        """
        query = """
            INSERT INTO users (username, password_hash)
            VALUES (?, ?)
        """
        self.db_manager.execute_query(query, (username, password_hash))
        
        # Retrieve the created user
        created_user = self.find_by_username(username)
        if not created_user:
            raise Exception("Failed to create user")
        
        return created_user
    
    def username_exists(self, username: str) -> bool:
        """
        Check if username already exists using parameterized query.
        
        SECURE: Uses ? placeholder to prevent SQL injection.
        
        Args:
            username: Username to check
            
        Returns:
            True if username exists, False otherwise
        """
        query = "SELECT COUNT(*) FROM users WHERE username = ?"
        results = self.db_manager.execute_query(query, (username,))
        return results[0][0] > 0
    
    def record_failed_login(self, username: str) -> None:
        """
        Record a failed login attempt using parameterized query.
        
        SECURE: Uses ? placeholders to prevent SQL injection.
        
        Args:
            username: Username that failed login
        """
        query = """
            INSERT INTO login_attempts (username, failed_attempts, last_failed_attempt)
            VALUES (?, 1, ?)
            ON CONFLICT(username) DO UPDATE SET
                failed_attempts = failed_attempts + 1,
                last_failed_attempt = ?
        """
        now = datetime.now().isoformat()
        self.db_manager.execute_query(query, (username, now, now))
    
    def reset_failed_logins(self, username: str) -> None:
        """
        Reset failed login attempts using parameterized query.
        
        SECURE: Uses ? placeholder to prevent SQL injection.
        
        Args:
            username: Username to reset attempts for
        """
        query = "DELETE FROM login_attempts WHERE username = ?"
        self.db_manager.execute_query(query, (username,))
    
    def get_failed_login_count(self, username: str) -> int:
        """
        Get number of failed login attempts using parameterized query.
        
        SECURE: Uses ? placeholder to prevent SQL injection.
        
        Args:
            username: Username to check
            
        Returns:
            Number of failed attempts
        """
        query = "SELECT failed_attempts FROM login_attempts WHERE username = ?"
        results = self.db_manager.execute_query(query, (username,))
        
        if not results:
            return 0
        
        return results[0][0]


# Made with Bob
