"""
User Repository - Data access layer for user operations
Implements Repository pattern with parameterized queries to prevent SQL injection
"""

from typing import Optional, Tuple
from datetime import datetime
import logging

from demo_app.database.db_manager import DatabaseManager


logger = logging.getLogger(__name__)


class User:
    """User domain model"""
    
    def __init__(
        self,
        user_id: int,
        username: str,
        password_hash: str,
        created_at: datetime
    ):
        self.id = user_id
        self.username = username
        self.password_hash = password_hash
        self.created_at = created_at
    
    @classmethod
    def from_db_row(cls, row: Tuple) -> 'User':
        """Create User instance from database row"""
        return cls(
            user_id=row[0],
            username=row[1],
            password_hash=row[2],
            created_at=row[3]
        )


class UserRepository:
    """
    Repository for user data access operations.
    
    All queries use parameterized statements to prevent SQL injection.
    Follows Single Responsibility Principle - only handles data access.
    """
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize repository with database manager.
        
        Args:
            db_manager: DatabaseManager instance for executing queries
        """
        self.db = db_manager
    
    def find_by_username(self, username: str) -> Optional[User]:
        """
        Find user by username using parameterized query.
        
        Args:
            username: Username to search for
            
        Returns:
            User instance if found, None otherwise
        """
        # SECURE: Using parameterized query with ? placeholder
        query = "SELECT id, username, password_hash, created_at FROM users WHERE username = ?"
        
        try:
            results = self.db.execute_query(query, (username,))
            
            if results:
                return User.from_db_row(results[0])
            
            return None
            
        except Exception as e:
            logger.error(f"Error finding user by username: {e}")
            raise
    
    def find_by_id(self, user_id: int) -> Optional[User]:
        """
        Find user by ID using parameterized query.
        
        Args:
            user_id: User ID to search for
            
        Returns:
            User instance if found, None otherwise
        """
        # SECURE: Using parameterized query
        query = "SELECT id, username, password_hash, created_at FROM users WHERE id = ?"
        
        try:
            results = self.db.execute_query(query, (user_id,))
            
            if results:
                return User.from_db_row(results[0])
            
            return None
            
        except Exception as e:
            logger.error(f"Error finding user by ID: {e}")
            raise
    
    def create(self, username: str, password_hash: str) -> User:
        """
        Create new user with parameterized query.
        
        Args:
            username: Username for new user
            password_hash: Hashed password
            
        Returns:
            Created User instance
            
        Raises:
            ValueError: If username already exists
        """
        # SECURE: Using parameterized query
        query = "INSERT INTO users (username, password_hash) VALUES (?, ?)"
        
        try:
            self.db.execute_query(query, (username, password_hash))
            
            # Retrieve the created user
            user = self.find_by_username(username)
            
            if user:
                logger.info(f"User created successfully: {username}")
                return user
            
            raise ValueError("Failed to create user")
            
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            raise
    
    def update_password(self, user_id: int, new_password_hash: str) -> bool:
        """
        Update user password using parameterized query.
        
        Args:
            user_id: ID of user to update
            new_password_hash: New hashed password
            
        Returns:
            True if update successful, False otherwise
        """
        # SECURE: Using parameterized query
        query = "UPDATE users SET password_hash = ? WHERE id = ?"
        
        try:
            self.db.execute_query(query, (new_password_hash, user_id))
            logger.info(f"Password updated for user ID: {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating password: {e}")
            return False
    
    def delete(self, user_id: int) -> bool:
        """
        Delete user using parameterized query.
        
        Args:
            user_id: ID of user to delete
            
        Returns:
            True if deletion successful, False otherwise
        """
        # SECURE: Using parameterized query
        query = "DELETE FROM users WHERE id = ?"
        
        try:
            self.db.execute_query(query, (user_id,))
            logger.info(f"User deleted: {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error deleting user: {e}")
            return False
    
    def record_failed_login(self, username: str) -> None:
        """
        Record failed login attempt using parameterized query.
        
        Args:
            username: Username that failed login
        """
        # SECURE: Using parameterized query with UPSERT pattern
        query = """
            INSERT INTO login_attempts (username, failed_attempts, last_failed_attempt)
            VALUES (?, 1, ?)
            ON CONFLICT(username) DO UPDATE SET
                failed_attempts = failed_attempts + 1,
                last_failed_attempt = ?
        """
        
        now = datetime.now()
        
        try:
            self.db.execute_query(query, (username, now, now))
            
        except Exception as e:
            logger.error(f"Error recording failed login: {e}")
    
    def get_failed_login_count(self, username: str) -> int:
        """
        Get number of failed login attempts using parameterized query.
        
        Args:
            username: Username to check
            
        Returns:
            Number of failed attempts
        """
        # SECURE: Using parameterized query
        query = "SELECT failed_attempts FROM login_attempts WHERE username = ?"
        
        try:
            results = self.db.execute_query(query, (username,))
            
            if results:
                return results[0][0]
            
            return 0
            
        except Exception as e:
            logger.error(f"Error getting failed login count: {e}")
            return 0
    
    def reset_failed_logins(self, username: str) -> None:
        """
        Reset failed login attempts using parameterized query.
        
        Args:
            username: Username to reset
        """
        # SECURE: Using parameterized query
        query = "DELETE FROM login_attempts WHERE username = ?"
        
        try:
            self.db.execute_query(query, (username,))
            
        except Exception as e:
            logger.error(f"Error resetting failed logins: {e}")


# Made with Bob
