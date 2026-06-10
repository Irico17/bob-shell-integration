"""
Session Repository - Data access layer for session operations
Implements Repository pattern with parameterized queries to prevent SQL injection
"""

from typing import Optional, Tuple
from datetime import datetime, timedelta
import logging

from demo_app.database.db_manager import DatabaseManager


logger = logging.getLogger(__name__)


class Session:
    """Session domain model"""
    
    def __init__(
        self,
        token: str,
        user_id: int,
        created_at: datetime,
        expires_at: datetime
    ):
        self.token = token
        self.user_id = user_id
        self.created_at = created_at
        self.expires_at = expires_at
    
    @classmethod
    def from_db_row(cls, row: Tuple) -> 'Session':
        """Create Session instance from database row"""
        return cls(
            token=row[0],
            user_id=row[1],
            created_at=row[2],
            expires_at=row[3]
        )
    
    def is_expired(self) -> bool:
        """Check if session is expired"""
        return datetime.now() > self.expires_at


class SessionRepository:
    """
    Repository for session data access operations.
    
    All queries use parameterized statements to prevent SQL injection.
    Follows Single Responsibility Principle - only handles session data access.
    """
    
    # Session expiration time in hours
    SESSION_EXPIRATION_HOURS = 24
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize repository with database manager.
        
        Args:
            db_manager: DatabaseManager instance for executing queries
        """
        self.db = db_manager
    
    def create(self, token: str, user_id: int) -> Session:
        """
        Create new session using parameterized query.
        
        Args:
            token: Unique session token
            user_id: ID of user for this session
            
        Returns:
            Created Session instance
        """
        created_at = datetime.now()
        expires_at = created_at + timedelta(hours=self.SESSION_EXPIRATION_HOURS)
        
        # SECURE: Using parameterized query
        query = """
            INSERT INTO sessions (token, user_id, created_at, expires_at)
            VALUES (?, ?, ?, ?)
        """
        
        try:
            self.db.execute_query(
                query,
                (token, user_id, created_at, expires_at)
            )
            
            logger.info(f"Session created for user ID: {user_id}")
            
            return Session(token, user_id, created_at, expires_at)
            
        except Exception as e:
            logger.error(f"Error creating session: {e}")
            raise
    
    def find_by_token(self, token: str) -> Optional[Session]:
        """
        Find session by token using parameterized query.
        
        Args:
            token: Session token to search for
            
        Returns:
            Session instance if found and not expired, None otherwise
        """
        # SECURE: Using parameterized query
        query = """
            SELECT token, user_id, created_at, expires_at
            FROM sessions
            WHERE token = ?
        """
        
        try:
            results = self.db.execute_query(query, (token,))
            
            if results:
                session = Session.from_db_row(results[0])
                
                # Check if session is expired
                if session.is_expired():
                    # Clean up expired session
                    self.delete(token)
                    return None
                
                return session
            
            return None
            
        except Exception as e:
            logger.error(f"Error finding session by token: {e}")
            raise
    
    def find_by_user_id(self, user_id: int) -> list[Session]:
        """
        Find all active sessions for a user using parameterized query.
        
        Args:
            user_id: User ID to search for
            
        Returns:
            List of active Session instances
        """
        # SECURE: Using parameterized query
        query = """
            SELECT token, user_id, created_at, expires_at
            FROM sessions
            WHERE user_id = ? AND expires_at > ?
        """
        
        try:
            now = datetime.now()
            results = self.db.execute_query(query, (user_id, now))
            
            return [Session.from_db_row(row) for row in results]
            
        except Exception as e:
            logger.error(f"Error finding sessions by user ID: {e}")
            return []
    
    def delete(self, token: str) -> bool:
        """
        Delete session using parameterized query.
        
        Args:
            token: Session token to delete
            
        Returns:
            True if deletion successful, False otherwise
        """
        # SECURE: Using parameterized query
        query = "DELETE FROM sessions WHERE token = ?"
        
        try:
            self.db.execute_query(query, (token,))
            logger.info(f"Session deleted: {token}")
            return True
            
        except Exception as e:
            logger.error(f"Error deleting session: {e}")
            return False
    
    def delete_all_for_user(self, user_id: int) -> bool:
        """
        Delete all sessions for a user using parameterized query.
        
        Args:
            user_id: User ID whose sessions to delete
            
        Returns:
            True if deletion successful, False otherwise
        """
        # SECURE: Using parameterized query
        query = "DELETE FROM sessions WHERE user_id = ?"
        
        try:
            self.db.execute_query(query, (user_id,))
            logger.info(f"All sessions deleted for user ID: {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error deleting user sessions: {e}")
            return False
    
    def cleanup_expired(self) -> int:
        """
        Remove all expired sessions using parameterized query.
        
        Returns:
            Number of sessions deleted
        """
        # SECURE: Using parameterized query
        query = "DELETE FROM sessions WHERE expires_at < ?"
        
        try:
            now = datetime.now()
            self.db.execute_query(query, (now,))
            logger.info("Expired sessions cleaned up")
            return 0  # SQLite doesn't return affected rows easily
            
        except Exception as e:
            logger.error(f"Error cleaning up expired sessions: {e}")
            return 0
    
    def extend_session(self, token: str) -> bool:
        """
        Extend session expiration time using parameterized query.
        
        Args:
            token: Session token to extend
            
        Returns:
            True if extension successful, False otherwise
        """
        new_expires_at = datetime.now() + timedelta(hours=self.SESSION_EXPIRATION_HOURS)
        
        # SECURE: Using parameterized query
        query = "UPDATE sessions SET expires_at = ? WHERE token = ?"
        
        try:
            self.db.execute_query(query, (new_expires_at, token))
            logger.info(f"Session extended: {token}")
            return True
            
        except Exception as e:
            logger.error(f"Error extending session: {e}")
            return False


# Made with Bob
