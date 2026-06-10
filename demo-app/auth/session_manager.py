"""
Session Manager - Secure session token generation and validation
"""

import secrets
from datetime import datetime, timedelta
from typing import Optional, Tuple
from ..database.db_manager import DatabaseManager


class SessionManager:
    """
    Manages user sessions securely.
    
    Follows Single Responsibility Principle - only handles session management.
    Uses Dependency Injection for database access.
    """
    
    TOKEN_LENGTH = 32
    SESSION_DURATION_HOURS = 24
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize session manager.
        
        Args:
            db_manager: Database manager instance for dependency injection
        """
        self.db_manager = db_manager
    
    def create_session(self, user_id: int) -> str:
        """
        Create a new session for user.
        
        Args:
            user_id: User ID to create session for
            
        Returns:
            Session token
        """
        token = secrets.token_urlsafe(self.TOKEN_LENGTH)
        expires_at = datetime.now() + timedelta(hours=self.SESSION_DURATION_HOURS)
        
        query = """
            INSERT INTO sessions (token, user_id, expires_at)
            VALUES (?, ?, ?)
        """
        self.db_manager.execute_query(
            query,
            (token, user_id, expires_at.isoformat())
        )
        
        return token
    
    def validate_session(self, token: str) -> Tuple[bool, Optional[int]]:
        """
        Validate session token and return user ID if valid.
        
        Args:
            token: Session token to validate
            
        Returns:
            Tuple of (is_valid, user_id)
        """
        if not token:
            return False, None
        
        query = """
            SELECT user_id, expires_at
            FROM sessions
            WHERE token = ?
        """
        results = self.db_manager.execute_query(query, (token,))
        
        if not results:
            return False, None
        
        user_id, expires_at_str = results[0]
        expires_at = datetime.fromisoformat(expires_at_str)
        
        if datetime.now() > expires_at:
            # Session expired, delete it
            self.delete_session(token)
            return False, None
        
        return True, user_id
    
    def delete_session(self, token: str) -> None:
        """
        Delete a session (logout).
        
        Args:
            token: Session token to delete
        """
        query = "DELETE FROM sessions WHERE token = ?"
        self.db_manager.execute_query(query, (token,))
    
    def delete_user_sessions(self, user_id: int) -> None:
        """
        Delete all sessions for a user.
        
        Args:
            user_id: User ID to delete sessions for
        """
        query = "DELETE FROM sessions WHERE user_id = ?"
        self.db_manager.execute_query(query, (user_id,))
    
    def cleanup_expired_sessions(self) -> None:
        """
        Remove all expired sessions from database.
        
        Should be called periodically for maintenance.
        """
        query = "DELETE FROM sessions WHERE expires_at < ?"
        self.db_manager.execute_query(query, (datetime.now().isoformat(),))


# Made with Bob
