"""
Input Validator - Validates and sanitizes user input
"""

import re
from typing import Tuple


class InputValidator:
    """
    Validates user input to prevent injection attacks and ensure data quality.
    
    Follows Single Responsibility Principle - only handles input validation.
    """
    
    USERNAME_MIN_LENGTH = 3
    USERNAME_MAX_LENGTH = 50
    USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')
    
    EMAIL_PATTERN = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )
    
    @staticmethod
    def validate_username(username: str) -> Tuple[bool, str]:
        """
        Validate username format and length.
        
        Args:
            username: Username to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not username:
            return False, "Username cannot be empty"
        
        if len(username) < InputValidator.USERNAME_MIN_LENGTH:
            return False, f"Username must be at least {InputValidator.USERNAME_MIN_LENGTH} characters"
        
        if len(username) > InputValidator.USERNAME_MAX_LENGTH:
            return False, f"Username must not exceed {InputValidator.USERNAME_MAX_LENGTH} characters"
        
        if not InputValidator.USERNAME_PATTERN.match(username):
            return False, "Username can only contain letters, numbers, hyphens, and underscores"
        
        return True, ""
    
    @staticmethod
    def validate_email(email: str) -> Tuple[bool, str]:
        """
        Validate email format.
        
        Args:
            email: Email to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not email:
            return False, "Email cannot be empty"
        
        if not InputValidator.EMAIL_PATTERN.match(email):
            return False, "Invalid email format"
        
        return True, ""
    
    @staticmethod
    def sanitize_string(value: str, max_length: int = 255) -> str:
        """
        Sanitize string input by trimming and limiting length.
        
        Args:
            value: String to sanitize
            max_length: Maximum allowed length
            
        Returns:
            Sanitized string
        """
        if not value:
            return ""
        
        # Trim whitespace
        sanitized = value.strip()
        
        # Limit length
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        return sanitized


# Made with Bob
