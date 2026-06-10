"""
Input Validators - Validation and sanitization for user inputs
Prevents injection attacks and ensures data integrity
"""

import re
import logging
from typing import Optional


logger = logging.getLogger(__name__)


class ValidationError(Exception):
    """Raised when input validation fails"""
    pass


class InputValidator:
    """
    Validates and sanitizes user inputs.
    
    Follows Single Responsibility Principle - only handles validation.
    """
    
    # Username validation rules
    USERNAME_MIN_LENGTH = 3
    USERNAME_MAX_LENGTH = 50
    USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')
    
    # Password validation rules
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_MAX_LENGTH = 128
    
    # Email validation pattern (basic)
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    
    def validate_username(self, username: str) -> str:
        """
        Validate and sanitize username.
        
        Args:
            username: Username to validate
            
        Returns:
            Sanitized username
            
        Raises:
            ValidationError: If username is invalid
        """
        if not username:
            raise ValidationError("Username is required")
        
        # Strip whitespace
        username = username.strip()
        
        # Check length
        if len(username) < self.USERNAME_MIN_LENGTH:
            raise ValidationError(
                f"Username must be at least {self.USERNAME_MIN_LENGTH} characters"
            )
        
        if len(username) > self.USERNAME_MAX_LENGTH:
            raise ValidationError(
                f"Username must not exceed {self.USERNAME_MAX_LENGTH} characters"
            )
        
        # Check pattern (alphanumeric, underscore, hyphen only)
        if not self.USERNAME_PATTERN.match(username):
            raise ValidationError(
                "Username can only contain letters, numbers, underscores, and hyphens"
            )
        
        return username
    
    def validate_password_format(self, password: str) -> None:
        """
        Validate password format (basic checks).
        
        Args:
            password: Password to validate
            
        Raises:
            ValidationError: If password format is invalid
        """
        if not password:
            raise ValidationError("Password is required")
        
        if len(password) < self.PASSWORD_MIN_LENGTH:
            raise ValidationError(
                f"Password must be at least {self.PASSWORD_MIN_LENGTH} characters"
            )
        
        if len(password) > self.PASSWORD_MAX_LENGTH:
            raise ValidationError(
                f"Password must not exceed {self.PASSWORD_MAX_LENGTH} characters"
            )
    
    def validate_password_strength(self, password: str) -> None:
        """
        Validate password strength (comprehensive checks).
        
        Args:
            password: Password to validate
            
        Raises:
            ValidationError: If password is not strong enough
        """
        # First check basic format
        self.validate_password_format(password)
        
        # Check for at least one uppercase letter
        if not re.search(r'[A-Z]', password):
            raise ValidationError(
                "Password must contain at least one uppercase letter"
            )
        
        # Check for at least one lowercase letter
        if not re.search(r'[a-z]', password):
            raise ValidationError(
                "Password must contain at least one lowercase letter"
            )
        
        # Check for at least one digit
        if not re.search(r'\d', password):
            raise ValidationError(
                "Password must contain at least one digit"
            )
        
        # Check for at least one special character
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValidationError(
                "Password must contain at least one special character"
            )
    
    def validate_email(self, email: str) -> str:
        """
        Validate and sanitize email address.
        
        Args:
            email: Email to validate
            
        Returns:
            Sanitized email
            
        Raises:
            ValidationError: If email is invalid
        """
        if not email:
            raise ValidationError("Email is required")
        
        # Strip whitespace and convert to lowercase
        email = email.strip().lower()
        
        # Check pattern
        if not self.EMAIL_PATTERN.match(email):
            raise ValidationError("Invalid email format")
        
        # Check length
        if len(email) > 255:
            raise ValidationError("Email address is too long")
        
        return email
    
    def sanitize_string(self, value: str, max_length: Optional[int] = None) -> str:
        """
        Sanitize a general string input.
        
        Args:
            value: String to sanitize
            max_length: Optional maximum length
            
        Returns:
            Sanitized string
            
        Raises:
            ValidationError: If validation fails
        """
        if not value:
            raise ValidationError("Value is required")
        
        # Strip whitespace
        value = value.strip()
        
        # Check length if specified
        if max_length and len(value) > max_length:
            raise ValidationError(f"Value exceeds maximum length of {max_length}")
        
        return value
    
    def validate_integer(
        self,
        value: any,
        min_value: Optional[int] = None,
        max_value: Optional[int] = None
    ) -> int:
        """
        Validate and convert to integer.
        
        Args:
            value: Value to validate
            min_value: Optional minimum value
            max_value: Optional maximum value
            
        Returns:
            Validated integer
            
        Raises:
            ValidationError: If validation fails
        """
        try:
            int_value = int(value)
        except (ValueError, TypeError):
            raise ValidationError("Value must be an integer")
        
        if min_value is not None and int_value < min_value:
            raise ValidationError(f"Value must be at least {min_value}")
        
        if max_value is not None and int_value > max_value:
            raise ValidationError(f"Value must not exceed {max_value}")
        
        return int_value


# Made with Bob
