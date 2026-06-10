"""
Password Service - Secure password hashing and validation
"""

import hashlib
import secrets
import re
from typing import Tuple


class PasswordValidator:
    """
    Validates password strength according to security requirements.
    
    Follows Single Responsibility Principle - only handles password validation.
    """
    
    MIN_LENGTH = 8
    MAX_LENGTH = 128
    
    @staticmethod
    def validate(password: str) -> Tuple[bool, str]:
        """
        Validate password strength.
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not password:
            return False, "Password cannot be empty"
        
        if len(password) < PasswordValidator.MIN_LENGTH:
            return False, f"Password must be at least {PasswordValidator.MIN_LENGTH} characters"
        
        if len(password) > PasswordValidator.MAX_LENGTH:
            return False, f"Password must not exceed {PasswordValidator.MAX_LENGTH} characters"
        
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        
        if not re.search(r'\d', password):
            return False, "Password must contain at least one digit"
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"
        
        return True, ""


class PasswordHasher:
    """
    Handles secure password hashing using SHA-256 with salt.
    
    Follows Single Responsibility Principle - only handles password hashing.
    Note: In production, use bcrypt, argon2, or scrypt instead.
    """
    
    SALT_LENGTH = 32
    ITERATIONS = 100000
    
    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash password securely with salt.
        
        Args:
            password: Plain text password
            
        Returns:
            Hashed password with salt (format: salt$hash)
        """
        salt = secrets.token_hex(PasswordHasher.SALT_LENGTH)
        pwd_hash = PasswordHasher._hash_with_salt(password, salt)
        return f"{salt}${pwd_hash}"
    
    @staticmethod
    def verify_password(password: str, hashed_password: str) -> bool:
        """
        Verify password against hash.
        
        Args:
            password: Plain text password to verify
            hashed_password: Stored hash (format: salt$hash)
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            salt, stored_hash = hashed_password.split('$', 1)
            pwd_hash = PasswordHasher._hash_with_salt(password, salt)
            return secrets.compare_digest(pwd_hash, stored_hash)
        except (ValueError, AttributeError):
            return False
    
    @staticmethod
    def _hash_with_salt(password: str, salt: str) -> str:
        """
        Internal method to hash password with given salt.
        
        Args:
            password: Plain text password
            salt: Salt string
            
        Returns:
            Hexadecimal hash string
        """
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            PasswordHasher.ITERATIONS
        ).hex()


# Made with Bob
