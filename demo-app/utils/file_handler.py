"""
File Handler Module - Secure file operations with proper validation
Fixed security vulnerabilities and improved code quality
"""

import os
import sqlite3
from pathlib import Path
from typing import List, Optional, Dict, Any


# Configuration - should be loaded from environment variables in production
DEFAULT_BASE_DIR = "/app/uploads"


class FileHandler:
    """
    Handles file operations securely with proper validation and sanitization.
    """
    
    # Allowed file extensions for uploads
    ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.doc', '.docx'}
    
    # Maximum file size (10MB)
    MAX_FILE_SIZE = 10 * 1024 * 1024

    def __init__(self, base_dir: str = DEFAULT_BASE_DIR):
        """
        Initialize file handler with validated base directory.
        
        Args:
            base_dir: Base directory for file operations
        """
        self.base_dir = Path(base_dir).resolve()
        
        # Ensure base directory exists and is a directory
        if not self.base_dir.exists():
            self.base_dir.mkdir(parents=True, exist_ok=True)
        
        if not self.base_dir.is_dir():
            raise ValueError(f"Base directory is not a directory: {base_dir}")

    def _validate_path(self, username: str, filename: str) -> Path:
        """
        Validate and sanitize file path to prevent path traversal attacks.
        
        Args:
            username: Username for user directory
            filename: Filename to access
            
        Returns:
            Validated absolute path
            
        Raises:
            ValueError: If path is invalid or attempts traversal
        """
        # Validate username (alphanumeric, underscore, hyphen only)
        if not username or not isinstance(username, str):
            raise ValueError("Invalid username")
        
        if not all(c.isalnum() or c in ('_', '-') for c in username):
            raise ValueError("Username contains invalid characters")
        
        # Validate filename (no path separators, no hidden files)
        if not filename or not isinstance(filename, str):
            raise ValueError("Invalid filename")
        
        if '/' in filename or '\\' in filename or filename.startswith('.'):
            raise ValueError("Filename contains invalid characters")
        
        # Construct and resolve path
        user_dir = self.base_dir / username
        file_path = (user_dir / filename).resolve()
        
        # Ensure resolved path is within base directory (prevents path traversal)
        if not str(file_path).startswith(str(self.base_dir)):
            raise ValueError("Path traversal attempt detected")
        
        return file_path

    def read_user_file(self, username: str, filename: str) -> str:
        """
        Read a file for a given user with proper validation.
        
        Args:
            username: Username for user directory
            filename: Filename to read
            
        Returns:
            File content as string
            
        Raises:
            ValueError: If path validation fails
            FileNotFoundError: If file doesn't exist
            PermissionError: If file cannot be read
        """
        try:
            file_path = self._validate_path(username, filename)
            
            if not file_path.exists():
                raise FileNotFoundError(f"File not found: {filename}")
            
            if not file_path.is_file():
                raise ValueError(f"Path is not a file: {filename}")
            
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
                
        except (ValueError, FileNotFoundError, PermissionError) as e:
            # Log specific error
            print(f"Error reading file for user {username}: {e}")
            raise
        except Exception as e:
            # Log unexpected error
            print(f"Unexpected error reading file: {e}")
            raise

    def get_user_files(self, username: str, extensions: Optional[List[str]] = None) -> List[str]:
        """
        Get list of files for a user with optional extension filtering.
        
        Args:
            username: Username for user directory
            extensions: Optional list of file extensions to filter (e.g., ['.txt', '.pdf'])
            
        Returns:
            List of filenames
        """
        # Fix mutable default argument issue
        if extensions is None:
            extensions = []
        
        try:
            # Validate username
            if not username or not isinstance(username, str):
                return []
            
            if not all(c.isalnum() or c in ('_', '-') for c in username):
                return []
            
            user_dir = self.base_dir / username
            
            if not user_dir.exists() or not user_dir.is_dir():
                return []
            
            files = []
            for item in user_dir.iterdir():
                if item.is_file():
                    filename = item.name
                    # Filter by extensions if provided
                    if not extensions or any(filename.endswith(ext) for ext in extensions):
                        files.append(filename)
            
            return sorted(files)
            
        except Exception as e:
            print(f"Error listing files for user {username}: {e}")
            return []

    def get_file_metadata(self, db_path: str, filename: str) -> Dict[str, Any]:
        """
        Get file metadata from database using parameterized query.
        
        SECURE: Uses parameterized query to prevent SQL injection
        
        Args:
            db_path: Path to database file
            filename: Filename to query
            
        Returns:
            Dictionary with file metadata
        """
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # SECURE: Parameterized query prevents SQL injection
            query = "SELECT * FROM files WHERE filename = ?"
            cursor.execute(query, (filename,))
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return {
                    "id": result[0],
                    "filename": result[1],
                    "size": result[2]
                }
            return {}
            
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return {}
        except Exception as e:
            print(f"Error getting file metadata: {e}")
            return {}

    def _validate_file_type(self, filename: str) -> bool:
        """
        Validate file type based on extension.
        
        Args:
            filename: Filename to validate
            
        Returns:
            True if file type is allowed
        """
        file_ext = Path(filename).suffix.lower()
        return file_ext in self.ALLOWED_EXTENSIONS

    def process_upload(self, file_data: bytes, destination: str, filename: str) -> bool:
        """
        Process and save an uploaded file with validation.
        
        Args:
            file_data: File content as bytes
            destination: Destination directory (relative to base_dir)
            filename: Original filename
            
        Returns:
            True if upload successful
            
        Raises:
            ValueError: If validation fails
        """
        try:
            # Validate file size
            if len(file_data) > self.MAX_FILE_SIZE:
                raise ValueError(f"File size exceeds maximum allowed size of {self.MAX_FILE_SIZE} bytes")
            
            # Validate file type
            if not self._validate_file_type(filename):
                raise ValueError(f"File type not allowed. Allowed types: {', '.join(self.ALLOWED_EXTENSIONS)}")
            
            # Validate and construct destination path
            if not destination or not isinstance(destination, str):
                raise ValueError("Invalid destination")
            
            # Remove any path traversal attempts from destination
            safe_destination = destination.replace('..', '').replace('/', '').replace('\\', '')
            
            dest_dir = self.base_dir / safe_destination
            dest_dir.mkdir(parents=True, exist_ok=True)
            
            # Sanitize filename
            safe_filename = Path(filename).name
            dest_path = dest_dir / safe_filename
            
            # Ensure destination is within base directory
            if not str(dest_path.resolve()).startswith(str(self.base_dir)):
                raise ValueError("Invalid destination path")
            
            # Write file
            with open(dest_path, 'wb') as f:
                f.write(file_data)
            
            print(f"File uploaded successfully: {safe_filename}")
            return True
            
        except ValueError as e:
            print(f"Validation error during upload: {e}")
            raise
        except OSError as e:
            print(f"File system error during upload: {e}")
            return False
        except Exception as e:
            print(f"Unexpected error during upload: {e}")
            return False

    def delete_user_file(self, username: str, filename: str) -> bool:
        """
        Delete a user's file with proper validation.
        
        Args:
            username: Username for user directory
            filename: Filename to delete
            
        Returns:
            True if file was deleted successfully
        """
        try:
            file_path = self._validate_path(username, filename)
            
            if not file_path.exists():
                print(f"File not found: {filename}")
                return False
            
            if not file_path.is_file():
                print(f"Path is not a file: {filename}")
                return False
            
            file_path.unlink()
            print(f"File deleted successfully: {filename}")
            return True
            
        except (ValueError, PermissionError) as e:
            print(f"Error deleting file: {e}")
            return False
        except Exception as e:
            print(f"Unexpected error deleting file: {e}")
            return False


# Made with Bob