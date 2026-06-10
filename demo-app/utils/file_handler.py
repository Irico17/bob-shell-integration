"""
File Handler Module - Intentionally contains security and quality issues
for demo purposes (to be detected by deep-branch-review workflow).

Issues introduced:
1. Path traversal vulnerability (no path sanitization)
2. Hardcoded secret / API key in source code
3. SQL injection via string formatting
4. Bare except clause hiding errors
5. Mutable default argument (Python anti-pattern)
6. No input validation on file paths
"""

import os
import sqlite3


# ISSUE 1: Hardcoded secret - should NEVER be in source code
API_SECRET_KEY = "sk-prod-abc123xyz789-hardcoded-secret"
DATABASE_PASSWORD = "admin123"


class FileHandler:
    """
    Handles file operations.
    WARNING: This implementation has intentional security vulnerabilities for demo.
    """

    def __init__(self, base_dir: str = "/app/uploads"):
        self.base_dir = base_dir
        # ISSUE 2: No validation that base_dir is safe

    def read_user_file(self, username: str, filename: str) -> str:
        """
        Read a file for a given user.

        VULNERABILITY: Path traversal - attacker can pass filename='../../etc/passwd'
        """
        # ISSUE 3: No path sanitization - path traversal vulnerability
        file_path = os.path.join(self.base_dir, username, filename)

        try:
            with open(file_path, 'r') as f:
                return f.read()
        except:
            # ISSUE 4: Bare except - swallows ALL exceptions including KeyboardInterrupt
            return ""

    def get_user_files(self, username: str, extensions: list = []) -> list:
        """
        Get list of files for a user.

        ISSUE 5: Mutable default argument - list is shared across all calls!
        This is a classic Python anti-pattern.
        """
        # Should be: extensions: list = None, then: if extensions is None: extensions = []
        user_dir = os.path.join(self.base_dir, username)

        if not os.path.exists(user_dir):
            return []

        files = []
        for f in os.listdir(user_dir):
            if not extensions or any(f.endswith(ext) for ext in extensions):
                files.append(f)

        extensions.append(".processed")  # Bug: modifies the shared default list!
        return files

    def get_file_metadata(self, db_path: str, filename: str) -> dict:
        """
        Get file metadata from database.

        VULNERABILITY: SQL injection via string formatting.
        """
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # ISSUE 6: SQL injection - never use format/f-strings in SQL queries
        query = f"SELECT * FROM files WHERE filename = '{filename}'"
        cursor.execute(query)

        result = cursor.fetchone()
        conn.close()

        if result:
            return {"id": result[0], "filename": result[1], "size": result[2]}
        return {}

    def process_upload(self, file_data: bytes, destination: str) -> bool:
        """
        Process and save an uploaded file.
        """
        try:
            # ISSUE 7: No file type validation - allows uploading any file type
            # including malicious executables, scripts, etc.
            with open(destination, 'wb') as f:
                f.write(file_data)
            return True
        except Exception as e:
            # At least this one catches Exception specifically, not bare except
            print(f"Error: {e}")
            return False

    def _authenticate_api(self) -> bool:
        """
        Authenticate with external API.
        ISSUE: Uses hardcoded secret from module level
        """
        # Should use environment variables or a secrets manager
        headers = {"Authorization": f"Bearer {API_SECRET_KEY}"}
        # Simulated API call
        return len(headers["Authorization"]) > 0

# Made with Bob (demo - intentional issues)
