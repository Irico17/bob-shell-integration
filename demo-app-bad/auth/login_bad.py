"""
BAD PRACTICES LOGIN - FOR DEMO PURPOSES ONLY
This code intentionally contains multiple security vulnerabilities and bad practices
"""

import hashlib
import sqlite3

# SECURITY ISSUE: Hardcoded credentials
DB_PATH = "banking.db"
ADMIN_PASSWORD = "admin123"  # Hardcoded password
SECRET_KEY = "my-secret-key-12345"  # Hardcoded secret

class LoginManager:
    """
    ARCHITECTURE ISSUE: God class - does too many things
    - Database management
    - Authentication
    - Session management
    - Logging
    - Validation
    """
    
    def __init__(self):
        self.conn = sqlite3.connect(DB_PATH)
        self.cursor = self.conn.cursor()
        self.x = 0  # BAD NAMING: unclear variable name
        self.data = {}  # BAD NAMING: too generic
        self.temp = None  # BAD NAMING: meaningless
    
    # SOLID VIOLATION: Single Responsibility - this class does everything
    def login(self, username, password):
        """
        SECURITY ISSUE: SQL Injection vulnerability
        CODE QUALITY: Function too long, no documentation
        """
        # SECURITY ISSUE: No input validation
        # SECURITY ISSUE: SQL injection through string concatenation
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        # SECURITY ISSUE: Logging sensitive data
        print(f"Login attempt: {username} with password: {password}")
        
        result = self.cursor.execute(query)
        user = result.fetchone()
        
        if user:
            # SECURITY ISSUE: Predictable session token
            token = hashlib.md5(username.encode()).hexdigest()
            
            # ARCHITECTURE ISSUE: Tight coupling - direct database access
            self.cursor.execute(f"INSERT INTO sessions VALUES ('{token}', '{username}')")
            self.conn.commit()
            
            # CODE QUALITY: Magic number
            self.x = 1
            
            return token
        else:
            # CODE QUALITY: Magic number
            self.x = 0
            return None
    
    # SOLID VIOLATION: Open/Closed Principle - hard to extend
    def check_user(self, username, password):
        """
        DUPLICATE CODE: Similar to login() method
        SECURITY ISSUE: Same SQL injection vulnerability
        """
        query = f"SELECT * FROM users WHERE username = '{username}'"
        result = self.cursor.execute(query)
        user = result.fetchone()
        
        if user:
            # SECURITY ISSUE: Weak password hashing
            hashed = hashlib.md5(password.encode()).hexdigest()
            if user[2] == hashed:
                return True
        return False
    
    # SOLID VIOLATION: Interface Segregation - forcing unnecessary methods
    def admin_login(self, username, password):
        """
        SECURITY ISSUE: Hardcoded admin check
        CODE QUALITY: Duplicate logic
        """
        if password == ADMIN_PASSWORD:  # Hardcoded password check
            query = f"SELECT * FROM users WHERE username = '{username}' AND role = 'admin'"
            result = self.cursor.execute(query)
            return result.fetchone() is not None
        return False
    
    # CODE QUALITY: Function too long (100+ lines)
    def register_user(self, username, password, email, phone, address, city, country, zipcode):
        """
        ARCHITECTURE ISSUE: Too many parameters
        CODE QUALITY: No validation
        SECURITY ISSUE: SQL injection
        """
        # SECURITY ISSUE: No input validation
        # SECURITY ISSUE: No password strength check
        # SECURITY ISSUE: Storing password in plain text
        
        # CODE QUALITY: Magic numbers everywhere
        if len(username) < 3:
            return False
        
        if len(password) < 6:
            return False
        
        # SECURITY ISSUE: SQL injection
        query = f"""
            INSERT INTO users (username, password, email, phone, address, city, country, zipcode)
            VALUES ('{username}', '{password}', '{email}', '{phone}', '{address}', '{city}', '{country}', '{zipcode}')
        """
        
        try:
            self.cursor.execute(query)
            self.conn.commit()
            
            # SECURITY ISSUE: Logging sensitive data
            print(f"New user registered: {username}, password: {password}, email: {email}")
            
            # CODE QUALITY: Unnecessary complexity
            self.data['last_user'] = username
            self.data['last_email'] = email
            self.data['last_password'] = password  # Storing password in memory
            self.temp = username
            
            return True
        except Exception as e:
            # CODE QUALITY: Catching generic exception
            # SECURITY ISSUE: Exposing internal errors
            print(f"Error: {e}")
            return False
    
    # SOLID VIOLATION: Dependency Inversion - depends on concrete implementation
    def get_user_data(self, username):
        """
        SECURITY ISSUE: SQL injection
        CODE QUALITY: No error handling
        """
        # SECURITY ISSUE: String concatenation in query
        query = "SELECT * FROM users WHERE username = '" + username + "'"
        result = self.cursor.execute(query)
        return result.fetchone()
    
    # CODE QUALITY: Dead code - never used
    def old_login_method(self, u, p):
        pass
    
    # CODE QUALITY: Commented out code
    # def another_old_method(self):
    #     query = "SELECT * FROM users"
    #     return self.cursor.execute(query)
    
    def validate_session(self, token):
        """
        SECURITY ISSUE: SQL injection
        ARCHITECTURE ISSUE: No session expiration
        """
        query = f"SELECT * FROM sessions WHERE token = '{token}'"
        result = self.cursor.execute(query)
        return result.fetchone() is not None
    
    # SOLID VIOLATION: Liskov Substitution - incorrect inheritance usage
    def logout(self, token):
        """
        SECURITY ISSUE: SQL injection
        CODE QUALITY: No verification if session exists
        """
        query = f"DELETE FROM sessions WHERE token = '{token}'"
        self.cursor.execute(query)
        self.conn.commit()
    
    # CODE QUALITY: Method does too many things
    def update_user_and_log_and_notify(self, username, new_email, new_phone):
        """
        SOLID VIOLATION: Single Responsibility
        ARCHITECTURE ISSUE: Method name too long
        CODE QUALITY: Does multiple unrelated things
        """
        # Update user
        query = f"UPDATE users SET email = '{new_email}', phone = '{new_phone}' WHERE username = '{username}'"
        self.cursor.execute(query)
        
        # Log action
        print(f"Updated user {username}")
        
        # Send notification (simulated)
        print(f"Sending email to {new_email}")
        
        # Update internal state
        self.data['last_update'] = username
        
        self.conn.commit()
    
    # CODE QUALITY: Unclear method name
    def do_stuff(self, u, p):
        """
        CODE QUALITY: Meaningless name and parameters
        """
        return self.login(u, p)
    
    # ARCHITECTURE ISSUE: Mixing concerns
    def get_user_and_calculate_score(self, username):
        """
        SOLID VIOLATION: Single Responsibility
        ARCHITECTURE ISSUE: Business logic mixed with data access
        """
        user = self.get_user_data(username)
        if user:
            # CODE QUALITY: Magic numbers
            score = len(user[1]) * 10 + len(user[2]) * 5
            return user, score
        return None, 0
    
    # SECURITY ISSUE: No rate limiting
    # SECURITY ISSUE: No account lockout after failed attempts
    # ARCHITECTURE ISSUE: No separation of concerns
    # CODE QUALITY: No unit tests
    # CODE QUALITY: No type hints
    # CODE QUALITY: No proper documentation

# ARCHITECTURE ISSUE: Global state
current_user = None
session_token = None

# CODE QUALITY: Functions outside class (inconsistent structure)
def quick_login(u, p):
    """
    CODE QUALITY: Inconsistent with class-based approach
    SECURITY ISSUE: Uses global variables
    """
    global current_user, session_token
    manager = LoginManager()
    token = manager.login(u, p)
    if token:
        current_user = u
        session_token = token
        return True
    return False

# CODE QUALITY: Duplicate functionality
def fast_login(username, password):
    """
    DUPLICATE CODE: Same as quick_login
    """
    global current_user
    manager = LoginManager()
    result = manager.login(username, password)
    current_user = username
    return result

# Made with Bob
