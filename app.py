
# night 9-5-25
import pyrebase
import firebase_admin
from firebase_admin import credentials, auth as admin_auth
from pymongo import MongoClient
from datetime import datetime
import bcrypt
import subprocess
import sys
import os
import re
from typing import Optional, Dict

def initialize_firebase():
    if not firebase_admin._apps:
        cred = credentials.Certificate("serviceAccountKey.json")
        firebase_admin.initialize_app(cred)
    
    firebase_config = {
        "apiKey": "AIzaSyDmRLIlWmrG6luirX8ElFD6XXqlVF05CNk",
        "authDomain": "ai-visualization-web-app.firebaseapp.com",
        "projectId": "ai-visualization-web-app",
        "storageBucket": "ai-visualization-web-app.appspot.com",
        "messagingSenderId": "471686906282",
        "appId": "1:471686906282:web:caf4b441312f11bd0a6bd3",
        "measurementId": "G-NZ8TTXJL1V",
        "databaseURL": ""
    }
    return pyrebase.initialize_app(firebase_config)

# MongoDB setup
mongo_client = MongoClient("mongodb://localhost:27017/")
db = mongo_client["threatguard_ai"]
users_collection = db["users"]

def validate_email(email: str) -> bool:
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password: str) -> bool:
    """Validate password strength"""
    if len(password) < 8:
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(char in '!@#$%^&*()_+' for char in password):
        return False
    return True

def authenticate_user(email: str, password: str) -> Optional[Dict]:
    """Authenticate user with email and password"""
    firebase = initialize_firebase()
    auth_fb = firebase.auth()
    
    try:
        if not validate_email(email):
            raise ValueError("Invalid email format")
            
        # Admin special handling
        if email == "admin@gmail.com" and password == "Admin@123":
            users_collection.update_one(
                {"email": email},
                {"$set": {"last_login": datetime.now()}},
                upsert=True
            )
            # Launch admin panel in a new process
            admin_path = os.path.join(os.path.dirname(__file__), "admin.py")
            subprocess.Popen([sys.executable, admin_path])
            
            return {
                "email": email,
                "is_admin": True,
                "localId": "admin",
                "authenticated": True,
                "username": "Admin"
            }

        # Regular user authentication
        user = auth_fb.sign_in_with_email_and_password(email, password)
        mongo_user = users_collection.find_one({"email": email})
        
        if not mongo_user:
            raise ValueError("User not found in system")
            
        if not bcrypt.checkpw(password.encode(), mongo_user["password_hash"]):
            raise ValueError("Invalid credentials")
        
        users_collection.update_one(
            {"email": email},
            {"$set": {"last_login": datetime.now()}}
        )
        
        return {
            "email": user["email"],
            "localId": user["localId"],
            "is_admin": False,
            "authenticated": True,
            "username": mongo_user.get("username", "User")
        }

    except Exception as e:
        raise Exception(f"Authentication failed: {str(e)}")

def handle_password_reset(email: str, new_password: str, confirm_password: str) -> bool:
    """Handle password reset process"""
    firebase = initialize_firebase()
    auth_fb = firebase.auth()
    
    try:
        if not all([email, new_password, confirm_password]):
            raise ValueError("Please fill all fields")
            
        if not validate_email(email):
            raise ValueError("Invalid email format")
            
        if new_password != confirm_password:
            raise ValueError("Passwords don't match")
            
        if not validate_password(new_password):
            raise ValueError("Password must be at least 8 characters with uppercase, number and special character")
            
        # Verify user exists in MongoDB
        mongo_user = users_collection.find_one({"email": email})
        if not mongo_user:
            raise ValueError("Email not registered")
        
        # Update Firebase password directly (no need to sign in first)
        try:
            # Get the user by email
            user = auth_fb.get_user_by_email(email)
            
            # Update password in Firebase
            auth_fb.update_user(user['localId'], password=new_password)
            
            # Update password in MongoDB
            hashed_pw = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
            users_collection.update_one(
                {"email": email},
                {"$set": {"password_hash": hashed_pw}}
            )
            
            return True
        except Exception as firebase_error:
            # Fallback to sending reset email if direct update fails
            auth_fb.send_password_reset_email(email)
            raise ValueError("Password reset email sent. Please check your inbox.")
        
    except Exception as e:
        raise Exception(f"Password reset failed: {str(e)}")

        
def register_user(email: str, password: str, username: str) -> bool:
    """Register a new user"""
    firebase = initialize_firebase()
    auth_fb = firebase.auth()
    
    try:
        if not validate_email(email):
            raise ValueError("Invalid email format")
            
        if users_collection.find_one({"email": email}):
            raise ValueError("Email already exists")
        
        if not username or len(username) < 3:
            raise ValueError("Username must be at least 3 characters")
        
        if not validate_password(password):
            raise ValueError("Password must be at least 8 characters with uppercase, number and special character")
        
        # Create Firebase user
        user = auth_fb.create_user_with_email_and_password(email, password)
        
        # Store in MongoDB
        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        
        users_collection.insert_one({
            "firebase_uid": user['localId'],
            "email": email,
            "username": username,
            "password_hash": hashed_pw,
            "created_at": datetime.now(),
            "last_login": None,
            "is_admin": False
        })
        
        # Update display name in Firebase
        admin_auth.update_user(user['localId'], display_name=username)
        return True
        
    except Exception as e:
        raise Exception(f"Registration failed: {str(e)}")