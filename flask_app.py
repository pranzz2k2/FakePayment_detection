

from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from datetime import datetime
import os
from dotenv import load_dotenv
import firebase_admin
from firebase_admin import credentials, auth
import bcrypt
import uuid
import hashlib
import magic
import re
import math
import joblib
import numpy as np
import pandas as pd
from werkzeug.utils import secure_filename

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# MongoDB Setupz
mongo_client = MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27017/"))
db = mongo_client["threatguard_ai"]

# Collections
users_collection = db["users"]
scan_history_collection = db["scan_history"]
fraud_transactions_collection = db["fraud_transactions"]
phishing_analysis_collection = db["phishing_analysis"]
login_history_collection = db["login_history"]
user_activities_collection = db["user_activities"]

# File upload configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf', 'docx', 'doc', 'xls', 'xlsx', 'ppt', 'pptx'}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Known malicious indicators
KNOWN_MALICIOUS_HASHES = [
    "a1b2c3d4e5f6...",  # Example ransomware hash
    "7g8h9i0j1k2l3...",  # Example malicious PDF hash
    "4m5n6o7p8q9r0..."   # Example malicious DOCX hash
]

SUSPICIOUS_PATTERNS = [
    r"javascript:", r"eval\(", r"unescape\(", r"shellcode",
    r"powershell", r"cmd\.exe", r"wscript\.shell", r"macro",
    r"\\x[0-9a-f]{2}",  # Hex encoded characters
    r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"  # URLs
]

# Fraud detection model
try:
    fraud_model = joblib.load("models/enhanced_upi_fraud_model.pkl")
    MODEL_LOADED = True
except Exception as e:
    print(f"Error loading fraud model: {str(e)}")
    MODEL_LOADED = False

# Firebase Setup
if not firebase_admin._apps:
    try:
        cred = credentials.Certificate("serviceAccountKey.json")
        firebase_admin.initialize_app(cred)
    except Exception as e:
        print(f"Firebase initialization error: {str(e)}")

# Helper Functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def calculate_entropy(file_path):
    """Calculate the entropy of a file to detect potential encryption/obfuscation"""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            if not data:
                return 0
            byte_counts = [0]*256
            for byte in data:
                byte_counts[byte] += 1
            entropy = 0
            for count in byte_counts:
                if count:
                    p = count / len(data)
                    entropy -= p * math.log2(p)
            return entropy
    except Exception as e:
        print(f"Error calculating entropy: {str(e)}")
        return 0

def get_file_hash(filepath):
    """Calculate SHA256 hash of a file"""
    try:
        with open(filepath, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        print(f"Error calculating file hash: {str(e)}")
        return ""

def scan_for_suspicious_content(filepath):
    """Scan file for suspicious patterns"""
    try:
        with open(filepath, 'rb') as f:
            content = f.read().decode('utf-8', errors='ignore')
            
            findings = []
            for pattern in SUSPICIOUS_PATTERNS:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    findings.append({
                        'pattern': pattern,
                        'count': len(matches),
                        'sample': matches[0] if matches else None
                    })
            return findings
    except Exception as e:
        print(f"Error scanning file content: {str(e)}")
        return [{'error': str(e)}]

def log_activity(user_id, activity_type, metadata=None):
    """Log user activity to MongoDB"""
    try:
        activity = {
            "user_id": user_id,
            "activity_type": activity_type,
            "timestamp": datetime.now(),
            "metadata": metadata or {}
        }
        scan_history_collection.insert_one(activity)
    except Exception as e:
        print(f"Error logging activity: {str(e)}")

def log_user_activity(user_id, action, details=None):
    """Log detailed user activity"""
    try:
        activity = {
            "user_id": user_id,
            "action": action,
            "timestamp": datetime.now(),
            "details": details or {},
            "ip_address": request.remote_addr,
            "user_agent": request.headers.get('User-Agent')
        }
        user_activities_collection.insert_one(activity)
    except Exception as e:
        print(f"Error logging user activity: {str(e)}")

# Auth Endpoints
@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        username = data.get('username')

        if not all([email, password, username]):
            return jsonify({"error": "Missing required fields"}), 400

        # Create Firebase user
        fb_user = auth.create_user(
            email=email,
            password=password,
            display_name=username
        )

        # Store in MongoDB
        user_data = {
            "firebase_uid": fb_user.uid,
            "email": email,
            "username": username,
            "created_at": datetime.now(),
            "last_login": None,
            "is_admin": False
        }
        users_collection.insert_one(user_data)

        log_activity(fb_user.uid, "registration")
        log_user_activity(fb_user.uid, "account_creation")
        return jsonify({"success": True, "uid": fb_user.uid}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')

        if not all([email, password]):
            return jsonify({"error": "Email and password required"}), 400

        # Verify with Firebase
        fb_user = auth.get_user_by_email(email)
        
        # Update MongoDB
        users_collection.update_one(
            {"firebase_uid": fb_user.uid},
            {"$set": {"last_login": datetime.now()}}
        )

        # Log login
        login_history_collection.insert_one({
            "user_id": fb_user.uid,
            "timestamp": datetime.now(),
            "ip_address": request.remote_addr,
            "user_agent": request.headers.get('User-Agent')
        })
        
        log_user_activity(fb_user.uid, "login")

        return jsonify({
            "success": True,
            "user": {
                "uid": fb_user.uid,
                "email": fb_user.email,
                "username": fb_user.display_name
            }
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 401

# Security Endpoints
@app.route('/api/scan/file', methods=['POST'])
def scan_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        user_id = request.form.get('user_id')
        
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed'}), 400
        
        if file:
            filename = secure_filename(file.filename)
            file_id = str(uuid.uuid4())
            file_path = os.path.join(UPLOAD_FOLDER, f"{file_id}_{filename}")
            file.save(file_path)
            
            # File analysis
            file_hash = get_file_hash(file_path)
            entropy = calculate_entropy(file_path)
            suspicious_patterns = scan_for_suspicious_content(file_path)
            
            # Determine threat status
            is_malicious = file_hash in KNOWN_MALICIOUS_HASHES
            threat_score = min(0.95, entropy / 8)  # Normalize entropy to 0-0.95 range
            
            if is_malicious:
                status = "malicious"
                threat_score = 1.0
            elif suspicious_patterns or threat_score > 0.7:
                status = "suspicious"
                threat_score = max(threat_score, 0.7)
            else:
                status = "clean"
                threat_score = 0.1  # Baseline for clean files
                
            # Save to history if user is logged in
            if user_id:
                log_activity(user_id, "file_scan", {
                    "filename": filename,
                    "status": status,
                    "threat_score": threat_score,
                    "hash": file_hash,
                    "entropy": entropy,
                    "suspicious_patterns": suspicious_patterns
                })
                log_user_activity(user_id, "file_scan", {
                    "filename": filename,
                    "status": status,
                    "threat_score": threat_score
                })
            
            # Clean up
            try:
                os.remove(file_path)
            except Exception as e:
                print(f"Error removing file: {str(e)}")
            
            return jsonify({
                "status": status,
                "threat_score": threat_score,
                "hash": file_hash,
                "entropy": entropy,
                "suspicious_patterns": suspicious_patterns,
                "filename": filename,
                "method": "static+heuristic"
            })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/qr', methods=['POST'])
def scan_qr():
    try:
        data = request.json
        url = data.get('url')
        user_id = data.get('user_id')
        
        if not url:
            return jsonify({'error': 'No URL provided'}), 400
        
        # Enhanced fraud detection logic
        suspicious_domains = ["phish", "fake", "login", "verify", "bank", "secure"]
        suspicious_keywords = ["password", "account", "update", "credentials"]
        
        domain = url.lower().split('//')[-1].split('/')[0]
        is_fraud = any(sd in domain for sd in suspicious_domains) or any(sk in url.lower() for sk in suspicious_keywords)
        
        # Calculate confidence score
        confidence = 0.9 if is_fraud else 0.1
        
        # Save to history if user is logged in
        if user_id:
            log_activity(user_id, "qr_scan", {
                "url": url,
                "is_fraud": is_fraud,
                "confidence": confidence,
                "timestamp": datetime.now()
            })
            log_user_activity(user_id, "qr_scan", {
                "url": url,
                "is_fraud": is_fraud
            })
        
        return jsonify({
            "url": url,
            "is_fraud": is_fraud,
            "confidence": confidence,
            "analysis": {
                "suspicious_domains": [sd for sd in suspicious_domains if sd in domain],
                "suspicious_keywords": [sk for sk in suspicious_keywords if sk in url.lower()]
            }
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/fraud/detect', methods=['POST'])
def detect_fraud():
    try:
        data = request.json
        user_id = data.get('user_id')
        
        if not MODEL_LOADED:
            return jsonify({'error': 'Fraud detection model not available'}), 503
        
        # Prepare features for model
        features = {
            'amount': float(data.get('amount', 0)),
            'sender_upi': data.get('sender_upi', ''),
            'receiver_upi': data.get('receiver_upi', ''),
            'location': data.get('location', ''),
            'state': data.get('state', ''),
            'transaction_time': data.get('transaction_time', '')
        }
        
        # Convert to DataFrame for model
        df = pd.DataFrame([features])
        
        # Predict (example - replace with actual model prediction)
        is_fraud = fraud_model.predict(df)[0]
        confidence = fraud_model.predict_proba(df)[0][1]
        
        # Save to history if user is logged in
        if user_id:
            log_activity(user_id, "fraud_check", {
                "is_fraud": bool(is_fraud),
                "confidence": float(confidence),
                "details": features,
                "timestamp": datetime.now()
            })
            log_user_activity(user_id, "fraud_check", {
                "is_fraud": bool(is_fraud),
                "confidence": float(confidence),
                "amount": features['amount']
            })
        
        return jsonify({
            "is_fraud": bool(is_fraud),
            "confidence": float(confidence),
            "features": features
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/phishing/analyze', methods=['POST'])
def analyze_phishing():
    try:
        data = request.json
        url = data.get('url')
        user_id = data.get('user_id')
        
        if not url:
            return jsonify({'error': 'No URL provided'}), 400
        
        # Enhanced phishing detection logic
        phishing_keywords = ["login", "verify", "account", "secure", "update"]
        suspicious_tlds = [".tk", ".gq", ".ml", ".cf", ".ga", ".xyz"]
        
        domain = url.lower().split('//')[-1].split('/')[0]
        tld = "." + domain.split('.')[-1] if '.' in domain else ""
        
        is_phishing = any(pk in url.lower() for pk in phishing_keywords) or tld in suspicious_tlds
        confidence = 0.85 if is_phishing else 0.15
        
        # Save to history if user is logged in
        if user_id:
            log_activity(user_id, "phishing_check", {
                "url": url,
                "is_phishing": is_phishing,
                "confidence": confidence,
                "timestamp": datetime.now()
            })
            log_user_activity(user_id, "phishing_check", {
                "url": url,
                "is_phishing": is_phishing
            })
        
        return jsonify({
            "url": url,
            "is_phishing": is_phishing,
            "confidence": confidence,
            "analysis": {
                "phishing_keywords": [pk for pk in phishing_keywords if pk in url.lower()],
                "suspicious_tld": tld if tld in suspicious_tlds else None
            }
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/history/<user_id>', methods=['GET'])
def get_user_history(user_id):
    try:
        if not user_id:
            return jsonify({'error': 'User ID required'}), 400
        
        # Get all history for user
        file_scans = list(scan_history_collection.find({
            "user_id": user_id,
            "activity_type": "file_scan"
        }, {'_id': 0}).sort("timestamp", -1).limit(50))
        
        qr_scans = list(scan_history_collection.find({
            "user_id": user_id,
            "activity_type": "qr_scan"
        }, {'_id': 0}).sort("timestamp", -1).limit(50))
        
        fraud_checks = list(scan_history_collection.find({
            "user_id": user_id,
            "activity_type": "fraud_check"
        }, {'_id': 0}).sort("timestamp", -1).limit(50))
        
        phishing_checks = list(scan_history_collection.find({
            "user_id": user_id,
            "activity_type": "phishing_check"
        }, {'_id': 0}).sort("timestamp", -1).limit(50))
        
        return jsonify({
            "success": True,
            "file_scans": file_scans,
            "qr_scans": qr_scans,
            "fraud_checks": fraud_checks,
            "phishing_checks": phishing_checks
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/activities/<user_id>', methods=['GET'])
def get_user_activities(user_id):
    try:
        if not user_id:
            return jsonify({'error': 'User ID required'}), 400
            
        activities = list(user_activities_collection.find(
            {"user_id": user_id},
            {'_id': 0}
        ).sort("timestamp", -1).limit(100))
        
        return jsonify({
            "success": True,
            "activities": activities
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "database": "connected" if mongo_client.server_info() else "disconnected",
        "model_loaded": MODEL_LOADED,
        "timestamp": datetime.now().isoformat()
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)