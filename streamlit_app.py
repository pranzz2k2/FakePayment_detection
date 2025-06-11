# 8-05-2025
import streamlit as st
import requests
import uuid
import os
import numpy as np
import joblib
from streamlit.components.v1 import html
from PIL import Image
import cv2
from pyzbar.pyzbar import decode
import av
from streamlit_webrtc import webrtc_streamer, VideoTransformerBase
import pandas as pd
import re
import time
import random
import google.generativeai as genai
import json
from dotenv import load_dotenv
from streamlit_lottie import st_lottie
from datetime import datetime
from utils.analyzer import analyze_file
from app import authenticate_user, register_user, handle_password_reset
import pyrebase
import firebase_admin
from firebase_admin import credentials

# --- Firebase Initialization ---
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

# --- Configuration ---
BASE_URL = "http://127.0.0.1:5000"
MODEL_PATH = "models/fraud_detection_model.pkl"

# --- App Icons ---
LOGOS = {
    "home": "https://img.icons8.com/ios-filled/512/home.png",
    "file_scan": "https://img.icons8.com/ios-filled/512/virus.png",
    "qr_scan": "https://img.icons8.com/ios/512/qr-code--v1.png",
    "fraud": "https://img.icons8.com/ios-filled/512/security-shield-green.png",
    "phishing": "https://img.icons8.com/ios/512/phishing.png"
}

# --- Session State Initialization ---
if 'qr_data' not in st.session_state:
    st.session_state.qr_data = None
if 'current_page' not in st.session_state:
    st.session_state.current_page = "🏠 HOME"
if 'user' not in st.session_state:
    st.session_state.user = None
if 'scan_history' not in st.session_state:
    st.session_state.scan_history = []
if 'show_forgot_password' not in st.session_state:
    st.session_state.show_forgot_password = False
if 'auth_tab' not in st.session_state:
    st.session_state.auth_tab = "login"
if 'password_reset_success' not in st.session_state:
    st.session_state.password_reset_success = False
if 'current_tab' not in st.session_state:
    st.session_state.current_tab = "Sign In"

# --- Utility Functions ---
def load_lottie(filepath):
    """Load Lottie animation JSON file"""
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except:
        return {"url": "https://assets8.lottiefiles.com/packages/lf20_ktwnwv5m.json"}

# --- UI Styles ---
def set_custom_style():
    """Set custom CSS styles for the entire app"""
    st.markdown("""
        <style>
            /* Main container */
            .main-container {
                max-width: 1200px;
                margin: 0 auto;
                padding: 1rem;
            }
            
            /* Auth container */
            .auth-container {
                background-color: #ffffff;
                border-radius: 15px;
                padding: 2rem;
                box-shadow: 0 10px 25px rgba(0,0,0,0.1);
                border: 1px solid #e6e6e6;
                margin: 2rem auto;
                max-width: 500px;
            }
            
            /* Sidebar styles */
            .sidebar .sidebar-content {
                background-color: #e6f2ff !important;
                background-image: linear-gradient(to bottom, #e6f2ff, #cce6ff);
            }
            
            /* Input styles */
            .stTextInput>div>div>input {
                transition: all 0.3s;
                border: 1px solid #ced4da !important;
            }
            
            .stTextInput>div>div>input:focus {
                border-color: #ff66b2 !important;
                box-shadow: 0 0 0 2px rgba(255,102,178,0.2) !important;
            }
            
            /* Button styles */
            .stButton>button {
                background-color: #ff66b2;
                color: white !important;
                border: none;
                border-radius: 8px;
                padding: 0.75rem 1.5rem;
                font-weight: 600;
                transition: all 0.3s;
            }
            
            .stButton>button:hover {
                background-color: #ff3385;
                transform: translateY(-2px);
                box-shadow: 0 4px 8px rgba(255,102,178,0.3);
            }
            
            /* Secondary button styles */
            .secondary-btn>button {
                background-color: #f0f0f0 !important;
                color: #333 !important;
                border: 1px solid #ddd !important;
            }
            
            .secondary-btn>button:hover {
                background-color: #e6e6e6 !important;
            }
            
            /* Card styles */
            .card {
                background-color: #ffffff;
                border-radius: 10px;
                padding: 20px;
                margin-bottom: 20px;
                border: 1px solid #66b3ff;
                transition: all 0.3s;
                box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            }
            
            .card:hover {
                box-shadow: 0 0 15px #66b3ff;
                transform: translateY(-5px);
            }
            
            /* Terminal-like text */
            .terminal {
                background-color: #333333;
                color: #00ff00;
                padding: 15px;
                border-radius: 5px;
                border: 1px solid #ff66b2;
                font-family: 'Courier New', monospace;
            }
            
            /* Link styles */
            .auth-link {
                color: #ff66b2 !important;
                text-decoration: none;
                cursor: pointer;
                font-weight: 500;
                display: inline-block;
                margin-top: 0.5rem;
            }
            
            .auth-link:hover {
                text-decoration: underline;
            }
            
            /* Success message */
            .success-message {
                background-color: #e6ffed;
                color: #22863a;
                padding: 1rem;
                border-radius: 5px;
                border: 1px solid #22863a;
                margin: 1rem 0;
            }
            
            /* Google button */
            .google-btn {
                background-color: #4285F4 !important;
                color: white !important;
                width: 100%;
            }
            
            /* Divider */
            .divider {
                display: flex;
                align-items: center;
                text-align: center;
                margin: 1rem 0;
            }
            
            .divider::before, .divider::after {
                content: "";
                flex: 1;
                border-bottom: 1px solid #ddd;
            }
            
            .divider-text {
                padding: 0 10px;
            }
        </style>
    """, unsafe_allow_html=True)

# --- Authentication Components ---
# --- Authentication Components ---
def show_auth_ui():
    """Display authentication UI matching the reference style exactly"""
    st.set_page_config(
        page_title="Threat Guard AI | Login", 
        page_icon="🛡️",
        layout="centered"
    )
    
    # Apply the exact same styling as reference
    st.markdown("""
    <style>
        .main {
            max-width: 400px;
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin: 0 auto;
        }
        .stTextInput>div>div>input {
            padding: 10px !important;
        }
        .stButton>button {
            width: 100%;
            padding: 0.5rem;
            border-radius: 5px;
            margin: 0.25rem 0;
        }
        .google-btn {
            background-color: #4285F4 !important;
            color: white !important;
        }
        .error {
            color: #ff4b4b;
            font-size: 0.9rem;
        }
        .divider {
            display: flex;
            align-items: center;
            text-align: center;
            margin: 1rem 0;
        }
        .divider::before, .divider::after {
            content: "";
            flex: 1;
            border-bottom: 1px solid #ddd;
        }
        .divider-text {
            padding: 0 10px;
        }
    </style>
    """, unsafe_allow_html=True)
    
    # Main container with same styling
    st.markdown("<div class='main'>", unsafe_allow_html=True)
    
    if st.session_state.get('password_reset_success'):
        st.success("Password reset successfully! Please login with your new password.")
        st.session_state.password_reset_success = False
    
    if st.session_state.get('show_forgot_password'):
        show_forgot_password_page()
    else:
        # Exact same title structure as reference
        st.title("Threat Guard AI")
        st.subheader("Secure Authentication")
        
        # Tab selection - same implementation
        if 'current_tab' not in st.session_state:
            st.session_state.current_tab = "Sign In"

        tabs = ["Sign In", "Sign Up"]
        current_tab = st.radio("", tabs, 
                             index=tabs.index(st.session_state.current_tab),
                             horizontal=True,
                             label_visibility="collapsed")
        
        st.session_state.current_tab = current_tab
        
        # Tab content container
        with st.container():
            if current_tab == "Sign In":
                email = st.text_input("Email", placeholder="Enter your email", key="login_email")
                password = st.text_input("Password", type="password", placeholder="••••••••", key="login_password")
                
                if st.button("Login", type="primary", key="login_btn"):
                    if email and password:
                        handle_login(email, password)
                    else:
                        st.error("Please fill all fields")
                
                if st.button("Forgot Password?", key="forgot_btn"):
                    st.session_state.show_forgot_password = True
                    st.rerun()
                
                # Google Sign-In Button with same styling
                st.markdown('<div class="divider"><span class="divider-text">OR</span></div>', unsafe_allow_html=True)
                if st.button("Sign in with Google", key="google_btn", type="secondary", help="Sign in using your Google account"):
                    handle_google_signin()
                
            else:  # Sign Up
                username = st.text_input("Username", placeholder="Enter your username", key="signup_username")
                email = st.text_input("Email", placeholder="your@email.com", key="signup_email")
                password = st.text_input("Password", type="password", 
                                       placeholder="Create password (min 6 chars)", 
                                       key="signup_password")
                confirm = st.text_input("Confirm Password", type="password", 
                                      placeholder="Re-enter password", 
                                      key="confirm_password")
                
                if st.button("Create Account", type="primary", key="signup_btn"):
                    if not all([username, email, password, confirm]):
                        st.error("Please fill all fields")
                    elif password != confirm:
                        st.error("Passwords don't match")
                    elif len(password) < 6:
                        st.error("Password must be 6+ characters")
                    else:
                        handle_signup(username, email, password, confirm)
    
    st.markdown("</div>", unsafe_allow_html=True)

def show_forgot_password_page():
    """Password reset page matching reference exactly"""
    st.title("Reset Password")
    email = st.text_input("Registered Email", placeholder="your@email.com")
    new_password = st.text_input("New Password", type="password", placeholder="••••••••")
    confirm_password = st.text_input("Confirm New Password", type="password", placeholder="••••••••")
    
    if st.button("Update Password"):
        if not all([email, new_password, confirm_password]):
            st.error("Please fill all fields")
        elif new_password != confirm_password:
            st.error("Passwords don't match")
        elif len(new_password) < 6:
            st.error("Password must be 6+ characters")
        else:
            success = handle_password_reset_request(email, new_password, confirm_password)
            if success:
                st.session_state.show_forgot_password = False
                st.session_state.password_reset_success = True
                st.rerun()
    
    if st.button("Back to Login"):
        st.session_state.show_forgot_password = False
        st.rerun()
# --- Authentication Handlers ---
def handle_login(email, password):
    """Process login attempt with admin special handling"""
    if not email or not password:
        st.error("Please fill all fields")
        return
    
    try:
        # Special admin login handling
        if email == "admin@gmail.com" and password == "Admin@123":
            st.session_state.user = {
                "email": "admin@gmail.com",
                "is_admin": True,
                "username": "Admin"
            }
            st.success("Admin login successful! Launching admin panel...")
            time.sleep(1)
            
            # Launch admin panel in a new process
            import subprocess
            import sys
            import os
            admin_path = os.path.join(os.path.dirname(__file__), "upi_fraud.py")
            subprocess.Popen([sys.executable, "-m", "streamlit", "run", admin_path])
            
            # Stop the current app
            st.stop()
        else:
            # Regular user authentication
            user = authenticate_user(email, password)
            if user:
                st.session_state.user = user
                st.success("Login successful!")
                time.sleep(1)
                st.session_state.current_page = "🏠 HOME"
                st.rerun()
    except Exception as e:
        st.error(f"Login failed: {str(e)}")

def handle_signup(username, email, password, confirm_password):
    """Process user registration"""
    if not all([username, email, password, confirm_password]):
        st.error("Please fill all fields")
        return
    
    if password != confirm_password:
        st.error("Passwords don't match")
        return
    
    try:
        if register_user(email, password, username):
            st.success("Account created successfully! Please log in.")
            time.sleep(2)
            st.session_state.auth_tab = "login"
            st.rerun()
    except Exception as e:
        st.error(f"Registration failed: {str(e)}")

def handle_password_reset_request(email, new_password, confirm_password):
    """Process password reset request"""
    if not all([email, new_password, confirm_password]):
        st.error("Please fill all fields")
        return False
    
    if new_password != confirm_password:
        st.error("Passwords don't match")
        return False
    
    try:
        success = handle_password_reset(email, new_password, confirm_password)
        if success:
            st.success("Password updated successfully!")
            return True
    except Exception as e:
        st.error(f"Password reset failed: {str(e)}")
        return False

def handle_google_signin():
    """Handle Google Sign-In"""
    try:
        firebase = initialize_firebase()
        auth_url = f"https://{firebase.authDomain}/__/auth/handler"
        st.info("Please complete Google Sign-In in the browser window that will open")
        # In a production environment, you would use proper OAuth flow
        # This is a simplified approach
        import webbrowser
        webbrowser.open_new_tab(auth_url)
    except Exception as e:
        st.error(f"Google Sign-In failed: {str(e)}")

# --- Navigation ---
def navigation():
    """Display sidebar navigation"""
    st.sidebar.title("THREAT GUARD AI SYSTEM")
    
    if st.session_state.user:
        st.sidebar.markdown(f"**Welcome, {st.session_state.user.get('username', 'User')}**")
        if st.session_state.user.get('is_admin'):
            st.sidebar.markdown("**Admin Privileges** 🔒")
    
    pages = [
        "🏠 HOME", 
        "📁 FILE SCAN",
        "📷 QR SCAN", 
        "💸 FRAUD DETECTION",
        "🎣 PHISHING DETECTION",
        "📜 HISTORY"
    ]
    
    page = st.sidebar.radio("NAVIGATION", pages, 
                          index=pages.index(st.session_state.current_page))
    
    st.session_state.current_page = page
    
    if st.session_state.user:
        st.sidebar.markdown("---")
        if st.sidebar.button("Logout", key="sidebar_logout"):
            st.session_state.user = None
            st.session_state.current_page = "🏠 HOME"
            st.rerun()
    
    return page

# --- Utility Components ---
def scan_result_card(status, score=None, details=None):
    """Display a styled scan result card"""
    style_map = {
        "Malicious": ("#ff3333", "#ffe6e6"),
        "Suspicious": ("#ff9933", "#fff2e6"),
        "Clean": ("#33cc33", "#e6ffe6")
    }
    text_color, bg_color = style_map.get(status, ("#66b3ff", "#e6f2ff"))

    st.markdown(f"""
        <div style='
            border-left: 5px solid {text_color};
            background-color: {bg_color};
            padding: 1.5rem;
            border-radius: 5px;
            margin: 1rem 0;
            color: #333333;
            font-family: 'Courier New', monospace;
        '>
            <h4 style="margin-top: 0; color: {text_color};">> SCAN_RESULT: {status}</h4>
            <p style="color: #333333;">> MALWARE_PROBABILITY: {score if score is not None else "N/A"}</p>
            <p style="color: #333333;">> DETAILS: {details if details else "No further data available."}</p>
        </div>
    """, unsafe_allow_html=True)

def make_backend_request(endpoint, method="GET", data=None, files=None):
    """Make HTTP requests to backend API"""
    try:
        url = f"{BASE_URL}{endpoint}"
        if method == "GET":
            response = requests.get(url)
        elif method == "POST":
            if files:
                response = requests.post(url, files=files, data=data)
            else:
                response = requests.post(url, json=data)
        else:
            return None
        
        return response.json() if response.status_code == 200 else None
    except Exception as e:
        st.error(f"Connection error: {str(e)}")
        return None

# --- Page Components ---
def home_page():
    set_custom_style()
    st.title("THREAT GUARD AI SYSTEM v2.4.1")
    
    # Header with logo and pulse animation
    st.markdown(f"""
        <div style="text-align: center; margin-bottom: 2rem;">
            <img src="{LOGOS["home"]}" class="logo pulse" style="width: 50px;">
        </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
        <div class="terminal">
            > Initializing system...<br>
            > Loading modules...<br>
            > Establishing secure connection...<br>
            > System ready.<br><br>
            > Welcome to UPI Fraud Detection System<br>
            > Comprehensive security for digital transactions<br>
            > Type 'help' for commands
        </div>
    """, unsafe_allow_html=True)

    # Module showcase section with images
    st.subheader("MAIN SECURITY MODULES")
    
    # Create 4 columns for the module images
    img_col1, img_col2, img_col3, img_col4 = st.columns(4)
    
    with img_col1:
        st.image("images/phishing.png", 
                caption="Phishing Detection", width=130)
        st.markdown("""
        <div style="text-align: center; font-size: 0.9rem; margin-top: -1rem;">
            Detect fake UPI payment pages
        </div>
        """, unsafe_allow_html=True)
    
    with img_col2:
        st.image("images/malwarescan.webp", 
                caption="File Threat Analysis", width=120)
        st.markdown("""
        <div style="text-align: center; font-size: 0.9rem; margin-top: -1rem;">
            Scan malicious PDF/DOCX files
        </div>
        """, unsafe_allow_html=True)
    
    with img_col3:
        st.image("images/qr_scan.webp", 
                caption="QR Code Scanner", width=120)
        st.markdown("""
        <div style="text-align: center; font-size: 0.9rem; margin-top: -1rem;">
            Detect fraudulent QR codes
        </div>
        """, unsafe_allow_html=True)
    
    with img_col4:
        st.image("images/fraud.jpg", 
                caption="Fraud Detection", width=120)
        st.markdown("""
        <div style="text-align: center; font-size: 0.9rem; margin-top: -1rem;">
            Analyze suspicious transactions
        </div>
        """, unsafe_allow_html=True)

    # Interactive cards for navigation
    col1, col2 = st.columns(2)

    with col1:
        # File Threat Analysis Card
        if st.button("FILE THREAT ANALYSIS", key="file_scan_btn", use_container_width=True):
            st.session_state.current_page = "📁 FILE SCAN"
            st.rerun()
        st.markdown(f"""
            <div class='card' onclick="navigateTo('📁 FILE SCAN')">
                <div class='logo-container'>
                    <img src="{LOGOS["file_scan"]}" class="logo" style="width: 150px;">
                </div>
                <div class='card-title'>FILE THREAT ANALYSIS</div>
                <div class='card-desc'>Advanced scanning for PDF/DOCX files with heuristic analysis</div>
            </div>
        """, unsafe_allow_html=True)

        # Phishing Detection Card
        if st.button("PHISHING DETECTION", key="phishing_btn", use_container_width=True):
            st.session_state.current_page = "🎣 PHISHING DETECTION"
            st.rerun()
        st.markdown(f"""
            <div class='card' onclick="navigateTo('🎣 PHISHING DETECTION')">
                <div class='logo-container'>
                    <img src="{LOGOS["phishing"]}" class="logo" style="width: 150px;">
                </div>
                <div class='card-title'>PHISHING DETECTION</div>
                <div class='card-desc'>Identify and block phishing attempts targeting UPI users</div>
            </div>
        """, unsafe_allow_html=True)

    with col2:
        # QR Code Analysis Card
        if st.button("QR CODE ANALYSIS", key="qr_scan_btn", use_container_width=True):
            st.session_state.current_page = "📷 QR SCAN"
            st.rerun()
        st.markdown(f"""
            <div class='card' onclick="navigateTo('📷 QR SCAN')">
                <div class='logo-container'>
                    <img src="{LOGOS["qr_scan"]}" class="logo" style="width: 150px;">
                </div>
                <div class='card-title'>QR CODE ANALYSIS</div>
                <div class='card-desc'>Secure scanning of payment QR codes with tamper detection</div>
            </div>
        """, unsafe_allow_html=True)

        # Fraud Detection Card
        if st.button("FRAUD DETECTION", key="fraud_btn", use_container_width=True):
            st.session_state.current_page = "💸 FRAUD DETECTION"
            st.rerun()
        st.markdown(f"""
            <div class='card' onclick="navigateTo('💸 FRAUD DETECTION')">
                <div class='logo-container'>
                    <img src="{LOGOS["fraud"]}" class="logo" style="width: 150px;">
                </div>
                <div class='card-title'>FRAUD DETECTION</div>
                <div class='card-desc'>Analyze transactions for suspicious patterns and fraud</div>
            </div>
        """, unsafe_allow_html=True)

    # Add JavaScript for navigation
    st.markdown("""
        <script>
            // Function to handle card clicks
            function navigateTo(page) {
                window.streamlitSessionState.set('current_page', page);
            }
        </script>
    """, unsafe_allow_html=True)

    st.markdown("""
        <div class="terminal" style='margin-top: 2rem;'>
            > SYSTEM FEATURES:<br>
            > Real-time transaction monitoring<br>
            > Advanced anomaly detection<br>
            > Secure QR validation<br>
            > Document malware scanning<br>
            > Encrypted communication<br><br>
            > Last system update: 2023-11-15<br>
            > Security level: MAXIMUM<br>
            > Connection: SECURE
        </div>
    """, unsafe_allow_html=True)
def file_scan_page():
    set_custom_style()
    st.title("🛡️ FILE THREAT ANALYSIS")
    
    # Header with logo
    st.markdown(f"""
        <div style="text-align: center; margin-bottom: 2rem;">
            <img src="{LOGOS['file_scan']}" class="logo" style="width: 150px;">
        </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    <div class="terminal">
        > UPLOAD FILES FOR MALWARE ANALYSIS<br>
        > Supports: PDF, DOCX, XLSX, PPTX<br>
        > Maximum file size: 10MB
    </div>
    """, unsafe_allow_html=True)
    
    with st.expander("HOW TO USE", expanded=False):
        st.write("""
        1. Click 'Browse files' or drag and drop
        2. Select document to analyze
        3. View detailed threat report
        4. Check history for previous scans
        """)

    # File upload section
    uploaded_file = st.file_uploader(
        "UPLOAD FILE FOR ANALYSIS", 
        type=["pdf", "docx", "doc", "xls", "xlsx", "ppt", "pptx"],
        help="Supported formats: PDF, DOCX, DOC, XLS, XLSX, PPT, PPTX",
        label_visibility="collapsed"
    )
    
    if uploaded_file is not None:
        try:
            # Validate file size (10MB max)
            if uploaded_file.size > 10 * 1024 * 1024:
                st.error("File size exceeds 10MB limit")
                return
            
            st.success(f"FILE UPLOADED: {uploaded_file.name}")
            
            # Display file info
            with st.expander("📄 FILE INFORMATION", expanded=True):
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("File Name", uploaded_file.name)
                with col2:
                    st.metric("File Size", f"{uploaded_file.size / 1024:.2f} KB")
                with col3:
                    st.metric("File Type", uploaded_file.type.split('/')[-1].upper())
            
            # Perform the scan
            with st.spinner("🔍 ANALYZING FILE FOR THREATS..."):
                # Prepare request data
                user_id = st.session_state.user.get('localId') if st.session_state.user else None
                files = {'file': (uploaded_file.name, uploaded_file.getvalue())}
                data = {'user_id': user_id} if user_id else {}
                
                # Make backend request
                response = make_backend_request(
                    "/api/scan/file", 
                    method="POST", 
                    files=files, 
                    data=data
                )
                
                if not response:
                    st.error("Failed to connect to analysis service")
                    return
                
                if response.get('error'):
                    st.error(f"Analysis error: {response['error']}")
                    return
                
                # Display results
                st.subheader("SCAN RESULTS")
                
                # Result status with emoji
                if response['status'] == 'malicious':
                    st.error(f"🚨 MALICIOUS FILE DETECTED: {uploaded_file.name}")
                elif response['status'] == 'suspicious':
                    st.warning(f"⚠️ SUSPICIOUS FILE DETECTED: {uploaded_file.name}")
                else:
                    st.success(f"✅ FILE APPEARS SAFE: {uploaded_file.name}")
                
                # Threat score visualization
                threat_score = float(response['threat_score'])
                cols = st.columns([1, 3])
                with cols[0]:
                    st.metric("THREAT SCORE", f"{threat_score * 100:.0f}%")
                with cols[1]:
                    st.progress(threat_score)
                
                # Detailed analysis
                with st.expander("🔬 DETAILED ANALYSIS", expanded=True):
                    # Detection method
                    st.write(f"**Detection Method:** {response.get('method', 'heuristic').upper()}")
                    
                    # Technical indicators
                    st.subheader("TECHNICAL INDICATORS")
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("Entropy Level", f"{response.get('entropy', 0):.4f}")
                    with col2:
                        st.metric("File Hash", response.get('hash', 'N/A'))
                        st.caption("SHA256")
                    
                    # Suspicious patterns
                    if response.get('suspicious_patterns'):
                        st.subheader("SUSPICIOUS PATTERNS")
                        for pattern in response['suspicious_patterns']:
                            st.write(f"- **{pattern.get('pattern', 'Unknown')}**")
                            st.caption(f"Count: {pattern.get('count', 1)}")
                            if pattern.get('sample'):
                                st.code(pattern['sample'][:100] + ("..." if len(pattern['sample']) > 100 else ""))
                    
                    # Additional recommendations
                    st.subheader("RECOMMENDATIONS")
                    if response['status'] == 'malicious':
                        st.error("""
                        - DO NOT OPEN THIS FILE
                        - Delete it immediately
                        - Scan your system for malware
                        """)
                    elif response['status'] == 'suspicious':
                        st.warning("""
                        - Open with caution
                        - Verify file source
                        - Use sandboxed environment
                        """)
                    else:
                        st.success("""
                        - File appears safe
                        - Still verify the source
                        - Keep your antivirus updated
                        """)
            
            # Add to scan history
            scan_record = {
                'filename': uploaded_file.name,
                'status': response['status'],
                'threat_score': threat_score,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'hash': response.get('hash', ''),
                'type': uploaded_file.type
            }
            
            if 'scan_history' not in st.session_state:
                st.session_state.scan_history = []
            st.session_state.scan_history.insert(0, scan_record)
            
        except Exception as e:
            st.error(f"❌ ANALYSIS FAILED: {str(e)}")
            st.exception(e)
    
    # Display scan history in a table
    if 'scan_history' in st.session_state and st.session_state.scan_history:
        st.subheader("📜 SCAN HISTORY")
        
        # Convert history to DataFrame for better display
        history_df = pd.DataFrame(st.session_state.scan_history)
        
        # Add emoji to status
        def status_with_emoji(status):
            if status == 'malicious':
                return f"🚨 {status.upper()}"
            elif status == 'suspicious':
                return f"⚠️ {status.upper()}"
            else:
                return f"✅ {status.upper()}"
        
        history_df['Status'] = history_df['status'].apply(status_with_emoji)
        
        # Format threat score as percentage
        history_df['Threat Score'] = history_df['threat_score'].apply(lambda x: f"{x*100:.0f}%")
        
        # Select columns to display
        display_df = history_df[['timestamp', 'filename', 'Status', 'Threat Score', 'type']]
        display_df = display_df.rename(columns={
            'timestamp': 'Scan Time',
            'filename': 'File Name',
            'type': 'File Type'
        })
        
        # Display the table
        st.dataframe(
            display_df,
            column_config={
                "Scan Time": st.column_config.DatetimeColumn(
                    "Scan Time",
                    format="YYYY-MM-DD HH:mm:ss"
                )
            },
            use_container_width=True,
            hide_index=True
        )
        
        # Add download button for history
        csv = history_df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 DOWNLOAD SCAN HISTORY",
            data=csv,
            file_name="file_scan_history.csv",
            mime="text/csv"
        )

class QRScanner(VideoTransformerBase):
    def __init__(self):
        self.detected_qr = None
        self.frame = None
        
    def transform(self, frame):
        img = frame.to_ndarray(format="bgr24")
        self.frame = img.copy()  # Store the current frame
        
        # Convert to grayscale for QR detection
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        decoded = decode(gray)
        
        if decoded:
            # Get the first QR code found
            obj = decoded[0]
            qr_data = obj.data.decode("utf-8")
            self.detected_qr = qr_data
            
            # Draw bounding box around QR code
            points = obj.polygon
            if len(points) > 4:
                hull = cv2.convexHull(np.array([point for point in points], dtype=np.float32))
                hull = list(map(tuple, np.squeeze(hull)))
            else:
                hull = points
            
            # Draw the polygon
            for j in range(len(hull)):
                cv2.line(img, hull[j], hull[(j + 1) % len(hull)], (0, 255, 0), 3)
            
            # Put text
            cv2.putText(img, "QR DETECTED", (hull[0][0], hull[0][1] - 10),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.8, (0, 255, 0), 2)
        
        return img

def qr_scan_page():
    set_custom_style()
    st.title("📷 QR CODE ANALYSIS")
    
    st.markdown(f"""
        <div style="text-align: center; margin-bottom: 2rem;">
            <img src="{LOGOS["qr_scan"]}" class="logo" style="width: 150px;">
        </div>
    """, unsafe_allow_html=True)

    mode = st.radio("SELECT SCAN MODE:", ["📤 Upload Image", "🎥 Live Camera"])
    
    if mode == "📤 Upload Image":
        uploaded_file = st.file_uploader(
            "UPLOAD IMAGE CONTAINING QR", 
            type=["jpg", "jpeg", "png"]
        )
        
        if uploaded_file is not None:
            try:
                image = Image.open(uploaded_file)
                img_np = np.array(image.convert('RGB'))
                
                # Detect QR codes
                decoded = decode(img_np)
                
                if decoded:
                    qr_data = decoded[0].data.decode("utf-8")
                    st.session_state.qr_data = qr_data
                    
                    # Draw on image
                    points = decoded[0].polygon
                    if len(points) > 4:
                        hull = cv2.convexHull(np.array([point for point in points], dtype=np.float32))
                        hull = list(map(tuple, np.squeeze(hull)))
                    else:
                        hull = points
                    
                    for j in range(len(hull)):
                        cv2.line(img_np, hull[j], hull[(j + 1) % len(hull)], (0, 255, 0), 3)
                    
                    cv2.putText(img_np, "QR DETECTED", (hull[0][0], hull[0][1] - 10),
                                cv2.FONT_HERSHEY_SIMPLEX, 0.8, (0, 255, 0), 2)
                    
                    st.image(img_np, caption="SCANNED IMAGE", use_column_width=True)

                    # Check if link is safe or fraud
                    response = make_backend_request("/api/scan/qr", method="POST", data={
                        "url": qr_data,
                        "user_id": st.session_state.user.get('localId') if st.session_state.user else None
                    })
                    
                    if response:
                        if response['is_fraud']:
                            st.error(f"⚠️ Warning: Fraudulent QR Code!\n\nLink: {qr_data}")
                            st.write("Suspicious indicators found:")
                            for indicator in response['analysis']['suspicious_domains']:
                                st.write(f"- {indicator}")
                            for indicator in response['analysis']['suspicious_keywords']:
                                st.write(f"- {indicator}")
                        else:
                            st.success(f"✅ Safe QR Code Detected!\n\nLink: {qr_data}")
                else:
                    st.warning("NO QR CODE FOUND")
                    st.image(img_np, caption="UPLOADED IMAGE", use_column_width=True)
            except Exception as e:
                st.error(f"ERROR: {str(e)}")
    
    elif mode == "🎥 Live Camera":
        st.info("POINT CAMERA AT QR CODE TO SCAN")
        
        # Initialize session state variables if they don't exist
        if 'qr_data' not in st.session_state:
            st.session_state.qr_data = None
        if 'qr_status' not in st.session_state:
            st.session_state.qr_status = None
        if 'scanned_image' not in st.session_state:
            st.session_state.scanned_image = None
        
        # Start the webcam
        webrtc_ctx = webrtc_streamer(
            key="qr-scanner",
            video_transformer_factory=QRScanner,
            rtc_configuration={"iceServers": [{"urls": ["stun:stun.l.google.com:19302"]}]},
            media_stream_constraints={"video": True, "audio": False},
        )
        
        # Add scan button
        scan_button = st.button("Scan and Check")
        
        # Display area for QR code results
        result_placeholder = st.empty()
        image_placeholder = st.empty()
        
        # Check if we have a transformer and the scan button was clicked
        if webrtc_ctx.video_transformer and scan_button:
            scanner = webrtc_ctx.video_transformer
            if scanner.detected_qr:
                # Store the QR data
                st.session_state.qr_data = scanner.detected_qr
                
                # Call backend API
                response = make_backend_request("/api/scan/qr", method="POST", data={
                    "url": scanner.detected_qr,
                    "user_id": st.session_state.user.get('localId') if st.session_state.user else None
                })
                
                if response:
                    st.session_state.qr_status = "Fraud" if response['is_fraud'] else "Safe"
                
                # Store the captured frame
                if scanner.frame is not None:
                    st.session_state.scanned_image = scanner.frame
            
        # Display results if we have them
        if st.session_state.qr_data:
            # Show the captured image with QR code highlighted
            if st.session_state.scanned_image is not None:
                image_placeholder.image(st.session_state.scanned_image, 
                                      caption="Captured QR Code", 
                                      channels="BGR",
                                      use_column_width=True)
            
            # Show the safety status
            if st.session_state.qr_status == "Fraud":
                result_placeholder.error(f"⚠️ Warning: Fraudulent QR Code!\n\nLink: {st.session_state.qr_data}")
            else:
                result_placeholder.success(f"✅ Safe QR Code Detected!\n\nLink: {st.session_state.qr_data}")
            
            if st.button("Clear Scan"):
                st.session_state.qr_data = None
                st.session_state.qr_status = None
                st.session_state.scanned_image = None
                result_placeholder.empty()
                image_placeholder.empty()
                st.rerun()

def fraud_detection_page():
    set_custom_style()
    st.title("💸 UPI TRANSACTION ANALYSIS")
    
    # Header with logo
    st.markdown(f"""
        <div style="text-align: center; margin-bottom: 2rem;">
            <img src="{LOGOS['fraud']}" class="logo" style="width: 150px;">
        </div>
    """, unsafe_allow_html=True)

    # Define constants
    LOCATIONS = ['Mumbai', 'Delhi', 'Kolkata', 'Bangalore', 'Chennai',
                 'Hyderabad', 'Pune', 'Jaipur', 'Lucknow', 'Ahmedabad']
    STATES = ['Maharashtra', 'Delhi', 'West Bengal', 'Karnataka', 'Tamil Nadu',
              'Telangana', 'Uttar Pradesh', 'Gujarat', 'Rajasthan', 'Punjab']

    @st.cache_data
    def load_data():
        return pd.read_csv("upi_transaction_data.csv")

    def extract_upi_domain(upi_id):
        if pd.isna(upi_id) or upi_id == '':
            return 'unknown'
        patterns = [
            (r'.*@ok(sbi|hdfc|icici|axis|paytm)', 'legitimate_bank'),
            (r'.*@(oksbi|okhdfc|okicici|okaxis|okpaytm)', 'legitimate_bank'),
            (r'^\d+@upi$', 'legitimate_upi'),
        ]
        for pattern, label in patterns:
            if re.match(pattern, upi_id.lower()):
                return label
        return 'suspicious_domain' if '@' in upi_id else 'unknown'

    def validate_phone(phone):
        phone_str = str(phone)
        return phone_str.isdigit() and len(phone_str) == 10 and phone_str[0] in '6789'

    def preprocess_data(df):
        df['Sender_Domain_Type'] = df["Sender's UPI ID"].apply(extract_upi_domain)
        df['Receiver_Domain_Type'] = df["Receiver's UPI ID"].apply(extract_upi_domain)

        domain_map = {'legitimate_bank': 0, 'legitimate_upi': 1, 'suspicious_domain': 2, 'unknown': 3}
        df['Sender_Domain_Encoded'] = df['Sender_Domain_Type'].map(domain_map)
        df['Receiver_Domain_Encoded'] = df['Receiver_Domain_Type'].map(domain_map)

        df['Phone_Valid'] = df["Sender's Phone Number"].apply(lambda x: int(validate_phone(x)))

        if 'Time of Transaction' in df.columns:
            # Convert to datetime first if it's not already
            if not pd.api.types.is_datetime64_any_dtype(df['Time of Transaction']):
                df['Transaction_Date'] = pd.to_datetime(df['Time of Transaction'])
            else:
                df['Transaction_Date'] = df['Time of Transaction']
            
            df['Is_Night'] = ((df['Transaction_Date'].dt.hour >= 22) | 
                              (df['Transaction_Date'].dt.hour <= 6)).astype(int)

        df['Location_Encoded'] = df['Location'].apply(lambda x: LOCATIONS.index(x) if x in LOCATIONS else -1)
        df['State_Encoded'] = df['State'].apply(lambda x: STATES.index(x) if x in STATES else -1)

        bins = [0, 1000, 10000, 50000, 100000, float('inf')]
        df['Amount_Bin'] = pd.cut(df['Transaction Amount'], bins=bins, labels=False)

        return df

    # Load dataset and model
    df = load_data()
    df_processed = preprocess_data(df)

    try:
        model = joblib.load("enhanced_upi_fraud_model.pkl")
        model_loaded = True
    except FileNotFoundError:
        st.error("ERROR: MODEL NOT FOUND")
        model_loaded = False

    if model_loaded:
        with st.form("fraud_form"):
            st.subheader("ENTER TRANSACTION DETAILS")

            col1, col2 = st.columns(2)
            with col1:
                sender_name = st.text_input("SENDER NAME", "Pranjal Bhinge")
                sender_upi = st.text_input("SENDER UPI ID", "pranjalbhinge@oksbi")
                phone = st.text_input("SENDER PHONE", "8431212363")
                amount = st.number_input("AMOUNT(₹)", min_value=1, value=5000)

            with col2:
                receiver_upi = st.text_input("RECEIVER UPI ID", "merchant@okhdfc")
                location = st.selectbox("LOCATION", LOCATIONS, index=2)
                state = st.selectbox("STATE", STATES, index=5)
                trans_time = st.time_input("TRANSACTION TIME", value=datetime.now().time())

            if st.form_submit_button("ANALYZE TRANSACTION"):
                if amount > 60000:
                    st.error("ERROR: AMOUNT EXCEEDS LIMIT")
                elif not validate_phone(phone):
                    st.error("ERROR: INVALID PHONE FORMAT")
                else:
                    # Create a datetime object from the time input
                    trans_datetime = datetime.combine(datetime.today(), trans_time)
                    
                    # Simulate one transaction
                    new_data = pd.DataFrame({
                        "Sender's UPI ID": [sender_upi],
                        "Sender's Phone Number": [phone],
                        "Transaction Amount": [amount],
                        "Receiver's UPI ID": [receiver_upi],
                        "Location": [location],
                        "State": [state],
                        "Time of Transaction": [trans_datetime.strftime("%Y-%m-%d %H:%M:%S")],
                        "Fraudulent": [0]  # Dummy
                    })

                    processed = preprocess_data(new_data)

                    features = ['Transaction Amount', 'Sender_Domain_Encoded',
                                'Receiver_Domain_Encoded', 'Location_Encoded',
                                'State_Encoded', 'Phone_Valid', 'Amount_Bin']
                    if 'Is_Night' in processed.columns:
                        features.append('Is_Night')

                    probas = model.predict_proba(processed[features])[0]
                    prediction = model.predict(processed[features])[0]

                    st.subheader("ANALYSIS RESULT")
                    if prediction:
                        st.error(f"🚨 FRAUD DETECTED [CONFIDENCE: {probas[1]*100:.2f}%]")

                        st.markdown("**RISK FACTORS:**")
                        risks = []
                        if extract_upi_domain(sender_upi) not in ['legitimate_bank', 'legitimate_upi']:
                            risks.append("UNVERIFIED SENDER UPI")
                        if extract_upi_domain(receiver_upi) == 'suspicious_domain':
                            risks.append("SUSPICIOUS RECEIVER DOMAIN")
                        if not validate_phone(phone):
                            risks.append("INVALID PHONE FORMAT")
                        if amount > 50000:
                            risks.append("HIGH TRANSACTION AMOUNT")
                        if processed.get('Is_Night', [0])[0]:
                            risks.append("ODD HOURS TRANSACTION (10PM-6AM)")

                        for r in risks:
                            st.write(f"- {r}")
                    else:
                        st.success(f"✅ CLEAN TRANSACTION [CONFIDENCE: {probas[0]*100:.2f}%]")
                        st.markdown("**PASSED CHECKS:**")
                        if extract_upi_domain(sender_upi) in ['legitimate_bank', 'legitimate_upi']:
                            st.write("- VERIFIED SENDER UPI")
                        if validate_phone(phone):
                            st.write("- VALID PHONE FORMAT")
                        if amount <= 50000:
                            st.write("- REASONABLE AMOUNT")
                        if not processed.get('Is_Night', [1])[0]:
                            st.write("- NORMAL TRANSACTION HOURS")
                            
def display_results(response, sender_upi, receiver_upi, phone, amount, trans_time):
    """Display analysis results from backend response"""
    st.subheader("FRAUD ANALYSIS REPORT")
    
    # Result container
    with st.container():
        cols = st.columns([1, 3])
        with cols[0]:
            if response['is_fraud']:
                st.error("🚨 FRAUD DETECTED")
            else:
                st.success("✅ CLEAN TRANSACTION")
        
        with cols[1]:
            confidence = response['confidence'] * 100
            st.metric("CONFIDENCE LEVEL", f"{confidence:.1f}%")
            st.progress(int(confidence)/100)

    # Risk factors analysis
    with st.expander("DETAILED RISK ASSESSMENT", expanded=True):
        st.subheader("RISK FACTORS")
        
        risks = []
        if "@ok" not in sender_upi.lower() and "@upi" not in sender_upi.lower():
            risks.append("UNVERIFIED SENDER UPI")
        if "@example" in receiver_upi.lower():
            risks.append("SUSPICIOUS RECEIVER DOMAIN")
        if not phone.isdigit() or len(phone) != 10:
            risks.append("INVALID PHONE FORMAT")
        if amount > 50000:
            risks.append("HIGH TRANSACTION AMOUNT")
        if trans_time.hour < 6 or trans_time.hour > 22:
            risks.append("UNUSUAL TRANSACTION TIME")
        
        if risks:
            for risk in risks:
                st.error(f"- {risk}")
        else:
            st.success("- No significant risk factors detected")

    # Recommendations
    with st.expander("SAFETY RECOMMENDATIONS", expanded=False):
        if response['is_fraud']:
            st.error("""
            ❌ DO NOT PROCEED WITH THIS TRANSACTION
            - Contact your bank immediately
            - Report to National Cyber Crime Portal
            - Freeze your UPI if needed
            """)
        else:
            st.success("""
            ✅ TRANSACTION APPEARS SAFE
            - Always verify receiver details
            - Enable transaction alerts
            - Use UPI PIN carefully
            """)

def frontend_analysis(sender_upi, receiver_upi, phone, amount, trans_time):
    """Fallback frontend analysis if backend fails"""
    # Simple heuristic-based analysis
    is_fraud = False
    confidence = 0.1  # Base confidence for clean
    
    risk_factors = []
    
    # Check sender UPI
    if "@ok" not in sender_upi.lower() and "@upi" not in sender_upi.lower():
        risk_factors.append("UNVERIFIED_SENDER")
        confidence += 0.3
    
    # Check receiver UPI
    if "@example" in receiver_upi.lower():
        risk_factors.append("SUSPICIOUS_RECEIVER") 
        confidence += 0.4
    
    # Check phone
    if not phone.isdigit() or len(phone) != 10:
        risk_factors.append("INVALID_PHONE")
        confidence += 0.2
    
    # Check amount
    if amount > 50000:
        risk_factors.append("LARGE_AMOUNT")
        confidence += 0.1
    
    # Check time
    if trans_time.hour < 6 or trans_time.hour > 22:
        risk_factors.append("UNUSUAL_TIME")
        confidence += 0.1
    
    # Determine final result
    is_fraud = len(risk_factors) > 1 or confidence > 0.7
    confidence = min(0.95, confidence)  # Cap at 95%
    
    # Create mock response
    response = {
        'is_fraud': is_fraud,
        'confidence': confidence,
        'risk_factors': risk_factors
    }
    
    display_results(response, sender_upi, receiver_upi, phone, amount, trans_time)
    
def phishing_detection_page():
    set_custom_style()
    st.title("🎣 PHISHING DETECTION SYSTEM")
    
    # Header with logo
    st.markdown(f"""
        <div style="text-align: center; margin-bottom: 2rem;">
            <img src="{LOGOS['phishing']}" class="logo" style="width: 150px;">
        </div>
    """, unsafe_allow_html=True)

    # Load environment variables
    load_dotenv()

    # Configure Gemini
    try:
        genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
        model_name = 'gemini-1.5-flash'
        model = genai.GenerativeModel(model_name)
        st.info(f"USING MODEL: {model_name}")
    except Exception as e:
        st.error(f"ERROR: Failed to configure Gemini API - {str(e)}")
        st.stop()

    # Load Lottie animations with error handling
    def load_lottie_url(url):
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                return r.json()
            return None
        except:
            return None

    safe_animation = load_lottie_url("https://assets1.lottiefiles.com/packages/lf20_jbrw3hcz.json")
    danger_animation = load_lottie_url("https://assets1.lottiefiles.com/packages/lf20_6wutsrox.json")
    scanning_animation = load_lottie_url("https://assets1.lottiefiles.com/packages/lf20_pmvvft6i.json")

    # Website categories database (simplified example)
    WEBSITE_CATEGORIES = {
        "google.com": {"category": "Search Engine", "trust_score": 100},
        "facebook.com": {"category": "Social Media", "trust_score": 90},
        "amazon.com": {"category": "E-Commerce", "trust_score": 95},
        "sgbit.com": {"category": "Unknown", "trust_score": 10},
        "example.com": {"category": "Demo", "trust_score": 50}
    }

    def get_website_category(url):
        """Extract domain and match with known categories"""
        if not url:
            return {"category": "Unknown", "trust_score": 0}
            
        try:
            domain = url.split('//')[-1].split('/')[0].split('?')[0].lower()
            for site, data in WEBSITE_CATEGORIES.items():
                if site in domain:
                    return data
            return {"category": "Unknown", "trust_score": random.randint(10, 60)}
        except:
            return {"category": "Unknown", "trust_score": 0}

    def analyze_url(url):
        """Analyze URL for phishing and return enhanced output"""
        if not url:
            return {"error": "No URL provided", "category": "Unknown", "trust_score": 0}
            
        category_data = get_website_category(url)
        
        prompt = f"""Analyze this URL for phishing risk: {url}
        Respond with ONLY a valid JSON object containing:
        - is_phishing (boolean)
        - confidence (string: Low/Medium/High)
        - reasons (array of strings)
        - safe_to_visit (boolean)
        - website_type (string: Social Media/Banking/E-commerce/etc.)
        - risk_score (integer 0-100)
        - additional_advice (array of strings)

        Example output:
        {{
            "is_phishing": true,
            "confidence": "High",
            "reasons": [
                "Misspelled domain name (sgbit vs sbi)",
                "No SSL certificate",
                "Suspicious login form"
            ],
            "safe_to_visit": false,
            "website_type": "Fake Banking",
            "risk_score": 87,
            "additional_advice": [
                "Do not enter personal information",
                "Check URL carefully",
                "Report to your IT department"
            ]
        }}"""

        try:
            response = model.generate_content(prompt)
            json_str = response.text.strip().replace('```json', '').replace('```', '')
            result = json.loads(json_str)
            result.update(category_data)  # Add category data
            return result
        except Exception as e:
            return {"error": str(e), "category": "Unknown", "trust_score": 0}

    # Streamlit UI for Phishing Detection page
    st.markdown("""
        <div class="terminal">
            > PROTECT YOURSELF FROM MALICIOUS WEBSITES<br>
            > Enter URL to scan for phishing threats<br>
            > System will analyze website safety
        </div>
    """, unsafe_allow_html=True)
    
    with st.expander("HOW TO USE", expanded=False):
        st.write("""
        1. Enter any website URL
        2. Click 'Analyze' to check for threats
        3. View security analysis
        4. Get safety recommendations
        """)

    url = st.text_input("ENTER URL TO ANALYZE:", placeholder="https://example.com", key="phish_url")

    if st.button("ANALYZE", key="analyze_btn", use_container_width=True):
        if url:
            with st.spinner("SCANNING URL..."):
                # Show scanning animation if available
                if scanning_animation:
                    try:
                        st_lottie(scanning_animation, height=200, key="scanning")
                    except:
                        pass
                
                result = analyze_url(url)
                
                # Send to backend if user is logged in
                if st.session_state.user:
                    try:
                        response = requests.post(f"{BASE_URL}/api/phishing/analyze", json={
                            'url': url,
                            'user_id': st.session_state.user['localId']
                        })
                        if response.status_code != 200:
                            st.warning("Could not save analysis to history")
                    except:
                        pass
                
                time.sleep(1)  # Simulate processing time

            st.subheader("ANALYSIS RESULTS")
            
            # Display result
            if "error" in result:
                st.error(f"ERROR: {result['error']}")
            else:
                # Result container with animation
                with st.container():
                    cols = st.columns([1, 3])
                    with cols[0]:
                        if result['is_phishing']:
                            if danger_animation:
                                try:
                                    st_lottie(danger_animation, height=150, key="danger")
                                except:
                                    pass
                            st.error("DANGEROUS WEBSITE")
                        else:
                            if safe_animation:
                                try:
                                    st_lottie(safe_animation, height=150, key="safe")
                                except:
                                    pass
                            st.success("SAFE WEBSITE")
                    
                    with cols[1]:
                        st.metric("RISK SCORE", f"{result.get('risk_score', 0)}/100", 
                                 delta_color="inverse")
                        st.metric("WEBSITE TYPE", result.get('website_type', 'UNKNOWN'))
                        st.metric("CATEGORY", result.get('category', 'UNKNOWN'))
                
                # Detailed results in expandable sections
                with st.expander("DETAILED ANALYSIS", expanded=True):
                    st.write(f"CONFIDENCE LEVEL: {result['confidence']}")
                    
                    # Risk meter
                    risk_score = result.get('risk_score', 0)
                    st.progress(risk_score/100, text=f"RISK METER: {risk_score}%")
                    
                    # Reasons section
                    st.markdown("### POTENTIAL RISKS")
                    if result.get("reasons"):
                        for reason in result["reasons"]:
                            st.write(f"- {reason}")
                    else:
                        st.write("No specific risks identified")
                    
                    # Advice section
                    st.markdown("### SAFETY RECOMMENDATIONS")
                    if result.get("additional_advice"):
                        for advice in result["additional_advice"]:
                            st.write(f"- {advice}")
                    else:
                        st.write("No specific recommendations")
                
                # Popup notification
                if result['is_phishing']:
                    st.warning("""
                    WARNING: POTENTIAL PHISHING SITE
                    DO NOT ENTER SENSITIVE DATA
                    """, icon="⚠️")
                else:
                    st.balloons()
                    st.success("""
                    CLEAN WEBSITE
                    VERIFY URL BEFORE PROCEEDING
                    """, icon="✅")
                
                # Website comparison (if known)
                if result.get('trust_score', 0) > 0:
                    st.markdown("### TRUST COMPARISON")
                    trust_score = result['trust_score']
                    if trust_score > 80:
                        st.success(f"TRUST SCORE: {trust_score}/100 (HIGH)")
                    elif trust_score > 50:
                        st.warning(f"TRUST SCORE: {trust_score}/100 (MEDIUM)")
                    else:
                        st.error(f"TRUST SCORE: {trust_score}/100 (LOW)")
        else:
            st.warning("ERROR: NO URL PROVIDED")

    # Footer with tips
    st.markdown("---")
    st.markdown("""
    <div class="terminal">
        > SECURITY TIPS:<br>
        > - Check for HTTPS<br>
        > - Verify domain spelling<br>
        > - Beware of unsolicited login pages<br>
        > - Hover over links before clicking
    </div>
    """, unsafe_allow_html=True)

def history_page():
    set_custom_style()
    st.title("📜 SCAN HISTORY")
    
    if not st.session_state.user:
        st.warning("Please login to view your scan history")
    else:
        try:
            response = make_backend_request(f"/api/history/{st.session_state.user['localId']}")
            
            if response and response.get('success'):
                # File Scans
                if response.get('file_scans'):
                    st.subheader("📁 File Scans")
                    file_data = []
                    for scan in response['file_scans']:
                        file_data.append({
                            "Timestamp": scan['timestamp'],
                            "Filename": scan['metadata'].get('filename', 'N/A'),
                            "Status": scan['metadata'].get('status', 'N/A').capitalize(),
                            "Threat Score": f"{scan['metadata'].get('threat_score', 0) * 100:.1f}%",
                            "Hash": scan['metadata'].get('hash', 'N/A')[:8] + "..."
                        })
                    
                    file_df = pd.DataFrame(file_data)
                    st.dataframe(
                        file_df,
                        column_config={
                            "Timestamp": st.column_config.DatetimeColumn("Scan Time"),
                            "Threat Score": st.column_config.ProgressColumn(
                                "Threat Score",
                                help="Threat probability",
                                format="%.1f%%",
                                min_value=0,
                                max_value=100
                            )
                        },
                        use_container_width=True,
                        hide_index=True
                    )
                else:
                    st.info("No file scan history available")
                
                # QR Scans
                if response.get('qr_scans'):
                    st.subheader("📷 QR Scans")
                    qr_data = []
                    for scan in response['qr_scans']:
                        qr_data.append({
                            "Timestamp": scan['timestamp'],
                            "URL": scan['metadata'].get('url', 'N/A'),
                            "Status": "⚠️ Fraud" if scan['metadata'].get('is_fraud') else "✅ Safe",
                            "Confidence": f"{scan['metadata'].get('confidence', 0) * 100:.1f}%"
                        })
                    
                    qr_df = pd.DataFrame(qr_data)
                    st.dataframe(
                        qr_df,
                        column_config={
                            "Timestamp": st.column_config.DatetimeColumn("Scan Time"),
                            "Confidence": st.column_config.ProgressColumn(
                                "Confidence",
                                format="%.1f%%",
                                min_value=0,
                                max_value=100
                            )
                        },
                        use_container_width=True,
                        hide_index=True
                    )
                else:
                    st.info("No QR scan history available")
                
                # Fraud Checks
                if response.get('fraud_checks'):
                    st.subheader("💸 Fraud Checks")
                    fraud_data = []
                    for check in response['fraud_checks']:
                        fraud_data.append({
                            "Timestamp": check['timestamp'],
                            "Status": "⚠️ Fraud" if check['metadata'].get('is_fraud') else "✅ Clean",
                            "Confidence": f"{check['metadata'].get('confidence', 0) * 100:.1f}%",
                            "Amount": f"₹{check['metadata'].get('details', {}).get('amount', 0):,}",
                            "Receiver": check['metadata'].get('details', {}).get('receiver_upi', 'N/A')
                        })
                    
                    fraud_df = pd.DataFrame(fraud_data)
                    st.dataframe(
                        fraud_df,
                        column_config={
                            "Timestamp": st.column_config.DatetimeColumn("Check Time"),
                            "Confidence": st.column_config.ProgressColumn(
                                "Confidence",
                                format="%.1f%%",
                                min_value=0,
                                max_value=100
                            )
                        },
                        use_container_width=True,
                        hide_index=True
                    )
                else:
                    st.info("No fraud check history available")
                
                # Phishing Checks
                if response.get('phishing_checks'):
                    st.subheader("🎣 Phishing Checks")
                    phishing_data = []
                    for check in response['phishing_checks']:
                        phishing_data.append({
                            "Timestamp": check['timestamp'],
                            "URL": check['metadata'].get('url', 'N/A'),
                            "Status": "⚠️ Phishing" if check['metadata'].get('is_phishing') else "✅ Safe",
                            "Confidence": f"{check['metadata'].get('confidence', 0) * 100:.1f}%"
                        })
                    
                    phishing_df = pd.DataFrame(phishing_data)
                    st.dataframe(
                        phishing_df,
                        column_config={
                            "Timestamp": st.column_config.DatetimeColumn("Check Time"),
                            "Confidence": st.column_config.ProgressColumn(
                                "Confidence",
                                format="%.1f%%",
                                min_value=0,
                                max_value=100
                            )
                        },
                        use_container_width=True,
                        hide_index=True
                    )
                else:
                    st.info("No phishing check history available")
                
            else:
                st.error("Failed to fetch history data")
        except Exception as e:
            st.error(f"Error fetching history: {str(e)}")

# --- Main App Flow ---
def main():
    # Check authentication status
    if 'user' not in st.session_state or not st.session_state.user:
        show_auth_ui()
        return
    
    # Set page config for the main app
    st.set_page_config(
        page_title="Threat Guard AI",
        page_icon="💻",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Get current page from navigation
    page = navigation()
    
    # Page routing
    if page == "🏠 HOME":
        home_page()
    elif page == "📁 FILE SCAN":
        file_scan_page()
    elif page == "📷 QR SCAN":
        qr_scan_page()
    elif page == "💸 FRAUD DETECTION":
        fraud_detection_page()
    elif page == "🎣 PHISHING DETECTION":
        phishing_detection_page()
    elif page == "📜 HISTORY":
        history_page()

if __name__ == "__main__":
    main()