# # import streamlit as st
# # import pandas as pd
# # import numpy as np
# # from sklearn.feature_extraction.text import TfidfVectorizer
# # from sklearn.ensemble import RandomForestClassifier
# # import joblib
# # import re
# # import requests
# # from urllib.parse import urlparse
# # import matplotlib.pyplot as plt
# # import seaborn as sns
# # from datetime import datetime, timedelta
# # import nltk
# # from nltk.corpus import stopwords
# # nltk.download('stopwords')

# # # Configuration
# # st.set_page_config(page_title="AI Phishing Detector", page_icon="🛡️", layout="wide")

# # # Mock AI Models (in a real app, these would be pre-trained)
# # def load_models():
# #     # Sample training data
# #     phishing_keywords = ["urgent", "password", "verify", "account", "suspended", 
# #                        "login", "security", "update", "bank", "paypal"]
# #     legitimate_keywords = ["meeting", "project", "report", "team", "schedule"]
    
# #     # Create sample dataset
# #     texts = []
# #     labels = []
# #     for _ in range(1000):
# #         if np.random.rand() > 0.5:
# #             text = " ".join(np.random.choice(phishing_keywords, 5))
# #             texts.append(text)
# #             labels.append(1)
# #         else:
# #             text = " ".join(np.random.choice(legitimate_keywords, 5))
# #             texts.append(text)
# #             labels.append(0)
    
# #     # Train simple models
# #     vectorizer = TfidfVectorizer(stop_words=stopwords.words('english'))
# #     X = vectorizer.fit_transform(texts)
    
# #     email_model = RandomForestClassifier()
# #     email_model.fit(X, labels)
    
# #     return vectorizer, email_model

# # vectorizer, email_model = load_models()

# # # Threat Intelligence Database Simulation
# # class ThreatIntelDB:
# #     def __init__(self):
# #         self.known_phishing_domains = {
# #             "paypa1.com", "secure-login.net", "update-your-info.com",
# #             "amaz0n.com", "appleid-verify.org"
# #         }
# #         self.suspicious_keywords = [
# #             "urgent", "verify", "account", "suspended", "password",
# #             "login", "security", "update", "bank", "immediately"
# #         ]
    
# #     def check_url(self, url):
# #         domain = urlparse(url).netloc
# #         if domain in self.known_phishing_domains:
# #             return {"status": "malicious", "confidence": 0.95}
        
# #         # Check for suspicious patterns
# #         suspicious = False
# #         for kw in self.suspicious_keywords:
# #             if kw in url.lower():
# #                 suspicious = True
# #                 break
                
# #         return {
# #             "status": "suspicious" if suspicious else "clean",
# #             "confidence": 0.85 if suspicious else 0.10
# #         }

# # threat_db = ThreatIntelDB()

# # # UI Components
# # def sidebar():
# #     st.sidebar.title("Settings")
# #     detection_mode = st.sidebar.radio(
# #         "Detection Mode",
# #         ["Standard", "Aggressive", "Permissive"]
# #     )
# #     st.sidebar.info("""
# #     **Aggressive mode:** Higher detection rate but more false positives  
# #     **Standard mode:** Balanced approach  
# #     **Permissive mode:** Fewer false positives but may miss some threats
# #     """)
# #     return detection_mode

# # def analyze_email(email_text):
# #     # Preprocess
# #     email_text = re.sub(r'[^\w\s]', '', email_text.lower())
    
# #     # Vectorize
# #     X = vectorizer.transform([email_text])
    
# #     # Predict
# #     proba = email_model.predict_proba(X)[0][1]
# #     prediction = proba > 0.7
    
# #     # Extract suspicious phrases
# #     suspicious_phrases = []
# #     for word in email_text.split():
# #         if word in threat_db.suspicious_keywords:
# #             suspicious_phrases.append(word)
    
# #     return {
# #         "is_phishing": bool(prediction),
# #         "confidence": float(proba),
# #         "suspicious_phrases": list(set(suspicious_phrases)),
# #         "risk_score": min(100, int(proba * 100))
# #     }

# # def analyze_url(url):
# #     result = threat_db.check_url(url)
    
# #     # Enhance with additional checks
# #     url_length = len(url)
# #     num_subdomains = len(urlparse(url).netloc.split('.'))
# #     has_https = url.startswith('https')
    
# #     # Simple heuristic scoring
# #     score = 0
# #     if not has_https:
# #         score += 20
# #     if url_length > 75:
# #         score += 15
# #     if num_subdomains > 3:
# #         score += 15
    
# #     result['risk_score'] = min(100, int(result['confidence'] * 70 + score))
    
# #     return result

# # def generate_threat_report(email_result, url_result):
# #     report = {
# #         "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
# #         "email_risk": email_result["risk_score"],
# #         "url_risk": url_result["risk_score"],
# #         "combined_risk": max(email_result["risk_score"], url_result["risk_score"]),
# #         "verdict": "Phishing" if (email_result["risk_score"] > 70 or url_result["risk_score"] > 70) else "Legitimate"
# #     }
# #     return report

# # # Main App
# # def main():
# #     st.title("🛡️ AI-Powered Phishing Detection")
# #     st.markdown("""
# #     This system simulates commercial AI phishing detection solutions like **Darktrace** and **Vade Secure**  
# #     using machine learning and threat intelligence to identify phishing attempts in real-time.
# #     """)
    
# #     detection_mode = sidebar()
    
# #     tab1, tab2, tab3 = st.tabs(["Email Analysis", "URL Scanner", "Threat Dashboard"])
    
# #     with tab1:
# #         st.subheader("Email Content Analysis")
# #         email_text = st.text_area("Paste email content here:", height=200)
        
# #         if st.button("Analyze Email"):
# #             if email_text.strip():
# #                 with st.spinner("Analyzing with AI..."):
# #                     result = analyze_email(email_text)
                    
# #                     col1, col2 = st.columns(2)
# #                     with col1:
# #                         st.metric("Phishing Probability", f"{result['confidence']*100:.1f}%")
# #                         st.metric("Risk Score", result["risk_score"])
                        
# #                     with col2:
# #                         if result["is_phishing"]:
# #                             st.error("🚨 Phishing Detected")
# #                         else:
# #                             st.success("✅ Likely Legitimate")
                    
# #                     if result["suspicious_phrases"]:
# #                         st.warning(f"⚠️ Suspicious phrases detected: {', '.join(result['suspicious_phrases'])}")
                    
# #                     # Show explanation
# #                     with st.expander("Analysis Details"):
# #                         st.write("""
# #                         **How this works:**  
# #                         - Natural Language Processing (NLP) analyzes email content  
# #                         - Machine learning model detects phishing patterns  
# #                         - Threat intelligence database checks for known tactics  
# #                         - Behavioral analysis identifies anomalies
# #                         """)
# #             else:
# #                 st.warning("Please enter email content to analyze")
    
# #     with tab2:
# #         st.subheader("URL Scanner")
# #         url = st.text_input("Enter URL to scan:")
        
# #         if st.button("Scan URL"):
# #             if url.startswith(('http://', 'https://')):
# #                 with st.spinner("Scanning with threat intelligence..."):
# #                     result = analyze_url(url)
                    
# #                     col1, col2 = st.columns(2)
# #                     with col1:
# #                         st.metric("Threat Confidence", f"{result['confidence']*100:.1f}%")
# #                         st.metric("Risk Score", result["risk_score"])
                        
# #                     with col2:
# #                         if result["status"] == "malicious":
# #                             st.error("🚨 Known Malicious URL")
# #                         elif result["status"] == "suspicious":
# #                             st.warning("⚠️ Suspicious URL")
# #                         else:
# #                             st.success("✅ Likely Safe")
                    
# #                     # Show explanation
# #                     with st.expander("Scan Details"):
# #                         st.write(f"""
# #                         **URL Analysis Results:**  
# #                         - Domain: `{urlparse(url).netloc}`  
# #                         - Protocol: {'Secure (HTTPS)' if url.startswith('https') else 'Insecure (HTTP)'}  
# #                         - Threat Status: {result['status'].upper()}  
# #                         - Detection Engine: AI + Threat Intelligence  
# #                         """)
# #             else:
# #                 st.warning("Please enter a valid URL (include http:// or https://)")
    
# #     with tab3:
# #         st.subheader("Threat Intelligence Dashboard")
        
# #         # Generate mock historical data
# #         dates = [datetime.now() - timedelta(days=i) for i in range(30)]
# #         threats = np.random.randint(5, 50, size=30)
        
# #         # Create dataframe
# #         df = pd.DataFrame({
# #             "Date": [d.strftime("%Y-%m-%d") for d in dates],
# #             "Threats Detected": threats
# #         })
        
# #         # Plot
# #         fig, ax = plt.subplots(figsize=(10, 4))
# #         sns.lineplot(data=df, x="Date", y="Threats Detected", marker="o", ax=ax)
# #         plt.xticks(rotation=45)
# #         plt.title("Phishing Threats Detected (Last 30 Days)")
# #         st.pyplot(fig)
        
# #         # Stats
# #         col1, col2, col3 = st.columns(3)
# #         col1.metric("Total Threats", f"{sum(threats):,}")
# #         col2.metric("Avg Daily Threats", f"{np.mean(threats):.1f}")
# #         col3.metric("Peak Threats", max(threats))
        
# #         # Top threats
# #         st.subheader("Recent Threat Patterns")
# #         st.write("""
# #         - **Impersonation Attacks:** 42% (Pretending to be known services)  
# #         - **Credential Harvesting:** 33% (Fake login pages)  
# #         - **Malware Distribution:** 15% (Attachments with malware)  
# #         - **Financial Scams:** 10% (Fake invoices/payments)  
# #         """)

# # if __name__ == "__main__":
# #     main()


# # import streamlit as st
# # import requests
# # import whois
# # from datetime import datetime
# # import ssl
# # import socket
# # import time  # For rate limiting

# # # --- Config ---
# # VIRUSTOTAL_API_KEY = "e82fbc7ef0dd2786700b6977b30796118c6ee59aeed5ac43b0421dab16cdbfe5"  # Replace with your VirusTotal API key
# # st.set_page_config(page_title="Phishing Detector", layout="wide")

# # # --- Helper Functions ---
# # def scan_url(url):
# #     """Check URL with VirusTotal"""
# #     headers = {"x-apikey": VIRUSTOTAL_API_KEY}
# #     try:
# #         # Submit URL for scanning
# #         response = requests.post(
# #             "https://www.virustotal.com/api/v3/urls",
# #             headers=headers,
# #             data={"url": url}
# #         )
        
# #         if response.status_code != 200:
# #             st.error(f"API Error: {response.json().get('error', {}).get('message', 'Unknown error')}")
# #             return None
            
# #         url_id = response.json().get("data", {}).get("id")
# #         if not url_id:
# #             st.error("Could not get URL ID from response")
# #             return None
        
# #         # Wait a moment for analysis to complete (free tier limitation)
# #         time.sleep(15)
        
# #         # Get report
# #         report_response = requests.get(
# #             f"https://www.virustotal.com/api/v3/urls/{url_id}",
# #             headers=headers
# #         )
        
# #         if report_response.status_code != 200:
# #             st.error(f"Report fetch failed: {report_response.json().get('error', {}).get('message', 'Unknown error')}")
# #             return None
            
# #         return report_response.json()
# #     except Exception as e:
# #         st.error(f"VirusTotal Error: {str(e)}")
# #         return None

# # def check_domain(domain):
# #     """Check domain reputation"""
# #     headers = {"x-apikey": VIRUSTOTAL_API_KEY}
# #     try:
# #         response = requests.get(
# #             f"https://www.virustotal.com/api/v3/domains/{domain}",
# #             headers=headers
# #         )
# #         return response.json() if response.status_code == 200 else None
# #     except Exception as e:
# #         st.error(f"Domain check failed: {str(e)}")
# #         return None

# # def check_ssl(url):
# #     """Check SSL certificate validity"""
# #     hostname = url.split("//")[-1].split("/")[0]
# #     try:
# #         context = ssl.create_default_context()
# #         with socket.create_connection((hostname, 443), timeout=5) as sock:
# #             with context.wrap_socket(sock, server_hostname=hostname) as ssock:
# #                 cert = ssock.getpeercert()
        
# #         expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
# #         days_left = (expiry_date - datetime.now()).days
# #         issuer = dict(x[0] for x in cert['issuer'])
# #         return {
# #             "issuer": issuer.get('organizationName', 'Unknown'),
# #             "expiry_date": expiry_date,
# #             "days_left": days_left,
# #             "is_valid": days_left > 0
# #         }
# #     except Exception as e:
# #         st.error(f"SSL Error: {str(e)}")
# #         return None

# # def is_new_domain(domain):
# #     """Check if domain is recently registered (likely phishing)"""
# #     try:
# #         domain_info = whois.whois(domain)
# #         creation_date = domain_info.creation_date
# #         if isinstance(creation_date, list):
# #             creation_date = creation_date[0]
# #         age = (datetime.now() - creation_date).days
# #         return age < 30  # Less than 30 days old = suspicious
# #     except Exception as e:
# #         st.error(f"WHOIS Error: {str(e)}")
# #         return False

# # # --- Streamlit UI ---
# # def main():
# #     st.title("🔍 Phishing Website Detector")
# #     st.markdown("Check if a website is **malicious** or **phishing** using VirusTotal.")

# #     # Input URL
# #     url = st.text_input("Enter URL to analyze (e.g., https://example.com)", "")
    
# #     if st.button("Scan Website") and url:
# #         with st.spinner("Analyzing..."):
# #             # --- VirusTotal Scan ---
# #             st.header("🛡️ VirusTotal Report")
# #             report = scan_url(url)
            
# #             if report and "data" in report and "attributes" in report["data"]:
# #                 stats = report["data"]["attributes"].get("last_analysis_stats", {})
# #                 st.write(f"**Malicious Detections:** {stats.get('malicious', 0)}")
# #                 st.write(f"**Suspicious Detections:** {stats.get('suspicious', 0)}")
                
# #                 if stats.get('malicious', 0) > 0:
# #                     st.error("⚠️ **This URL is flagged as malicious!**")
# #                 else:
# #                     st.success("✅ **No threats detected.**")
# #             else:
# #                 st.warning("Could not get valid report from VirusTotal")

# #             # --- Domain Check ---
# #             st.header("🌐 Domain Information")
# #             domain = url.split("//")[-1].split("/")[0]
# #             domain_report = check_domain(domain)
            
# #             if domain_report and "data" in domain_report and "attributes" in domain_report["data"]:
# #                 categories = domain_report["data"]["attributes"].get("categories", {})
# #                 st.write(f"**Categories:** {categories}")
# #                 if "phishing" in str(categories).lower():
# #                     st.error("⚠️ **Phishing domain detected!**")
# #             else:
# #                 st.warning("Could not get domain information")

# #             # --- SSL Check ---
# #             st.header("🔒 SSL Certificate Check")
# #             ssl_info = check_ssl(url)
            
# #             if ssl_info:
# #                 st.write(f"**Issuer:** {ssl_info['issuer']}")
# #                 st.write(f"**Expires on:** {ssl_info['expiry_date']} ({ssl_info['days_left']} days left)")
# #                 if not ssl_info["is_valid"]:
# #                     st.error("⚠️ **SSL Certificate is expired or invalid!**")
# #             else:
# #                 st.warning("Could not verify SSL certificate")

# #             # --- Domain Age Check ---
# #             st.header("📅 Domain Age Check")
# #             if is_new_domain(domain):
# #                 st.warning("⚠️ **This domain is very new (possible phishing).**")
# #             else:
# #                 st.success("✅ **Domain is not recently registered.**")

# # # Run the main function
# # if __name__ == "__main__":
# #     main()



# # import streamlit as st
# # import requests
# # import whois
# # from datetime import datetime
# # import ssl
# # import socket
# # import re
# # from urllib.parse import urlparse
# # import time

# # st.set_page_config(page_title="Phishing Detector", layout="wide")

# # # --- Heuristic Detection Functions ---
# # def check_url_structure(url):
# #     """Analyze URL for suspicious patterns"""
# #     score = 0
# #     warnings = []
    
# #     # Check for IP address instead of domain
# #     domain = urlparse(url).netloc
# #     if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
# #         score += 2
# #         warnings.append("⚠️ Uses IP address instead of domain name")
    
# #     # Check for @ symbol (credentials in URL)
# #     if "@" in url:
# #         score += 2
# #         warnings.append("⚠️ Contains @ symbol (possible credential embedding)")
    
# #     # Check for subdomains length
# #     if len(domain.split(".")) > 3:
# #         score += 1
# #         warnings.append("⚠️ Unusually long subdomain structure")
    
# #     # Check for hyphens in domain
# #     if "-" in domain:
# #         score += 0.5
# #         warnings.append("⚠️ Hyphens in domain (common in phishing)")
    
# #     return score, warnings

# # def check_ssl_certificate(url):
# #     """Verify SSL certificate validity"""
# #     hostname = urlparse(url).netloc
# #     try:
# #         context = ssl.create_default_context()
# #         with socket.create_connection((hostname, 443), timeout=5) as sock:
# #             with context.wrap_socket(sock, server_hostname=hostname) as ssock:
# #                 cert = ssock.getpeercert()
        
# #         issuer = dict(x[0] for x in cert['issuer'])
# #         expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
# #         days_left = (expiry_date - datetime.now()).days
        
# #         return {
# #             "valid": True,
# #             "issuer": issuer.get('organizationName', 'Unknown'),
# #             "expiry_date": expiry_date,
# #             "days_left": days_left,
# #             "self_signed": "organizationName" not in issuer
# #         }
# #     except Exception:
# #         return {"valid": False}

# # def check_domain_age(domain):
# #     """Check if domain is recently registered"""
# #     try:
# #         domain_info = whois.whois(domain)
# #         creation_date = domain_info.creation_date
# #         if isinstance(creation_date, list):
# #             creation_date = creation_date[0]
# #         age = (datetime.now() - creation_date).days if creation_date else 0
# #         return age
# #     except Exception:
# #         return None

# # def check_typosquatting(domain):
# #     """Detect common typosquatting patterns"""
# #     popular_domains = ["paypal", "google", "amazon", "facebook", "apple", "microsoft"]
# #     for legit_domain in popular_domains:
# #         if legit_domain in domain.lower():
# #             # Check for character substitutions
# #             if domain.lower() != legit_domain and len(domain) <= len(legit_domain) + 2:
# #                 return True
# #     return False

# # def analyze_page_content(url):
# #     """Check for common phishing page characteristics"""
# #     try:
# #         response = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
# #         content = response.text.lower()
        
# #         red_flags = 0
# #         warnings = []
        
# #         # Check for login forms
# #         if "login" in content or "password" in content:
# #             red_flags += 1
# #             warnings.append("⚠️ Contains login/password fields")
        
# #         # Check for urgency cues
# #         urgency_phrases = ["verify now", "account suspended", "immediate action", "security alert"]
# #         if any(phrase in content for phrase in urgency_phrases):
# #             red_flags += 1
# #             warnings.append("⚠️ Uses urgency-inducing language")
        
# #         # Check for brand impersonation
# #         brands = ["paypal", "google", "microsoft", "apple", "amazon"]
# #         if any(brand in content for brand in brands):
# #             red_flags += 0.5
# #             warnings.append("⚠️ Mentions popular brand names")
        
# #         return red_flags, warnings
# #     except Exception:
# #         return 0, ["⚠️ Could not fetch page content"]

# # # --- Streamlit UI ---
# # def main():
# #     st.title("🔍 Phishing Website Detector (No API Needed)")
# #     st.markdown("Analyze websites for phishing characteristics using heuristic methods")
    
# #     url = st.text_input("Enter URL to analyze (e.g., https://example.com)", "")
    
# #     if st.button("Analyze Website") and url:
# #         with st.spinner("Running security checks..."):
# #             # Initialize results
# #             total_score = 0
# #             max_score = 10
# #             all_warnings = []
            
# #             # --- URL Structure Analysis ---
# #             st.header("🔗 URL Analysis")
# #             url_score, url_warnings = check_url_structure(url)
# #             total_score += url_score
# #             all_warnings.extend(url_warnings)
            
# #             for warning in url_warnings:
# #                 st.warning(warning)
            
# #             # Check for typosquatting
# #             domain = urlparse(url).netloc
# #             if check_typosquatting(domain):
# #                 total_score += 2
# #                 all_warnings.append("⚠️ Possible typosquatting detected")
# #                 st.error("🚨 Possible typosquatting detected!")
            
# #             # --- SSL Certificate Check ---
# #             st.header("🔒 SSL Certificate")
# #             ssl_info = check_ssl_certificate(url)
            
# #             if not ssl_info["valid"]:
# #                 total_score += 2
# #                 all_warnings.append("⚠️ No valid SSL certificate")
# #                 st.error("🚨 No valid SSL certificate!")
# #             else:
# #                 st.write(f"**Issuer:** {ssl_info['issuer']}")
# #                 st.write(f"**Expires:** {ssl_info['expiry_date']} ({ssl_info['days_left']} days remaining)")
                
# #                 if ssl_info["self_signed"]:
# #                     total_score += 1
# #                     all_warnings.append("⚠️ Self-signed certificate detected")
# #                     st.warning("Self-signed certificate (less trustworthy)")
            
# #             # --- Domain Age Check ---
# #             st.header("📅 Domain Age")
# #             domain_age = check_domain_age(domain)
            
# #             if domain_age is not None:
# #                 st.write(f"**Domain age:** {domain_age} days")
# #                 if domain_age < 30:
# #                     total_score += 1.5
# #                     all_warnings.append("⚠️ Newly registered domain (<30 days)")
# #                     st.warning("New domain (common with phishing sites)")
# #             else:
# #                 st.warning("Could not verify domain age")
            
# #             # --- Page Content Analysis ---
# #             st.header("📄 Page Content")
# #             content_score, content_warnings = analyze_page_content(url)
# #             total_score += content_score
# #             all_warnings.extend(content_warnings)
            
# #             for warning in content_warnings:
# #                 st.warning(warning)
            
# #             # --- Final Assessment ---
# #             st.header("📊 Risk Assessment")
# #             risk_percentage = min(int((total_score / max_score) * 100), 100)
            
# #             st.progress(risk_percentage)
# #             st.write(f"**Phishing probability:** {risk_percentage}%")
            
# #             if risk_percentage > 70:
# #                 st.error("🚨 HIGH RISK: Likely phishing website!")
# #             elif risk_percentage > 40:
# #                 st.warning("⚠️ MEDIUM RISK: Suspicious characteristics detected")
# #             else:
# #                 st.success("✅ LOW RISK: No obvious phishing indicators found")
            
# #             # Show all warnings
# #             if all_warnings:
# #                 st.header("🔍 All Detected Warnings")
# #                 for warning in set(all_warnings):  # Remove duplicates
# #                     st.write(warning)

# # if __name__ == "__main__":
# #     main()




# # for real time detection 

# # import streamlit as st
# # import requests
# # import re
# # import socket
# # import ssl
# # import whois
# # from urllib.parse import urlparse
# # from datetime import datetime

# # # --- Configuration ---
# # st.set_page_config(page_title="Real-Time Phishing Detector", layout="wide")

# # # --- Free API Endpoints ---
# # PHISHTANK_API = "http://checkurl.phishtank.com/checkurl/"
# # GOOGLE_TRANSPARENCY_API = "https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status?site="

# # # --- Advanced Heuristic Checks ---
# # def advanced_heuristic_checks(url):
# #     """Comprehensive phishing detection without ML"""
# #     risk_score = 0
# #     warnings = []
# #     parsed = urlparse(url)
# #     domain = parsed.netloc
    
# #     # 1. URL Structure Analysis
# #     if len(url) > 75:
# #         risk_score += 15
# #         warnings.append("⚠️ Long URL (common in phishing)")
    
# #     if url.count('.') > 5:
# #         risk_score += 10
# #         warnings.append("⚠️ Too many dots in URL")
    
# #     if '@' in url:
# #         risk_score += 20
# #         warnings.append("🚨 Contains @ symbol (credential embedding attempt)")
    
# #     # 2. Domain Analysis
# #     if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
# #         risk_score += 25
# #         warnings.append("🚨 Uses IP address instead of domain")
    
# #     if '-' in domain:
# #         risk_score += 5
# #         warnings.append("⚠️ Hyphen in domain (suspicious)")
    
# #     # 3. SSL/TLS Verification
# #     try:
# #         ctx = ssl.create_default_context()
# #         with socket.create_connection((domain, 443), timeout=3) as sock:
# #             with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
# #                 cert = ssock.getpeercert()
# #                 issuer = dict(x[0] for x in cert['issuer'])
# #                 if 'organizationName' not in issuer:
# #                     risk_score += 20
# #                     warnings.append("⚠️ Self-signed SSL certificate")
# #     except:
# #         risk_score += 30
# #         warnings.append("🚨 No SSL certificate or connection failed")

# #     # 4. Domain Age Check
# #     try:
# #         dom_info = whois.whois(domain)
# #         if dom_info.creation_date:
# #             cr_date = dom_info.creation_date[0] if isinstance(dom_info.creation_date, list) else dom_info.creation_date
# #             age_days = (datetime.now() - cr_date).days
# #             if age_days < 30:
# #                 risk_score += 15
# #                 warnings.append(f"⚠️ New domain ({age_days} days old)")
# #     except:
# #         pass

# #     # 5. Content Analysis (Basic)
# #     try:
# #         resp = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
# #         content = resp.text.lower()
        
# #         # Check for login forms
# #         if ('<input type="password"' in content) or ('<form' in content and ('login' in content or 'password' in content)):
# #             risk_score += 10
# #             warnings.append("⚠️ Contains password input field")
        
# #         # Check for brand names
# #         brands = ['paypal', 'bank', 'amazon', 'ebay', 'facebook', 'apple']
# #         if any(brand in content for brand in brands):
# #             risk_score += 5
# #             warnings.append("⚠️ Mentions well-known brand")
# #     except:
# #         pass

# #     return min(risk_score, 100), warnings

# # # --- Free API Checks ---
# # def check_phishtank(url):
# #     """PhishTank public API check"""
# #     try:
# #         response = requests.post(
# #             PHISHTANK_API,
# #             data={'url': url, 'format': 'json'},
# #             headers={'User-Agent': 'phishtank/streamlit'},
# #             timeout=5
# #         )
# #         if response.status_code == 200:
# #             return response.json().get('results', {}).get('valid', False)
# #     except:
# #         pass
# #     return False

# # def check_google_safebrowsing(url):
# #     """Google Transparency Report check"""
# #     try:
# #         domain = urlparse(url).netloc
# #         response = requests.get(f"{GOOGLE_TRANSPARENCY_API}{domain}", timeout=5)
# #         if response.status_code == 200:
# #             return "malicious" in response.text.lower()
# #     except:
# #         pass
# #     return False

# # # --- Streamlit UI ---
# # def main():
# #     st.title("🔍 Real-Time Phishing Detector")
# #     st.markdown("No ML models required - uses advanced heuristics and free APIs")
    
# #     url = st.text_input("Enter URL to analyze:", "https://")
    
# #     if st.button("Analyze") and url:
# #         with st.spinner("Running comprehensive checks..."):
# #             # Run all checks
# #             heuristic_score, warnings = advanced_heuristic_checks(url)
# #             phishtank_result = check_phishtank(url)
# #             google_result = check_google_safebrowsing(url)
            
# #             # Calculate composite score
# #             final_score = heuristic_score
# #             if phishtank_result:
# #                 final_score += 30
# #             if google_result:
# #                 final_score += 25
# #             final_score = min(final_score, 100)
            
# #             # Display results
# #             col1, col2 = st.columns(2)
            
# #             with col1:
# #                 st.subheader("Security Assessment")
# #                 st.progress(final_score)
# #                 st.metric("Risk Score", f"{final_score}/100")
                
# #                 if final_score >= 70:
# #                     st.error("🚨 HIGH RISK: Likely phishing website!")
# #                 elif final_score >= 40:
# #                     st.warning("⚠️ MEDIUM RISK: Suspicious characteristics")
# #                 else:
# #                     st.success("✅ LOW RISK: Appears legitimate")
                
# #                 st.metric("PhishTank Verified", "✅ Yes" if phishtank_result else "❌ No")
# #                 st.metric("Google Safebrowsing", "⚠️ Blocked" if google_result else "✅ Clean")
            
# #             with col2:
# #                 st.subheader("Detailed Findings")
# #                 if not warnings:
# #                     st.success("No suspicious elements detected")
# #                 else:
# #                     for warning in set(warnings):  # Remove duplicates
# #                         if warning.startswith("🚨"):
# #                             st.error(warning)
# #                         else:
# #                             st.warning(warning)
            
# #             # Technical details
# #             with st.expander("Technical Details"):
# #                 st.write(f"**Analyzed URL:** `{url}`")
# #                 st.write(f"**Domain:** `{urlparse(url).netloc}`")
# #                 st.write(f"**Heuristic Score:** {heuristic_score}/100")
# #                 st.write(f"**PhishTank Match:** {phishtank_result}")
# #                 st.write(f"**Google Safebrowsing:** {google_result}")

# # if __name__ == "__main__":
# #     main()
# import streamlit as st
# import pandas as pd
# import numpy as np
# import joblib
# from urllib.parse import urlparse
# import re
# import matplotlib.pyplot as plt

# # Page configuration
# st.set_page_config(
#     page_title="Phishing URL Detector",
#     page_icon="🔍",
#     layout="wide",
#     initial_sidebar_state="expanded"
# )

# # Custom CSS
# st.markdown("""
# <style>
#     .main {
#         background-color: #f8f9fa;
#     }
#     .report {
#         padding: 20px;
#         border-radius: 10px;
#         margin-bottom: 20px;
#         transition: all 0.3s ease;
#     }
#     .safe {
#         background-color: #d4edda;
#         border-left: 5px solid #28a745;
#     }
#     .warning {
#         background-color: #fff3cd;
#         border-left: 5px solid #ffc107;
#     }
#     .danger {
#         background-color: #f8d7da;
#         border-left: 5px solid #dc3545;
#         animation: pulse 2s infinite;
#     }
#     @keyframes pulse {
#         0% { box-shadow: 0 0 0 0 rgba(220, 53, 69, 0.4); }
#         70% { box-shadow: 0 0 0 10px rgba(220, 53, 69, 0); }
#         100% { box-shadow: 0 0 0 0 rgba(220, 53, 69, 0); }
#     }
#     .feature-card {
#         background-color: white;
#         border-radius: 10px;
#         padding: 15px;
#         margin-bottom: 10px;
#         box-shadow: 0 2px 4px rgba(0,0,0,0.1);
#     }
# </style>
# """, unsafe_allow_html=True)

# # Load model
# @st.cache_resource
# def load_model():
#     try:
#         model = joblib.load('models/phishing_detector.pkl')
#         st.sidebar.success("Model loaded successfully")
#         return model
#     except Exception as e:
#         st.sidebar.error(f"Error loading model: {str(e)}")
#         return None

# model = load_model()

# # Threat type mapping
# threat_types = {
#     0: ('Benign', '✅', 'safe', 'This URL appears safe'),
#     1: ('Defacement', '⚠️', 'warning', 'Possible website defacement risk'),
#     2: ('Phishing', '🛑', 'danger', 'High probability of phishing attempt'),
#     3: ('Malware', '☠️', 'danger', 'Malware distribution risk detected')
# }

# # Feature extraction
# def extract_features(url):
#     try:
#         parsed = urlparse(url)
        
#         features = {
#             'use_of_ip': 1 if re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc) else 0,
#             'abnormal_url': 1 if parsed.netloc and not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', parsed.netloc) else 0,
#             'google_index': 0,  # Placeholder - would require API call
#             'count.': url.count('.'),
#             'count-www': 1 if parsed.netloc.startswith('www.') else 0,
#             'count@': url.count('@'),
#             'count_dir': parsed.path.count('/') - 1 if parsed.path else 0,
#             'count_embed_domain': len(parsed.netloc.split('.')) - 2 if parsed.netloc.count('.') > 1 else 0,
#             'sus_url': len(re.findall(r'(login|secure|account|verify|update|bank)', url.lower())),
#             'short_url': 1 if any(x in parsed.netloc for x in ['bit.ly', 'goo.gl', 'tinyurl']) else 0,
#             'count_https': 1 if url.startswith('https://') else 0,
#             'count_http': 1 if url.startswith('http://') else 0,
#             'count%': url.count('%'),
#             'count?': url.count('?'),
#             'count-': url.count('-'),
#             'count=': url.count('='),
#             'url_length': len(url),
#             'hostname_length': len(parsed.netloc),
#             'fd_length': len(parsed.path.split('/')[0]) if parsed.path else 0,
#             'tld_length': len(parsed.netloc.split('.')[-1]),
#             'count_digits': sum(c.isdigit() for c in url),
#             'count_letters': sum(c.isalpha() for c in url),
#         }
#         return pd.DataFrame([features])
#     except Exception as e:
#         st.error(f"Error extracting features: {str(e)}")
#         return None

# # Prediction function
# def predict_url(url):
#     features = extract_features(url)
#     if features is not None and model is not None:
#         try:
#             prediction = model.predict(features)[0]
#             probabilities = model.predict_proba(features)[0]
#             return prediction, probabilities, features
#         except Exception as e:
#             st.error(f"Prediction error: {str(e)}")
#     return None, None, None

# # Main app
# def main():
#     st.title("Phishing URL Detection System")
#     st.markdown("Analyze URLs for potential phishing, malware, and other security threats")
    
#     col1, col2 = st.columns([2, 1])
    
#     with col1:
#         url_input = st.text_input("Enter URL to analyze:", "https://www.example.com")
        
#         if st.button("Analyze URL", type="primary"):
#             with st.spinner("Analyzing URL features..."):
#                 prediction, probabilities, features = predict_url(url_input)
                
#                 if prediction is not None:
#                     name, icon, alert_class, description = threat_types[prediction]
                    
#                     # Display results
#                     st.markdown(f"""
#                     <div class="report {alert_class}">
#                         <h2>{icon} {name}</h2>
#                         <p>{description}</p>
#                         <p><strong>Confidence:</strong> {probabilities[prediction]*100:.1f}%</p>
#                     </div>
#                     """, unsafe_allow_html=True)
                    
#                     # Show probability distribution
#                     st.subheader("Threat Probability Distribution")
#                     prob_df = pd.DataFrame({
#                         'Threat Type': [threat_types[i][0] for i in range(4)],
#                         'Probability': [f"{p*100:.1f}%" for p in probabilities],
#                         'Value': probabilities
#                     }).sort_values('Value', ascending=False)
                    
#                     fig, ax = plt.subplots()
#                     colors = ['#28a745' if i == 0 else '#ffc107' if i == 1 else '#dc3545' for i in range(4)]
#                     ax.barh(prob_df['Threat Type'], prob_df['Value'], color=colors)
#                     ax.set_xlim(0, 1)
#                     ax.set_title('Prediction Probabilities')
#                     st.pyplot(fig)
                    
#                     # Show important features
#                     st.subheader("Key Detection Features")
#                     if hasattr(model, 'feature_importances_'):
#                         feature_importance = pd.DataFrame({
#                             'Feature': features.columns,
#                             'Importance': model.feature_importances_
#                         }).sort_values('Importance', ascending=False).head(10)
                        
#                         fig2, ax2 = plt.subplots()
#                         ax2.barh(feature_importance['Feature'], feature_importance['Importance'])
#                         ax2.set_title('Top 10 Important Features')
#                         st.pyplot(fig2)
                    
#                     # Show all extracted features
#                     with st.expander("View All Extracted Features"):
#                         st.dataframe(features.T.style.background_gradient(cmap='Blues'))
    
#     with col2:
#         st.markdown("""
#         ### About This Tool
#         This system analyzes URLs for malicious characteristics using machine learning.
        
#         **Detects:**
#         - Phishing attempts
#         - Malware distribution sites
#         - Website defacement
#         - Suspicious URL patterns
        
#         **How it works:**
#         1. Extracts 21 security-relevant features
#         2. Uses a trained Random Forest model
#         3. Evaluates threat probability
#         """)
        
#         st.markdown("""
#         ### Example URLs to Test
#         **Safe:**
#         - `https://www.google.com`
#         - `https://github.com`
        
#         **Suspicious:**
#         - `http://free-gift-cards.com`
#         - `https://login-facebook.xyz`
        
#         **Malicious:**
#         - `http://paypal-secure-login.com`
#         - `http://192.168.1.1/login.php`
#         """)

# if __name__ == "__main__":
#     main()

# import streamlit as st
# import google.generativeai as genai

# # Configure Gemini (Use your actual API key)
# GEMINI_API_KEY = "AIzaSyCeP2xZuyEsPTWFzZ92voUmcM5rz8YsoNQ"  # 🔴 Replace with your key
# genai.configure(api_key=GEMINI_API_KEY)

# # Use the correct model name for your API version
# try:
#     model = genai.GenerativeModel('gemini-pro')  # Try default name
# except:
#     # Fallback to newer model name if needed
#     model = genai.GenerativeModel('gemini-1.0-pro')

# def analyze_website_safety(url):
#     prompt = f"""Analyze this URL for phishing: {url}
#     Return a JSON response with:
#     - "is_phishing": boolean
#     - "confidence": "Low/Medium/High"
#     - "reasons": [list of reasons]
#     Example: {{"is_phishing": true, "confidence": "High", "reasons": ["misspelled domain"]}}"""
    
#     try:
#         response = model.generate_content(prompt)
#         return response.text
#     except Exception as e:
#         return {"error": str(e)}

# # Streamlit UI
# st.title("🔍 Phishing Detector (Gemini)")
# url = st.text_input("Enter URL:")
# if st.button("Check"):
#     if url:
#         with st.spinner("Analyzing..."):
#             result = analyze_website_safety(url)
#             st.subheader("Result")
#             if "error" in str(result):
#                 st.error(f"Error: {result}")
#             else:
#                 try:
#                     # Try to parse as JSON
#                     import json
#                     st.json(json.loads(result.replace('```json','').replace('```','').strip()))
#                 except:
#                     st.code(result)  # Fallback to raw output
#     else:
#         st.warning("Please enter a URL")

import streamlit as st
import google.generativeai as genai
import json
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure Gemini
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

# Specify the new model
model_name = 'gemini-1.5-flash'
try:
    model = genai.GenerativeModel(model_name)
    st.info(f"Using model: {model_name}")
except Exception as e:
    st.error(f"Error loading model '{model_name}': {e}")
    st.stop()

def analyze_url(url):
    """Analyze URL for phishing and return JSON output"""
    prompt = f"""Analyze this URL for phishing risk: {url}
    Respond with ONLY a valid JSON object containing:
    - is_phishing (boolean)
    - confidence (string: Low/Medium/High)
    - reasons (array of strings)
    - safe_to_visit (boolean)

    Example output:
    {{
        "is_phishing": true,
        "confidence": "High",
        "reasons": [
            "Misspelled domain name",
            "No SSL certificate",
            "Suspicious login form"
        ],
        "safe_to_visit": false
    }}"""

    try:
        response = model.generate_content(prompt)
        # Extract JSON from response
        json_str = response.text.strip().replace('```json', '').replace('```', '')
        return json.loads(json_str)
    except Exception as e:
        return {"error": str(e)}

# Streamlit UI
st.title("🔒 Advanced Phishing Detector")
url = st.text_input("Enter URL to analyze:", placeholder="https://example.com")

if st.button("Analyze"):
    if url:
        with st.spinner("Scanning URL..."):
            result = analyze_url(url)

        st.subheader("Analysis Results")
        if "error" in result:
            st.error(f"Error: {result['error']}")
        else:
            st.json(result)

            # Display formatted results
            st.markdown("### Summary")
            st.write(f"**Phishing Risk:** {'✅ Low' if not result['is_phishing'] else '❌ High'}")
            st.write(f"**Confidence:** {result['confidence']}")
            st.write(f"**Safe to Visit:** {'Yes' if result['safe_to_visit'] else 'No'}")

            st.markdown("### Reasons")
            for reason in result["reasons"]:
                st.write(f"- {reason}")
    else:
        st.warning("Please enter a URL")

st.caption("Note: Uses Google Gemini AI for phishing detection")