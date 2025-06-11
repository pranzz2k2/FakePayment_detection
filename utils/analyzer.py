
import os
import magic
import hashlib
import math
import re
from datetime import datetime

# Known malicious indicators
KNOWN_MALICIOUS_HASHES = [
    "a1b2c3d4e5f6...",  # Example ransomware hash
    "7g8h9i0j1k2l3...",  # Example malicious PDF hash
    "4m5n6o7p8q9r0..."   # Example malicious DOCX hash
]

SUSPICIOUS_PATTERNS = [
    r"(?i)(?:<\s*script[^>]*>.*?<\s*/\s*script\s*>|javascript:)",  # Script tags/js
    r"(?i)(?:eval\s*\(|unescape\s*\()",  # Dangerous JS functions
    r"(?i)(?:powershell|cmd\.exe|wscript\.shell|mshta)",  # Shell commands
    r"(?i)(?:macro\s*enabled|auto_open)",  # Office macros
    r"(?i)(?:\\x[0-9a-f]{2}|%[0-9a-f]{2}){5,}",  # Hex/URL encoding (5+ consecutive)
    r"(?i)(?:https?://(?:[^\s/$.?#].[^\s]*))"  # URLs (more precise)
]

def calculate_entropy(file_path):
    """Calculate the entropy of a file to detect potential encryption/obfuscation"""
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

def get_file_hash(filepath):
    """Calculate SHA256 hash of a file"""
    with open(filepath, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

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
        return [{'error': str(e)}]

def analyze_file(filepath, filename):
    """Analyze a file for potential threats with improved accuracy"""
    try:
        # Basic file info
        mime_type = magic.from_file(filepath, mime=True)
        file_hash = get_file_hash(filepath)
        
        # Known malicious check
        if file_hash in KNOWN_MALICIOUS_HASHES:
            return {
                'filename': filename,
                'status': 'malicious',
                'threat_score': 1.0,
                'method': 'signature',
                'details': 'Matched known malicious file signature',
                'mime_type': mime_type,
                'hash': file_hash
            }
        
        # Calculate metrics
        entropy = calculate_entropy(filepath)
        suspicious_findings = scan_for_suspicious_content(filepath)
        valid_patterns = [p for p in suspicious_findings if isinstance(p, dict)]
        
        # -- Improved Threat Scoring --
        base_score = 0.05  # Baseline for clean files
        
        # 1. Entropy Analysis (weight: 40%)
        if entropy > 6.5:  # Normal range is typically 4.5-6.5
            entropy_factor = min((entropy - 6.5) / 2.5, 1)  # Normalize 6.5-9.0 to 0-1
            base_score += entropy_factor * 0.4
        
        # 2. Suspicious Content (weight: 50%)
        if valid_patterns:
            # Basic pattern count scoring
            pattern_score = min(len(valid_patterns) * 0.1, 0.5)
            
            # High-risk pattern boost
            dangerous_patterns = {
                r'eval\s*\(': 0.3,      # JavaScript eval
                r'powershell': 0.25,     # PowerShell
                r'cmd\.exe': 0.25,      # Command prompt
                r'\\x[0-9a-f]{2}': 0.2, # Hex encoding
                r'http[s]?://': 0.1      # URLs
            }
            
            for pattern in valid_patterns:
                for dangerous_pattern, score_boost in dangerous_patterns.items():
                    if re.search(dangerous_pattern, pattern['pattern'], re.IGNORECASE):
                        pattern_score = min(pattern_score + score_boost, 0.7)
                        break
            
            base_score += pattern_score
        
        # 3. File Type Risk (weight: 10%)
        risky_types = {
            'application/x-msdownload': 0.3,       # Executables
            'application/x-msdos-program': 0.3,    # DOS programs
            'application/x-dosexec': 0.3,         # Windows executables
            'application/vnd.ms-office': 0.2,      # Office documents
            'application/x-shockwave-flash': 0.2   # Flash files
        }
        base_score += risky_types.get(mime_type, 0)
        
        # Final score adjustment
        threat_score = min(round(base_score, 2), 1.0)
        
        # Status determination
        if threat_score >= 0.85:
            status = 'malicious'
            details = "High confidence of malicious content"
        elif threat_score >= 0.6:
            status = 'suspicious'
            details = "Suspicious characteristics detected"
        else:
            status = 'safe'
            details = "No significant threats detected"
        
        return {
            'filename': filename,
            'status': status,
            'threat_score': threat_score,
            'method': 'heuristic',
            'details': details,
            'mime_type': mime_type,
            'entropy': round(entropy, 4),
            'hash': file_hash,
            'suspicious_patterns': valid_patterns,
            'timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        return {
            'filename': filename,
            'status': 'error',
            'threat_score': 0,
            'method': 'error',
            'details': str(e),
            'mime_type': '',
            'entropy': 0,
            'hash': ''
        }
    
    # """Comprehensive file analysis with multiple detection methods"""
    # try:
    #     # Basic file info
    #     mime_type = magic.from_file(filepath, mime=True)
    #     file_size = os.path.getsize(filepath)
    #     file_hash = get_file_hash(filepath)
        
    #     # Check against known malicious hashes
    #     if file_hash in KNOWN_MALICIOUS_HASHES:
    #         return {
    #             'filename': filename,
    #             'status': 'malicious',
    #             'threat_score': 1.0,
    #             'method': 'signature',
    #             'details': 'Matched known malicious file signature',
    #             'mime_type': mime_type,
    #             'file_size': file_size,
    #             'entropy': 0,
    #             'hash': file_hash,
    #             'suspicious_patterns': []
    #         }
        
    #     # Calculate entropy
    #     entropy = calculate_entropy(filepath)
        
    #     # Scan for suspicious content
    #     suspicious_findings = scan_for_suspicious_content(filepath)
        
    #     # Calculate threat score
    #     base_score = 0
        
    #     # Adjust score based on entropy
    #     entropy_factor = min(max((entropy - 4) / 4, 0), 1)  # Normalize 4-8 to 0-1
    #     base_score += entropy_factor * 0.4
        
    #     # Adjust score for suspicious patterns
    #     if suspicious_findings and not isinstance(suspicious_findings[0], dict):
    #         # Error case
    #         pass
    #     elif suspicious_findings:
    #         pattern_score = min(len(suspicious_findings) * 0.2, 0.6)
    #         base_score += pattern_score
        
    #     # Adjust score for file type
    #     if mime_type in ['application/x-msdownload', 'application/x-msdos-program']:
    #         base_score += 0.2
    #     elif mime_type in ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
    #         base_score += 0.1
        
    #     # Cap the score at 1.0
    #     threat_score = min(round(base_score, 2), 1.0)
        
    #     # Determine status
    #     if threat_score > 0.85:
    #         status = 'malicious'
    #         details = "High threat score based on multiple factors"
    #     elif threat_score > 0.6:
    #         status = 'suspicious'
    #         details = "Suspicious characteristics detected"
    #     else:
    #         status = 'safe'
    #         details = "No significant threats detected"
        
    #     # Prepare results
    #     result = {
    #         'filename': filename,
    #         'status': status,
    #         'threat_score': threat_score,
    #         'method': 'heuristic',
    #         'details': details,
    #         'mime_type': mime_type,
    #         'file_size': file_size,
    #         'entropy': round(entropy, 4),
    #         'hash': file_hash,
    #         'suspicious_patterns': suspicious_findings if suspicious_findings and isinstance(suspicious_findings[0], dict) else []
    #     }
        
    #     return result
    
    # except Exception as e:
    #     return {
    #         'filename': filename,
    #         'status': 'error',
    #         'threat_score': 0,
    #         'method': 'error',
    #         'details': str(e),
    #         'mime_type': '',
    #         'file_size': 0,
    #         'entropy': 0,
    #         'hash': '',
    #         'suspicious_patterns': []
    #     }