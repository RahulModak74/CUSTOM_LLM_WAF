"""
CSRF (Cross-Site Request Forgery) Protection Module
Add this file as: security_modules/csrf_protection.py
"""

import secrets
import hmac
import hashlib
import time
import json
from typing import Optional, Tuple
from dataclasses import dataclass


@dataclass
class CSRFResult:
    """CSRF validation result"""
    is_valid: bool
    message: str
    token: Optional[str] = None
    risk_level: str = "LOW"


class CSRFProtection:
    """CSRF token generation and validation"""
    
    def __init__(self, secret_key: str = None):
        self.secret_key = secret_key or secrets.token_hex(32)
        self.token_lifetime = 3600  # 1 hour in seconds
        self.trusted_origins = set()
        
        # State-changing methods that require CSRF protection
        self.protected_methods = {'POST', 'PUT', 'DELETE', 'PATCH'}
        
        # Safe HTTP methods that don't need CSRF protection
        self.safe_methods = {'GET', 'HEAD', 'OPTIONS', 'TRACE'}
    
    def add_trusted_origin(self, origin: str):
        """Add a trusted origin for CSRF validation"""
        self.trusted_origins.add(origin.lower())
    
    def generate_token(self, session_id: str) -> str:
        """Generate a CSRF token for a session"""
        timestamp = str(int(time.time()))
        
        # Create token data
        token_data = f"{session_id}:{timestamp}"
        
        # Generate HMAC signature
        signature = hmac.new(
            self.secret_key.encode(),
            token_data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Combine data and signature
        token = f"{token_data}:{signature}"
        
        # Base64 encode for safe transport
        import base64
        return base64.b64encode(token.encode()).decode()
    
    def validate_token(self, token: str, session_id: str) -> CSRFResult:
        """Validate a CSRF token"""
        if not token:
            return CSRFResult(False, "CSRF token missing", risk_level="HIGH")
        
        try:
            # Decode token
            import base64
            decoded_token = base64.b64decode(token.encode()).decode()
            
            # Parse token components
            parts = decoded_token.split(':')
            if len(parts) != 3:
                return CSRFResult(False, "Invalid CSRF token format", risk_level="HIGH")
            
            token_session_id, timestamp, signature = parts
            
            # Verify session ID matches
            if token_session_id != session_id:
                return CSRFResult(False, "CSRF token session mismatch", risk_level="CRITICAL")
            
            # Check token age
            current_time = int(time.time())
            token_time = int(timestamp)
            
            if current_time - token_time > self.token_lifetime:
                return CSRFResult(False, "CSRF token expired", risk_level="MEDIUM")
            
            # Verify signature
            expected_data = f"{token_session_id}:{timestamp}"
            expected_signature = hmac.new(
                self.secret_key.encode(),
                expected_data.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(signature, expected_signature):
                return CSRFResult(False, "CSRF token signature invalid", risk_level="CRITICAL")
            
            return CSRFResult(True, "CSRF token valid")
            
        except Exception as e:
            return CSRFResult(False, f"CSRF token validation error: {str(e)}", risk_level="HIGH")
    
    def validate_request(self, method: str, headers: dict, form_data: dict, 
                        session_id: str) -> CSRFResult:
        """Validate a request for CSRF protection"""
        # Skip validation for safe methods
        if method.upper() in self.safe_methods:
            return CSRFResult(True, "Safe HTTP method, CSRF not required")
        
        # Require CSRF protection for state-changing methods
        if method.upper() in self.protected_methods:
            return self._validate_state_changing_request(headers, form_data, session_id)
        
        return CSRFResult(True, "Method not subject to CSRF protection")
    
    def _validate_state_changing_request(self, headers: dict, form_data: dict, 
                                       session_id: str) -> CSRFResult:
        """Validate state-changing request for CSRF"""
        # Check Origin header first (primary defense)
        origin_result = self._validate_origin(headers)
        if not origin_result.is_valid and origin_result.risk_level == "CRITICAL":
            return origin_result
        
        # Check Referer header as fallback
        referer_result = self._validate_referer(headers)
        
        # Check CSRF token (strongest protection)
        token_result = self._validate_csrf_token(headers, form_data, session_id)
        
        # If we have a valid token, that's sufficient
        if token_result.is_valid:
            return token_result
        
        # If origin validation passed, that might be sufficient for some cases
        if origin_result.is_valid:
            return CSRFResult(True, "CSRF validated via Origin header (consider adding token)")
        
        # If referer validation passed, that's weaker but better than nothing
        if referer_result.is_valid:
            return CSRFResult(True, "CSRF validated via Referer header (weak, add token)", 
                            risk_level="MEDIUM")
        
        # No valid CSRF protection found
        return CSRFResult(False, "No valid CSRF protection found", risk_level="CRITICAL")
    
    def _validate_origin(self, headers: dict) -> CSRFResult:
        """Validate Origin header"""
        origin = headers.get('Origin', '').lower()
        
        if not origin:
            return CSRFResult(False, "Origin header missing", risk_level="MEDIUM")
        
        # Check against trusted origins
        if origin in self.trusted_origins:
            return CSRFResult(True, "Origin header validated")
        
        # Extract host from current request
        host = headers.get('Host', '').lower()
        if host and origin.endswith(f'//{host}'):
            return CSRFResult(True, "Origin matches request host")
        
        return CSRFResult(False, f"Untrusted origin: {origin}", risk_level="CRITICAL")
    
    def _validate_referer(self, headers: dict) -> CSRFResult:
        """Validate Referer header (weaker than Origin)"""
        referer = headers.get('Referer', '').lower()
        
        if not referer:
            return CSRFResult(False, "Referer header missing", risk_level="MEDIUM")
        
        host = headers.get('Host', '').lower()
        if host and host in referer:
            return CSRFResult(True, "Referer header validated")
        
        return CSRFResult(False, f"Referer doesn't match host: {referer}", risk_level="HIGH")
    
    def _validate_csrf_token(self, headers: dict, form_data: dict, 
                           session_id: str) -> CSRFResult:
        """Validate CSRF token from various sources"""
        # Try to get token from different sources
        token = None
        
        # 1. Check X-CSRFToken header
        token = headers.get('X-CSRFToken') or headers.get('X-CSRF-Token')
        
        # 2. Check form data
        if not token:
            token = form_data.get('csrf_token') or form_data.get('_token')
        
        # 3. Check Cookie (for double-submit pattern)
        if not token:
            cookies = headers.get('Cookie', '')
            import re
            cookie_match = re.search(r'csrf_token=([^;]+)', cookies)
            if cookie_match:
                token = cookie_match.group(1)
        
        if not token:
            return CSRFResult(False, "CSRF token not found in request", risk_level="HIGH")
        
        return self.validate_token(token, session_id)
    
    def get_csrf_headers(self, session_id: str) -> dict:
        """Get headers to include CSRF token in response"""
        token = self.generate_token(session_id)
        
        return {
            'X-CSRF-Token': token,
            'Set-Cookie': f'csrf_token={token}; HttpOnly; Secure; SameSite=Strict'
        }
    
    def is_csrf_attack(self, method: str, headers: dict, form_data: dict, 
                      session_id: str) -> Tuple[bool, str]:
        """Check if request appears to be a CSRF attack"""
        result = self.validate_request(method, headers, form_data, session_id)
        
        if not result.is_valid and result.risk_level in ['HIGH', 'CRITICAL']:
            return True, result.message
        
        return False, result.message


class DoubleSubmitCSRF:
    """Double Submit Cookie CSRF Protection (stateless)"""
    
    def __init__(self, secret_key: str = None):
        self.secret_key = secret_key or secrets.token_hex(32)
    
    def generate_token_pair(self) -> Tuple[str, str]:
        """Generate token pair for double-submit pattern"""
        # Generate random token
        random_token = secrets.token_urlsafe(32)
        
        # Create signed version for cookie
        signature = hmac.new(
            self.secret_key.encode(),
            random_token.encode(),
            hashlib.sha256
        ).hexdigest()
        
        signed_token = f"{random_token}.{signature}"
        
        return random_token, signed_token
    
    def validate_double_submit(self, form_token: str, cookie_token: str) -> CSRFResult:
        """Validate double-submit CSRF tokens"""
        if not form_token or not cookie_token:
            return CSRFResult(False, "Missing CSRF tokens", risk_level="HIGH")
        
        try:
            # Parse cookie token
            if '.' not in cookie_token:
                return CSRFResult(False, "Invalid cookie token format", risk_level="HIGH")
            
            token_value, signature = cookie_token.rsplit('.', 1)
            
            # Verify signature
            expected_signature = hmac.new(
                self.secret_key.encode(),
                token_value.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(signature, expected_signature):
                return CSRFResult(False, "Cookie token signature invalid", risk_level="CRITICAL")
            
            # Compare tokens
            if not hmac.compare_digest(form_token, token_value):
                return CSRFResult(False, "CSRF tokens don't match", risk_level="CRITICAL")
            
            return CSRFResult(True, "Double-submit CSRF validation passed")
            
        except Exception as e:
            return CSRFResult(False, f"CSRF validation error: {str(e)}", risk_level="HIGH")
