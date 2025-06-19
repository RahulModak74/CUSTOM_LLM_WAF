"""
Updated Response Builder module - Build auth responses with security headers
Replace your existing response_builder.py with this version
"""

from sanic import response
from models import AuthResponse
from security_modules.security_headers import SecurityHeadersManager, SecurityHeadersConfig


class ResponseBuilder:
    """Build authentication responses with enhanced security headers"""
    
    def __init__(self):
        # Initialize security headers manager
        self.security_headers = SecurityHeadersManager()
    
    def send_auth_response(self, auth_response: AuthResponse, debug: bool = False, 
                          request_uri: str = "", is_https: bool = True):
        """Send authentication response with security headers"""
        headers = {
            "X-Session-ID": auth_response.session_id,
            "X-Threat-Level": auth_response.threat_level,
            "X-Anomaly-Score": str(auth_response.anomaly_score),
            "X-Response-Time": f"{auth_response.response_time_ms}ms"
        }
        
        # Add comprehensive security headers
        security_headers = self.security_headers.generate_headers(request_uri, is_https)
        headers.update(security_headers)
        
        # Add API-specific headers for auth endpoint
        api_headers = self.security_headers.get_secure_headers_for_api()
        headers.update(api_headers)
        
        # Override some CSP settings for auth endpoint
        if not auth_response.allow:
            # For blocked requests, use stricter CSP
            headers["Content-Security-Policy"] = "default-src 'none'"
        
        if debug:
            # In debug mode, return JSON with full details
            response_data = {
                **auth_response.dict(),
                "security_headers_applied": len(security_headers),
                "timestamp": auth_response.response_time_ms
            }
            return response.json(response_data, status=auth_response.status, headers=headers)
        else:
            # In production mode, return simple text response
            if auth_response.allow:
                return response.text("OK", status=auth_response.status, headers=headers)
            else:
                return response.text(auth_response.message, status=auth_response.status, headers=headers)
    
    def send_json(self, data: dict, status: int = 200, secure: bool = True):
        """Send JSON response with optional security headers"""
        headers = {}
        
        if secure:
            # Add security headers for JSON responses
            security_headers = self.security_headers.get_secure_headers_for_api()
            headers.update(security_headers)
            
            # JSON-specific security headers
            headers.update({
                "Content-Type": "application/json; charset=utf-8",
                "X-Content-Type-Options": "nosniff"
            })
        
        return response.json(data, status=status, headers=headers)
    
    def send_error(self, message: str, status: int = 500, threat_level: str = "HIGH"):
        """Send error response with security headers"""
        headers = {
            "X-Threat-Level": threat_level,
            "Content-Security-Policy": "default-src 'none'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store"
        }
        
        return response.text(message, status=status, headers=headers)
    
    def send_health_response(self, health_data: dict):
        """Send health check response"""
        # Health endpoints get minimal security headers
        headers = {
            "Cache-Control": "no-cache, max-age=60",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'"
        }
        
        return response.json(health_data, headers=headers)
    
    def send_stats_response(self, stats_data: dict):
        """Send statistics response with caching"""
        headers = {
            "Cache-Control": "private, max-age=30",
            "X-Content-Type-Options": "nosniff", 
            "Content-Security-Policy": "default-src 'none'"
        }
        
        return response.json(stats_data, headers=headers)
