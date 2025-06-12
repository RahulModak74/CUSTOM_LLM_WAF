"""
Request Parser module - Parse nginx auth requests
"""

from sanic import Request
from models import AuthRequest


class RequestParser:
    """Parse incoming nginx auth requests"""
    
    def parse_nginx_request(self, request: Request) -> AuthRequest:
        """Parse nginx auth request from Sanic request"""
        return AuthRequest(
            method=self._get_header(request, "X-Original-Method", request.method),
            uri=self._get_header(request, "X-Original-URI", request.path),
            client_ip=self._extract_client_ip(request),
            user_agent=self._get_header(request, "X-Original-User-Agent", ""),
            referer=self._get_header(request, "X-Original-Referer", ""),
            cookie=self._get_header(request, "X-Original-Cookie", ""),
            host=self._get_header(request, "X-Original-Host", ""),
            accept_lang=self._get_header(request, "X-Original-Accept-Language", ""),
            accept_enc=self._get_header(request, "X-Original-Accept-Encoding", ""),
            request_id=self._get_header(request, "X-Request-ID", ""),
            request_body=self._get_request_body(request)  # Add this line
        )
    def _get_request_body(self, request: Request) -> str:  # Add this entire method
     """Get request body as string"""
     try:
        if hasattr(request, 'body') and request.body:
            return request.body.decode('utf-8', errors='ignore')
        elif hasattr(request, 'form') and request.form:
            # Handle form data
            form_parts = []
            for key, value in request.form.items():
                form_parts.append(f"{key}={value}")
            return "&".join(form_parts)
        return ""
     except Exception:
        return ""
    
    def _get_header(self, request: Request, key: str, default: str = "") -> str:
        """Get header value with default"""
        return request.headers.get(key, default)
    
    def _extract_client_ip(self, request: Request) -> str:
        """Extract client IP from various headers"""
        # Try X-Original-Remote-Addr first (nginx forward)
        if ip := request.headers.get("X-Original-Remote-Addr"):
            return ip.split(":")[0]
        
        # Try X-Real-IP
        if ip := request.headers.get("X-Real-IP"):
            return ip
        
        # Try X-Forwarded-For
        if forwarded := request.headers.get("X-Forwarded-For"):
            return forwarded.split(",")[0].strip()
        
        # Fallback to request IP
        return request.ip.split(":")[0] if request.ip else "127.0.0.1"
