"""
Security Headers Module
Add this file as: security_modules/security_headers.py
"""

from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum


class CSPDirective(Enum):
    """Content Security Policy directive types"""
    DEFAULT_SRC = "default-src"
    SCRIPT_SRC = "script-src"
    STYLE_SRC = "style-src"
    IMG_SRC = "img-src"
    CONNECT_SRC = "connect-src"
    FONT_SRC = "font-src"
    OBJECT_SRC = "object-src"
    MEDIA_SRC = "media-src"
    FRAME_SRC = "frame-src"
    WORKER_SRC = "worker-src"
    CHILD_SRC = "child-src"
    FORM_ACTION = "form-action"
    FRAME_ANCESTORS = "frame-ancestors"
    BASE_URI = "base-uri"
    UPGRADE_INSECURE_REQUESTS = "upgrade-insecure-requests"
    BLOCK_ALL_MIXED_CONTENT = "block-all-mixed-content"


@dataclass
class SecurityHeadersConfig:
    """Configuration for security headers"""
    # Content Security Policy
    enable_csp: bool = True
    csp_policy: Dict[str, List[str]] = None
    csp_report_only: bool = False
    csp_report_uri: Optional[str] = None
    
    # HSTS (HTTP Strict Transport Security)
    enable_hsts: bool = True
    hsts_max_age: int = 31536000  # 1 year
    hsts_include_subdomains: bool = True
    hsts_preload: bool = False
    
    # Frame options
    enable_frame_options: bool = True
    frame_options: str = "DENY"  # DENY, SAMEORIGIN, ALLOW-FROM
    
    # Content type options
    enable_content_type_options: bool = True
    
    # XSS Protection
    enable_xss_protection: bool = True
    
    # Referrer Policy
    enable_referrer_policy: bool = True
    referrer_policy: str = "strict-origin-when-cross-origin"
    
    # Feature Policy / Permissions Policy
    enable_permissions_policy: bool = True
    permissions_policy: Dict[str, List[str]] = None
    
    # Additional security headers
    enable_expect_ct: bool = False
    expect_ct_max_age: int = 86400
    expect_ct_enforce: bool = False
    expect_ct_report_uri: Optional[str] = None


class SecurityHeadersManager:
    """Manage HTTP security headers"""
    
    def __init__(self, config: SecurityHeadersConfig = None):
        self.config = config or SecurityHeadersConfig()
        
        # Default CSP policy if not provided
        if self.config.csp_policy is None:
            self.config.csp_policy = self._get_default_csp_policy()
        
        # Default permissions policy if not provided
        if self.config.permissions_policy is None:
            self.config.permissions_policy = self._get_default_permissions_policy()
    
    def _get_default_csp_policy(self) -> Dict[str, List[str]]:
        """Get default Content Security Policy"""
        return {
            CSPDirective.DEFAULT_SRC.value: ["'self'"],
            CSPDirective.SCRIPT_SRC.value: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
            CSPDirective.STYLE_SRC.value: ["'self'", "'unsafe-inline'"],
            CSPDirective.IMG_SRC.value: ["'self'", "data:", "https:"],
            CSPDirective.CONNECT_SRC.value: ["'self'"],
            CSPDirective.FONT_SRC.value: ["'self'", "https:"],
            CSPDirective.OBJECT_SRC.value: ["'none'"],
            CSPDirective.MEDIA_SRC.value: ["'self'"],
            CSPDirective.FRAME_SRC.value: ["'none'"],
            CSPDirective.FRAME_ANCESTORS.value: ["'none'"],
            CSPDirective.FORM_ACTION.value: ["'self'"],
            CSPDirective.BASE_URI.value: ["'self'"],
            CSPDirective.UPGRADE_INSECURE_REQUESTS.value: [],
        }
    
    def _get_default_permissions_policy(self) -> Dict[str, List[str]]:
        """Get default Permissions Policy"""
        return {
            "geolocation": ["'none'"],
            "microphone": ["'none'"],
            "camera": ["'none'"],
            "payment": ["'none'"],
            "usb": ["'none'"],
            "gyroscope": ["'none'"],
            "magnetometer": ["'none'"],
            "accelerometer": ["'none'"],
            "fullscreen": ["'self'"],
        }
    
    def generate_headers(self, request_uri: str = "", is_https: bool = True) -> Dict[str, str]:
        """Generate all security headers"""
        headers = {}
        
        # Content Security Policy
        if self.config.enable_csp:
            csp_header = self._generate_csp_header()
            header_name = "Content-Security-Policy-Report-Only" if self.config.csp_report_only else "Content-Security-Policy"
            headers[header_name] = csp_header
        
        # HTTP Strict Transport Security (only for HTTPS)
        if self.config.enable_hsts and is_https:
            headers["Strict-Transport-Security"] = self._generate_hsts_header()
        
        # X-Frame-Options
        if self.config.enable_frame_options:
            headers["X-Frame-Options"] = self.config.frame_options
        
        # X-Content-Type-Options
        if self.config.enable_content_type_options:
            headers["X-Content-Type-Options"] = "nosniff"
        
        # X-XSS-Protection
        if self.config.enable_xss_protection:
            headers["X-XSS-Protection"] = "1; mode=block"
        
        # Referrer-Policy
        if self.config.enable_referrer_policy:
            headers["Referrer-Policy"] = self.config.referrer_policy
        
        # Permissions-Policy
        if self.config.enable_permissions_policy:
            headers["Permissions-Policy"] = self._generate_permissions_policy_header()
        
        # Expect-CT (for certificate transparency)
        if self.config.enable_expect_ct and is_https:
            headers["Expect-CT"] = self._generate_expect_ct_header()
        
        # Additional security headers
        headers.update({
            "X-Permitted-Cross-Domain-Policies": "none",
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
        })
        
        return headers
    
    def _generate_csp_header(self) -> str:
        """Generate Content Security Policy header value"""
        directives = []
        
        for directive, sources in self.config.csp_policy.items():
            if sources:
                directive_str = f"{directive} {' '.join(sources)}"
            else:
                directive_str = directive
            directives.append(directive_str)
        
        # Add report URI if configured
        if self.config.csp_report_uri:
            directives.append(f"report-uri {self.config.csp_report_uri}")
        
        return "; ".join(directives)
    
    def _generate_hsts_header(self) -> str:
        """Generate HSTS header value"""
        hsts_parts = [f"max-age={self.config.hsts_max_age}"]
        
        if self.config.hsts_include_subdomains:
            hsts_parts.append("includeSubDomains")
        
        if self.config.hsts_preload:
            hsts_parts.append("preload")
        
        return "; ".join(hsts_parts)
    
    def _generate_permissions_policy_header(self) -> str:
        """Generate Permissions Policy header value"""
        policies = []
        
        for feature, allowlist in self.config.permissions_policy.items():
            if allowlist:
                policy_str = f"{feature}=({' '.join(allowlist)})"
            else:
                policy_str = f"{feature}=()"
            policies.append(policy_str)
        
        return ", ".join(policies)
    
    def _generate_expect_ct_header(self) -> str:
        """Generate Expect-CT header value"""
        ct_parts = [f"max-age={self.config.expect_ct_max_age}"]
        
        if self.config.expect_ct_enforce:
            ct_parts.append("enforce")
        
        if self.config.expect_ct_report_uri:
            ct_parts.append(f'report-uri="{self.config.expect_ct_report_uri}"')
        
        return ", ".join(ct_parts)
    
    def validate_csp_violation(self, violation_report: dict) -> Dict[str, any]:
        """Validate and analyze CSP violation reports"""
        analysis = {
            "is_valid": False,
            "violation_type": "unknown",
            "risk_level": "LOW",
            "blocked_uri": "",
            "violated_directive": "",
            "source_file": "",
            "line_number": 0,
            "recommendations": []
        }
        
        try:
            csp_report = violation_report.get("csp-report", {})
            
            analysis.update({
                "is_valid": True,
                "blocked_uri": csp_report.get("blocked-uri", ""),
                "violated_directive": csp_report.get("violated-directive", ""),
                "source_file": csp_report.get("source-file", ""),
                "line_number": csp_report.get("line-number", 0),
                "original_policy": csp_report.get("original-policy", "")
            })
            
            # Analyze violation type and risk
            blocked_uri = analysis["blocked_uri"]
            directive = analysis["violated_directive"]
            
            if "script-src" in directive:
                if "unsafe-inline" in blocked_uri or "javascript:" in blocked_uri:
                    analysis["violation_type"] = "inline_script"
                    analysis["risk_level"] = "HIGH"
                    analysis["recommendations"].append("Remove inline scripts or add nonce/hash")
                elif "unsafe-eval" in blocked_uri:
                    analysis["violation_type"] = "script_eval"
                    analysis["risk_level"] = "MEDIUM"
                    analysis["recommendations"].append("Avoid eval() and similar functions")
                else:
                    analysis["violation_type"] = "external_script"
                    analysis["risk_level"] = "MEDIUM"
                    analysis["recommendations"].append("Add script domain to CSP whitelist if trusted")
            
            elif "style-src" in directive:
                analysis["violation_type"] = "style_violation"
                analysis["risk_level"] = "LOW"
                analysis["recommendations"].append("Add style source to CSP or use nonce/hash")
            
            elif "img-src" in directive:
                analysis["violation_type"] = "image_violation"
                analysis["risk_level"] = "LOW"
                analysis["recommendations"].append("Add image source to CSP whitelist")
            
            elif "frame-src" in directive or "frame-ancestors" in directive:
                analysis["violation_type"] = "frame_violation"
                analysis["risk_level"] = "HIGH"
                analysis["recommendations"].append("Review frame embedding - potential clickjacking")
            
        except Exception as e:
            analysis["violation_type"] = "parse_error"
            analysis["risk_level"] = "MEDIUM"
            analysis["recommendations"].append(f"Error parsing CSP report: {str(e)}")
        
        return analysis
    
    def get_secure_headers_for_api(self) -> Dict[str, str]:
        """Get security headers specifically for API endpoints"""
        return {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'none'",
            "Cross-Origin-Resource-Policy": "same-origin",
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
            "Pragma": "no-cache",
            "Expires": "0"
        }
    
    def get_headers_for_file_upload(self) -> Dict[str, str]:
        """Get security headers for file upload endpoints"""
        return {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "Cross-Origin-Resource-Policy": "same-origin",
            "Cache-Control": "no-store"
        }
    
    def customize_csp_for_route(self, route_type: str) -> Dict[str, str]:
        """Customize CSP for specific route types"""
        csp_policies = {
            "admin": {
                CSPDirective.DEFAULT_SRC.value: ["'self'"],
                CSPDirective.SCRIPT_SRC.value: ["'self'"],
                CSPDirective.STYLE_SRC.value: ["'self'"],
                CSPDirective.FRAME_ANCESTORS.value: ["'none'"],
                CSPDirective.FORM_ACTION.value: ["'self'"],
            },
            "api": {
                CSPDirective.DEFAULT_SRC.value: ["'none'"],
            },
            "public": {
                CSPDirective.DEFAULT_SRC.value: ["'self'"],
                CSPDirective.SCRIPT_SRC.value: ["'self'", "'unsafe-inline'"],
                CSPDirective.STYLE_SRC.value: ["'self'", "'unsafe-inline'"],
                CSPDirective.IMG_SRC.value: ["'self'", "data:", "https:"],
            }
        }
        
        policy = csp_policies.get(route_type, self.config.csp_policy)
        
        # Generate CSP header
        directives = []
        for directive, sources in policy.items():
            if sources:
                directive_str = f"{directive} {' '.join(sources)}"
            else:
                directive_str = directive
            directives.append(directive_str)
        
        return {"Content-Security-Policy": "; ".join(directives)}


class SubresourceIntegrityManager:
    """Manage Subresource Integrity (SRI) for external resources"""
    
    def __init__(self):
        self.known_hashes = {
            # Common CDN resources with their SRI hashes
            "https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css": 
                "sha384-1BmE4kWBq78iYhFldvKuhfTAU6auU8tT94WrHftjDbrCEXSU1oBoqyl2QvZ6jIW3",
            "https://code.jquery.com/jquery-3.6.0.min.js": 
                "sha384-vtXRMe3mGCbOeY7l30aIg8H9p3GdeSe4IFlP6G8JMa7o7lXvnz3GFKzPxzJdPfGK",
        }
    
    def generate_sri_hash(self, content: bytes, algorithm: str = "sha384") -> str:
        """Generate SRI hash for content"""
        import hashlib
        import base64
        
        if algorithm == "sha256":
            hash_obj = hashlib.sha256()
        elif algorithm == "sha384":
            hash_obj = hashlib.sha384()
        elif algorithm == "sha512":
            hash_obj = hashlib.sha512()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        hash_obj.update(content)
        hash_digest = base64.b64encode(hash_obj.digest()).decode()
        
        return f"{algorithm}-{hash_digest}"
    
    def get_sri_attributes(self, url: str) -> Dict[str, str]:
        """Get SRI attributes for a URL"""
        if url in self.known_hashes:
            return {
                "integrity": self.known_hashes[url],
                "crossorigin": "anonymous"
            }
        return {}
    
    def validate_sri_hash(self, content: bytes, expected_hash: str) -> bool:
        """Validate content against expected SRI hash"""
        try:
            algorithm, expected_digest = expected_hash.split('-', 1)
            actual_hash = self.generate_sri_hash(content, algorithm)
            return actual_hash == expected_hash
        except (ValueError, KeyError):
            return False
