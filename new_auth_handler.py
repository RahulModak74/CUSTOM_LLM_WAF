"""
Updated Auth Handler module - Main authentication logic with enhanced security
Replace your existing auth_handler.py with this version
"""

import time
import logging
import urllib.parse
from datetime import datetime
from sanic import Request, response
from auth_server import AuthServer
from request_parser import RequestParser
from response_builder import ResponseBuilder
from server_stats import StatsCollector
from models import AuthRequest, AuthResponse, WAFResult, SessionResult

# NEW: Import additional security modules
from security_modules.waf_context import WAFContext
from security_modules.ssrf_detector import SSRFDetector
from security_modules.csrf_protection import CSRFProtection
from security_modules.security_headers import SecurityHeadersManager, SecurityHeadersConfig
from security_modules.request_smuggling_detector import RequestSmugglingDetector


class AuthHandler:
    """Handle authentication requests with enhanced security"""
    
    def __init__(self, server: AuthServer, parser: RequestParser, 
                 responder: ResponseBuilder, stats: StatsCollector, mode: str):
        self.server = server
        self.parser = parser
        self.responder = responder
        self.stats = stats
        self.mode = mode
        self.logger = logging.getLogger(__name__)
        
        # NEW: Initialize additional security modules
        self.ssrf_detector = SSRFDetector()
        self.csrf_protection = CSRFProtection()
        self.security_headers = SecurityHeadersManager()
        self.smuggling_detector = RequestSmugglingDetector()
        
        # Configure CSRF protection with trusted origins
        if mode == "local":
            self.csrf_protection.add_trusted_origin("http://localhost")
            self.csrf_protection.add_trusted_origin("http://127.0.0.1")
        
        # Security event counters
        self.security_stats = {
            "ssrf_blocked": 0,
            "csrf_blocked": 0,
            "smuggling_blocked": 0,
            "total_security_blocks": 0
        }
    
    async def handle_auth(self, request: Request):
        """Handle authentication request"""
        start_time = datetime.now()
        self.stats.increment_total()
        
        # Handle preflight OPTIONS request
        if request.method == "OPTIONS":
            return self._handle_options(request)
        
        # Set mode-specific headers
        headers = self._get_mode_specific_headers()
        
        # Parse the incoming request
        auth_req = self.parser.parse_nginx_request(request)
        
        # Debug logging
        if self.server.config.debug:
            self.logger.info(
                f"🔍 [{self.mode.upper()}] Auth request: {auth_req.method} {auth_req.uri} "
                f"from {auth_req.client_ip} (UA: {auth_req.user_agent})"
            )
        
        # Process authentication with enhanced security
        auth_response = await self._process_auth_enhanced(auth_req, start_time)
        
        # Update statistics
        if auth_response.allow:
            self.stats.increment_allowed()
            if self.server.config.debug:
                self.logger.info(
                    f"✅ [{self.mode.upper()}] Request ALLOWED: {auth_req.method} {auth_req.uri} "
                    f"(Session: {auth_response.session_id}, Score: {auth_response.anomaly_score})"
                )
        else:
            self.stats.increment_blocked()
            if self.server.config.debug:
                self.logger.warning(
                    f"🚫 [{self.mode.upper()}] Request BLOCKED: {auth_req.method} {auth_req.uri} "
                    f"- {auth_response.message} (Score: {auth_response.anomaly_score})"
                )
        
        # Build response with enhanced headers
        is_https = request.scheme == "https" or request.headers.get("X-Forwarded-Proto") == "https"
        sanic_response = self.responder.send_auth_response(
            auth_response, 
            self.server.config.debug,
            auth_req.uri,
            is_https
        )
        
        # Add mode-specific headers
        for key, value in headers.items():
            sanic_response.headers[key] = value
        
        # NEW: Add CSRF token for valid sessions
        if auth_response.allow and auth_response.session_id:
            csrf_headers = self.csrf_protection.get_csrf_headers(auth_response.session_id)
            for key, value in csrf_headers.items():
                sanic_response.headers[key] = value
        
        return sanic_response
    
    def _handle_options(self, request: Request):
        """Handle OPTIONS preflight request"""
        headers = self._get_mode_specific_headers()
        
        # NEW: Add security headers to OPTIONS responses
        security_headers = self.security_headers.get_secure_headers_for_api()
        headers.update(security_headers)
        
        return response.text("", status=200, headers=headers)
    
    def _get_mode_specific_headers(self) -> dict:
        """Get headers based on mode"""
        common_headers = {
            "X-Auth-Server": "nginx-security-enhanced",
            "X-Security-Modules": "WAF,Sessions,SSRF,CSRF,Headers,Smuggling",
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
            "X-Auth-Mode": self.mode
        }
        
        if self.mode == "local":
            common_headers.update({
                "Access-Control-Allow-Origin": "http://localhost:*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization, X-CSRF-Token"
            })
        else:  # remote
            common_headers.update({
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS, HEAD",
                "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With, X-CSRF-Token",
                "Access-Control-Expose-Headers": "X-Session-ID, X-Threat-Level, X-Anomaly-Score, X-CSRF-Token"
            })
        
        return common_headers
    
    async def _process_auth_enhanced(self, req: AuthRequest, start_time: datetime) -> AuthResponse:
        """Process authentication request with enhanced security checks"""
        auth_response = AuthResponse(
            allow=True,
            status=200,
            threat_level="LOW",
            message="Authentication successful",
            anomaly_score=0,
            response_time_ms=0
        )
        
        # NEW: Step 0 - Check for Request Smuggling
        smuggling_result = self.smuggling_detector.analyze_request(
            raw_headers=self._build_raw_headers(req),
            body=req.request_body
        )
        
        if smuggling_result.is_smuggling:
            auth_response.allow = False
            auth_response.status = 400
            auth_response.message = f"Request Smuggling: {smuggling_result.message}"
            auth_response.threat_level = "CRITICAL"
            auth_response.anomaly_score += 10
            
            self.security_stats["smuggling_blocked"] += 1
            self.security_stats["total_security_blocks"] += 1
            
            if self.server.config.debug:
                self.logger.critical(
                    f"🚨 [{self.mode.upper()}] REQUEST SMUGGLING: {smuggling_result.message} "
                    f"- Attack Type: {smuggling_result.attack_type}"
                )
            
            auth_response.response_time_ms = int((datetime.now() - start_time).total_seconds() * 1000)
            return auth_response
        
        # NEW: Step 0.5 - Check for SSRF attempts
        ssrf_result = self.ssrf_detector.analyze_request(
            method=req.method,
            uri=req.uri,
            request_body=req.request_body,
            headers={
                'User-Agent': req.user_agent,
                'Referer': req.referer,
                'Host': req.host,
                'Accept-Language': req.accept_lang,
                'Accept-Encoding': req.accept_enc
            }
        )
        
        if ssrf_result.is_ssrf:
            auth_response.allow = False
            auth_response.status = 403
            auth_response.message = f"SSRF: {ssrf_result.message}"
            auth_response.threat_level = "CRITICAL" if ssrf_result.risk_level == "CRITICAL" else "HIGH"
            auth_response.anomaly_score += 8
            
            self.security_stats["ssrf_blocked"] += 1
            self.security_stats["total_security_blocks"] += 1
            
            if self.server.config.debug:
                self.logger.critical(
                    f"🚨 [{self.mode.upper()}] SSRF DETECTED: {ssrf_result.message} "
                    f"- Risk: {ssrf_result.risk_level}, URLs: {ssrf_result.detected_urls}"
                )
            
            auth_response.response_time_ms = int((datetime.now() - start_time).total_seconds() * 1000)
            return auth_response
        
        # Step 1: WAF Analysis (Primary security check) - EXISTING
        waf_result = await self._run_waf(req)
        auth_response.anomaly_score += waf_result.score
        
        if not waf_result.allow:
            auth_response.allow = False
            auth_response.status = 403
            auth_response.message = f"WAF: {waf_result.message}"
            auth_response.threat_level = "HIGH"
            auth_response.response_time_ms = int((datetime.now() - start_time).total_seconds() * 1000)
            
            if self.server.config.debug:
                self.logger.warning(
                    f"🛡️  [{self.mode.upper()}] WAF BLOCK: {waf_result.message} (Score: {waf_result.score})"
                )
            
            return auth_response
        
        # Step 2: Session Management and Rate Limiting - EXISTING
        session_result = await self._run_session_check(req)
        auth_response.session_id = session_result.session_id
        
        if not session_result.allow:
            auth_response.allow = False
            auth_response.status = 429
            auth_response.message = f"Session: {session_result.message}"
            auth_response.threat_level = "MEDIUM"
            
            if self.server.config.debug:
                self.logger.warning(
                    f"🔄 [{self.mode.upper()}] SESSION BLOCK: {session_result.message} "
                    f"(Session: {session_result.session_id})"
                )
        
        # NEW: Step 3 - CSRF Protection for state-changing requests
        if req.method.upper() in ['POST', 'PUT', 'DELETE', 'PATCH'] and auth_response.allow:
            csrf_result = await self._check_csrf_protection(req, auth_response.session_id)
            
            if not csrf_result.is_valid and csrf_result.risk_level in ['HIGH', 'CRITICAL']:
                auth_response.allow = False
                auth_response.status = 403
                auth_response.message = f"CSRF: {csrf_result.message}"
                auth_response.threat_level = "HIGH"
                auth_response.anomaly_score += 6
                
                self.security_stats["csrf_blocked"] += 1
                self.security_stats["total_security_blocks"] += 1
                
                if self.server.config.debug:
                    self.logger.warning(
                        f"🛡️  [{self.mode.upper()}] CSRF BLOCK: {csrf_result.message}"
                    )
        
        # Calculate final response time
        auth_response.response_time_ms = int((datetime.now() - start_time).total_seconds() * 1000)
        
        # Mode-specific processing
        if self.mode == "remote":
            auth_response.message += " (remote-enhanced)"
        else:
            auth_response.message += " (local-enhanced)"
        
        return auth_response
    
    async def _check_csrf_protection(self, req: AuthRequest, session_id: str):
        """Check CSRF protection for request"""
        # Parse form data from request body
        form_data = self._parse_form_data(req.request_body)
        
        # Build headers dict for CSRF validation
        headers = {
            'Origin': self._extract_origin_from_referer(req.referer),
            'Host': req.host,
            'Cookie': req.cookie,
            'Referer': req.referer,
            'X-CSRF-Token': '',  # Will be extracted if present in actual headers
        }
        
        # Check for CSRF token in cookie
        if req.cookie:
            import re
            csrf_match = re.search(r'csrf_token=([^;]+)', req.cookie)
            if csrf_match:
                headers['X-CSRF-Token'] = csrf_match.group(1)
        
        return self.csrf_protection.validate_request(
            method=req.method,
            headers=headers,
            form_data=form_data,
            session_id=session_id
        )
    
    def _extract_origin_from_referer(self, referer: str) -> str:
        """Extract origin from referer header"""
        if not referer:
            return ""
        
        try:
            import urllib.parse
            parsed = urllib.parse.urlparse(referer)
            return f"{parsed.scheme}://{parsed.netloc}"
        except:
            return ""
    
    def _build_raw_headers(self, req: AuthRequest) -> str:
        """Build raw headers string for smuggling detection"""
        headers = []
        
        if req.host:
            headers.append(f"Host: {req.host}")
        if req.user_agent:
            headers.append(f"User-Agent: {req.user_agent}")
        if req.referer:
            headers.append(f"Referer: {req.referer}")
        if req.cookie:
            headers.append(f"Cookie: {req.cookie}")
        if req.accept_lang:
            headers.append(f"Accept-Language: {req.accept_lang}")
        if req.accept_enc:
            headers.append(f"Accept-Encoding: {req.accept_enc}")
        
        # Add Content-Length if we have request body
        if req.request_body:
            content_length = len(req.request_body.encode('utf-8'))
            headers.append(f"Content-Length: {content_length}")
        
        return '\n'.join(headers)
    
    def _parse_form_data(self, request_body: str) -> dict:
        """Parse form data from request body"""
        form_data = {}
        if not request_body:
            return form_data
        
        try:
            # Handle URL-encoded form data
            parsed = urllib.parse.parse_qs(request_body)
            for key, values in parsed.items():
                form_data[key] = values[0] if values else ''
        except Exception as e:
            if self.server.config.debug:
                self.logger.warning(f"Failed to parse form data: {e}")
        
        return form_data
    
    async def _run_waf(self, req: AuthRequest) -> WAFResult:
        """Run WAF analysis - EXISTING METHOD WITH ENHANCEMENTS"""
        # Create WAF context
        ctx = WAFContext(
            method=req.method,
            uri=req.uri,
            client_ip=req.client_ip,
            user_agent=req.user_agent,
            referer=req.referer,
            cookie=req.cookie,
            host=req.host,
            accept_language=req.accept_lang,
            accept_encoding=req.accept_enc,
            request_body=req.request_body
        )
        
        # Extract variables for WAF rules
        self.server.waf_engine.extract_variables(ctx)
        
        # Run WAF evaluation in phases
        from security_modules.rule import PhaseRequestHeaders, PhaseRequestBody
        blocked1 = self.server.waf_engine.evaluate_rules(ctx, PhaseRequestHeaders)
        blocked2 = self.server.waf_engine.evaluate_rules(ctx, PhaseRequestBody)
        
        blocked = blocked1 or blocked2
        message = "WAF analysis complete"
        
        if blocked:
            message = "; ".join(ctx.log_messages) if ctx.log_messages else "WAF rules triggered"
        
        # Enhanced logging for different modes
        if self.server.config.debug and blocked:
            self.logger.warning(
                f"🛡️  [{self.mode.upper()}] WAF Details - IP: {req.client_ip}, "
                f"URI: {req.uri}, UA: {req.user_agent}, Score: {ctx.anomaly_score}"
            )
        
        return WAFResult(
            allow=not blocked,
            message=message,
            score=ctx.anomaly_score
        )
    
    async def _run_session_check(self, req: AuthRequest) -> SessionResult:
        """Run session analysis - EXISTING METHOD"""
        # Extract session ID from cookies
        session_id = ""
        if req.cookie:
            cookies = req.cookie.split(";")
            for cookie in cookies:
                cookie = cookie.strip()
                if cookie.startswith("session_id="):
                    session_id = cookie[11:]  # Remove "session_id=" prefix
                    break
        
        if not session_id:
            # Create new session with client fingerprint
            from security_modules.fingerprint_generator import ClientFingerprint
            fingerprint = ClientFingerprint(
                ip_address=req.client_ip,
                user_agent=req.user_agent,
                accept_language=req.accept_lang,
                accept_encoding=req.accept_enc,
                x_forwarded_for=req.client_ip,
                referer=req.referer
            )
            
            session_id = await self.server.session_engine.create_session(fingerprint)
            
            if self.server.config.debug:
                self.logger.info(
                    f"🆕 [{self.mode.upper()}] New session created: {session_id} for IP: {req.client_ip}"
                )
            
            return SessionResult(
                allow=True,
                message="New session created",
                session_id=session_id
            )
        
        # Process existing session
        allowed, message = await self.server.session_engine.process_request(
            session_id, req.uri, req.user_agent, req.client_ip
        )
        
        if self.server.config.debug:
            status = "ALLOWED" if allowed else "BLOCKED"
            self.logger.info(
                f"🔄 [{self.mode.upper()}] Session {status}: {req.client_ip} "
                f"- {message} (Session: {session_id})"
            )
        
        return SessionResult(
            allow=allowed,
            message=message,
            session_id=session_id
        )
    
    def get_security_stats(self) -> dict:
        """Get security statistics"""
        return {
            **self.security_stats,
            "detection_modules": {
                "waf": "active",
                "sessions": "active", 
                "ssrf": "active",
                "csrf": "active",
                "request_smuggling": "active",
                "security_headers": "active"
            }
        }
