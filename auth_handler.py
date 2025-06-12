"""
Auth Handler module - Main authentication logic
"""

import time
import logging
from datetime import datetime
from sanic import Request, response
from auth_server import AuthServer
from request_parser import RequestParser
from response_builder import ResponseBuilder
from server_stats import StatsCollector
from models import AuthRequest, AuthResponse, WAFResult, SessionResult
from security_modules.waf_context import WAFContext


class AuthHandler:
    """Handle authentication requests"""
    
    def __init__(self, server: AuthServer, parser: RequestParser, 
                 responder: ResponseBuilder, stats: StatsCollector, mode: str):
        self.server = server
        self.parser = parser
        self.responder = responder
        self.stats = stats
        self.mode = mode
        self.logger = logging.getLogger(__name__)
    
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
        
        # Process authentication
        auth_response = await self._process_auth(auth_req, start_time)
        
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
        
        # Build response with headers
        sanic_response = self.responder.send_auth_response(auth_response, self.server.config.debug)
        
        # Add mode-specific headers
        for key, value in headers.items():
            sanic_response.headers[key] = value
        
        return sanic_response
    
    def _handle_options(self, request: Request):
        """Handle OPTIONS preflight request"""
        headers = self._get_mode_specific_headers()
        return response.text("", status=200, headers=headers)
    
    def _get_mode_specific_headers(self) -> dict:
        """Get headers based on mode"""
        common_headers = {
            "X-Auth-Server": "nginx-security",
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
            "X-Auth-Mode": self.mode
        }
        
        if self.mode == "local":
            common_headers.update({
                "Access-Control-Allow-Origin": "http://localhost:*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization"
            })
        else:  # remote
            common_headers.update({
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS, HEAD",
                "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
                "Access-Control-Expose-Headers": "X-Session-ID, X-Threat-Level, X-Anomaly-Score"
            })
        
        return common_headers
    
    async def _process_auth(self, req: AuthRequest, start_time: datetime) -> AuthResponse:
        """Process authentication request"""
        auth_response = AuthResponse(
            allow=True,
            status=200,
            threat_level="LOW",
            message="Authentication successful",
            anomaly_score=0,
            response_time_ms=0
        )
        
        # Step 1: WAF Analysis (Primary security check)
        waf_result = await self._run_waf(req)
        auth_response.anomaly_score = waf_result.score
        
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
        
        # Step 2: Session Management and Rate Limiting
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
        
        # Calculate final response time
        auth_response.response_time_ms = int((datetime.now() - start_time).total_seconds() * 1000)
        
        # Mode-specific processing
        if self.mode == "remote":
            auth_response.message += " (remote)"
        else:
            auth_response.message += " (local)"
        
        return auth_response
    
    async def _run_waf(self, req: AuthRequest) -> WAFResult:
        """Run WAF analysis"""
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
        """Run session analysis"""
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
