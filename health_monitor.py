"""
Health Monitor module - Health and status endpoints
"""

import time
from datetime import datetime
from sanic import Request
from auth_server import AuthServer
from response_builder import ResponseBuilder
from server_stats import StatsCollector


class HealthMonitor:
    """Monitor server health and provide status endpoints"""
    
    def __init__(self, server: AuthServer, responder: ResponseBuilder, stats: StatsCollector):
        self.server = server
        self.responder = responder
        self.stats = stats
    
    async def handle_health(self, request: Request):
        """Handle health check endpoint"""
        uptime_seconds = (datetime.now() - self.server.stats.start_time).total_seconds()
        
        health = {
            "status": "healthy",
            "timestamp": int(time.time()),
            "waf": "active",
            "sessions": "active",
            "uptime": uptime_seconds
        }
        return self.responder.send_json(health)
    
    async def handle_status(self, request: Request):
        """Handle detailed status endpoint"""
        uptime_seconds = (datetime.now() - self.server.stats.start_time).total_seconds()
        waf_report = self.server.waf_engine.generate_security_report()
        session_summary = self.server.session_engine.get_threat_summary()
        
        status = {
            "timestamp": int(time.time()),
            "server_stats": {
                "total_requests": self.server.stats.total_requests,
                "blocked_count": self.server.stats.blocked_count,
                "allowed_count": self.server.stats.allowed_count,
                "start_time": self.server.stats.start_time.isoformat()
            },
            "waf_stats": waf_report,
            "session_stats": session_summary,
            "uptime": uptime_seconds,
            "config": {
                "debug_mode": self.server.config.debug,
                "port": self.server.config.port
            }
        }
        return self.responder.send_json(status)
    
    async def handle_stats(self, request: Request):
        """Handle statistics endpoint"""
        stats_data = self.stats.get_stats()
        return self.responder.send_json(stats_data)
