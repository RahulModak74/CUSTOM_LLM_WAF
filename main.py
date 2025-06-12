#!/usr/bin/env python3
"""
Nginx Security Server - Python/Sanic Implementation
Main entry point for the application
"""

import sys
import asyncio
from datetime import timedelta
from sanic import Sanic, response
from sanic_cors import CORS

from config import Config
from auth_server import AuthServer
from request_parser import RequestParser
from response_builder import ResponseBuilder
from server_stats import StatsCollector
from auth_handler import AuthHandler
from health_monitor import HealthMonitor


def print_startup_info(config: Config, mode: str, waf_rules: int):
    """Print startup information"""
    print("🛡️  Nginx Security Server (Python)")
    print("=" * 40)
    print(f"✅ Mode: {mode}")
    print(f"✅ Port: {config.port}")
    print(f"✅ Debug: {config.debug}")
    print(f"✅ WAF Rules: {waf_rules}")
    print(f"✅ Auth Timeout: {config.auth_timeout}")
    print()
    print("📊 Available Endpoints:")
    print(f"   http://localhost:{config.port}/auth   - Main authentication endpoint")
    print(f"   http://localhost:{config.port}/health - Health check")
    print(f"   http://localhost:{config.port}/status - Security status")
    print(f"   http://localhost:{config.port}/stats  - Server statistics")
    print()


def print_local_nginx_config(port: str):
    """Print local nginx configuration"""
    print("🔧 Local Nginx Configuration:")
    print("=" * 30)
    print("# Add this to your Nginx server block:")
    print("location = /auth {")
    print("    internal;")
    print(f"    proxy_pass http://127.0.0.1:{port}/auth;")
    print("    proxy_pass_request_body off;")
    print('    proxy_set_header Content-Length "";')
    print("    proxy_set_header X-Original-URI $request_uri;")
    print("    proxy_set_header X-Original-Method $request_method;")
    print("    proxy_set_header X-Original-Remote-Addr $remote_addr;")
    print("    proxy_set_header X-Original-User-Agent $http_user_agent;")
    print("    proxy_set_header X-Original-Referer $http_referer;")
    print("    proxy_set_header X-Original-Cookie $http_cookie;")
    print("    proxy_set_header X-Original-Host $host;")
    print("    proxy_set_header X-Original-Accept-Language $http_accept_language;")
    print("    proxy_set_header X-Original-Accept-Encoding $http_accept_encoding;")
    print("}")
    print()
    print("# Protect your locations with auth_request:")
    print("location /protected/ {")
    print("    auth_request /auth;")
    print("    # Your protected content here")
    print("    try_files $uri $uri/ =404;")
    print("}")
    print()


def print_remote_nginx_config(port: str):
    """Print remote nginx configuration"""
    print("🔧 Remote Nginx Configuration:")
    print("=" * 31)
    print("# Add upstream block:")
    print("upstream security_auth {")
    print(f"    server your-remote-server:{port};")
    print("    # Optional: add backup servers")
    print(f"    # server backup-server:{port} backup;")
    print("}")
    print()
    print("# Auth endpoint configuration:")
    print("location = /auth {")
    print("    internal;")
    print("    proxy_pass http://security_auth/auth;")
    print("    proxy_pass_request_body off;")
    print('    proxy_set_header Content-Length "";')
    print("    proxy_set_header X-Original-URI $request_uri;")
    print("    proxy_set_header X-Original-Method $request_method;")
    print("    proxy_set_header X-Original-Remote-Addr $remote_addr;")
    print("    proxy_set_header X-Original-User-Agent $http_user_agent;")
    print("    proxy_set_header X-Original-Referer $http_referer;")
    print("    proxy_set_header X-Original-Cookie $http_cookie;")
    print("    proxy_set_header X-Original-Host $host;")
    print("    proxy_set_header X-Real-IP $remote_addr;")
    print("    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;")
    print("    proxy_connect_timeout 2s;")
    print("    proxy_read_timeout 2s;")
    print("}")
    print()
    print("# Protected location example:")
    print("location /app/ {")
    print("    auth_request /auth;")
    print("    # Pass session info from auth server")
    print("    auth_request_set $session_id $upstream_http_x_session_id;")
    print("    auth_request_set $threat_level $upstream_http_x_threat_level;")
    print("    proxy_set_header X-Session-ID $session_id;")
    print("    proxy_set_header X-Threat-Level $threat_level;")
    print("    # Your application backend")
    print("    proxy_pass http://your-app-backend;")
    print("}")
    print()


# Global variables for configuration
config = None
mode = None

def create_app():
    """Create and configure the Sanic application (synchronous)"""
    global config, mode
    
    # Create Sanic app
    app = Sanic("nginx-security")
    
    @app.before_server_start
    async def setup_server(app, loop):
        """Setup server components before starting"""
        # Initialize server components
        server = await AuthServer.create(config)
        parser = RequestParser()
        responder = ResponseBuilder()
        stats = StatsCollector(server.stats)
        auth_handler = AuthHandler(server, parser, responder, stats, mode)
        health_monitor = HealthMonitor(server, responder, stats)
        
        # Store components in app context
        app.ctx.server = server
        app.ctx.auth_handler = auth_handler
        app.ctx.health_monitor = health_monitor
        app.ctx.parser = parser
        app.ctx.responder = responder
        app.ctx.stats = stats
    
    # Add routes
    app.add_route(handle_auth, "/auth", methods=["GET", "POST", "OPTIONS"])
    app.add_route(handle_health, "/health", methods=["GET"])
    app.add_route(handle_status, "/status", methods=["GET"])
    app.add_route(handle_stats, "/stats", methods=["GET"])
    
    return app

# Route handlers that use app context
async def handle_auth(request):
    return await request.app.ctx.auth_handler.handle_auth(request)

async def handle_health(request):
    return await request.app.ctx.health_monitor.handle_health(request)

async def handle_status(request):
    return await request.app.ctx.health_monitor.handle_status(request)

async def handle_stats(request):
    return await request.app.ctx.health_monitor.handle_stats(request)

def main():
    """Main entry point"""
    global config, mode
    
    # Parse command line arguments
    config = Config()
    mode = "local"  # default mode
    
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg == "debug":
            config.debug = True
            print("🐛 Debug mode enabled")
        elif arg == "production":
            config.debug = False
            print("🚀 Production mode enabled")
        elif arg == "local":
            mode = "local"
            print("🏠 Local mode selected")
        elif arg == "local-debug":
            mode = "local"
            config.debug = True
            print("🏠🐛 Local debug mode enabled")
        elif arg == "remote":
            mode = "remote"
            print("☁️  Remote mode selected")
        elif arg == "remote-debug":
            mode = "remote"
            config.debug = True
            print("☁️🐛 Remote debug mode enabled")
        else:
            print(f"Unknown argument: {arg}")
            print("Available options: local, remote, debug, production, local-debug, remote-debug")
            sys.exit(1)
    
    # Print startup information (will be shown before server starts)
    print("🛡️  Nginx Security Server (Python)")
    print("=" * 40)
    print(f"✅ Mode: {mode}")
    print(f"✅ Port: {config.port}")
    print(f"✅ Debug: {config.debug}")
    print(f"✅ WAF Rules: 15")  # Will be updated after server components are created
    print(f"✅ Auth Timeout: {config.auth_timeout}")
    print()
    print("📊 Available Endpoints:")
    print(f"   http://localhost:{config.port}/auth   - Main authentication endpoint")
    print(f"   http://localhost:{config.port}/health - Health check")
    print(f"   http://localhost:{config.port}/status - Security status")
    print(f"   http://localhost:{config.port}/stats  - Server statistics")
    print()
    
    # Print configuration examples based on mode
    if mode == "local":
        print_local_nginx_config(config.port)
    else:
        print_remote_nginx_config(config.port)
    
    print(f"🚀 Server starting on port {config.port}")
    
    # Create and run app
    app = create_app()
    
    # Setup CORS
    CORS(app, 
         origins="*" if mode == "remote" else ["http://localhost:*"],
         methods=["GET", "POST", "OPTIONS", "HEAD"],
         headers=["Content-Type", "Authorization", "X-Requested-With"])
    
    try:
        app.run(
            host="0.0.0.0",
            port=int(config.port),
            debug=config.debug,
            access_log=config.debug,
            single_process=True  # Use single process to avoid the multiprocess issue
        )
    except KeyboardInterrupt:
        print("\n🛑 Server stopped")


if __name__ == "__main__":
    main()
