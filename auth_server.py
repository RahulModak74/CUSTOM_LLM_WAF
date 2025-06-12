"""
Auth Server module - Main server class
"""

from config import Config
from models import ServerStats
from security_modules.session_analytics import SecurityAnalytics
from security_modules.waf_engine import WAFEngine


class AuthServer:
    """Main authentication server"""
    
    def __init__(self, config: Config):
        self.config = config
        self.stats = ServerStats()
        self.session_engine = None
        self.waf_engine = None
    
    @classmethod
    async def create(cls, config: Config):
        """Async factory method to create AuthServer"""
        server = cls(config)
        server.session_engine = await SecurityAnalytics.create()
        server.waf_engine = WAFEngine()
        return server
