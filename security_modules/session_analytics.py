"""
Security Analytics - Main session and threat analysis
"""

from typing import Dict, Tuple
from .session_store import SessionStore, MemoryStore
from .sqlite_store import SQLiteStore
from .session_manager import SessionManager
from .threat_analyzer import ThreatAnalyzer
from .fingerprint_generator import ClientFingerprint


class SecurityAnalytics:
    """Main security analytics engine"""
    
    def __init__(self, store: SessionStore):
        self.store = store
        self.session_manager = SessionManager(store)
        self.threat_analyzer = ThreatAnalyzer(store)
    
    @classmethod
    async def create(cls, use_sqlite: bool = True):
        """Create SecurityAnalytics with appropriate store"""
        if use_sqlite:
            try:
                store = SQLiteStore("sessions.db")
                await store.initialize()
            except Exception:
                # Fallback to memory store
                store = MemoryStore()
        else:
            store = MemoryStore()
        
        return cls(store)
    
    async def create_session(self, fingerprint: ClientFingerprint) -> str:
        """Create new session"""
        return await self.session_manager.create_session(fingerprint)
    
    async def process_request(self, session_id: str, url: str, user_agent: str, ip: str) -> Tuple[bool, str]:
        """Process request and analyze for threats"""
        return await self.threat_analyzer.analyze_request(session_id, url, user_agent, ip)
    
    def get_threat_summary(self) -> Dict[str, int]:
        """Get threat analysis summary"""
        return self.threat_analyzer.get_threat_summary()
