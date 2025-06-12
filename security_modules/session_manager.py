"""
Session Manager
"""

import json
import time
from datetime import timedelta
from typing import Optional, Tuple
from .session_store import SessionStore
from .fingerprint_generator import ClientFingerprint, FingerprintGenerator


class SessionManager:
    """Manage user sessions and fingerprints"""
    
    def __init__(self, store: SessionStore):
        self.store = store
        self.fingerprint_gen = FingerprintGenerator()
        self.session_timeout = timedelta(minutes=30)
    
    async def create_session(self, fingerprint: ClientFingerprint) -> str:
        """Create new session with client fingerprint"""
        fingerprint_hash = self.fingerprint_gen.generate_hash(fingerprint)
        session_id = f"session:{fingerprint_hash}:{int(time.time())}"
        
        # Store fingerprint data
        fingerprint_data = {
            "ip_address": fingerprint.ip_address,
            "user_agent": fingerprint.user_agent,
            "accept_language": fingerprint.accept_language,
            "accept_encoding": fingerprint.accept_encoding,
            "connection_type": fingerprint.connection_type,
            "x_forwarded_for": fingerprint.x_forwarded_for,
            "referer": fingerprint.referer
        }
        
        await self.store.set(
            f"fingerprint:{session_id}",
            json.dumps(fingerprint_data),
            self.session_timeout
        )
        
        return session_id
    
    async def validate_session(self, session_id: str) -> bool:
        """Validate if session exists and is not expired"""
        data = await self.store.get(f"fingerprint:{session_id}")
        return data is not None
    
    async def get_session_data(self, session_id: str) -> Optional[ClientFingerprint]:
        """Get session fingerprint data"""
        data = await self.store.get(f"fingerprint:{session_id}")
        if not data:
            return None
        
        try:
            fingerprint_data = json.loads(data)
            return ClientFingerprint(
                ip_address=fingerprint_data.get("ip_address", ""),
                user_agent=fingerprint_data.get("user_agent", ""),
                accept_language=fingerprint_data.get("accept_language", ""),
                accept_encoding=fingerprint_data.get("accept_encoding", ""),
                connection_type=fingerprint_data.get("connection_type", ""),
                x_forwarded_for=fingerprint_data.get("x_forwarded_for", ""),
                referer=fingerprint_data.get("referer", "")
            )
        except (json.JSONDecodeError, KeyError):
            return None
