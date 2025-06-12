"""
Client Fingerprint Generator module
"""

import hashlib
from dataclasses import dataclass
from typing import Optional


@dataclass
class ClientFingerprint:
    """Client fingerprint data"""
    ip_address: str
    user_agent: str
    accept_language: str = ""
    accept_encoding: str = ""
    connection_type: str = ""
    x_forwarded_for: str = ""
    referer: str = ""
    
    def generate_hash(self) -> str:
        """Generate hash from fingerprint data"""
        data = f"{self.ip_address}|{self.user_agent}|{self.accept_language}|{self.accept_encoding}|{self.connection_type}|{self.x_forwarded_for}|{self.referer}"
        return hashlib.sha256(data.encode()).hexdigest()


class FingerprintGenerator:
    """Generate client fingerprints"""
    
    def generate_hash(self, fingerprint: ClientFingerprint) -> str:
        """Generate hash from client fingerprint"""
        return fingerprint.generate_hash()
    
    def create_fingerprint(self, ip: str, user_agent: str, accept_lang: str = "", 
                          accept_enc: str = "", conn_type: str = "", 
                          xff: str = "", referer: str = "") -> ClientFingerprint:
        """Create client fingerprint"""
        return ClientFingerprint(
            ip_address=ip,
            user_agent=user_agent,
            accept_language=accept_lang,
            accept_encoding=accept_enc,
            connection_type=conn_type,
            x_forwarded_for=xff,
            referer=referer
        )
