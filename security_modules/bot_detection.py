"""
Bot Detection Module
"""

import re
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class BotSignature:
    """Bot signature definition"""
    name: str
    pattern: str
    bot_type: str  # "good", "bad", "suspicious"
    compiled: Optional[re.Pattern] = None


class BotDetector:
    """Detect and classify bots"""
    
    def __init__(self):
        self.signatures: Dict[str, BotSignature] = {}
        self.lock = threading.RLock()
        self._load_default_signatures()
    
    def _load_default_signatures(self):
        """Load default bot signatures"""
        signatures = [
            BotSignature("Googlebot", r"(?i:googlebot)", "good"),
            BotSignature("Bingbot", r"(?i:bingbot)", "good"),
            BotSignature("FacebookBot", r"(?i:facebookexternalhit)", "good"),
            BotSignature("TwitterBot", r"(?i:twitterbot)", "good"),
            BotSignature("SQLMap", r"(?i:sqlmap)", "bad"),
            BotSignature("Nikto", r"(?i:nikto)", "bad"),
            BotSignature("Nessus", r"(?i:nessus)", "bad"),
            BotSignature("Burp", r"(?i:burp)", "bad"),
            BotSignature("Python", r"(?i:python-requests|python-urllib)", "suspicious"),
            BotSignature("Curl", r"(?i:curl/)", "suspicious"),
        ]
        
        for sig in signatures:
            try:
                sig.compiled = re.compile(sig.pattern)
                self.signatures[sig.name] = sig
            except re.error:
                continue
    
    def analyze(self, user_agent: str) -> Tuple[str, str]:
        """Analyze user agent and return (type, name)"""
        with self.lock:
            if not user_agent:
                return "suspicious", "Empty User-Agent"
            
            for sig in self.signatures.values():
                if sig.compiled and sig.compiled.search(user_agent):
                    return sig.bot_type, sig.name
            
            # Check for suspicious patterns
            if self._is_suspicious_ua(user_agent):
                return "suspicious", "Suspicious patterns"
            
            return "unknown", "Unknown bot"
    
    def _is_suspicious_ua(self, ua: str) -> bool:
        """Check for suspicious User-Agent patterns"""
        suspicious = [
            "bot", "crawler", "spider", "scraper", "scanner",
            "hack", "exploit", "injection", "payload"
        ]
        
        ua_lower = ua.lower()
        return any(pattern in ua_lower for pattern in suspicious)
