"""
Threat Analyzer
"""

from typing import Dict, Tuple
from .session_store import SessionStore


class ThreatAnalyzer:
    """Analyze threats and suspicious behavior"""
    
    def __init__(self, store: SessionStore):
        self.store = store
    
    async def analyze_request(self, session_id: str, url: str, user_agent: str, ip: str) -> Tuple[bool, str]:
        """Analyze request for threats"""
        # Simple implementation - can be extended with more sophisticated analysis
        
        # Check for suspicious patterns in URL
        suspicious_patterns = [
            'admin', 'wp-admin', '.env', 'config', 'backup',
            'phpmyadmin', 'mysql', 'database', 'passwd'
        ]
        
        url_lower = url.lower()
        for pattern in suspicious_patterns:
            if pattern in url_lower:
                return False, f"Suspicious URL pattern: {pattern}"
        
        # Check user agent
        if not user_agent or len(user_agent) < 10:
            return False, "Suspicious or missing User-Agent"
        
        # Check for scanner user agents
        scanner_patterns = ['sqlmap', 'nikto', 'nessus', 'burp', 'python-requests']
        user_agent_lower = user_agent.lower()
        for pattern in scanner_patterns:
            if pattern in user_agent_lower:
                return False, f"Scanner detected: {pattern}"
        
        return True, "OK"
    
    def get_threat_summary(self) -> Dict[str, int]:
        """Get threat analysis summary"""
        return {
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0,
            "BLOCKED": 0,
            "TOTAL": 0
        }
