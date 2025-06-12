"""
Server Statistics module
"""

from datetime import datetime
from models import ServerStats


class StatsCollector:
    """Collect and manage server statistics"""
    
    def __init__(self, stats: ServerStats):
        self.stats = stats
    
    def increment_total(self):
        """Increment total request count"""
        self.stats.total_requests += 1
    
    def increment_allowed(self):
        """Increment allowed request count"""
        self.stats.allowed_count += 1
    
    def increment_blocked(self):
        """Increment blocked request count"""
        self.stats.blocked_count += 1
    
    def get_stats(self) -> dict:
        """Get current statistics as dictionary"""
        success_rate = 0.0
        if self.stats.total_requests > 0:
            success_rate = (self.stats.allowed_count / self.stats.total_requests) * 100
        
        uptime_seconds = (datetime.now() - self.stats.start_time).total_seconds()
        requests_per_sec = self.stats.total_requests / uptime_seconds if uptime_seconds > 0 else 0
        
        return {
            "total_requests": self.stats.total_requests,
            "allowed_count": self.stats.allowed_count,
            "blocked_count": self.stats.blocked_count,
            "success_rate": success_rate,
            "uptime_seconds": uptime_seconds,
            "requests_per_sec": requests_per_sec
        }
