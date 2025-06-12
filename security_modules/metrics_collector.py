"""
Security Metrics Collector
"""

import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List


@dataclass
class SecurityMetrics:
    """Security metrics data"""
    total_requests: int = 0
    blocked_requests: int = 0
    allowed_requests: int = 0
    threats_by_type: Dict[str, int] = field(default_factory=dict)
    top_blocked_ips: Dict[str, int] = field(default_factory=dict)
    response_times: List[int] = field(default_factory=list)
    requests_by_hour: Dict[int, int] = field(default_factory=dict)
    last_updated: datetime = field(default_factory=datetime.now)


class MetricsCollector:
    """Collect and analyze security metrics"""
    
    def __init__(self):
        self.metrics = SecurityMetrics()
        self.metrics.threats_by_type = defaultdict(int)
        self.metrics.top_blocked_ips = defaultdict(int)
        self.metrics.requests_by_hour = defaultdict(int)
        self.metrics.response_times = deque(maxlen=1000)  # Keep last 1000
        self.lock = threading.RLock()
    
    def record_request(self, ip: str, blocked: bool, threat_type: str = "", response_time: int = 0):
        """Record a request and its metrics"""
        with self.lock:
            self.metrics.total_requests += 1
            self.metrics.last_updated = datetime.now()
            
            if blocked:
                self.metrics.blocked_requests += 1
                self.metrics.top_blocked_ips[ip] += 1
                if threat_type:
                    self.metrics.threats_by_type[threat_type] += 1
            else:
                self.metrics.allowed_requests += 1
            
            # Record response time
            if response_time > 0:
                self.metrics.response_times.append(response_time)
            
            # Record by hour
            hour = datetime.now().hour
            self.metrics.requests_by_hour[hour] += 1
    
    def get_metrics(self) -> SecurityMetrics:
        """Get current metrics (thread-safe copy)"""
        with self.lock:
            # Create a copy to avoid race conditions
            return SecurityMetrics(
                total_requests=self.metrics.total_requests,
                blocked_requests=self.metrics.blocked_requests,
                allowed_requests=self.metrics.allowed_requests,
                threats_by_type=dict(self.metrics.threats_by_type),
                top_blocked_ips=dict(self.metrics.top_blocked_ips),
                response_times=list(self.metrics.response_times),
                requests_by_hour=dict(self.metrics.requests_by_hour),
                last_updated=self.metrics.last_updated
            )
    
    def reset(self):
        """Reset all metrics"""
        with self.lock:
            self.metrics = SecurityMetrics()
            self.metrics.threats_by_type = defaultdict(int)
            self.metrics.top_blocked_ips = defaultdict(int)
            self.metrics.requests_by_hour = defaultdict(int)
            self.metrics.response_times = deque(maxlen=1000)
