"""
Rate Limiter Module
"""

import asyncio
import time
import threading
from dataclasses import dataclass
from datetime import timedelta
from typing import Dict


@dataclass
class RateLimit:
    """Rate limit configuration"""
    requests: int
    window: timedelta
    burst_limit: int


class TokenBucket:
    """Token bucket for rate limiting"""
    
    def __init__(self, max_tokens: int, refill_rate: int):
        self.tokens = max_tokens
        self.max_tokens = max_tokens
        self.refill_rate = refill_rate
        self.last_refill = time.time()
        self.lock = threading.Lock()
    
    def consume(self) -> bool:
        """Try to consume a token"""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_refill
            
            # Refill tokens if a minute has passed
            if elapsed >= 60:
                self.tokens = self.max_tokens
                self.last_refill = now
            
            if self.tokens > 0:
                self.tokens -= 1
                return True
            
            return False


class RateLimiter:
    """Rate limiting engine"""
    
    def __init__(self):
        self.limits: Dict[str, RateLimit] = {}
        self.buckets: Dict[str, TokenBucket] = {}
        self.lock = threading.RLock()
    
    def set_limit(self, key: str, requests: int, window: timedelta, burst: int):
        """Set rate limit for a key"""
        with self.lock:
            self.limits[key] = RateLimit(
                requests=requests,
                window=window,
                burst_limit=burst
            )
    
    def is_allowed(self, key: str) -> bool:
        """Check if request is allowed under rate limit"""
        with self.lock:
            limit = self.limits.get(key)
            if not limit:
                return True
            
            bucket = self.buckets.get(key)
            if not bucket:
                bucket = TokenBucket(limit.requests, limit.requests)
                self.buckets[key] = bucket
            
            return bucket.consume()
