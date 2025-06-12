"""
Cache Engine Module
"""

import asyncio
import hashlib
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Optional


@dataclass
class CacheEntry:
    """Cache entry data"""
    data: bytes
    headers: Dict[str, str] = field(default_factory=dict)
    expires_at: float = 0.0
    hit_count: int = 0


class CacheEngine:
    """Response caching engine"""
    
    def __init__(self, max_size: int = 1000, ttl: timedelta = timedelta(minutes=5)):
        self.entries: Dict[str, CacheEntry] = {}
        self.max_size = max_size
        self.ttl = ttl
        self.lock = threading.RLock()
        
        # Start cleanup task
        asyncio.create_task(self._cleanup())
    
    def _generate_key(self, method: str, uri: str, headers: Dict[str, str]) -> str:
        """Generate cache key"""
        data = f"{method}:{uri}"
        return hashlib.md5(data.encode()).hexdigest()
    
    def get(self, method: str, uri: str, headers: Dict[str, str]) -> Optional[CacheEntry]:
        """Get cached entry"""
        key = self._generate_key(method, uri, headers)
        
        with self.lock:
            entry = self.entries.get(key)
            if not entry or time.time() > entry.expires_at:
                if entry:
                    del self.entries[key]
                return None
            
            entry.hit_count += 1
            return entry
    
    def set(self, method: str, uri: str, headers: Dict[str, str], 
            data: bytes, response_headers: Dict[str, str]):
        """Set cache entry"""
        if len(self.entries) >= self.max_size:
            self._evict_oldest()
        
        key = self._generate_key(method, uri, headers)
        
        with self.lock:
            self.entries[key] = CacheEntry(
                data=data,
                headers=response_headers,
                expires_at=time.time() + self.ttl.total_seconds(),
                hit_count=0
            )
    
    def _evict_oldest(self):
        """Evict oldest cache entry"""
        with self.lock:
            if not self.entries:
                return
            
            oldest_key = min(self.entries.keys(), 
                           key=lambda k: self.entries[k].expires_at)
            del self.entries[oldest_key]
    
    async def _cleanup(self):
        """Cleanup expired entries periodically"""
        while True:
            try:
                await asyncio.sleep(300)  # Run every 5 minutes
                current_time = time.time()
                
                with self.lock:
                    expired_keys = [
                        key for key, entry in self.entries.items()
                        if current_time > entry.expires_at
                    ]
                    for key in expired_keys:
                        del self.entries[key]
            except asyncio.CancelledError:
                break
            except Exception:
                continue
