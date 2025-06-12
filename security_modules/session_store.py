"""
Session Storage interfaces and implementations
"""

import asyncio
import threading
import time
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Dict, List, Optional


class SessionStore(ABC):
    """Abstract session store interface"""
    
    @abstractmethod
    async def get(self, key: str) -> Optional[str]:
        """Get value by key"""
        pass
    
    @abstractmethod
    async def set(self, key: str, value: str, expiration: Optional[timedelta] = None) -> bool:
        """Set key-value with optional expiration"""
        pass
    
    @abstractmethod
    async def incr(self, key: str) -> int:
        """Increment counter and return new value"""
        pass
    
    @abstractmethod
    async def keys(self, pattern: str) -> List[str]:
        """Get keys matching pattern"""
        pass


class MemoryStore(SessionStore):
    """In-memory session store"""
    
    def __init__(self):
        self.data: Dict[str, str] = {}
        self.expiry: Dict[str, float] = {}
        self.lock = threading.RLock()
        
        # Start cleanup task
        asyncio.create_task(self._cleanup_expired())
    
    async def get(self, key: str) -> Optional[str]:
        """Get value by key"""
        with self.lock:
            # Check expiration
            if key in self.expiry and time.time() > self.expiry[key]:
                self.data.pop(key, None)
                self.expiry.pop(key, None)
                return None
            
            return self.data.get(key)
    
    async def set(self, key: str, value: str, expiration: Optional[timedelta] = None) -> bool:
        """Set key-value with optional expiration"""
        with self.lock:
            self.data[key] = value
            if expiration:
                self.expiry[key] = time.time() + expiration.total_seconds()
            return True
    
    async def incr(self, key: str) -> int:
        """Increment counter and return new value"""
        with self.lock:
            current_value = int(self.data.get(key, "0"))
            current_value += 1
            self.data[key] = str(current_value)
            return current_value
    
    async def keys(self, pattern: str) -> List[str]:
        """Get keys matching pattern (simple contains match)"""
        with self.lock:
            pattern = pattern.replace("*", "")
            return [key for key in self.data.keys() if pattern in key]
    
    async def _cleanup_expired(self):
        """Cleanup expired keys periodically"""
        while True:
            try:
                await asyncio.sleep(600)  # Run every 10 minutes
                current_time = time.time()
                with self.lock:
                    expired_keys = [
                        key for key, exp_time in self.expiry.items() 
                        if current_time > exp_time
                    ]
                    for key in expired_keys:
                        self.data.pop(key, None)
                        self.expiry.pop(key, None)
            except asyncio.CancelledError:
                break
            except Exception:
                continue
