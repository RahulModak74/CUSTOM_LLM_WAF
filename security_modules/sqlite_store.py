"""
SQLite Session Store implementation
"""

import asyncio
import aiosqlite
import time
from datetime import timedelta
from typing import List, Optional
from .session_store import SessionStore


class SQLiteStore(SessionStore):
    """SQLite-based session store"""
    
    def __init__(self, db_path: str = "sessions.db"):
        self.db_path = db_path
        self.db = None
    
    async def initialize(self):
        """Initialize database connection and tables"""
        self.db = await aiosqlite.connect(self.db_path)
        await self._create_table()
        
        # Start cleanup task
        asyncio.create_task(self._cleanup_expired())
    
    async def _create_table(self):
        """Create sessions table"""
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                expires_at INTEGER
            )
        """)
        await self.db.commit()
    
    async def get(self, key: str) -> Optional[str]:
        """Get value by key"""
        cursor = await self.db.execute(
            "SELECT value, expires_at FROM sessions WHERE key = ?", (key,)
        )
        row = await cursor.fetchone()
        
        if not row:
            return None
        
        value, expires_at = row
        
        # Check expiration
        if expires_at and time.time() > expires_at:
            await self._delete(key)
            return None
        
        return value
    
    async def set(self, key: str, value: str, expiration: Optional[timedelta] = None) -> bool:
        """Set key-value with optional expiration"""
        expires_at = None
        if expiration:
            expires_at = int(time.time() + expiration.total_seconds())
        
        try:
            await self.db.execute(
                "INSERT OR REPLACE INTO sessions (key, value, expires_at) VALUES (?, ?, ?)",
                (key, value, expires_at)
            )
            await self.db.commit()
            return True
        except Exception:
            return False
    
    async def incr(self, key: str) -> int:
        """Increment counter and return new value"""
        # Get current value
        current_value = 0
        cursor = await self.db.execute("SELECT value FROM sessions WHERE key = ?", (key,))
        row = await cursor.fetchone()
        
        if row:
            try:
                current_value = int(row[0])
            except ValueError:
                current_value = 0
        
        current_value += 1
        
        # Update value
        await self.db.execute(
            "INSERT OR REPLACE INTO sessions (key, value, expires_at) VALUES (?, ?, 0)",
            (key, str(current_value))
        )
        await self.db.commit()
        
        return current_value
    
    async def keys(self, pattern: str) -> List[str]:
        """Get keys matching pattern"""
        pattern = pattern.replace("*", "%")
        cursor = await self.db.execute("SELECT key FROM sessions WHERE key LIKE ?", (pattern,))
        rows = await cursor.fetchall()
        return [row[0] for row in rows]
    
    async def _delete(self, key: str):
        """Delete a key"""
        await self.db.execute("DELETE FROM sessions WHERE key = ?", (key,))
        await self.db.commit()
    
    async def _cleanup_expired(self):
        """Cleanup expired keys periodically"""
        while True:
            try:
                await asyncio.sleep(600)  # Run every 10 minutes
                await self.db.execute(
                    "DELETE FROM sessions WHERE expires_at > 0 AND expires_at < ?",
                    (int(time.time()),)
                )
                await self.db.commit()
            except asyncio.CancelledError:
                break
            except Exception:
                continue
    
    async def close(self):
        """Close database connection"""
        if self.db:
            await self.db.close()
