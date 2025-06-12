"""
Data models for the Nginx Security Server
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from pydantic import BaseModel


@dataclass
class ServerStats:
    """Server statistics"""
    total_requests: int = 0
    blocked_count: int = 0
    allowed_count: int = 0
    start_time: datetime = field(default_factory=datetime.now)


class AuthRequest(BaseModel):
    """Authentication request model"""
    method: str
    uri: str
    client_ip: str
    user_agent: str = ""
    referer: str = ""
    cookie: str = ""
    host: str = ""
    accept_lang: str = ""
    accept_enc: str = ""
    request_id: str = ""
    request_body: str = "" 


class AuthResponse(BaseModel):
    """Authentication response model"""
    allow: bool
    status: int
    message: str = ""
    session_id: str = ""
    threat_level: str
    anomaly_score: int
    response_time_ms: int


@dataclass
class WAFResult:
    """WAF evaluation result"""
    allow: bool
    message: str
    score: int


@dataclass
class SessionResult:
    """Session evaluation result"""
    allow: bool
    message: str
    session_id: str
