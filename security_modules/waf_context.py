"""
WAF Context for request analysis
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List


@dataclass
class WAFContext:
    """WAF evaluation context"""
    method: str
    uri: str
    client_ip: str
    user_agent: str = ""
    referer: str = ""
    cookie: str = ""
    host: str = ""
    accept_language: str = ""
    accept_encoding: str = ""
    request_body: str = ""
    start_time: datetime = field(default_factory=datetime.now)
    headers: Dict[str, str] = field(default_factory=dict)
    arguments: Dict[str, str] = field(default_factory=dict)
    post_args: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    variables: Dict[str, str] = field(default_factory=dict)
    anomaly_score: int = 0
    log_messages: List[str] = field(default_factory=list)
