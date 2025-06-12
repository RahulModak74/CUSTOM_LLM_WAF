"""
Configuration module for the Nginx Security Server
"""

from datetime import timedelta
from dataclasses import dataclass


@dataclass
class Config:
    """Server configuration"""
    port: str = "8080"
    debug: bool = False
    auth_timeout: timedelta = timedelta(seconds=2)
