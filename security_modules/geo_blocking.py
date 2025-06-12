"""
Geo Blocking Module
"""

import ipaddress
import threading
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class GeoBlock:
    """Geo blocking configuration"""
    country_codes: List[str] = field(default_factory=list)
    ip_ranges: List[str] = field(default_factory=list)
    whitelist: List[str] = field(default_factory=list)
    enabled: bool = False


class GeoBlocker:
    """IP-based geo blocking"""
    
    def __init__(self):
        self.config = GeoBlock()
        self.ip_nets: List[ipaddress.IPv4Network] = []
        self.whitelist: List[ipaddress.IPv4Network] = []
        self.lock = threading.RLock()
    
    def update_config(self, config: GeoBlock) -> bool:
        """Update geo blocking configuration"""
        with self.lock:
            self.config = config
            self.ip_nets.clear()
            self.whitelist.clear()
            
            # Parse IP ranges
            for ip_range in config.ip_ranges:
                try:
                    network = ipaddress.IPv4Network(ip_range, strict=False)
                    self.ip_nets.append(network)
                except (ipaddress.AddressValueError, ValueError):
                    continue
            
            # Parse whitelist
            for white_ip in config.whitelist:
                try:
                    network = ipaddress.IPv4Network(white_ip, strict=False)
                    self.whitelist.append(network)
                except (ipaddress.AddressValueError, ValueError):
                    continue
            
            return True
    
    def is_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        if not self.config.enabled:
            return False
        
        try:
            client_ip = ipaddress.IPv4Address(ip)
        except (ipaddress.AddressValueError, ValueError):
            return True  # Block invalid IPs
        
        with self.lock:
            # Check whitelist first
            for white_net in self.whitelist:
                if client_ip in white_net:
                    return False
            
            # Check blocked ranges
            for blocked_net in self.ip_nets:
                if client_ip in blocked_net:
                    return True
            
            return False
