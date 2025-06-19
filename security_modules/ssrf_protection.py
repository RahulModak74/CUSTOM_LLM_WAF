"""
SSRF (Server-Side Request Forgery) Detection Module
Add this file as: security_modules/ssrf_detector.py
"""

import re
import ipaddress
import urllib.parse
from typing import List, Tuple, Optional
from dataclasses import dataclass


@dataclass
class SSRFResult:
    """SSRF detection result"""
    is_ssrf: bool
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    message: str
    detected_urls: List[str]
    attack_type: str


class SSRFDetector:
    """Detect Server-Side Request Forgery attempts"""
    
    def __init__(self):
        # Private IP ranges (RFC 1918, RFC 4193, etc.)
        self.private_ranges = [
            ipaddress.IPv4Network('10.0.0.0/8'),
            ipaddress.IPv4Network('172.16.0.0/12'),
            ipaddress.IPv4Network('192.168.0.0/16'),
            ipaddress.IPv4Network('127.0.0.0/8'),  # Loopback
            ipaddress.IPv4Network('169.254.0.0/16'),  # Link-local
            ipaddress.IPv6Network('::1/128'),  # IPv6 loopback
            ipaddress.IPv6Network('fc00::/7'),  # IPv6 private
            ipaddress.IPv6Network('fe80::/10'),  # IPv6 link-local
        ]
        
        # Cloud metadata endpoints
        self.cloud_metadata_hosts = [
            '169.254.169.254',  # AWS, Azure, Google Cloud
            '100.100.100.200',  # Alibaba Cloud
            'metadata.google.internal',  # Google Cloud
            'metadata',
            'instance-data',
        ]
        
        # Dangerous protocols
        self.dangerous_protocols = [
            'file://', 'ftp://', 'gopher://', 'dict://', 'ldap://',
            'sftp://', 'tftp://', 'jar://', 'netdoc://', 'mailto:'
        ]
        
        # SSRF payload patterns
        self.ssrf_patterns = [
            # URL parameters that commonly contain URLs
            r'(?i)(?:url|uri|link|src|href|redirect|callback|jsonp|next|target|dest|goto|return)=([^&\s]+)',
            # Direct URL patterns in request body
            r'(?i)(?:https?|ftp|file|gopher|dict|ldap)://[^\s"\'<>]+',
            # Encoded URLs
            r'(?i)(?:%2[fF]){2}[^\s"\'<>]+',  # Encoded //
            # XML external entities (XXE leading to SSRF)
            r'<!ENTITY[^>]+SYSTEM[^>]+>',
            # JSON with URLs
            r'"(?:url|uri|link|endpoint)"\s*:\s*"([^"]+)"',
        ]
        
        self.compiled_patterns = [re.compile(pattern) for pattern in self.ssrf_patterns]
    
    def analyze_request(self, method: str, uri: str, request_body: str, 
                       headers: dict) -> SSRFResult:
        """Analyze request for SSRF attempts"""
        detected_urls = []
        max_risk = "LOW"
        messages = []
        attack_types = []
        
        # Combine all request data for analysis
        full_request_data = f"{uri} {request_body}"
        for header_name, header_value in headers.items():
            full_request_data += f" {header_value}"
        
        # Extract potential URLs from request
        urls = self._extract_urls(full_request_data)
        detected_urls.extend(urls)
        
        # Analyze each URL
        for url in urls:
            result = self._analyze_url(url)
            if result.is_ssrf:
                messages.append(result.message)
                attack_types.append(result.attack_type)
                if self._get_risk_priority(result.risk_level) > self._get_risk_priority(max_risk):
                    max_risk = result.risk_level
        
        # Check for protocol-based attacks
        protocol_result = self._check_dangerous_protocols(full_request_data)
        if protocol_result.is_ssrf:
            messages.append(protocol_result.message)
            attack_types.append(protocol_result.attack_type)
            if self._get_risk_priority(protocol_result.risk_level) > self._get_risk_priority(max_risk):
                max_risk = protocol_result.risk_level
        
        # Check for cloud metadata access attempts
        metadata_result = self._check_metadata_access(full_request_data)
        if metadata_result.is_ssrf:
            messages.append(metadata_result.message)
            attack_types.append(metadata_result.attack_type)
            if self._get_risk_priority(metadata_result.risk_level) > self._get_risk_priority(max_risk):
                max_risk = metadata_result.risk_level
        
        # Check for XML External Entity (XXE) attacks
        xxe_result = self._check_xxe_patterns(request_body)
        if xxe_result.is_ssrf:
            messages.append(xxe_result.message)
            attack_types.append(xxe_result.attack_type)
            if self._get_risk_priority(xxe_result.risk_level) > self._get_risk_priority(max_risk):
                max_risk = xxe_result.risk_level
        
        is_ssrf = len(messages) > 0
        combined_message = "; ".join(messages) if messages else "No SSRF detected"
        combined_attack_type = ", ".join(set(attack_types)) if attack_types else "None"
        
        return SSRFResult(
            is_ssrf=is_ssrf,
            risk_level=max_risk,
            message=combined_message,
            detected_urls=detected_urls,
            attack_type=combined_attack_type
        )
    
    def _extract_urls(self, data: str) -> List[str]:
        """Extract potential URLs from request data"""
        urls = []
        
        for pattern in self.compiled_patterns:
            matches = pattern.findall(data)
            for match in matches:
                if isinstance(match, tuple):
                    # Handle group captures
                    for group in match:
                        if group and self._looks_like_url(group):
                            urls.append(group)
                else:
                    if self._looks_like_url(match):
                        urls.append(match)
        
        return list(set(urls))  # Remove duplicates
    
    def _looks_like_url(self, text: str) -> bool:
        """Check if text looks like a URL"""
        try:
            parsed = urllib.parse.urlparse(text)
            return bool(parsed.scheme and parsed.netloc)
        except:
            return False
    
    def _analyze_url(self, url: str) -> SSRFResult:
        """Analyze a specific URL for SSRF risks"""
        try:
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.hostname
            
            if not hostname:
                return SSRFResult(False, "LOW", "Invalid hostname", [], "")
            
            # Check for IP addresses
            try:
                ip = ipaddress.ip_address(hostname)
                return self._check_ip_address(ip, url)
            except ValueError:
                # Not an IP address, check hostname
                return self._check_hostname(hostname, url)
                
        except Exception as e:
            return SSRFResult(True, "MEDIUM", f"URL parsing error: {str(e)}", [url], "Malformed URL")
    
    def _check_ip_address(self, ip: ipaddress._BaseAddress, url: str) -> SSRFResult:
        """Check IP address for SSRF risks"""
        # Check if IP is in private ranges
        for private_range in self.private_ranges:
            try:
                if ip in private_range:
                    if str(ip).startswith('127.'):
                        return SSRFResult(True, "CRITICAL", 
                                        f"SSRF attempt targeting localhost: {ip}", 
                                        [url], "Localhost targeting")
                    elif str(ip) == '169.254.169.254':
                        return SSRFResult(True, "CRITICAL", 
                                        f"SSRF attempt targeting cloud metadata: {ip}", 
                                        [url], "Cloud metadata access")
                    else:
                        return SSRFResult(True, "HIGH", 
                                        f"SSRF attempt targeting private network: {ip}", 
                                        [url], "Private network access")
            except TypeError:
                # Handle IPv4/IPv6 mismatch
                continue
        
        return SSRFResult(False, "LOW", "Public IP address", [], "")
    
    def _check_hostname(self, hostname: str, url: str) -> SSRFResult:
        """Check hostname for SSRF risks"""
        hostname_lower = hostname.lower()
        
        # Check for localhost variants
        localhost_variants = ['localhost', '0.0.0.0', '0', '127.1', '127.0.1', '0x7f.1', '0x7f.0.0.1']
        if hostname_lower in localhost_variants:
            return SSRFResult(True, "CRITICAL", 
                            f"SSRF attempt using localhost variant: {hostname}", 
                            [url], "Localhost bypass")
        
        # Check for cloud metadata hostnames
        if hostname_lower in [host.lower() for host in self.cloud_metadata_hosts]:
            return SSRFResult(True, "CRITICAL", 
                            f"SSRF attempt targeting cloud metadata: {hostname}", 
                            [url], "Cloud metadata access")
        
        # Check for suspicious TLDs and domains
        suspicious_patterns = [
            r'\.local$', r'\.internal$', r'\.corp$', r'\.lan$',
            r'admin\.', r'test\.', r'dev\.', r'staging\.',
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, hostname_lower):
                return SSRFResult(True, "MEDIUM", 
                                f"SSRF attempt targeting internal hostname: {hostname}", 
                                [url], "Internal hostname")
        
        return SSRFResult(False, "LOW", "External hostname", [], "")
    
    def _check_dangerous_protocols(self, data: str) -> SSRFResult:
        """Check for dangerous protocol usage"""
        data_lower = data.lower()
        
        for protocol in self.dangerous_protocols:
            if protocol in data_lower:
                risk_level = "CRITICAL" if protocol in ['file://', 'gopher://'] else "HIGH"
                return SSRFResult(True, risk_level, 
                                f"Dangerous protocol detected: {protocol}", 
                                [], "Protocol-based SSRF")
        
        return SSRFResult(False, "LOW", "No dangerous protocols", [], "")
    
    def _check_metadata_access(self, data: str) -> SSRFResult:
        """Check for cloud metadata access attempts"""
        # AWS metadata
        aws_patterns = [
            r'169\.254\.169\.254',
            r'metadata\.google\.internal',
            r'/latest/meta-data',
            r'/computeMetadata/v1',
            r'/metadata/identity',
        ]
        
        for pattern in aws_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                return SSRFResult(True, "CRITICAL", 
                                f"Cloud metadata access attempt detected: {pattern}", 
                                [], "Cloud metadata harvesting")
        
        return SSRFResult(False, "LOW", "No metadata access detected", [], "")
    
    def _check_xxe_patterns(self, data: str) -> SSRFResult:
        """Check for XML External Entity patterns that could lead to SSRF"""
        xxe_patterns = [
            r'<!ENTITY[^>]+SYSTEM[^>]+>',
            r'<!ENTITY[^>]+PUBLIC[^>]+>',
            r'<!DOCTYPE[^>]+SYSTEM[^>]+>',
            r'&[a-zA-Z][a-zA-Z0-9]*;.*(?:file://|http://|ftp://)',
        ]
        
        for pattern in xxe_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                return SSRFResult(True, "HIGH", 
                                f"XXE pattern detected (potential SSRF): {pattern}", 
                                [], "XXE-based SSRF")
        
        return SSRFResult(False, "LOW", "No XXE patterns detected", [], "")
    
    def _get_risk_priority(self, risk_level: str) -> int:
        """Get numeric priority for risk level"""
        priorities = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        return priorities.get(risk_level, 0)
