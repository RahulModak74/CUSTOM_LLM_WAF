import torch
import torch.nn as nn
import torch.nn.functional as F
from transformers import AutoModelForCausalLM, AutoTokenizer
import numpy as np
from typing import Dict, List, Tuple
import copy
import json
import re
import warnings
warnings.filterwarnings("ignore")

class ProfessionalWAFDetector:
    """Professional-grade WAF detector matching ModSecurity CRS standards"""
    
    def __init__(self):
        # Basic attack patterns (from your original)
        self.basic_patterns = [
            # SQL Injection patterns
            r"('|\").*(\bor\b|\bunion\b|\bselect\b|\bdrop\b|\binsert\b|\bdelete\b)",
            r";\s*--",
            r"('|\").*('|\")\s*=\s*('|\")",
            
            # XSS patterns
            r"<\s*script[^>]*>",
            r"javascript\s*:",
            r"<\s*iframe[^>]*>",
            r"onerror\s*=",
            r"onload\s*=",
            r"alert\s*\(",
            
            # Command injection
            r";\s*(cat|ls|dir|whoami|id|pwd)",
            r"\|\s*(nc|netcat|curl|wget)",
            r"&&\s*(rm|del|format)",
            r"`[^`]+`",
            r"\$\([^)]+\)",
            
            # Path traversal
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"\.\.%2f",
            
            # LDAP injection
            r"\*\)\(&",
            r"\)\(&",
            r"\*\)\(\|"
        ]
        
        # Advanced attack patterns (professional grade)
        self.advanced_sqli_patterns = [
            # Unicode/Encoding evasions
            r"%u[0-9a-f]{4}(union|select|drop|insert|delete)",
            r"\\u[0-9a-f]{4}(union|select|drop|insert|delete)",
            
            # Case variation with separators
            r"(?i)(u\s*n\s*i\s*o\s*n|s\s*e\s*l\s*e\s*c\s*t)",
            r"(?i)(u/\*\*/n/\*\*/i/\*\*/o/\*\*/n)",
            
            # Advanced comment injection
            r"/\*.*?\*/(union|select|drop|insert|delete)",
            r"--[^\r\n]*(union|select|drop|insert|delete)",
            r"#[^\r\n]*(union|select|drop|insert|delete)",
            
            # Time-based blind SQLi
            r"(?i)(sleep|pg_sleep|waitfor|delay)\s*\(\s*\d+\s*\)",
            r"(?i)benchmark\s*\(\s*\d+\s*,",
            
            # NoSQL injection patterns
            r"(?i)\$where.*?function",
            r"(?i)\$regex.*?\$options",
            r"(?i)\$gt:\s*\d+",
            r"(?i)\$ne:\s*null",
            
            # Boolean-based blind SQLi
            r"(?i)(and|or)\s+\d+\s*[=<>!]+\s*\d+",
        ]
        
        # Advanced XSS patterns
        self.advanced_xss_patterns = [
            # Event handlers (comprehensive)
            r"(?i)on(load|error|focus|blur|change|submit|reset|click|dblclick|mouseover|mouseout|mousemove|mousedown|mouseup|keydown|keyup|keypress|resize|scroll)\s*=",
            
            # Advanced script injection
            r"(?i)<\s*svg[^>]*?onload\s*=",
            r"(?i)<\s*iframe[^>]*?src\s*=\s*[\"']?javascript:",
            r"(?i)<\s*object[^>]*?data\s*=\s*[\"']?javascript:",
            
            # DOM manipulation
            r"(?i)document\.(write|writeln|createElement|getElementById)",
            r"(?i)window\.(open|location|eval)",
            r"(?i)eval\s*\(",
            r"(?i)setTimeout\s*\(",
            
            # Encoded XSS
            r"(?i)%3c\s*script",
            r"(?i)&lt;\s*script",
            r"(?i)\\x3c\s*script",
            r"(?i)\\u003c\s*script",
            
            # Data URIs
            r"(?i)data\s*:\s*text/html",
            r"(?i)data\s*:\s*image/svg\+xml",
        ]
        
        # Server-Side Template Injection (SSTI)
        self.ssti_patterns = [
            # Jinja2/Django/Flask
            r"\{\{.*?(config|request|session|g|url_for|get_flashed_messages).*?\}\}",
            r"\{\{.*?__class__.*?\}\}",
            r"\{\{.*?__mro__.*?\}\}",
            r"\{\{.*?__subclasses__.*?\}\}",
            
            # Twig
            r"\{\{.*?_self.*?\}\}",
            r"\{\{.*?dump\(.*?\).*?\}\}",
            
            # Expression Language (EL) - Spring/Java
            r"\$\{.*?(Runtime|ProcessBuilder|exec).*?\}",
            r"#\{.*?(Runtime|ProcessBuilder).*?\}",
            
            # Freemarker
            r"<#.*?#>",
            r"\$\{.*?new\s+.*?\}",
        ]
        
        # XXE (XML External Entity) patterns
        self.xxe_patterns = [
            r"<!ENTITY\s+\w+\s+SYSTEM\s+[\"'][^\"']*[\"']>",
            r"<!DOCTYPE\s+\w+\s+\[.*?<!ENTITY.*?\]>",
            r"file://",
            r"(?i)<!entity.*?system.*?>",
            r"(?i)<!doctype.*?\[.*?<!entity.*?\]>",
        ]
        
        # Advanced Path Traversal
        self.advanced_path_traversal = [
            # Double encoding
            r"%252e%252e%252f",
            r"%252e%252e%255c",
            
            # Unicode variations
            r"\.\.[\u002f\u005c]",
            r"\.\.[\uff0f\uff3c]",
            
            # Filter bypass attempts
            r"....[/\\]",
            r"..;[/\\]",
            r"..\x00[/\\]",
            
            # Specific file targeting
            r"(\.\.[\\/]){2,}(etc/passwd|windows/system32|boot\.ini)",
        ]
        
        # Advanced Command Injection
        self.advanced_cmd_patterns = [
            # Backtick and command substitution
            r"`[^`]*(whoami|id|pwd|uname|ps|netstat)[^`]*`",
            r"\$\([^)]*(whoami|id|pwd|uname|ps|netstat)[^)]*\)",
            
            # Environment variables
            r"\$\{[^}]*\}",
            r"\$[A-Z_][A-Z0-9_]*",
            
            # Binary execution paths
            r"/bin/(sh|bash|csh|tcsh|zsh)",
            r"/usr/bin/(perl|python|ruby|php|node)",
            r"cmd\.exe",
            r"powershell\.exe",
        ]
        
        # Bot patterns (from your original plus advanced)
        self.bot_patterns = [
            # Basic bots
            r"python-requests",
            r"urllib",
            r"wget",
            r"curl",
            r"scrapy",
            
            # Security scanners
            r"nikto",
            r"sqlmap",
            r"burp",
            r"owasp",
            r"nessus",
            r"acunetix",
            
            # Advanced scanners
            r"nuclei",
            r"ffuf",
            r"gobuster",
            r"wfuzz",
            r"feroxbuster",
            
            # Headless browsers
            r"headless",
            r"phantomjs",
            r"selenium",
            r"puppeteer",
            r"playwright",
        ]
        
        # IP reputation patterns
        self.suspicious_ip_patterns = [
            r"146\.148\.",  # From your data
            r"23\.27\.",    # From your data
            r"176\.65\.",   # From your data
        ]
        
        # Compile all patterns
        self.compiled_basic = [re.compile(p, re.IGNORECASE) for p in self.basic_patterns]
        self.compiled_advanced_sqli = [re.compile(p, re.IGNORECASE) for p in self.advanced_sqli_patterns]
        self.compiled_advanced_xss = [re.compile(p, re.IGNORECASE) for p in self.advanced_xss_patterns]
        self.compiled_ssti = [re.compile(p, re.IGNORECASE) for p in self.ssti_patterns]
        self.compiled_xxe = [re.compile(p, re.IGNORECASE) for p in self.xxe_patterns]
        self.compiled_advanced_path = [re.compile(p, re.IGNORECASE) for p in self.advanced_path_traversal]
        self.compiled_advanced_cmd = [re.compile(p, re.IGNORECASE) for p in self.advanced_cmd_patterns]
        self.compiled_bot_patterns = [re.compile(p, re.IGNORECASE) for p in self.bot_patterns]
        self.compiled_ip_patterns = [re.compile(p) for p in self.suspicious_ip_patterns]
    
    def detect_attack(self, request: str) -> Tuple[bool, str]:
        """
        Professional attack detection with comprehensive coverage
        Compatible with your existing runner interface
        """
        severity_score = 0
        detections = []
        
        # Basic attack detection (maintains backward compatibility)
        for i, pattern in enumerate(self.compiled_basic):
            if pattern.search(request):
                attack_types = {
                    0: "SQL Injection", 1: "SQL Injection", 2: "SQL Injection",
                    3: "XSS", 4: "XSS", 5: "XSS", 6: "XSS", 7: "XSS", 8: "XSS",
                    9: "Command Injection", 10: "Command Injection", 11: "Command Injection", 12: "Command Injection", 13: "Command Injection",
                    14: "Path Traversal", 15: "Path Traversal", 16: "Path Traversal", 17: "Path Traversal",
                    18: "LDAP Injection", 19: "LDAP Injection", 20: "LDAP Injection"
                }
                attack_type = attack_types.get(i, "Unknown Attack")
                return True, f"MALICIOUS - {attack_type} Detected - BLOCK"
        
        # Advanced SQL Injection detection
        for pattern in self.compiled_advanced_sqli:
            if pattern.search(request):
                detections.append("Advanced SQL Injection")
                severity_score += 5
                break
        
        # Advanced XSS detection
        for pattern in self.compiled_advanced_xss:
            if pattern.search(request):
                detections.append("Advanced XSS")
                severity_score += 4
                break
        
        # SSTI detection
        for pattern in self.compiled_ssti:
            if pattern.search(request):
                detections.append("Server-Side Template Injection")
                severity_score += 5
                break
        
        # XXE detection
        for pattern in self.compiled_xxe:
            if pattern.search(request):
                detections.append("XML External Entity (XXE)")
                severity_score += 4
                break
        
        # Advanced Path Traversal
        for pattern in self.compiled_advanced_path:
            if pattern.search(request):
                detections.append("Advanced Path Traversal")
                severity_score += 4
                break
        
        # Advanced Command Injection
        for pattern in self.compiled_advanced_cmd:
            if pattern.search(request):
                detections.append("Advanced Command Injection")
                severity_score += 5
                break
        
        # Bot/Scanner detection
        for pattern in self.compiled_bot_patterns:
            if pattern.search(request):
                detections.append("BOT_SCANNER")
                severity_score += 2
                break
        
        # Suspicious IP detection
        for pattern in self.compiled_ip_patterns:
            if pattern.search(request):
                detections.append("SUSPICIOUS_IP")
                severity_score += 2
                break
        
        # Additional automated request detection
        if self._is_automated_request(request):
            detections.append("AUTOMATED_BOT")
            severity_score += 2
        
        # Return detection result
        if detections:
            if severity_score >= 8:
                risk_level = "CRITICAL"
            elif severity_score >= 5:
                risk_level = "HIGH"
            elif severity_score >= 3:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"
            
            return True, f"MALICIOUS - {', '.join(detections)} - {risk_level} Risk (Score: {severity_score}) - BLOCK"
        
        return False, "SAFE - No Threat Detected - ALLOW"
    
    def _is_automated_request(self, request: str) -> bool:
        """Enhanced automated request detection"""
        bot_indicators = [
            # No referer + scripting user agent
            ("python-requests" in request.lower() and "referer:" not in request.lower()),
            ("curl" in request.lower() and "referer:" not in request.lower()),
            
            # Missing common browser headers
            ("user-agent:" in request.lower() and 
             not any(browser in request.lower() for browser in ["mozilla", "chrome", "firefox", "safari", "edge"])),
            
            # Suspicious user agent patterns
            any(suspicious in request.lower() for suspicious in [
                "python/", "go-http-client", "java/", "php/", "ruby/", 
                "perl/", "node/", "axios/", "okhttp/", "apache-httpclient"
            ]),
            
            # Empty or minimal user agents
            re.search(r"user-agent:\s*$", request.lower()),
            re.search(r"user-agent:\s*-\s*$", request.lower()),
            
            # High frequency scanning patterns
            re.search(r"/(admin|login|wp-admin|phpmyadmin|admin\.php)", request.lower()),
        ]
        
        return any(bot_indicators)

# Professional test cases for comprehensive testing
professional_waf_test_cases = [
    # Basic attacks (for backward compatibility)
    {
        'request': "GET /search?q=' OR '1'='1",
        'expected': 'malicious',
        'attack_type': 'basic_sqli'
    },
    {
        'request': "POST /comment data=<script>alert('XSS')</script>",
        'expected': 'malicious', 
        'attack_type': 'basic_xss'
    },
    
    # Advanced SQL Injection
    {
        'request': "GET /search?q=1' /**/UNION/**/SELECT/**/ user,pass /**/FROM/**/ admin--",
        'expected': 'malicious',
        'attack_type': 'advanced_sqli'
    },
    {
        'request': "POST /login data=username=admin&password=' or SLEEP(5)#",
        'expected': 'malicious', 
        'attack_type': 'advanced_sqli'
    },
    {
        'request': "GET /api?filter={\"$where\": \"function() { return true; }\"}",
        'expected': 'malicious',
        'attack_type': 'nosql_injection'
    },
    
    # Advanced XSS
    {
        'request': "GET /search?q=<svg onload=alert(String.fromCharCode(88,83,83))>",
        'expected': 'malicious',
        'attack_type': 'advanced_xss'
    },
    {
        'request': "POST /comment data=%3Cscript%3Ealert('encoded')%3C/script%3E",
        'expected': 'malicious',
        'attack_type': 'encoded_xss'
    },
    
    # SSTI
    {
        'request': "GET /template?name={{config.items()}}",
        'expected': 'malicious',
        'attack_type': 'ssti'
    },
    {
        'request': "POST /render data={{request.__class__.__mro__[1].__subclasses__()}}",
        'expected': 'malicious',
        'attack_type': 'ssti_advanced'
    },
    
    # XXE
    {
        'request': 'POST /xml data=<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        'expected': 'malicious',
        'attack_type': 'xxe'
    },
    
    # Advanced Path Traversal
    {
        'request': "GET /file?path=%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        'expected': 'malicious',
        'attack_type': 'advanced_path_traversal'
    },
    
    # Advanced Command Injection
    {
        'request': "GET /exec?cmd=`whoami`",
        'expected': 'malicious',
        'attack_type': 'advanced_cmd_injection'
    },
    
    # Bot Detection
    {
        'request': "GET /api/test User-Agent: python-requests/2.32.3",
        'expected': 'malicious',
        'attack_type': 'bot_scanner'
    },
    {
        'request': "GET /admin User-Agent: sqlmap/1.6.12",
        'expected': 'malicious',
        'attack_type': 'security_scanner'
    },
    
    # Benign requests
    {
        'request': "GET /api/users/profile User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        'expected': 'safe',
        'attack_type': 'benign'
    },
    {
        'request': "POST /search data=query=legitimate+search+term",
        'expected': 'safe',
        'attack_type': 'benign'
    }
]

# Replace PatternBasedWAFDetector with ProfessionalWAFDetector
PatternBasedWAFDetector = ProfessionalWAFDetector  # For backward compatibility
