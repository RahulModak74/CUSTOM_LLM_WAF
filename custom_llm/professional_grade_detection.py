"""Pl use these functions in dynamic_quant/n1 when running proferssionally"""
# Enhanced patterns for professional ModSecurity environments

class ProfessionalWAFDetector:
    """Professional-grade WAF detector matching ModSecurity CRS standards"""
    
    def __init__(self):
        # Advanced SQL Injection patterns (beyond basic ones)
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
            
            # Hex encoding
            r"0x[0-9a-f]+(union|select|drop|insert|delete)",
            
            # Conditional attacks
            r"(?i)(if|case|when|then|else).*?(union|select|drop)",
            r"(?i)(sleep|benchmark|waitfor|delay)\s*\(",
            
            # Boolean-based blind SQLi
            r"(?i)(and|or)\s+\d+\s*[=<>!]+\s*\d+",
            r"(?i)(and|or)\s+\w+\s*[=<>!]+\s*\w+",
            
            # Time-based blind SQLi
            r"(?i)(sleep|pg_sleep|waitfor|delay)\s*\(\s*\d+\s*\)",
            r"(?i)benchmark\s*\(\s*\d+\s*,",
            
            # NoSQL injection patterns
            r"(?i)\$where.*?function",
            r"(?i)\$regex.*?\$options",
            r"(?i)javascript:.*?(eval|function)",
            r"(?i)\$gt:\s*\d+",
            r"(?i)\$lt:\s*\d+",
            r"(?i)\$ne:\s*null",
        ]
        
        # Advanced XSS patterns
        self.advanced_xss_patterns = [
            # Event handlers
            r"(?i)on(load|error|focus|blur|change|submit|reset|click|dblclick|mouseover|mouseout|mousemove|mousedown|mouseup|keydown|keyup|keypress|resize|scroll)\s*=",
            
            # JavaScript protocols
            r"(?i)javascript\s*:",
            r"(?i)vbscript\s*:",
            r"(?i)data\s*:\s*text/html",
            r"(?i)data\s*:\s*image/svg\+xml",
            
            # Advanced script injection
            r"(?i)<\s*script[^>]*?>.*?</\s*script\s*>",
            r"(?i)<\s*svg[^>]*?onload\s*=",
            r"(?i)<\s*iframe[^>]*?src\s*=\s*[\"']?javascript:",
            r"(?i)<\s*object[^>]*?data\s*=\s*[\"']?javascript:",
            r"(?i)<\s*embed[^>]*?src\s*=\s*[\"']?javascript:",
            
            # DOM manipulation
            r"(?i)document\.(write|writeln|createElement|getElementById)",
            r"(?i)window\.(open|location|eval)",
            r"(?i)eval\s*\(",
            r"(?i)setTimeout\s*\(",
            r"(?i)setInterval\s*\(",
            
            # CSS injection
            r"(?i)expression\s*\(",
            r"(?i)@import\s+[\"']?javascript:",
            r"(?i)background(-image)?\s*:\s*url\s*\(\s*[\"']?javascript:",
            
            # Encoded XSS
            r"(?i)%3c\s*script",
            r"(?i)&lt;\s*script",
            r"(?i)\\x3c\s*script",
            r"(?i)\\u003c\s*script",
        ]
        
        # Advanced Path Traversal
        self.advanced_path_traversal = [
            # Various encoding methods
            r"\.\.[\\/]",
            r"%2e%2e[\\/]",
            r"\.\.%2f",
            r"\.\.%5c",
            r"%2e%2e%2f",
            r"%2e%2e%5c",
            r"..%252f",
            r"..%255c",
            
            # Double encoding
            r"%252e%252e%252f",
            r"%252e%252e%255c",
            
            # Unicode variations
            r"\.\.[\u002f\u005c]",
            r"\.\.[\uff0f\uff3c]",
            
            # URL encoding variations
            r"\.\.[/\\]",
            r"\.\.\x2f",
            r"\.\.\x5c",
            
            # Filter bypass attempts
            r"....[/\\]",
            r"..;[/\\]",
            r"..\x00[/\\]",
            
            # Windows/Unix path combinations
            r"(\.\.[\\/]){2,}(etc|boot|windows|system32)",
            r"(\.\.[\\/]){2,}(passwd|shadow|hosts|config)",
        ]
        
        # Advanced Command Injection
        self.advanced_command_injection = [
            # Command separators
            r"[;&|`]\s*(cat|ls|dir|type|more|less|head|tail|whoami|id|pwd|uname|ps|netstat|ifconfig|ipconfig)",
            
            # Backtick execution
            r"`[^`]*(cat|ls|dir|type|whoami|id|pwd|uname|ps|netstat|ifconfig|ipconfig)[^`]*`",
            
            # Command substitution
            r"\$\([^)]*(cat|ls|dir|type|whoami|id|pwd|uname|ps|netstat|ifconfig|ipconfig)[^)]*\)",
            
            # Piping and redirection
            r"\|\s*(nc|netcat|telnet|ncat|socat|bash|sh|cmd|powershell)",
            r">\s*/dev/tcp/",
            r">\s*/dev/udp/",
            
            # Environment variable manipulation
            r"\$\{[^}]*\}",
            r"\$[A-Z_][A-Z0-9_]*",
            
            # Binary execution
            r"/bin/(sh|bash|csh|tcsh|zsh|ksh)",
            r"/usr/bin/(perl|python|ruby|php|node|java)",
            r"cmd\.exe",
            r"powershell\.exe",
            
            # File operations
            r"(echo|printf|cat)\s+.*?>\s*",
            r"(wget|curl|fetch)\s+.*?-O",
            r"(chmod|chown|chgrp)\s+[0-9]{3,4}",
        ]
        
        # Server-Side Template Injection (SSTI)
        self.ssti_patterns = [
            # Jinja2/Django
            r"\{\{.*?\}\}",
            r"\{%.*?%\}",
            r"\{\{.*?(config|request|session|g).*?\}\}",
            
            # Twig
            r"\{\{.*?_self.*?\}\}",
            r"\{\{.*?dump\(.*?\).*?\}\}",
            
            # Smarty
            r"\{.*?\$smarty.*?\}",
            r"\{php\}.*?\{/php\}",
            
            # Freemarker
            r"<#.*?#>",
            r"\$\{.*?\}",
            
            # Velocity
            r"#set\s*\(",
            r"#foreach\s*\(",
            r"\$\{.*?\}",
            
            # Expression Language (EL)
            r"\$\{.*?(Runtime|ProcessBuilder|exec).*?\}",
        ]
        
        # XXE (XML External Entity) patterns
        self.xxe_patterns = [
            r"<!ENTITY\s+\w+\s+SYSTEM\s+[\"'][^\"']*[\"']>",
            r"<!ENTITY\s+\w+\s+PUBLIC\s+[\"'][^\"']*[\"']\s+[\"'][^\"']*[\"']>",
            r"<!DOCTYPE\s+\w+\s+\[.*?<!ENTITY.*?\]>",
            r"&\w+;",
            r"file://",
            r"http://.*?/etc/passwd",
            r"gopher://",
            r"ftp://.*?/etc/passwd",
        ]
        
        # HTTP Request Smuggling
        self.request_smuggling_patterns = [
            r"Transfer-Encoding:\s*chunked",
            r"Content-Length:\s*\d+.*?Content-Length:\s*\d+",
            r"Transfer-Encoding:.*?Transfer-Encoding:",
            r"\r\n\r\n[A-Fa-f0-9]+\r\n",
            r"Content-Length:\s*0\r\n\r\n[^\r\n]",
        ]
        
        # Advanced Bot Detection (beyond basic)
        self.advanced_bot_patterns = [
            # Headless browsers
            r"headless",
            r"phantomjs",
            r"selenium",
            r"puppeteer",
            r"playwright",
            r"chromedriver",
            r"geckodriver",
            
            # Automated testing tools
            r"postman",
            r"insomnia",
            r"httpie",
            r"rest-client",
            
            # Missing or suspicious headers
            r"user-agent:\s*$",  # Empty user agent
            r"user-agent:\s*-$",  # Dash user agent
            
            # Reconnaissance tools
            r"whatweb",
            r"wappalyzer",
            r"builtwith",
            r"shodan",
            
            # Fuzzing tools
            r"ffuf",
            r"wfuzz",
            r"dirb",
            r"gobuster",
            r"feroxbuster",
        ]
        
        # Compile all patterns
        self.compiled_advanced_sqli = [re.compile(p, re.IGNORECASE) for p in self.advanced_sqli_patterns]
        self.compiled_advanced_xss = [re.compile(p, re.IGNORECASE) for p in self.advanced_xss_patterns]
        self.compiled_advanced_path = [re.compile(p, re.IGNORECASE) for p in self.advanced_path_traversal]
        self.compiled_advanced_cmd = [re.compile(p, re.IGNORECASE) for p in self.advanced_command_injection]
        self.compiled_ssti = [re.compile(p, re.IGNORECASE) for p in self.ssti_patterns]
        self.compiled_xxe = [re.compile(p, re.IGNORECASE) for p in self.xxe_patterns]
        self.compiled_smuggling = [re.compile(p, re.IGNORECASE) for p in self.request_smuggling_patterns]
        self.compiled_advanced_bot = [re.compile(p, re.IGNORECASE) for p in self.advanced_bot_patterns]
    
    def detect_professional_attacks(self, request: str) -> Tuple[bool, str, int]:
        """
        Professional attack detection with scoring
        Returns: (is_malicious, detection_message, severity_score)
        """
        severity_score = 0
        detections = []
        
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
        
        # Request smuggling
        for pattern in self.compiled_smuggling:
            if pattern.search(request):
                detections.append("HTTP Request Smuggling")
                severity_score += 5
                break
        
        # Advanced bot detection
        for pattern in self.compiled_advanced_bot:
            if pattern.search(request):
                detections.append("Advanced Bot/Scanner")
                severity_score += 2
                break
        
        if detections:
            return True, f"MALICIOUS - {', '.join(detections)} - BLOCK (Score: {severity_score})", severity_score
        
        return False, "SAFE - No Advanced Threats Detected - ALLOW", 0

# Professional test cases that would bypass basic detection
professional_test_cases = [
    # Advanced SQL Injection
    {
        'request': "GET /search?q=1' /**/UNION/**/SELECT/**/ user,pass /**/FROM/**/ admin--",
        'expected': 'malicious',
        'attack_type': 'advanced_sqli'
    },
    {
        'request': "POST /login data=username=admin&password=' or 1=1#",
        'expected': 'malicious', 
        'attack_type': 'advanced_sqli'
    },
    {
        'request': "GET /user?id=1' AND (SELECT SLEEP(5))--",
        'expected': 'malicious',
        'attack_type': 'advanced_sqli'
    },
    
    # Advanced XSS
    {
        'request': "GET /search?q=<svg onload=alert(String.fromCharCode(88,83,83))>",
        'expected': 'malicious',
        'attack_type': 'advanced_xss'
    },
    {
        'request': "POST /comment data=<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycp'))>",
        'expected': 'malicious',
        'attack_type': 'advanced_xss'
    },
    
    # SSTI
    {
        'request': "GET /template?name={{config.items()}}",
        'expected': 'malicious',
        'attack_type': 'ssti'
    },
    {
        'request': "POST /render data=${T(java.lang.Runtime).getRuntime().exec('id')}",
        'expected': 'malicious',
        'attack_type': 'ssti'
    },
    
    # XXE
    {
        'request': 'POST /xml data=<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        'expected': 'malicious',
        'attack_type': 'xxe'
    },
    
    # Request Smuggling
    {
        'request': 'POST /api HTTP/1.1\r\nContent-Length: 44\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: vulnerable.com\r\n\r\n',
        'expected': 'malicious',
        'attack_type': 'request_smuggling'
    }
]
