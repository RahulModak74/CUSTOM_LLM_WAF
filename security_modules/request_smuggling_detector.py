"""
HTTP Request Smuggling Detection Module
Add this file as: security_modules/request_smuggling_detector.py
"""

import re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass


@dataclass
class SmugglingResult:
    """Request smuggling detection result"""
    is_smuggling: bool
    attack_type: str
    risk_level: str
    message: str
    suspicious_headers: List[str]


class RequestSmugglingDetector:
    """Detect HTTP Request Smuggling attempts"""
    
    def __init__(self):
        # Patterns that indicate potential request smuggling
        self.cl_te_patterns = [
            # Content-Length and Transfer-Encoding conflicts
            r'Content-Length:\s*\d+.*Transfer-Encoding:\s*chunked',
            r'Transfer-Encoding:\s*chunked.*Content-Length:\s*\d+',
        ]
        
        self.te_cl_patterns = [
            # Transfer-Encoding variations that might bypass validation
            r'Transfer-Encoding:\s*[^,\r\n]*,\s*chunked',
            r'Transfer-Encoding:\s*chunked[^,\r\n]*,',
            r'Transfer-Encoding:\s*[^c][^h][^u][^n][^k][^e][^d].*chunked',
        ]
        
        self.header_smuggling_patterns = [
            # Header name obfuscation
            r'Content-Length\s*:\s*\d+',  # Space before colon
            r'Transfer-Encoding\s*:\s*chunked',  # Space before colon
            r'Content-Length\x09:\s*\d+',  # Tab before colon
            r'Transfer-Encoding\x09:\s*chunked',  # Tab before colon
            # Multiple Content-Length headers
            r'Content-Length:.*\r?\n.*Content-Length:',
            # Multiple Transfer-Encoding headers
            r'Transfer-Encoding:.*\r?\n.*Transfer-Encoding:',
        ]
        
        self.chunked_encoding_exploits = [
            # Malformed chunk sizes
            r'[0-9a-fA-F]+[^0-9a-fA-F\r\n]',  # Invalid characters in chunk size
            r'[0-9a-fA-F]{8,}',  # Extremely large chunk sizes
            # Chunk extension exploits
            r'[0-9a-fA-F]+;[^=]*=[^;\r\n]*[;\r\n]',  # Suspicious chunk extensions
            # Invalid chunk termination
            r'[0-9a-fA-F]+\r?\n[^\r\n]*[^\r\n]',  # Missing CRLF after chunk data
        ]
        
        # Compile patterns for performance
        self.compiled_patterns = {
            'cl_te': [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.cl_te_patterns],
            'te_cl': [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.te_cl_patterns],
            'header_smuggling': [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.header_smuggling_patterns],
            'chunked_exploits': [re.compile(p, re.IGNORECASE) for p in self.chunked_encoding_exploits],
        }
    
    def analyze_request(self, raw_headers: str, body: str = "") -> SmugglingResult:
        """Analyze request for smuggling attempts"""
        suspicious_headers = []
        max_risk = "LOW"
        messages = []
        attack_types = []
        
        # Parse headers
        headers = self._parse_headers(raw_headers)
        
        # Check for CL.TE (Content-Length + Transfer-Encoding) attacks
        cl_te_result = self._check_cl_te_attack(raw_headers, headers)
        if cl_te_result.is_smuggling:
            messages.append(cl_te_result.message)
            attack_types.append(cl_te_result.attack_type)
            suspicious_headers.extend(cl_te_result.suspicious_headers)
            if self._get_risk_priority(cl_te_result.risk_level) > self._get_risk_priority(max_risk):
                max_risk = cl_te_result.risk_level
        
        # Check for TE.CL (Transfer-Encoding + Content-Length) attacks
        te_cl_result = self._check_te_cl_attack(raw_headers, headers)
        if te_cl_result.is_smuggling:
            messages.append(te_cl_result.message)
            attack_types.append(te_cl_result.attack_type)
            suspicious_headers.extend(te_cl_result.suspicious_headers)
            if self._get_risk_priority(te_cl_result.risk_level) > self._get_risk_priority(max_risk):
                max_risk = te_cl_result.risk_level
        
        # Check for TE.TE (Transfer-Encoding desync) attacks
        te_te_result = self._check_te_te_attack(raw_headers, headers)
        if te_te_result.is_smuggling:
            messages.append(te_te_result.message)
            attack_types.append(te_te_result.attack_type)
            suspicious_headers.extend(te_te_result.suspicious_headers)
            if self._get_risk_priority(te_te_result.risk_level) > self._get_risk_priority(max_risk):
                max_risk = te_te_result.risk_level
        
        # Check for chunked encoding exploits
        chunked_result = self._check_chunked_exploits(body)
        if chunked_result.is_smuggling:
            messages.append(chunked_result.message)
            attack_types.append(chunked_result.attack_type)
            if self._get_risk_priority(chunked_result.risk_level) > self._get_risk_priority(max_risk):
                max_risk = chunked_result.risk_level
        
        # Check for header smuggling
        header_result = self._check_header_smuggling(raw_headers)
        if header_result.is_smuggling:
            messages.append(header_result.message)
            attack_types.append(header_result.attack_type)
            suspicious_headers.extend(header_result.suspicious_headers)
            if self._get_risk_priority(header_result.risk_level) > self._get_risk_priority(max_risk):
                max_risk = header_result.risk_level
        
        is_smuggling = len(messages) > 0
        combined_message = "; ".join(messages) if messages else "No request smuggling detected"
        combined_attack_type = ", ".join(set(attack_types)) if attack_types else "None"
        
        return SmugglingResult(
            is_smuggling=is_smuggling,
            attack_type=combined_attack_type,
            risk_level=max_risk,
            message=combined_message,
            suspicious_headers=list(set(suspicious_headers))
        )
    
    def _parse_headers(self, raw_headers: str) -> Dict[str, List[str]]:
        """Parse raw headers into dictionary (supporting multiple values)"""
        headers = {}
        lines = raw_headers.split('\n')
        
        for line in lines:
            line = line.strip()
            if ':' in line:
                name, value = line.split(':', 1)
                name = name.strip().lower()
                value = value.strip()
                
                if name not in headers:
                    headers[name] = []
                headers[name].append(value)
        
        return headers
    
    def _check_cl_te_attack(self, raw_headers: str, headers: Dict[str, List[str]]) -> SmugglingResult:
        """Check for CL.TE (Content-Length + Transfer-Encoding) attacks"""
        content_length = headers.get('content-length', [])
        transfer_encoding = headers.get('transfer-encoding', [])
        
        # Both headers present - potential smuggling
        if content_length and transfer_encoding:
            # Check if Transfer-Encoding contains 'chunked'
            te_has_chunked = any('chunked' in te.lower() for te in transfer_encoding)
            
            if te_has_chunked:
                return SmugglingResult(
                    is_smuggling=True,
                    attack_type="CL.TE",
                    risk_level="CRITICAL",
                    message="CL.TE request smuggling: Both Content-Length and Transfer-Encoding headers present",
                    suspicious_headers=['content-length', 'transfer-encoding']
                )
        
        # Check for patterns in raw headers
        for pattern in self.compiled_patterns['cl_te']:
            if pattern.search(raw_headers):
                return SmugglingResult(
                    is_smuggling=True,
                    attack_type="CL.TE",
                    risk_level="CRITICAL",
                    message="CL.TE request smuggling pattern detected",
                    suspicious_headers=['content-length', 'transfer-encoding']
                )
        
        return SmugglingResult(False, "", "LOW", "", [])
    
    def _check_te_cl_attack(self, raw_headers: str, headers: Dict[str, List[str]]) -> SmugglingResult:
        """Check for TE.CL (Transfer-Encoding + Content-Length) attacks"""
        transfer_encoding = headers.get('transfer-encoding', [])
        
        # Check for malformed Transfer-Encoding headers
        for te in transfer_encoding:
            # Check for obfuscated chunked encoding
            if 'chunked' in te.lower():
                # Look for additional values after chunked
                if te.lower().strip() != 'chunked':
                    return SmugglingResult(
                        is_smuggling=True,
                        attack_type="TE.CL",
                        risk_level="CRITICAL",
                        message=f"TE.CL request smuggling: Malformed Transfer-Encoding header: {te}",
                        suspicious_headers=['transfer-encoding']
                    )
        
        # Check for patterns
        for pattern in self.compiled_patterns['te_cl']:
            if pattern.search(raw_headers):
                return SmugglingResult(
                    is_smuggling=True,
                    attack_type="TE.CL",
                    risk_level="CRITICAL",
                    message="TE.CL request smuggling pattern detected",
                    suspicious_headers=['transfer-encoding']
                )
        
        return SmugglingResult(False, "", "LOW", "", [])
    
    def _check_te_te_attack(self, raw_headers: str, headers: Dict[str, List[str]]) -> SmugglingResult:
        """Check for TE.TE (Transfer-Encoding desync) attacks"""
        transfer_encoding = headers.get('transfer-encoding', [])
        
        # Multiple Transfer-Encoding headers
        if len(transfer_encoding) > 1:
            return SmugglingResult(
                is_smuggling=True,
                attack_type="TE.TE",
                risk_level="HIGH",
                message="TE.TE request smuggling: Multiple Transfer-Encoding headers",
                suspicious_headers=['transfer-encoding']
            )
        
        # Check for obfuscated Transfer-Encoding values
        for te in transfer_encoding:
            # Check for case variations or extra characters
            if 'chunked' in te.lower() and te.lower().strip() != 'chunked':
                # Look for common obfuscation techniques
                obfuscations = [
                    'xchunked', 'chunkedx', 'chunked ', ' chunked',
                    'chunked\t', '\tchunked', 'Chunked', 'CHUNKED'
                ]
                
                for obf in obfuscations:
                    if obf in te:
                        return SmugglingResult(
                            is_smuggling=True,
                            attack_type="TE.TE",
                            risk_level="HIGH",
                            message=f"TE.TE request smuggling: Obfuscated Transfer-Encoding: {te}",
                            suspicious_headers=['transfer-encoding']
                        )
        
        return SmugglingResult(False, "", "LOW", "", [])
    
    def _check_chunked_exploits(self, body: str) -> SmugglingResult:
        """Check for chunked encoding exploits in request body"""
        if not body:
            return SmugglingResult(False, "", "LOW", "", [])
        
        # Check for malformed chunk patterns
        for pattern in self.compiled_patterns['chunked_exploits']:
            match = pattern.search(body)
            if match:
                return SmugglingResult(
                    is_smuggling=True,
                    attack_type="Chunked Exploit",
                    risk_level="HIGH",
                    message=f"Malformed chunked encoding detected: {match.group()}",
                    suspicious_headers=[]
                )
        
        # Check for suspicious chunk sizes
        chunk_size_pattern = re.compile(r'^([0-9a-fA-F]+)', re.MULTILINE)
        matches = chunk_size_pattern.findall(body)
        
        for chunk_size_hex in matches:
            try:
                chunk_size = int(chunk_size_hex, 16)
                # Suspiciously large chunks
                if chunk_size > 1000000:  # 1MB
                    return SmugglingResult(
                        is_smuggling=True,
                        attack_type="Large Chunk",
                        risk_level="MEDIUM",
                        message=f"Suspiciously large chunk size: {chunk_size} bytes",
                        suspicious_headers=[]
                    )
            except ValueError:
                return SmugglingResult(
                    is_smuggling=True,
                    attack_type="Invalid Chunk",
                    risk_level="HIGH",
                    message=f"Invalid chunk size format: {chunk_size_hex}",
                    suspicious_headers=[]
                )
        
        return SmugglingResult(False, "", "LOW", "", [])
    
    def _check_header_smuggling(self, raw_headers: str) -> SmugglingResult:
        """Check for header-based smuggling attempts"""
        suspicious_headers = []
        
        for pattern in self.compiled_patterns['header_smuggling']:
            match = pattern.search(raw_headers)
            if match:
                return SmugglingResult(
                    is_smuggling=True,
                    attack_type="Header Smuggling",
                    risk_level="HIGH",
                    message=f"Header smuggling pattern detected: {match.group()}",
                    suspicious_headers=['content-length', 'transfer-encoding']
                )
        
        # Check for header name obfuscation
        header_lines = raw_headers.split('\n')
        for line in header_lines:
            line = line.strip()
            if ':' in line:
                header_name = line.split(':', 1)[0]
                
                # Check for spaces or tabs in header names
                if ' ' in header_name or '\t' in header_name:
                    suspicious_headers.append(header_name.lower())
                
                # Check for case variations in critical headers
                critical_headers = ['content-length', 'transfer-encoding']
                for critical in critical_headers:
                    if header_name.lower() == critical and header_name != critical:
                        suspicious_headers.append(header_name.lower())
        
        if suspicious_headers:
            return SmugglingResult(
                is_smuggling=True,
                attack_type="Header Obfuscation",
                risk_level="MEDIUM",
                message="Suspicious header formatting detected",
                suspicious_headers=suspicious_headers
            )
        
        return SmugglingResult(False, "", "LOW", "", [])
    
    def _get_risk_priority(self, risk_level: str) -> int:
        """Get numeric priority for risk level"""
        priorities = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        return priorities.get(risk_level, 0)
    
    def generate_safe_headers(self) -> Dict[str, str]:
        """Generate headers to prevent request smuggling"""
        return {
            # Prevent ambiguous content length
            "Connection": "close",
            # Ensure consistent processing
            "X-Content-Type-Options": "nosniff",
            # Add security headers
            "X-Request-Smuggling-Protection": "1",
        }
    
    def normalize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Normalize headers to prevent smuggling"""
        normalized = {}
        
        for name, value in headers.items():
            # Convert to lowercase and strip
            clean_name = name.lower().strip()
            clean_value = value.strip()
            
            # Skip duplicate critical headers
            if clean_name in ['content-length', 'transfer-encoding']:
                if clean_name not in normalized:
                    normalized[clean_name] = clean_value
            else:
                normalized[clean_name] = clean_value
        
        return normalized
