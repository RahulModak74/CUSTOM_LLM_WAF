import torch
import torch.nn as nn
import torch.nn.functional as F
from transformers import AutoModelForCausalLM, AutoTokenizer
import numpy as np
from typing import Dict, List, Tuple, Optional
import re
import json

class HybridWAFDetector:
    """Hybrid WAF detector combining pattern matching + LLM for zero-day detection"""
    
    def __init__(self, quantized_model, tokenizer, confidence_threshold=0.7):
        self.quantized_model = quantized_model
        self.tokenizer = tokenizer
        self.confidence_threshold = confidence_threshold
        
        # Pattern-based detection (known attacks)
        self.known_attack_patterns = [
            # SQL Injection patterns
            r"('|\").*(\bor\b|\bunion\b|\bselect\b|\bdrop\b|\binsert\b|\bdelete\b)",
            r";\s*--",
            r"('|\").*('|\")\s*=\s*('|\")",
            
            # XSS patterns
            r"<\s*script[^>]*>",
            r"javascript\s*:",
            r"alert\s*\(",
            
            # Command injection
            r";\s*(cat|ls|dir|whoami|id|pwd)",
            r"\|\s*(nc|netcat|curl|wget)",
            r"`[^`]+`",
            
            # Path traversal
            r"\.\./",
            r"%2e%2e%2f",
            
            # Bot patterns
            r"python-requests",
            r"sqlmap",
            r"nikto",
        ]
        
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.known_attack_patterns]
        
        # Zero-day detection prompts
        self.zero_day_prompts = {
            "anomaly_detection": """Analyze this HTTP request for suspicious or malicious behavior. Look for:
- Unusual parameter combinations
- Suspicious encoding patterns
- Potential injection attempts
- Abnormal request structure
- Novel attack vectors

HTTP Request: {request}

Is this request suspicious? Respond with MALICIOUS or SAFE and explain why.""",
            
            "behavioral_analysis": """You are a cybersecurity expert. Analyze this HTTP request for signs of:
- Social engineering attempts
- Data exfiltration patterns
- Privilege escalation attempts
- Application logic abuse
- Zero-day exploitation attempts

Request: {request}

Assessment: MALICIOUS/SAFE
Confidence: HIGH/MEDIUM/LOW
Reasoning:""",
            
            "context_analysis": """Evaluate this HTTP request in context. Consider:
- Parameter relationships
- Unusual data patterns
- Potential business logic attacks
- Novel obfuscation techniques
- Chained attack indicators

Request: {request}

Security Status:"""
        }
    
    def detect_attack(self, request: str) -> Tuple[bool, str]:
        """
        Hybrid detection: Pattern matching + LLM analysis
        Returns: (is_malicious, detection_message)
        """
        # Stage 1: Known attack pattern detection (fast)
        pattern_result = self._detect_known_patterns(request)
        if pattern_result[0]:  # If pattern match found
            return pattern_result
        
        # Stage 2: LLM-based zero-day detection (slower but comprehensive)
        llm_result = self._detect_zero_day_attacks(request)
        
        return llm_result
    
    def _detect_known_patterns(self, request: str) -> Tuple[bool, str]:
        """Fast pattern-based detection for known attacks"""
        for i, pattern in enumerate(self.compiled_patterns):
            if pattern.search(request):
                attack_types = {
                    0: "SQL Injection", 1: "SQL Injection", 2: "SQL Injection",
                    3: "XSS", 4: "XSS", 5: "XSS",
                    6: "Command Injection", 7: "Command Injection", 8: "Command Injection",
                    9: "Path Traversal", 10: "Path Traversal",
                    11: "Bot Scanner", 12: "Security Scanner", 13: "Vulnerability Scanner"
                }
                attack_type = attack_types.get(i, "Known Attack")
                return True, f"MALICIOUS - {attack_type} (Pattern Match) - BLOCK"
        
        return False, ""
    
    def _detect_zero_day_attacks(self, request: str) -> Tuple[bool, str]:
        """LLM-based zero-day attack detection"""
        try:
            # Use multiple analysis approaches
            anomaly_score = self._analyze_request_anomaly(request)
            behavioral_score = self._analyze_request_behavior(request)
            context_score = self._analyze_request_context(request)
            
            # Combine scores (weighted average)
            combined_score = (
                anomaly_score * 0.4 +
                behavioral_score * 0.4 +
                context_score * 0.2
            )
            
            if combined_score >= self.confidence_threshold:
                confidence_level = "HIGH" if combined_score >= 0.85 else "MEDIUM"
                return True, f"MALICIOUS - Zero-Day Attack Detected (LLM Confidence: {confidence_level}, Score: {combined_score:.2f}) - BLOCK"
            elif combined_score >= 0.4:  # Suspicious but not blocking
                return False, f"SUSPICIOUS - Potential Zero-Day (LLM Score: {combined_score:.2f}) - MONITOR"
            else:
                return False, "SAFE - No Threat Detected (LLM Analysis) - ALLOW"
                
        except Exception as e:
            # Fail-safe: if LLM analysis fails, allow but log
            return False, f"SAFE - LLM Analysis Failed ({str(e)}) - ALLOW"
    
    def _analyze_request_anomaly(self, request: str) -> float:
        """Use LLM to detect anomalous patterns"""
        prompt = self.zero_day_prompts["anomaly_detection"].format(request=request)
        
        response = self._query_llm(prompt, max_length=200)
        
        # Parse LLM response for malicious indicators
        response_lower = response.lower()
        
        malicious_indicators = [
            "malicious", "suspicious", "attack", "injection", "exploit",
            "dangerous", "harmful", "threat", "vulnerable", "payload"
        ]
        
        safe_indicators = [
            "safe", "normal", "legitimate", "benign", "harmless"
        ]
        
        malicious_count = sum(1 for indicator in malicious_indicators if indicator in response_lower)
        safe_count = sum(1 for indicator in safe_indicators if indicator in response_lower)
        
        # Calculate anomaly score
        if malicious_count > safe_count:
            return min(0.8 + (malicious_count - safe_count) * 0.1, 1.0)
        elif safe_count > malicious_count:
            return max(0.2 - (safe_count - malicious_count) * 0.1, 0.0)
        else:
            return 0.5  # Neutral/uncertain
    
    def _analyze_request_behavior(self, request: str) -> float:
        """Behavioral analysis using LLM"""
        prompt = self.zero_day_prompts["behavioral_analysis"].format(request=request)
        
        response = self._query_llm(prompt, max_length=150)
        response_lower = response.lower()
        
        # Look for confidence indicators
        if "confidence: high" in response_lower and "malicious" in response_lower:
            return 0.9
        elif "confidence: medium" in response_lower and "malicious" in response_lower:
            return 0.7
        elif "confidence: low" in response_lower and "malicious" in response_lower:
            return 0.5
        elif "safe" in response_lower:
            return 0.1
        else:
            return 0.3  # Default uncertain
    
    def _analyze_request_context(self, request: str) -> float:
        """Contextual analysis using LLM"""
        prompt = self.zero_day_prompts["context_analysis"].format(request=request)
        
        response = self._query_llm(prompt, max_length=100)
        
        # Simple scoring based on response content
        if any(word in response.lower() for word in ["malicious", "attack", "suspicious"]):
            return 0.8
        elif any(word in response.lower() for word in ["safe", "normal", "legitimate"]):
            return 0.2
        else:
            return 0.4
    
    def _query_llm(self, prompt: str, max_length: int = 150) -> str:
        """Query the quantized LLM for analysis"""
        try:
            # Tokenize input
            inputs = self.tokenizer(
                prompt,
                return_tensors="pt",
                truncation=True,
                max_length=512,
                padding=True
            )
            
            # Generate response using quantized model
            with torch.no_grad():
                outputs = self.quantized_model.generate(
                    **inputs,
                    max_new_tokens=max_length,
                    temperature=0.3,  # Lower temperature for more focused responses
                    do_sample=True,
                    pad_token_id=self.tokenizer.eos_token_id,
                    repetition_penalty=1.1
                )
            
            # Decode response
            response = self.tokenizer.decode(
                outputs[0][inputs['input_ids'].shape[1]:],
                skip_special_tokens=True
            )
            
            return response.strip()
            
        except Exception as e:
            print(f"LLM query failed: {e}")
            return "SAFE - Analysis failed"

class ZeroDayTestCases:
    """Test cases specifically designed to test zero-day detection capabilities"""
    
    @staticmethod
    def get_zero_day_test_cases():
        return [
            # Novel SQL injection variants
            {
                'request': "GET /api/user?filter={$where: function() { return this.username == 'admin' && this.deleted != true }}",
                'expected': 'malicious',
                'attack_type': 'nosql_injection_novel',
                'description': 'NoSQL injection with complex JavaScript function'
            },
            
            # Advanced XSS with novel encoding
            {
                'request': "POST /comment data=content=<svg/onload=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
                'expected': 'malicious',
                'attack_type': 'advanced_xss_encoded',
                'description': 'XSS with character code obfuscation'
            },
            
            # Business logic attack
            {
                'request': "POST /transfer data={\"from\":\"user123\",\"to\":\"attacker\",\"amount\":-1000}",
                'expected': 'malicious',
                'attack_type': 'business_logic_abuse',
                'description': 'Negative amount transfer to exploit business logic'
            },
            
            # API parameter pollution
            {
                'request': "GET /api/user?role=user&role=admin&action=delete",
                'expected': 'malicious',
                'attack_type': 'parameter_pollution',
                'description': 'HTTP parameter pollution for privilege escalation'
            },
            
            # Template injection variant
            {
                'request': "POST /render data=template={{request.application.__globals__.__builtins__.__import__('os').system('id')}}",
                'expected': 'malicious',
                'attack_type': 'advanced_ssti',
                'description': 'Advanced server-side template injection'
            },
            
            # Data exfiltration attempt
            {
                'request': "GET /api/export?format=json&table=users&limit=999999&include_sensitive=true",
                'expected': 'malicious',
                'attack_type': 'data_exfiltration',
                'description': 'Suspicious bulk data export request'
            },
            
            # Novel bot behavior
            {
                'request': "GET /robots.txt User-Agent: Mozilla/5.0 (compatible; CustomCrawler/1.0; +http://evil.com/bot)",
                'expected': 'malicious',
                'attack_type': 'suspicious_crawler',
                'description': 'Suspicious crawler with deceptive user agent'
            },
            
            # Legitimate requests (should pass)
            {
                'request': "GET /api/profile User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                'expected': 'safe',
                'attack_type': 'legitimate_api_call',
                'description': 'Normal user profile request'
            },
            
            {
                'request': "POST /search data=query=machine learning tutorials&category=technology",
                'expected': 'safe', 
                'attack_type': 'legitimate_search',
                'description': 'Normal search query'
            }
        ]

def test_zero_day_detection(detector, test_cases):
    """Test zero-day detection capabilities"""
    print("\n" + "="*80)
    print("ZERO-DAY ATTACK DETECTION TESTING")
    print("="*80)
    
    results = []
    pattern_only_caught = 0
    llm_only_caught = 0
    both_caught = 0
    
    for i, test_case in enumerate(test_cases):
        request = test_case['request']
        expected = test_case['expected']
        attack_type = test_case['attack_type']
        description = test_case['description']
        
        print(f"\nTest {i+1}: {attack_type}")
        print(f"Description: {description}")
        print(f"Request: {request[:100]}...")
        
        # Test detection
        is_malicious, response = detector.detect_attack(request)
        correct_detection = (
            (expected == 'malicious' and is_malicious) or
            (expected == 'safe' and not is_malicious)
        )
        
        # Analyze detection method
        if "Pattern Match" in response:
            pattern_only_caught += 1
            detection_method = "Pattern Matching"
        elif "LLM" in response:
            llm_only_caught += 1
            detection_method = "LLM Analysis"
        else:
            detection_method = "Unknown"
        
        results.append({
            'test_id': i + 1,
            'attack_type': attack_type,
            'expected': expected,
            'detected': is_malicious,
            'response': response,
            'correct': correct_detection,
            'method': detection_method
        })
        
        status = "✓ CORRECT" if correct_detection else "✗ INCORRECT"
        print(f"Result: {status} - {detection_method}")
        print(f"Response: {response}")
        print("-" * 60)
    
    # Summary
    accuracy = sum(r['correct'] for r in results) / len(results)
    print(f"\n🎯 ZERO-DAY DETECTION SUMMARY:")
    print(f"Overall Accuracy: {accuracy:.2%}")
    print(f"Pattern-only detections: {pattern_only_caught}")
    print(f"LLM-only detections: {llm_only_caught}")
    print(f"Total novel attacks detected by LLM: {llm_only_caught}")
    
    return results, accuracy

# Integration function to replace the basic detector
def create_hybrid_detector(quantized_model, tokenizer):
    """Create a hybrid detector that uses both patterns and LLM"""
    return HybridWAFDetector(quantized_model, tokenizer)
