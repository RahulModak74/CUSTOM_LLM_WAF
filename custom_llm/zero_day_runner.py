#!/usr/bin/env python3
"""
Hybrid WAF Detection Runner for Session CSV Data
Combines pattern matching + LLM analysis for zero-day detection
"""

import pandas as pd
import json
import sys
import os
from datetime import datetime
from urllib.parse import unquote
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the hybrid detector from your integrated WAF
try:
    from zero_day_waf import HybridWAFDetector, PatternBasedWAFDetector
    print("✅ Successfully imported HybridWAFDetector")
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("📁 Current working directory:", os.getcwd())
    print("📁 Script directory:", os.path.dirname(os.path.abspath(__file__)))
    print("📄 Files in current directory:")
    for file in os.listdir('.'):
        if file.endswith('.py'):
            print(f"  - {file}")
    
    # Try to define a minimal PatternBasedWAFDetector as fallback
    print("⚠️  Creating fallback PatternBasedWAFDetector...")
    
    import re
    
    class PatternBasedWAFDetector:
        """Fallback pattern-based WAF detector"""
        
        def __init__(self):
            self.attack_patterns = [
                r"('|\").*(\bor\b|\bunion\b|\bselect\b|\bdrop\b|\binsert\b|\bdelete\b)",
                r";\s*--",
                r"<\s*script[^>]*>",
                r"javascript\s*:",
                r"alert\s*\(",
                r"python-requests",
                r"sqlmap",
                r"nikto",
            ]
            self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.attack_patterns]
        
        def detect_attack(self, request: str):
            """Basic pattern matching detection"""
            for i, pattern in enumerate(self.compiled_patterns):
                if pattern.search(request):
                    attack_types = {
                        0: "SQL Injection", 1: "SQL Injection", 2: "XSS", 3: "XSS", 4: "XSS",
                        5: "Bot Scanner", 6: "Security Scanner", 7: "Vulnerability Scanner"
                    }
                    attack_type = attack_types.get(i, "Known Attack")
                    return True, f"MALICIOUS - {attack_type} (Pattern Match) - BLOCK"
            
            return False, "SAFE - No Known Patterns Detected - ALLOW"
    
    # Set HybridWAFDetector to None to indicate it's not available
    HybridWAFDetector = None

def load_quantized_model():
    """Load and return the quantized model and tokenizer"""
    models_to_try = [
        "Qwen/Qwen2.5-0.5B-Instruct",
        "Qwen/Qwen2.5-0.5B", 
        "gpt2"
    ]
    
    for model_name in models_to_try:
        print(f"Trying to load model: {model_name}")
        try:
            if "Qwen2.5" in model_name:
                model = AutoModelForCausalLM.from_pretrained(
                    model_name,
                    torch_dtype="auto",
                    device_map="auto"
                )
                tokenizer = AutoTokenizer.from_pretrained(model_name)
            else:
                model = AutoModelForCausalLM.from_pretrained(model_name)
                tokenizer = AutoTokenizer.from_pretrained(model_name)
            
            if tokenizer.pad_token is None:
                tokenizer.pad_token = tokenizer.eos_token
                
            print(f"✅ Successfully loaded {model_name}")
            return model, tokenizer, model_name
            
        except Exception as e:
            print(f"❌ Failed to load {model_name}: {e}")
            continue
    
    return None, None, None

def extract_request_components(session_data):
    """Extract and format HTTP request components from session data"""
    try:
        # Parse the JSON value field
        data = json.loads(session_data['value'])
        
        # Build comprehensive request representation
        request_parts = []
        
        # Add IP address
        if data.get('ip_address'):
            request_parts.append(f"IP: {data['ip_address']}")
        
        # Add user agent (primary attack vector)
        if data.get('user_agent'):
            request_parts.append(f"User-Agent: {data['user_agent']}")
        
        # Add referer if present (common attack vector)
        if data.get('referer') and data['referer'].strip():
            referer = unquote(data['referer'])  # URL decode
            request_parts.append(f"Referer: {referer}")
        
        # Add other headers that might contain attacks
        for field in ['accept_language', 'accept_encoding', 'x_forwarded_for']:
            if data.get(field) and data[field].strip():
                value = unquote(data[field])
                request_parts.append(f"{field.replace('_', '-').title()}: {value}")
        
        # Create a realistic HTTP request format
        http_request = " | ".join(request_parts)
        
        # If we have a referer with parameters, treat it as a GET request
        if data.get('referer') and '?' in data.get('referer', ''):
            referer_decoded = unquote(data['referer'])
            http_request = f"GET {referer_decoded} | " + http_request
        
        return http_request
        
    except (json.JSONDecodeError, KeyError) as e:
        # Fallback to using the session key
        return f"Session: {session_data['key']}"

def analyze_session_with_llm_context(session_data):
    """Analyze session data and provide context for LLM analysis"""
    try:
        data = json.loads(session_data['value'])
        
        # Extract key indicators for LLM context
        analysis_context = {
            'has_referer': bool(data.get('referer', '').strip()),
            'user_agent_type': 'browser' if any(browser in data.get('user_agent', '').lower() 
                                              for browser in ['mozilla', 'chrome', 'firefox', 'safari']) else 'automated',
            'ip_reputation': 'suspicious' if data.get('ip_address', '').startswith(('146.148', '23.27', '176.65')) else 'unknown',
            'encoded_content': '%' in data.get('referer', ''),
            'script_indicators': any(indicator in data.get('referer', '').lower() 
                                   for indicator in ['script', 'alert', 'javascript', 'eval'])
        }
        
        return analysis_context
        
    except:
        return {}

def main():
    print("=" * 80)
    print("🛡️  HYBRID WAF DETECTION RUNNER (Pattern + LLM)")
    print("=" * 80)
    
    # Load the quantized model
    print("\n🔄 Loading Quantized Model for Zero-Day Detection...")
    model, tokenizer, model_name = load_quantized_model()
    
    if model is None or HybridWAFDetector is None:
        print("❌ Failed to load model or HybridWAFDetector! Falling back to pattern-only detection.")
        waf_detector = PatternBasedWAFDetector()
        detection_mode = "Pattern-Only"
    else:
        print(f"✅ Model loaded successfully: {model_name}")
        print("🧠 Initializing Hybrid Detector (Pattern + LLM)...")
        waf_detector = HybridWAFDetector(model, tokenizer, confidence_threshold=0.6)
        detection_mode = "Hybrid (Pattern + LLM)"
    
    # Read the CSV file
    csv_file = "sample_session.csv"
    
    if not os.path.exists(csv_file):
        print(f"❌ Error: CSV file '{csv_file}' not found!")
        print("📁 Files in current directory:")
        for file in os.listdir('.'):
            if file.endswith('.csv'):
                print(f"  - {file}")
        return
    
    try:
        print(f"\n📊 Loading session data from {csv_file}...")
        df = pd.read_csv(csv_file)
        print(f"📈 Loaded {len(df)} session records")
        
    except Exception as e:
        print(f"❌ Error reading CSV file: {e}")
        return
    
    # Process each session record
    print(f"\n{'=' * 80}")
    print(f"🔍 ANALYZING SESSION DATA WITH {detection_mode.upper()}")
    print(f"{'=' * 80}")
    
    results = []
    attack_count = 0
    safe_count = 0
    pattern_detections = 0
    llm_detections = 0
    
    for idx, row in df.iterrows():
        try:
            # Extract request components from session data
            request_string = extract_request_components(row)
            
            # Get additional context for analysis
            session_context = analyze_session_with_llm_context(row)
            
            print(f"\n{'─' * 60}")
            print(f"🔍 Session {idx + 1}")
            print(f"📋 Request: {request_string[:120]}{'...' if len(request_string) > 120 else ''}")
            
            # Analyze session context
            if session_context:
                context_summary = []
                if session_context.get('user_agent_type') == 'automated':
                    context_summary.append("🤖 Automated")
                if session_context.get('ip_reputation') == 'suspicious':
                    context_summary.append("🚨 Suspicious IP")
                if session_context.get('script_indicators'):
                    context_summary.append("⚠️  Script Content")
                if session_context.get('encoded_content'):
                    context_summary.append("🔢 Encoded Data")
                
                if context_summary:
                    print(f"🎯 Context: {' | '.join(context_summary)}")
            
            # Run detection
            print("🔄 Running detection analysis...")
            is_malicious, response = waf_detector.detect_attack(request_string)
            
            # Determine detection method
            if "Pattern Match" in response:
                detection_method = "Pattern"
                pattern_detections += 1
            elif "LLM" in response or "Zero-Day" in response:
                detection_method = "LLM"
                llm_detections += 1
            else:
                detection_method = "Unknown"
            
            # Store results
            result = {
                'session_id': idx + 1,
                'session_key': row['key'][:50] + "...",
                'timestamp': row['expires_at'],
                'request_data': request_string,
                'is_attack': is_malicious,
                'detection_response': response,
                'detection_method': detection_method,
                'session_context': session_context
            }
            results.append(result)
            
            # Count results
            if is_malicious:
                attack_count += 1
                status_icon = "🚨"
                status_color = "THREAT DETECTED"
            else:
                safe_count += 1
                status_icon = "✅"
                status_color = "SAFE"
            
            # Display result
            print(f"🎯 Result: {status_icon} {status_color} ({detection_method})")
            print(f"📝 Detection: {response}")
            
        except Exception as e:
            print(f"❌ Error processing session {idx + 1}: {e}")
            continue
    
    # Summary
    print(f"\n{'=' * 80}")
    print("📊 DETECTION SUMMARY")
    print(f"{'=' * 80}")
    print(f"🔍 Detection Mode: {detection_mode}")
    print(f"📈 Total sessions analyzed: {len(results)}")
    print(f"🚨 Threats detected: {attack_count}")
    print(f"✅ Safe sessions: {safe_count}")
    print(f"📊 Threat detection rate: {(attack_count/len(results)*100):.1f}%")
    print(f"🎯 Pattern-based detections: {pattern_detections}")
    print(f"🧠 LLM-based detections: {llm_detections}")
    
    # Show detection method breakdown
    if detection_mode == "Hybrid (Pattern + LLM)":
        print(f"\n🔬 DETECTION METHOD ANALYSIS:")
        print(f"  📐 Pattern matching: {pattern_detections} detections")
        print(f"  🧠 LLM analysis: {llm_detections} detections")
        print(f"  📊 LLM caught novel attacks: {llm_detections > 0}")
        
        if llm_detections > 0:
            print(f"  ✨ Zero-day detection capability: ACTIVE")
        else:
            print(f"  ⚠️  Zero-day detection capability: UNUSED (no novel attacks in data)")
    
    # Detailed attack analysis
    if attack_count > 0:
        print(f"\n📋 DETAILED THREAT ANALYSIS:")
        print(f"{'─' * 40}")
        
        attack_types = {}
        for result in results:
            if result['is_attack']:
                response = result['detection_response']
                
                # Categorize attack types
                if "SQL Injection" in response:
                    attack_type = "SQL Injection"
                elif "XSS" in response:
                    attack_type = "XSS"
                elif "BOT_SCANNER" in response or "Bot" in response:
                    attack_type = "Bot/Scanner"
                elif "SUSPICIOUS_IP" in response:
                    attack_type = "Suspicious IP"
                elif "Zero-Day" in response:
                    attack_type = "Zero-Day Attack"
                else:
                    attack_type = "Other Attack"
                
                attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
        
        for attack_type, count in attack_types.items():
            print(f"  🎯 {attack_type}: {count} occurrence(s)")
    
    # Save detailed results
    output_file = f"hybrid_waf_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n💾 Detailed results saved to: {output_file}")
    except Exception as e:
        print(f"⚠️  Warning: Could not save results file: {e}")
    
    # Show most critical findings
    critical_attacks = [r for r in results if r['is_attack']]
    if critical_attacks:
        print(f"\n🚨 CRITICAL SECURITY ALERTS:")
        print(f"{'─' * 40}")
        for i, attack in enumerate(critical_attacks[:3], 1):  # Show first 3 attacks
            print(f"🔥 Alert {i}: {attack['detection_response']}")
            print(f"   📍 Session: {attack['session_id']}")
            print(f"   🔍 Method: {attack['detection_method']}")
            print(f"   📄 Request: {attack['request_data'][:80]}...")
            print()
    
    # Final recommendations
    print(f"\n🎯 DEPLOYMENT RECOMMENDATIONS:")
    print(f"{'─' * 40}")
    if detection_mode == "Hybrid (Pattern + LLM)":
        print("   ✅ Hybrid detection active - both known and zero-day attacks covered")
        print("   🧠 LLM provides contextual analysis for novel threats")
        print("   ⚡ Pattern matching ensures fast detection of known attacks")
        print("   📊 System ready for production deployment")
    else:
        print("   ⚠️  Pattern-only detection - limited to known attack signatures")
        print("   🎯 Recommend enabling LLM for zero-day detection capability")
        print("   📈 Consider upgrading to hybrid detection for better coverage")
    
    print(f"\n🛡️  WAF Analysis Complete!")

if __name__ == "__main__":
    main()
