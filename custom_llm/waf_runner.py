#!/usr/bin/env python3
"""
WAF Attack Detection Runner Script
Imports PatternBasedWAFDetector from dynamic_quant.py and runs detection on CSV data
"""

import pandas as pd
import json
import sys
import os
from datetime import datetime
from urllib.parse import unquote

# Import the WAF detector from your dynamic quantization script
try:
    from dynamic_quant import PatternBasedWAFDetector
except ImportError:
    print("Error: Could not import PatternBasedWAFDetector from dynamic_quant.py")
    print("Make sure dynamic_quant.py is in the same directory or in Python path")
    sys.exit(1)

def extract_request_components(session_data):
    """Extract and format HTTP request components from session data"""
    try:
        # Parse the JSON value field
        data = json.loads(session_data['value'])
        
        # Build request components
        request_parts = []
        
        # Add referer if present (common attack vector)
        if data.get('referer') and data['referer'].strip():
            referer = unquote(data['referer'])  # URL decode
            request_parts.append(f"Referer: {referer}")
        
        # Add user agent (another attack vector)
        if data.get('user_agent'):
            request_parts.append(f"User-Agent: {data['user_agent']}")
        
        # Add other headers that might contain attacks
        for field in ['accept_language', 'accept_encoding']:
            if data.get(field) and data[field].strip():
                value = unquote(data[field])
                request_parts.append(f"{field.replace('_', '-').title()}: {value}")
        
        # If no specific request parts found, use the raw session key
        if not request_parts:
            request_parts.append(f"Session: {session_data['key']}")
        
        return " | ".join(request_parts)
        
    except (json.JSONDecodeError, KeyError) as e:
        # Fallback to using the session key
        return f"Session: {session_data['key']}"

def main():
    print("="*80)
    print("WAF ATTACK DETECTION RUNNER")
    print("="*80)
    
    # Initialize the pattern-based WAF detector
    print("Initializing PatternBasedWAFDetector...")
    waf_detector = PatternBasedWAFDetector()
    
    # Read the CSV file
    csv_file = "sample_session.csv"  # Update this path as needed
    
    if not os.path.exists(csv_file):
        print(f"Error: CSV file '{csv_file}' not found!")
        print("Please ensure the CSV file is in the current directory")
        return
    
    try:
        print(f"Loading data from {csv_file}...")
        df = pd.read_csv(csv_file)
        print(f"Loaded {len(df)} session records")
        
    except Exception as e:
        print(f"Error reading CSV file: {e}")
        return
    
    # Process each session record
    print("\n" + "="*80)
    print("PROCESSING SESSION DATA FOR ATTACK DETECTION")
    print("="*80)
    
    results = []
    attack_count = 0
    safe_count = 0
    
    for idx, row in df.iterrows():
        try:
            # Extract request components from session data
            request_string = extract_request_components(row)
            
            # Run attack detection
            is_malicious, response = waf_detector.detect_attack(request_string)
            
            # Store results
            result = {
                'session_id': idx + 1,
                'session_key': row['key'],
                'timestamp': row['expires_at'],
                'request_data': request_string,
                'is_attack': is_malicious,
                'detection_response': response,
                'raw_value': row['value']
            }
            results.append(result)
            
            # Count results
            if is_malicious:
                attack_count += 1
                status_icon = "🚨"
                status_color = "ATTACK"
            else:
                safe_count += 1
                status_icon = "✅"
                status_color = "SAFE"
            
            # Display result
            print(f"\n{status_icon} Session {idx + 1}: {status_color}")
            print(f"Request: {request_string[:100]}{'...' if len(request_string) > 100 else ''}")
            print(f"Detection: {response}")
            print("-" * 60)
            
        except Exception as e:
            print(f"Error processing session {idx + 1}: {e}")
            continue
    
    # Summary
    print("\n" + "="*80) 
    print("DETECTION SUMMARY")
    print("="*80)
    print(f"Total sessions analyzed: {len(results)}")
    print(f"Attacks detected: {attack_count}")
    print(f"Safe sessions: {safe_count}")
    print(f"Attack detection rate: {(attack_count/len(results)*100):.1f}%")
    
    # Detailed attack analysis
    if attack_count > 0:
        print(f"\n📊 DETECTED ATTACKS BREAKDOWN:")
        print("-" * 40)
        
        attack_types = {}
        for result in results:
            if result['is_attack']:
                # Extract attack type from response
                response = result['detection_response']
                if "SQL Injection" in response:
                    attack_type = "SQL Injection"
                elif "XSS" in response:
                    attack_type = "XSS"
                elif "Command Injection" in response:
                    attack_type = "Command Injection" 
                elif "Path Traversal" in response:
                    attack_type = "Path Traversal"
                elif "LDAP Injection" in response:
                    attack_type = "LDAP Injection"
                else:
                    attack_type = "Unknown Attack"
                
                attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
        
        for attack_type, count in attack_types.items():
            print(f"  {attack_type}: {count} occurrence(s)")
    
    # Save detailed results to file
    output_file = f"waf_detection_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n💾 Detailed results saved to: {output_file}")
    except Exception as e:
        print(f"Warning: Could not save results file: {e}")
    
    print(f"\n🛡️  WAF Detection Analysis Complete!")
    
    # Show most critical findings
    critical_attacks = [r for r in results if r['is_attack']]
    if critical_attacks:
        print(f"\n⚠️  CRITICAL SECURITY ALERTS:")
        print("-" * 40)
        for attack in critical_attacks[:3]:  # Show first 3 attacks
            print(f"Session {attack['session_id']}: {attack['detection_response']}")
            print(f"Request: {attack['request_data'][:80]}...")
            print()

if __name__ == "__main__":
    main()
