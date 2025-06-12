#!/usr/bin/env python3
"""
Runner for dynamic_quant.py with sample_session.csv
Usage: python session_runner.py
"""

import pandas as pd
import json
from urllib.parse import unquote
import os
import sys

def process_session_csv():
    """Process sample_session.csv and extract security data"""
    print("🔍 Processing sample_session.csv...")
    
    try:
        df = pd.read_csv('sample_session.csv')
        print(f"Loaded {len(df)} sessions")
        
        attacks_detected = []
        
        for _, row in df.iterrows():
            try:
                session_data = json.loads(row['value'])
                ip = session_data.get('ip_address', 'unknown')
                referer = session_data.get('referer', '')
                user_agent = session_data.get('user_agent', '')
                
                attack_types = []
                
                if referer:
                    decoded_ref = unquote(referer)
                    
                    # Check for XSS
                    if '<script>' in decoded_ref or 'alert(' in decoded_ref:
                        attack_types.append('XSS')
                    
                    # Check for SQL injection
                    if "' OR '" in decoded_ref or 'UNION SELECT' in decoded_ref.upper():
                        attack_types.append('SQL_INJECTION')
                
                # Check for bots
                if 'python' in user_agent.lower() or 'curl' in user_agent.lower():
                    attack_types.append('BOT_SCANNER')
                
                if attack_types:
                    attacks_detected.append({
                        'ip': ip,
                        'types': attack_types,
                        'referer': decoded_ref if referer else 'N/A',
                        'user_agent': user_agent
                    })
                    print(f"🚨 ATTACK: {ip} - {', '.join(attack_types)}")
                    
            except Exception as e:
                continue
        
        print(f"\n📊 SESSION ANALYSIS:")
        print(f"Total sessions: {len(df)}")
        print(f"Malicious sessions: {len(attacks_detected)}")
        print(f"Attack rate: {(len(attacks_detected)/len(df))*100:.1f}%")
        
        if attacks_detected:
            print(f"\n🎯 ATTACK BREAKDOWN:")
            all_types = []
            for attack in attacks_detected:
                all_types.extend(attack['types'])
            
            from collections import Counter
            for attack_type, count in Counter(all_types).items():
                print(f"{attack_type}: {count}")
        
        return attacks_detected
        
    except FileNotFoundError:
        print("❌ sample_session.csv not found!")
        return []
    except Exception as e:
        print(f"❌ Error: {e}")
        return []

def run_dynamic_quantizer():
    """Run the dynamic quantizer"""
    print("\n🚀 Running dynamic quantizer...")
    
    # Check if dynamic_quant.py exists
    if not os.path.exists('dynamic_quant.py'):
        print("❌ dynamic_quant.py not found!")
        return False
    
    # Import and run the quantizer
    try:
        import dynamic_quant
        
        # Run the main function
        dynamic_quant.main()
        return True
        
    except ImportError as e:
        print(f"❌ Could not import dynamic_quant.py: {e}")
        return False
    except Exception as e:
        print(f"❌ Error running quantizer: {e}")
        return False

def main():
    print("🛡️  WAF Session Data Processor & Dynamic Quantizer Runner")
    print("=" * 60)
    
    # Step 1: Process session data
    attacks = process_session_csv()
    if not attacks:
        print("❌ No session data processed")
        return
    
    print("\n" + "=" * 60)
    
    # Step 2: Run dynamic quantizer
    if not run_dynamic_quantizer():
        print("❌ Failed to run dynamic quantizer")
        print("\nTo run the quantizer manually:")
        print("python dynamic_quant.py")
        return
    
    print("\n🎉 Complete! Check output for quantization results.")

if __name__ == "__main__":
    main()
