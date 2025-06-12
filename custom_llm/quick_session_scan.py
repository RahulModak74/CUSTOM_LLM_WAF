#!/usr/bin/env python3
"""
WAF Session Data Analyzer for sample_session.csv with dynamic_quant integration
Usage: python quick_session_scan.py
"""

import pandas as pd
import json
from urllib.parse import unquote
from collections import Counter
import os
import sys

def analyze_session_data():
    """Analyze WAF session data for security patterns"""
    print("🔍 Analyzing WAF session data from sample_session.csv...")
    
    try:
        df = pd.read_csv('sample_session.csv')
        print(f"Loaded {len(df)} session records")
        
        attacks_detected = []
        
        for _, row in df.iterrows():
            try:
                session_data = json.loads(row['value'])
                ip = session_data.get('ip_address', 'unknown')
                referer = session_data.get('referer', '')
                user_agent = session_data.get('user_agent', '')
                
                attack_types = []
                risk_score = 0
                
                if referer:
                    decoded_ref = unquote(referer)
                    
                    # XSS detection
                    if '<script>' in decoded_ref or 'alert(' in decoded_ref or 'javascript:' in decoded_ref:
                        attack_types.append('XSS')
                        risk_score += 30
                    
                    # SQL injection detection
                    if "' OR '" in decoded_ref or 'UNION SELECT' in decoded_ref.upper() or 'DROP TABLE' in decoded_ref.upper():
                        attack_types.append('SQL_INJECTION')
                        risk_score += 35
                    
                    # Command injection
                    if '; cat ' in decoded_ref or '; ls ' in decoded_ref or '| nc ' in decoded_ref:
                        attack_types.append('CMD_INJECTION')
                        risk_score += 40
                    
                    # Path traversal
                    if '../' in decoded_ref or '..\\' in decoded_ref:
                        attack_types.append('PATH_TRAVERSAL')
                        risk_score += 25
                
                # Bot/Scanner detection
                if any(bot in user_agent.lower() for bot in ['python', 'curl', 'wget', 'bot', 'scanner']):
                    attack_types.append('BOT_SCANNER')
                    risk_score += 15
                
                if attack_types:
                    attacks_detected.append({
                        'ip': ip,
                        'types': attack_types,
                        'risk_score': risk_score,
                        'referer': decoded_ref if referer else 'N/A',
                        'user_agent': user_agent[:50] + '...' if len(user_agent) > 50 else user_agent
                    })
                    
            except Exception as e:
                continue
        
        # Print results
        print(f"\n📊 SESSION ANALYSIS RESULTS:")
        print(f"Total sessions: {len(df)}")
        print(f"Malicious sessions: {len(attacks_detected)}")
        print(f"Benign sessions: {len(df) - len(attacks_detected)}")
        print(f"Attack rate: {(len(attacks_detected)/len(df))*100:.1f}%")
        
        if attacks_detected:
            print(f"\n🚨 DETECTED ATTACKS:")
            for i, attack in enumerate(attacks_detected, 1):
                print(f"{i}. IP: {attack['ip']} | Risk: {attack['risk_score']} | Types: {', '.join(attack['types'])}")
                if attack['referer'] != 'N/A':
                    print(f"   URL: {attack['referer'][:80]}...")
                print(f"   UA: {attack['user_agent']}")
                print()
            
            # Attack type summary
            all_types = []
            for attack in attacks_detected:
                all_types.extend(attack['types'])
            
            print(f"🎯 ATTACK TYPE BREAKDOWN:")
            for attack_type, count in Counter(all_types).items():
                print(f"{attack_type}: {count} occurrences")
            
            # Top risk IPs
            ip_risks = {}
            for attack in attacks_detected:
                ip = attack['ip']
                ip_risks[ip] = ip_risks.get(ip, 0) + attack['risk_score']
            
            if ip_risks:
                print(f"\n🎯 TOP RISK IPs:")
                for ip, total_risk in sorted(ip_risks.items(), key=lambda x: x[1], reverse=True):
                    attack_count = sum(1 for a in attacks_detected if a['ip'] == ip)
                    print(f"{ip}: {total_risk} total risk ({attack_count} attacks)")
        
        else:
            print("\n✅ No attacks detected in session data")
        
        return attacks_detected
        
    except FileNotFoundError:
        print("❌ sample_session.csv not found in current directory!")
        print("Please ensure the file exists and try again.")
        return []
    except Exception as e:
        print(f"❌ Error analyzing session data: {e}")
        return []

def run_dynamic_quantizer():
    """Import and run dynamic_quant.py"""
    print("\n🚀 Running dynamic quantizer...")
    
    if not os.path.exists('dynamic_quant.py'):
        print("❌ dynamic_quant.py not found!")
        return False
    
    try:
        import dynamic_quant
        print("✅ Successfully imported dynamic_quant")
        
        # Run the main function
        dynamic_quant.main()
        return True
        
    except ImportError as e:
        print(f"❌ Could not import dynamic_quant.py: {e}")
        return False
    except Exception as e:
        print(f"❌ Error running dynamic quantizer: {e}")
        return False

def main():
    print("🛡️  WAF Session Data Analyzer with Dynamic Quantizer")
    print("=" * 60)
    
    # Step 1: Analyze session data
    attacks = analyze_session_data()
    
    print(f"\n💡 SUMMARY:")
    if attacks:
        print(f"Found {len(attacks)} malicious sessions - security analysis complete")
    else:
        print("No attacks detected - session data appears clean")
    
    # Step 2: Ask user if they want to run quantizer
    print(f"\n" + "=" * 60)
    print("Would you like to run the dynamic quantizer? (downloads models)")
    choice = input("Enter 'y' to run quantizer or any other key to skip: ").lower().strip()
    
    if choice == 'y':
        if not run_dynamic_quantizer():
            print("❌ Failed to run dynamic quantizer")
            print("You can run it manually: python dynamic_quant.py")
    else:
        print("Skipped quantizer. Run manually if needed: python dynamic_quant.py")
    
    print(f"\n✅ Session analysis complete!")

if __name__ == "__main__":
    main()
