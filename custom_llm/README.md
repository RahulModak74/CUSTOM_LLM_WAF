this script runs with sample_session.csv file and predicts attacks using quanitzed LLMs using unsloth like approach

Run it as below.. 

python3 quick_session_scan.py 
🛡️  WAF Session Data Analyzer with Dynamic Quantizer
============================================================
🔍 Analyzing WAF session data from sample_session.csv...
Loaded 11 session records

📊 SESSION ANALYSIS RESULTS:
Total sessions: 11
Malicious sessions: 3
Benign sessions: 8
Attack rate: 27.3%

🚨 DETECTED ATTACKS:
1. IP: 103.48.102.181 | Risk: 30 | Types: XSS
   URL: https://waf.bayesiancybersecurity.com/?q=<script>alert('xss')</script>...
   UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0...

2. IP: 103.48.102.181 | Risk: 30 | Types: XSS
   URL: https://waf.bayesiancybersecurity.com/?q=<script>alert('xss')</script>...
   UA: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0...

3. IP: 146.148.7.25 | Risk: 15 | Types: BOT_SCANNER
   UA: python-requests/2.32.3

🎯 ATTACK TYPE BREAKDOWN:
XSS: 2 occurrences
BOT_SCANNER: 1 occurrences

🎯 TOP RISK IPs:
103.48.102.181: 60 total risk (2 attacks)
146.148.7.25: 15 total risk (1 attacks)

💡 SUMMARY:
Found 3 malicious sessions - security analysis complete

============================================================
Would you like to run the dynamic quantizer? (downloads models)
Enter 'y' to run quantizer or any other key to skip: y


U can download the quantizer with y
