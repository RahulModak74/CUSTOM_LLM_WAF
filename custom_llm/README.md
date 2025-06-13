this script runs with sample_session.csv file and predicts attacks using quanitzed LLMs using unsloth like approach

Run it as below.. (Just for session data without Quantized LLM)

python3 quick_session_scan.py 



Output




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


--------------------------------------------
----------------------------------------------
-----------------------------------------------

If you want to use the quantized_llm in dynamic_quant.py then

1. Convert the session csv in the required format by


   python3 csv_converter.py sample_session.csv improved_sample.csv

   

3. Then run


   python3 waf_runner.py improved_sample.csv 
================================================================================
WAF ATTACK DETECTION RUNNER
================================================================================
Initializing PatternBasedWAFDetector...
Loading data from sample_session.csv...
Loaded 11 session records

================================================================================
PROCESSING SESSION DATA FOR ATTACK DETECTION
================================================================================

✅ Session 1: SAFE
Request: User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0 | Accep...
Detection: SAFE - No Threat Detected - ALLOW
------------------------------------------------------------

🚨 Session 2: ATTACK
Request: Referer: https://waf.bayesiancybersecurity.com/?q=<script>alert('xss')</script> | User-Agent: Mozill...
Detection: MALICIOUS - XSS Detected - BLOCK
------------------------------------------------------------

🚨 Session 3: ATTACK
Request: Referer: https://waf.bayesiancybersecurity.com/?q=<script>alert('xss')</script> | User-Agent: Mozill...
Detection: MALICIOUS - XSS Detected - BLOCK
------------------------------------------------------------

✅ Session 4: SAFE
Request: Referer: https://waf.bayesiancybersecurity.com/content.html | User-Agent: Mozilla/5.0 (Windows NT 10...
Detection: SAFE - No Threat Detected - ALLOW
------------------------------------------------------------

✅ Session 5: SAFE
Request: Referer: https://waf.bayesiancybersecurity.com/dashboard.html | User-Agent: Mozilla/5.0 (Windows NT ...
Detection: SAFE - No Threat Detected - ALLOW
------------------------------------------------------------

✅ Session 6: SAFE
Request: Referer: https://waf.bayesiancybersecurity.com/content.html | User-Agent: Mozilla/5.0 (Windows NT 10...
Detection: SAFE - No Threat Detected - ALLOW
------------------------------------------------------------

✅ Session 7: SAFE
Request: Referer: https://waf.bayesiancybersecurity.com/logout | User-Agent: Mozilla/5.0 (Windows NT 10.0; Wi...
Detection: SAFE - No Threat Detected - ALLOW
------------------------------------------------------------

✅ Session 8: SAFE
Request: Referer: https://waf.bayesiancybersecurity.com/ | User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x...
Detection: SAFE - No Threat Detected - ALLOW
------------------------------------------------------------

✅ Session 9: SAFE
Request: User-Agent: Mozilla/5.0 (X11; Linux i686; rv:109.0) Gecko/20100101 Firefox/120.0 | Accept-Language: ...
Detection: SAFE - No Threat Detected - ALLOW
------------------------------------------------------------

✅ Session 10: SAFE
Request: User-Agent: python-requests/2.32.3 | Accept-Encoding: gzip, deflate
Detection: SAFE - No Threat Detected - ALLOW
------------------------------------------------------------

✅ Session 11: SAFE
Request: User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0
Detection: SAFE - No Threat Detected - ALLOW
------------------------------------------------------------

================================================================================
DETECTION SUMMARY
================================================================================
Total sessions analyzed: 11
Attacks detected: 2
Safe sessions: 9
Attack detection rate: 18.2%

📊 DETECTED ATTACKS BREAKDOWN:
----------------------------------------
  XSS: 2 occurrence(s)

💾 Detailed results saved to: waf_detection_results_20250613_062634.json

🛡️  WAF Detection Analysis Complete!

⚠️  CRITICAL SECURITY ALERTS:
----------------------------------------
Session 2: MALICIOUS - XSS Detected - BLOCK
Request: Referer: https://waf.bayesiancybersecurity.com/?q=<script>alert('xss')</script> ...

Session 3: MALICIOUS - XSS Detected - BLOCK
Request: Referer: https://waf.bayesiancybersecurity.com/?q=<script>alert('xss')</script> ...

rahul@rahul-LOQ-15IRH8:~$ 



============================================================
Would you like to run the dynamic quantizer? (downloads models)
Enter 'y' to run quantizer or any other key to skip: y


U can download the quantizer with y
