"""
Default WAF Rules Loader
"""

from typing import List
from .rule import WAFRule


class RuleLoader:
    """Load default WAF rules"""
    
    def load_default_rules(self) -> List[WAFRule]:
        """Load default security rules"""
        rules = [
            WAFRule(1002, r"(?i:<script)", "XSS Attack", 4),
            WAFRule(1003, r"(?i:.*'.*or.*'.*=.*')", "SQL Injection - OR", 5),
            WAFRule(1004, r"(?i:.*'.*and.*'.*=.*')", "SQL Injection - AND", 5),
            WAFRule(1005, r"(?i:select.*from)", "SQL Injection - SELECT", 5),
            WAFRule(1006, r"(?i:insert.*into)", "SQL Injection - INSERT", 5),
            WAFRule(1007, r"(?i:union.*select)", "SQL Injection - UNION", 5),
            WAFRule(1008, r"(?i:\.\./|\.\.\))", "Path Traversal", 4),
            WAFRule(1009, r"(?i:/etc/passwd|/etc/shadow)", "System File Access", 5),
            WAFRule(1010, r"(?i:\.\..*etc)", "Directory Traversal", 4),
            WAFRule(1011, r"(?i:sqlmap)", "SQLMap Scanner", 4),
            WAFRule(1012, r"(?i:nikto)", "Nikto Scanner", 4),
            WAFRule(1013, r"(?i:nessus)", "Nessus Scanner", 4),
            WAFRule(1014, r"(?i:burp)", "Burp Suite", 4),
            WAFRule(1015, r"(?i:;.*cat|;.*ls|;.*pwd)", "Command Injection", 5),
            WAFRule(1016, r"(?i:\|\|.*cat|\|\|.*ls)", "Command Chaining", 5),
        ]
        
        # Compile all rules
        for rule in rules:
            rule.compile()
        
        return rules
