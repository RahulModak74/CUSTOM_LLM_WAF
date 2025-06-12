"""
Threat Detection Engine
"""

from typing import List
from .waf_context import WAFContext
from .rule import WAFRule


class ThreatDetector:
    """Detect threats using WAF rules"""
    
    def evaluate_rules(self, ctx: WAFContext, rules: List[WAFRule], test_data: str) -> bool:
        """Evaluate rules against test data"""
        blocked = False
        
        for rule in rules:
            if rule.match(test_data):
                ctx.log_messages.append(rule.message)
                ctx.anomaly_score += rule.severity
                if rule.severity >= 4:
                    blocked = True
        
        return blocked
