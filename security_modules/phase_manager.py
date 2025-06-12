"""
WAF Phase Manager
"""

import threading
from typing import Dict, List
from .rule import WAFRule, RulePhase


class PhaseManager:
    """Manage rules by execution phase"""
    
    def __init__(self):
        self.rules_by_phase: Dict[RulePhase, List[WAFRule]] = {}
        self.lock = threading.RLock()
    
    def add_rule(self, rule: WAFRule, *phases: RulePhase):
        """Add rule to specified phases"""
        with self.lock:
            for phase in phases:
                if phase not in self.rules_by_phase:
                    self.rules_by_phase[phase] = []
                self.rules_by_phase[phase].append(rule)
    
    def get_rules(self, phase: RulePhase) -> List[WAFRule]:
        """Get rules for a specific phase"""
        with self.lock:
            return self.rules_by_phase.get(phase, []).copy()
