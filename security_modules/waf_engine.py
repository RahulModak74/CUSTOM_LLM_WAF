"""
WAF Engine - Main WAF processing engine
"""

import threading
from typing import Dict
from .rule import WAFRule, RulePhase
from .rule_loader import RuleLoader
from .custom_rules import CustomRuleManager, CustomRule
from .context_extractor import ContextExtractor
from .phase_manager import PhaseManager
from .threat_detector import ThreatDetector
from .waf_context import WAFContext


class WAFEngine:
    """Main WAF processing engine"""
    
    def __init__(self):
        self.rules: Dict[int, WAFRule] = {}
        self.rule_loader = RuleLoader()
        self.custom_rule_manager = CustomRuleManager()
        self.context_extractor = ContextExtractor()
        self.phase_manager = PhaseManager()
        self.threat_detector = ThreatDetector()
        self.paranoia_level = 1
        self.lock = threading.RLock()
        
        self._load_rules()
    
    def _load_rules(self):
        """Load all rules (static + custom)"""
        with self.lock:
            # Clear existing rules
            self.rules.clear()
            
            # Load static rules
            static_rules = self.rule_loader.load_default_rules()
            for rule in static_rules:
                self.rules[rule.id] = rule
                self.phase_manager.add_rule(rule, RulePhase.PhaseRequestHeaders, RulePhase.PhaseRequestBody)
            
            # Load custom rules and convert to WAFRule format
            custom_rules = self._convert_custom_rules()
            for rule in custom_rules:
                self.rules[rule.id] = rule
                self.phase_manager.add_rule(rule, RulePhase.PhaseRequestHeaders, RulePhase.PhaseRequestBody)
    
    def _convert_custom_rules(self) -> list[WAFRule]:
        """Convert custom rules to WAFRule format"""
        custom_rules = self.custom_rule_manager.get_rules()
        waf_rules = []
        
        for custom_rule in custom_rules:
            if custom_rule.enabled:
                waf_rule = WAFRule(
                    id=custom_rule.id,
                    pattern=custom_rule.pattern,
                    message=custom_rule.message,
                    severity=custom_rule.severity
                )
                waf_rule.compile()
                waf_rules.append(waf_rule)
        
        return waf_rules
    
    def reload_rules(self):
        """Reload all rules"""
        self._load_rules()
    
    def add_custom_rule(self, rule: CustomRule) -> bool:
        """Add custom rule"""
        success = self.custom_rule_manager.add_rule(rule)
        if success:
            self._load_rules()  # Reload all rules
        return success
    
    def remove_custom_rule(self, rule_id: int):
        """Remove custom rule"""
        self.custom_rule_manager.remove_rule(rule_id)
        self._load_rules()  # Reload all rules
    
    def get_custom_rule_manager(self) -> CustomRuleManager:
        """Get custom rule manager"""
        return self.custom_rule_manager
    
    def extract_variables(self, ctx: WAFContext):
        """Extract variables from context"""
        self.context_extractor.extract_variables(ctx)
    
    def evaluate_rules(self, ctx: WAFContext, phase: RulePhase) -> bool:
        """Evaluate rules for a specific phase"""
        rules = self.phase_manager.get_rules(phase)
        test_data = self.context_extractor.build_test_data(ctx)
        return self.threat_detector.evaluate_rules(ctx, rules, test_data)
    
    def generate_security_report(self) -> dict:
        """Generate security status report"""
        with self.lock:
            static_count = len(self.rule_loader.load_default_rules())
            custom_count = len(self.custom_rule_manager.get_rules())
            
            return {
                "rules_loaded": len(self.rules),
                "static_rules": static_count,
                "custom_rules": custom_count,
                "paranoia_level": self.paranoia_level
            }
