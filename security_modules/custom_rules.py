"""
Custom WAF Rules Manager
"""

import json
import re
import threading
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class CustomRule:
    """Custom WAF rule"""
    id: int
    name: str
    pattern: str
    message: str
    severity: int
    enabled: bool
    created_by: str
    compiled: Optional[re.Pattern] = None


class CustomRuleManager:
    """Manage custom WAF rules"""
    
    def __init__(self):
        self.rules: Dict[int, CustomRule] = {}
        self.next_id = 2000  # Start custom rules at 2000
        self.lock = threading.RLock()
    
    def add_rule(self, rule: CustomRule) -> bool:
        """Add a custom rule"""
        try:
            compiled = re.compile(rule.pattern, re.IGNORECASE)
        except re.error:
            return False
        
        with self.lock:
            # Auto-assign ID if not provided
            if rule.id == 0:
                rule.id = self.next_id
                self.next_id += 1
            
            rule.compiled = compiled
            self.rules[rule.id] = rule
            return True
    
    def remove_rule(self, rule_id: int):
        """Remove a custom rule"""
        with self.lock:
            self.rules.pop(rule_id, None)
    
    def get_rules(self) -> List[CustomRule]:
        """Get enabled custom rules"""
        with self.lock:
            return [rule for rule in self.rules.values() if rule.enabled]
    
    def get_all_rules(self) -> List[CustomRule]:
        """Get all custom rules"""
        with self.lock:
            return list(self.rules.values())
    
    def export_rules(self) -> str:
        """Export rules to JSON"""
        with self.lock:
            rules_dict = {
                rule_id: {
                    "id": rule.id,
                    "name": rule.name,
                    "pattern": rule.pattern,
                    "message": rule.message,
                    "severity": rule.severity,
                    "enabled": rule.enabled,
                    "created_by": rule.created_by
                }
                for rule_id, rule in self.rules.items()
            }
            return json.dumps(rules_dict, indent=2)
    
    def save_to_file(self, filename: str) -> bool:
        """Save rules to file"""
        try:
            with open(filename, 'w') as f:
                f.write(self.export_rules())
            return True
        except Exception:
            return False
    
    def load_from_file(self, filename: str) -> bool:
        """Load rules from file"""
        try:
            with open(filename, 'r') as f:
                rules_data = json.load(f)
            
            with self.lock:
                for rule_data in rules_data.values():
                    rule = CustomRule(
                        id=rule_data["id"],
                        name=rule_data["name"],
                        pattern=rule_data["pattern"],
                        message=rule_data["message"],
                        severity=rule_data["severity"],
                        enabled=rule_data["enabled"],
                        created_by=rule_data["created_by"]
                    )
                    
                    # Compile pattern
                    try:
                        rule.compiled = re.compile(rule.pattern, re.IGNORECASE)
                        self.rules[rule.id] = rule
                        
                        # Update next_id to avoid conflicts
                        if rule.id >= self.next_id:
                            self.next_id = rule.id + 1
                    except re.error:
                        continue  # Skip invalid patterns
            
            return True
        except Exception:
            return False
    
    def import_modsecurity(self, filename: str) -> int:
        """Import ModSecurity rules (basic parsing)"""
        imported_count = 0
        
        try:
            with open(filename, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue
                    
                    # Parse ModSecurity SecRule
                    if line.startswith('SecRule'):
                        rule = self._parse_modsec_rule(line, line_num)
                        if rule and self.add_rule(rule):
                            imported_count += 1
        except Exception:
            pass
        
        return imported_count
    
    def _parse_modsec_rule(self, line: str, line_num: int) -> Optional[CustomRule]:
        """Parse ModSecurity rule (basic implementation)"""
        try:
            # Basic ModSecurity rule parsing
            # Format: SecRule VARIABLES "OPERATOR" "ACTIONS"
            parts = line.split('"')
            if len(parts) < 3:
                return None
            
            pattern = parts[1]  # The operator/pattern
            actions = parts[2] if len(parts) >= 3 else ""
            
            # Extract message and severity from actions
            message = f"ModSec rule from line {line_num}"
            severity = 3  # Default severity
            
            if "msg:" in actions:
                msg_start = actions.find("msg:") + 4
                msg_end = actions.find(",", msg_start)
                if msg_end == -1:
                    msg_end = len(actions)
                message = actions[msg_start:msg_end].strip("' \"")
            
            if "severity:" in actions:
                sev_start = actions.find("severity:") + 9
                sev_end = actions.find(",", sev_start)
                if sev_end == -1:
                    sev_end = len(actions)
                sev_str = actions[sev_start:sev_end].strip("' \"")
                try:
                    severity = int(sev_str)
                except ValueError:
                    pass
            
            return CustomRule(
                id=0,  # Will be auto-assigned
                name=f"ModSec_{line_num}",
                pattern=pattern,
                message=message,
                severity=severity,
                enabled=True,
                created_by="modsecurity_import"
            )
        except Exception:
            return None
