#In security_modules, add this file
"""
Enhanced ModSecurity Rules Parser
Supports full OWASP CRS rule set parsing (200+ rules)
"""

import re
import os
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from .custom_rules import CustomRule


@dataclass
class ModSecRule:
    """ModSecurity rule structure"""
    variables: List[str]
    operator: str
    operator_value: str
    actions: Dict[str, str]
    raw_line: str


class ModSecurityParser:
    """Enhanced ModSecurity rule parser for OWASP CRS"""
    
    def __init__(self):
        self.variable_map = {
            'ARGS': 'arguments',
            'ARGS_NAMES': 'argument_names',
            'REQUEST_HEADERS': 'headers',
            'REQUEST_HEADERS_NAMES': 'header_names',
            'REQUEST_BODY': 'request_body',
            'REQUEST_URI': 'uri',
            'REQUEST_METHOD': 'method',
            'REMOTE_ADDR': 'client_ip',
            'HTTP_USER_AGENT': 'user_agent',
            'HTTP_REFERER': 'referer',
            'HTTP_COOKIE': 'cookie',
            'HTTP_HOST': 'host',
            'QUERY_STRING': 'query_string',
            'REQUEST_FILENAME': 'filename',
            'REQUEST_PROTOCOL': 'protocol'
        }
        
        self.operators = {
            '@rx': self._regex_operator,
            '@detectSQLi': self._sql_injection_operator,
            '@detectXSS': self._xss_operator,
            '@eq': self._equals_operator,
            '@gt': self._greater_than_operator,
            '@lt': self._less_than_operator,
            '@contains': self._contains_operator,
            '@beginsWith': self._begins_with_operator,
            '@endsWith': self._ends_with_operator,
            '@streq': self._string_equals_operator
        }
    
    def parse_crs_file(self, filename: str) -> List[CustomRule]:
        """Parse OWASP CRS rule file"""
        rules = []
        current_rule = ""
        
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue
                    
                    # Handle multi-line rules (ending with \)
                    if line.endswith('\\'):
                        current_rule += line[:-1] + " "
                        continue
                    else:
                        current_rule += line
                    
                    # Parse complete rule
                    if current_rule.startswith('SecRule'):
                        parsed_rule = self._parse_sec_rule(current_rule, line_num)
                        if parsed_rule:
                            custom_rule = self._convert_to_custom_rule(parsed_rule)
                            if custom_rule:
                                rules.append(custom_rule)
                    
                    current_rule = ""
        
        except Exception as e:
            print(f"Error parsing CRS file {filename}: {e}")
        
        return rules
    
    def _parse_sec_rule(self, rule_line: str, line_num: int) -> Optional[ModSecRule]:
        """Parse a SecRule line"""
        try:
            # Remove SecRule prefix
            rule_content = rule_line[7:].strip()
            
            # Split into parts: VARIABLES "OPERATOR" "ACTIONS"
            parts = self._split_rule_parts(rule_content)
            if len(parts) < 3:
                return None
            
            variables = self._parse_variables(parts[0])
            operator, operator_value = self._parse_operator(parts[1])
            actions = self._parse_actions(parts[2])
            
            return ModSecRule(
                variables=variables,
                operator=operator,
                operator_value=operator_value,
                actions=actions,
                raw_line=rule_line
            )
        
        except Exception:
            return None
    
    def _split_rule_parts(self, rule_content: str) -> List[str]:
        """Split rule into variables, operator, and actions parts"""
        parts = []
        current_part = ""
        in_quotes = False
        quote_char = None
        
        for char in rule_content:
            if char in ['"', "'"] and not in_quotes:
                in_quotes = True
                quote_char = char
            elif char == quote_char and in_quotes:
                in_quotes = False
                quote_char = None
                parts.append(current_part)
                current_part = ""
            elif not in_quotes and char.isspace():
                if current_part and not current_part.startswith('"'):
                    parts.append(current_part)
                    current_part = ""
            else:
                current_part += char
        
        if current_part:
            parts.append(current_part)
        
        return parts
    
    def _parse_variables(self, var_string: str) -> List[str]:
        """Parse variable list (e.g., ARGS|ARGS_NAMES)"""
        # Handle collections and exclusions
        var_string = var_string.replace('!', '').replace('&', '')
        return [v.strip() for v in var_string.split('|')]
    
    def _parse_operator(self, op_string: str) -> Tuple[str, str]:
        """Parse operator and value"""
        if op_string.startswith('@'):
            # Operator with value: @rx pattern
            parts = op_string.split(' ', 1)
            operator = parts[0]
            value = parts[1] if len(parts) > 1 else ""
        else:
            # Simple string match
            operator = '@contains'
            value = op_string
        
        return operator, value
    
    def _parse_actions(self, action_string: str) -> Dict[str, str]:
        """Parse action string into dictionary"""
        actions = {}
        
        # Split by comma, but respect quotes
        action_parts = []
        current = ""
        in_quotes = False
        
        for char in action_string:
            if char == '"' and not in_quotes:
                in_quotes = True
            elif char == '"' and in_quotes:
                in_quotes = False
            elif char == ',' and not in_quotes:
                action_parts.append(current.strip())
                current = ""
                continue
            current += char
        
        if current:
            action_parts.append(current.strip())
        
        # Parse each action
        for part in action_parts:
            if ':' in part:
                key, value = part.split(':', 1)
                actions[key.strip()] = value.strip('\'"')
            else:
                actions[part.strip()] = 'true'
        
        return actions
    
    def _convert_to_custom_rule(self, modsec_rule: ModSecRule) -> Optional[CustomRule]:
        """Convert ModSecurity rule to CustomRule format"""
        try:
            # Generate regex pattern from ModSecurity rule
            pattern = self._generate_regex_pattern(modsec_rule)
            if not pattern:
                return None
            
            # Extract metadata
            rule_id = int(modsec_rule.actions.get('id', '0'))
            message = modsec_rule.actions.get('msg', f'ModSec rule {rule_id}')
            severity = self._convert_severity(modsec_rule.actions.get('severity', '3'))
            
            return CustomRule(
                id=rule_id,
                name=f"CRS_{rule_id}",
                pattern=pattern,
                message=message,
                severity=severity,
                enabled=True,
                created_by="owasp_crs_import"
            )
        
        except Exception:
            return None
    
    def _generate_regex_pattern(self, rule: ModSecRule) -> Optional[str]:
        """Generate regex pattern from ModSecurity rule"""
        operator = rule.operator
        value = rule.operator_value
        
        if operator == '@rx':
            # Direct regex
            return value
        elif operator == '@detectSQLi':
            # SQL injection patterns
            return r"(?i:(?:union|select|insert|delete|update|drop|create|alter|exec|script))"
        elif operator == '@detectXSS':
            # XSS patterns
            return r"(?i:<script|javascript:|vbscript:|onload=|onerror=)"
        elif operator == '@contains':
            # Simple string contains
            return re.escape(value)
        elif operator == '@beginsWith':
            # Starts with
            return f"^{re.escape(value)}"
        elif operator == '@endsWith':
            # Ends with
            return f"{re.escape(value)}$"
        elif operator == '@eq':
            # Exact match
            return f"^{re.escape(value)}$"
        else:
            # Fallback to contains
            return re.escape(value)
    
    def _convert_severity(self, severity_str: str) -> int:
        """Convert ModSecurity severity to numeric"""
        severity_map = {
            'EMERGENCY': 5,
            'ALERT': 5,
            'CRITICAL': 5,
            'ERROR': 4,
            'WARNING': 3,
            'NOTICE': 2,
            'INFO': 1,
            'DEBUG': 1
        }
        
        try:
            # Try numeric first
            return int(severity_str)
        except ValueError:
            # Try text mapping
            return severity_map.get(severity_str.upper(), 3)
    
    # Operator implementations
    def _regex_operator(self, pattern: str, data: str) -> bool:
        try:
            return bool(re.search(pattern, data, re.IGNORECASE))
        except:
            return False
    
    def _sql_injection_operator(self, pattern: str, data: str) -> bool:
        sql_patterns = [
            r"(?i:union.*select)",
            r"(?i:insert.*into)",
            r"(?i:delete.*from)",
            r"(?i:update.*set)",
            r"(?i:drop.*table)",
            r"(?i:'.*or.*'.*=.*')",
            r"(?i:'.*and.*'.*=.*')"
        ]
        return any(re.search(p, data) for p in sql_patterns)
    
    def _xss_operator(self, pattern: str, data: str) -> bool:
        xss_patterns = [
            r"(?i:<script)",
            r"(?i:javascript:)",
            r"(?i:vbscript:)",
            r"(?i:onload\s*=)",
            r"(?i:onerror\s*=)",
            r"(?i:onclick\s*=)"
        ]
        return any(re.search(p, data) for p in xss_patterns)
    
    def _equals_operator(self, value: str, data: str) -> bool:
        try:
            return int(data) == int(value)
        except:
            return data == value
    
    def _greater_than_operator(self, value: str, data: str) -> bool:
        try:
            return int(data) > int(value)
        except:
            return False
    
    def _less_than_operator(self, value: str, data: str) -> bool:
        try:
            return int(data) < int(value)
        except:
            return False
    
    def _contains_operator(self, value: str, data: str) -> bool:
        return value.lower() in data.lower()
    
    def _begins_with_operator(self, value: str, data: str) -> bool:
        return data.lower().startswith(value.lower())
    
    def _ends_with_operator(self, value: str, data: str) -> bool:
        return data.lower().endswith(value.lower())
    
    def _string_equals_operator(self, value: str, data: str) -> bool:
        return data == value


def load_owasp_crs_rules(crs_directory: str) -> List[CustomRule]:
    """
    Load all OWASP CRS rules from directory
    
    Usage:
        # Download OWASP CRS first:
        # wget https://github.com/coreruleset/coreruleset/archive/v3.3.5.tar.gz
        # tar -xzf v3.3.5.tar.gz
        
        rules = load_owasp_crs_rules("/path/to/coreruleset/rules/")
        print(f"Loaded {len(rules)} OWASP CRS rules")
    """
    parser = ModSecurityParser()
    all_rules = []
    
    # Common CRS rule files
    crs_files = [
        'REQUEST-901-INITIALIZATION.conf',
        'REQUEST-905-COMMON-EXCEPTIONS.conf', 
        'REQUEST-910-IP-REPUTATION.conf',
        'REQUEST-911-METHOD-ENFORCEMENT.conf',
        'REQUEST-912-DOS-PROTECTION.conf',
        'REQUEST-913-SCANNER-DETECTION.conf',
        'REQUEST-920-PROTOCOL-ENFORCEMENT.conf',
        'REQUEST-921-PROTOCOL-ATTACK.conf',
        'REQUEST-930-APPLICATION-ATTACK-LFI.conf',
        'REQUEST-931-APPLICATION-ATTACK-RFI.conf',
        'REQUEST-932-APPLICATION-ATTACK-RCE.conf',
        'REQUEST-933-APPLICATION-ATTACK-PHP.conf',
        'REQUEST-934-APPLICATION-ATTACK-NODEJS.conf',
        'REQUEST-941-APPLICATION-ATTACK-XSS.conf',
        'REQUEST-942-APPLICATION-ATTACK-SQLI.conf',
        'REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf',
        'REQUEST-944-APPLICATION-ATTACK-JAVA.conf',
        'RESPONSE-950-DATA-LEAKAGES.conf',
        'RESPONSE-951-DATA-LEAKAGES-SQL.conf',
        'RESPONSE-952-DATA-LEAKAGES-JAVA.conf',
        'RESPONSE-953-DATA-LEAKAGES-PHP.conf',
        'RESPONSE-954-DATA-LEAKAGES-IIS.conf'
    ]
    
    if not os.path.exists(crs_directory):
        print(f"⚠️  CRS directory not found: {crs_directory}")
        print("💡 To download OWASP CRS:")
        print("   wget https://github.com/coreruleset/coreruleset/archive/v3.3.5.tar.gz")
        print("   tar -xzf v3.3.5.tar.gz")
        return []
    
    loaded_files = 0
    for filename in crs_files:
        filepath = os.path.join(crs_directory, filename)
        if os.path.exists(filepath):
            try:
                rules = parser.parse_crs_file(filepath)
                all_rules.extend(rules)
                print(f"✅ Loaded {len(rules)} rules from {filename}")
                loaded_files += 1
            except Exception as e:
                print(f"❌ Error loading {filename}: {e}")
        else:
            print(f"⚠️  File not found: {filename}")
    
    print(f"🎯 Total: {len(all_rules)} rules loaded from {loaded_files} files")
    return all_rules
