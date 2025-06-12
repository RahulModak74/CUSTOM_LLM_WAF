"""
WAF Rule definitions
"""

import re
from enum import IntEnum
from dataclasses import dataclass
from typing import Optional


class RulePhase(IntEnum):
    """Rule execution phases"""
    PhaseRequestHeaders = 0
    PhaseRequestBody = 1
    PhaseResponseHeaders = 2
    PhaseResponseBody = 3
    PhaseLogging = 4


# Export phases for import
PhaseRequestHeaders = RulePhase.PhaseRequestHeaders
PhaseRequestBody = RulePhase.PhaseRequestBody
PhaseResponseHeaders = RulePhase.PhaseResponseHeaders
PhaseResponseBody = RulePhase.PhaseResponseBody
PhaseLogging = RulePhase.PhaseLogging


@dataclass
class WAFRule:
    """WAF rule definition"""
    id: int
    pattern: str
    message: str
    severity: int
    compiled: Optional[re.Pattern] = None
    
    def compile(self) -> bool:
        """Compile the regex pattern"""
        try:
            self.compiled = re.compile(self.pattern, re.IGNORECASE)
            return True
        except re.error:
            return False
    
    def match(self, data: str) -> bool:
        """Check if data matches the rule pattern"""
        return self.compiled is not None and self.compiled.search(data) is not None
