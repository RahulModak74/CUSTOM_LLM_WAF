"""
WAF Context Extractor
"""

from .waf_context import WAFContext


class ContextExtractor:
    """Extract variables and build test data from WAF context"""
    
    def extract_variables(self, ctx: WAFContext):
        """Extract variables from context for rule evaluation"""
        ctx.variables["REQUEST_URI"] = ctx.uri
        ctx.variables["REQUEST_METHOD"] = ctx.method
        ctx.variables["REMOTE_ADDR"] = ctx.client_ip
        ctx.variables["HTTP_USER_AGENT"] = ctx.user_agent
        ctx.variables["HTTP_REFERER"] = ctx.referer
        ctx.variables["HTTP_COOKIE"] = ctx.cookie
        ctx.variables["HTTP_HOST"] = ctx.host
    
    def build_test_data(self, ctx: WAFContext) -> str:
        """Build test data string for rule evaluation"""
        return f"{ctx.uri} {ctx.request_body} {ctx.user_agent}"
