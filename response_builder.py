"""
Response Builder module - Build auth responses
"""

from sanic import response
from models import AuthResponse


class ResponseBuilder:
    """Build authentication responses"""
    
    def send_auth_response(self, auth_response: AuthResponse, debug: bool = False):
        """Send authentication response"""
        headers = {
            "X-Session-ID": auth_response.session_id,
            "X-Threat-Level": auth_response.threat_level,
            "X-Anomaly-Score": str(auth_response.anomaly_score)
        }
        
        if debug:
            return response.json(auth_response.dict(), status=auth_response.status, headers=headers)
        else:
            if auth_response.allow:
                return response.text("OK", status=auth_response.status, headers=headers)
            else:
                return response.text(auth_response.message, status=auth_response.status, headers=headers)
    
    def send_json(self, data: dict):
        """Send JSON response"""
        return response.json(data)
