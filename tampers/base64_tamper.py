"""
MCPReconX - Base64 Tamper Script
=================================
Base64 encodes payloads to bypass simple filters.

ETHICAL USE NOTICE:
This tool is intended for authorized security testing only.
"""

import base64
from typing import Any

from .base import BaseTamper


class Base64Tamper(BaseTamper):
    """Base64 encode payloads."""
    
    name = "base64"
    description = "Base64 encode string payloads"
    
    def tamper(self, payload: Any) -> Any:
        """Base64 encode the payload if it's a string."""
        if isinstance(payload, str):
            encoded = base64.b64encode(payload.encode()).decode()
            return f"base64:{encoded}"
        return payload
