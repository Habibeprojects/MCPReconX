"""
MCPReconX - URL Encode Tamper Script
=====================================
URL encodes special characters to bypass filters.

ETHICAL USE NOTICE:
This tool is intended for authorized security testing only.
"""

from urllib.parse import quote
from typing import Any

from .base import BaseTamper


class URLEncodeTamper(BaseTamper):
    """URL encode special characters."""
    
    name = "urlencode"
    description = "URL encode special characters"
    
    def __init__(self, config=None):
        super().__init__(config)
        self.safe_chars = config.get("safe_chars", "") if config else ""
    
    def tamper(self, payload: Any) -> Any:
        """URL encode the payload if it's a string."""
        if isinstance(payload, str):
            return quote(payload, safe=self.safe_chars)
        return payload
