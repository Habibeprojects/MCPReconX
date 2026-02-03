"""
MCPReconX - Case Tamper Script
===============================
Randomizes case to bypass case-sensitive filters.

ETHICAL USE NOTICE:
This tool is intended for authorized security testing only.
"""

import random
from typing import Any

from .base import BaseTamper


class CaseTamper(BaseTamper):
    """Randomize case of alphabetic characters."""
    
    name = "case"
    description = "Random case variation"
    
    def tamper(self, payload: Any) -> Any:
        """Randomize case of string payloads."""
        if not isinstance(payload, str):
            return payload
        
        result = []
        for char in payload:
            if char.isalpha():
                # Randomly choose upper or lower case
                if random.random() < 0.5:
                    result.append(char.upper())
                else:
                    result.append(char.lower())
            else:
                result.append(char)
        
        return "".join(result)
