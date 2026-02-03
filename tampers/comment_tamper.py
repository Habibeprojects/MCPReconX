"""
MCPReconX - Comment Tamper Script
==================================
Inserts comments to break up keywords and bypass filters.

ETHICAL USE NOTICE:
This tool is intended for authorized security testing only.
"""

import random
from typing import Any

from .base import BaseTamper


class CommentTamper(BaseTamper):
    """Insert comments to bypass filters."""
    
    name = "comment"
    description = "Insert comments between characters"
    
    COMMENT_STYLES = [
        "<!--{comment}-->",
        "/*{comment}*/",
        "//{comment}\n",
        "#{comment}\n",
    ]
    
    def __init__(self, config=None):
        super().__init__(config)
        self.insertion_rate = config.get("insertion_rate", 0.3) if config else 0.3
    
    def tamper(self, payload: Any) -> Any:
        """Insert random comments into string payloads."""
        if not isinstance(payload, str):
            return payload
        
        result = []
        for char in payload:
            result.append(char)
            # Randomly insert comment after character
            if random.random() < self.insertion_rate:
                comment_style = random.choice(self.COMMENT_STYLES)
                comment = comment_style.format(comment="x")
                result.append(comment)
        
        return "".join(result)
