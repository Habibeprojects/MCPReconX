"""
MCPReconX - Tamper Scripts Package
===================================
Tamper scripts for payload obfuscation and filter evasion.

ETHICAL USE NOTICE:
This tool is intended for authorized security testing only.
"""

from .base import BaseTamper, TamperChain
from .base64_tamper import Base64Tamper
from .comment_tamper import CommentTamper
from .case_tamper import CaseTamper
from .urlencode_tamper import URLEncodeTamper

__all__ = [
    "BaseTamper",
    "TamperChain",
    "Base64Tamper",
    "CommentTamper",
    "CaseTamper",
    "URLEncodeTamper",
]

# Registry of available tampers
AVAILABLE_TAMPERS = {
    "base64": Base64Tamper,
    "comment": CommentTamper,
    "case": CaseTamper,
    "urlencode": URLEncodeTamper,
}


def get_tamper(name: str):
    """Get tamper class by name."""
    return AVAILABLE_TAMPERS.get(name.lower())


def list_tampers():
    """List all available tamper scripts."""
    return list(AVAILABLE_TAMPERS.keys())
