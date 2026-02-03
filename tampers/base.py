"""
MCPReconX - Base Tamper Class
==============================
Base class for all tamper scripts.

ETHICAL USE NOTICE:
This tool is intended for authorized security testing only.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List


class BaseTamper(ABC):
    """Base class for payload tampering scripts."""
    
    name = "base"
    description = "Base tamper class"
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
    
    @abstractmethod
    def tamper(self, payload: Any) -> Any:
        """
        Tamper a payload.
        
        Args:
            payload: The payload to tamper
        
        Returns:
            Tampered payload
        """
        pass
    
    def __call__(self, payload: Any) -> Any:
        """Allow tamper to be called as a function."""
        return self.tamper(payload)


class TamperChain:
    """Chain multiple tampers together."""
    
    def __init__(self, tampers: List[BaseTamper] = None):
        self.tampers = tampers or []
    
    def add(self, tamper: BaseTamper):
        """Add a tamper to the chain."""
        self.tampers.append(tamper)
    
    def tamper(self, payload: Any) -> Any:
        """Apply all tampers in sequence."""
        result = payload
        for tamper in self.tampers:
            result = tamper.tamper(result)
        return result
    
    def __call__(self, payload: Any) -> Any:
        """Allow chain to be called as a function."""
        return self.tamper(payload)
