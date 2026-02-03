"""
MCPReconX Modules Package v2.0
==============================
Core scanning and detection modules for MCP security assessment.
Enhanced with real-world CVE detection and attack pattern analysis.

ETHICAL USE NOTICE:
This tool is intended for authorized security testing only.
"""

from .fingerprint import FingerprintEngine
from .scanner import ActiveScanner
from .detect_poison import PoisonDetector
from .exploit_sim import ExploitSimulator
from .report import ReportGenerator
from .target import TargetValidator, TargetInfo
from .utils import Colors, Banner, setup_logging, load_config
from .cve_detector import CVEDetector, CVEFinding
from .attack_patterns import AttackPatternDetector, AttackPatternFinding
from .mcp_client import MCPClient
from .github_discovery import GitHubDiscovery
from .internet_discovery import InternetDiscovery

__all__ = [
    "FingerprintEngine",
    "ActiveScanner",
    "PoisonDetector",
    "ExploitSimulator",
    "ReportGenerator",
    "TargetValidator",
    "TargetInfo",
    "Colors",
    "Banner",
    "setup_logging",
    "load_config",
    "CVEDetector",
    "CVEFinding",
    "AttackPatternDetector",
    "AttackPatternFinding",
    "MCPClient",
    "GitHubDiscovery",
    "InternetDiscovery",
]

__version__ = "2.0.0"
