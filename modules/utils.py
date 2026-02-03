"""
MCPReconX - Utility Functions
==============================
Common utilities, logging setup, and helper functions.

ETHICAL USE NOTICE:
This tool is intended for authorized security testing only.
"""

import logging
import sys
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime


class Colors:
    """ANSI color codes for terminal output."""
    RESET = '\033[0m'
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    
    @classmethod
    def disable(cls):
        """Disable colors (for non-TTY output)."""
        for attr in dir(cls):
            if not attr.startswith('_') and isinstance(getattr(cls, attr), str):
                setattr(cls, attr, '')


class Banner:
    """Application banner and branding."""
    
    ASCII_ART = """
    ███╗   ███╗ ██████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
    ████╗ ████║██╔════╝██╔══██╗██╔════╝██╔═══██╗██╔══██╗████╗  ██║╚██╗██╔╝
    ██╔████╔██║██║     ██████╔╝█████╗  ██║   ██║██████╔╝██╔██╗ ██║ ╚███╔╝ 
    ██║╚██╔╝██║██║     ██╔══██╗██╔══╝  ██║   ██║██╔══██╗██║╚██╗██║ ██╔██╗ 
    ██║ ╚═╝ ██║╚██████╗██║  ██║██║     ╚██████╔╝██║  ██║██║ ╚████║██╔╝ ██╗
    ╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝
    """
    
    TAGLINE = "Model Context Protocol Security Scanner"
    VERSION_FMT = "v{version} - Ethical Security Testing Framework"
    
    @classmethod
    def print(cls, version: str):
        """Print the application banner."""
        print(f"{Colors.CYAN}{cls.ASCII_ART}{Colors.RESET}")
        print(f"{Colors.BOLD}{cls.TAGLINE}{Colors.RESET}")
        print(f"{Colors.DIM}{cls.VERSION_FMT.format(version=version)}{Colors.RESET}")
        print(f"{Colors.YELLOW}{'='*70}{Colors.RESET}")
        print(f"{Colors.RED}⚠️  FOR AUTHORIZED SECURITY TESTING ONLY ⚠️{Colors.RESET}")
        print(f"{Colors.YELLOW}{'='*70}{Colors.RESET}\n")


def setup_logging(
    log_file: str,
    verbose: int = 0,
    quiet: bool = False
) -> logging.Logger:
    """
    Setup logging configuration.
    
    Args:
        log_file: Path to log file
        verbose: Verbosity level (0-2)
        quiet: Suppress console output
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger("mcpreconx")
    logger.setLevel(logging.DEBUG)
    logger.handlers = []  # Clear existing handlers
    
    # File handler - always log everything
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(file_format)
    logger.addHandler(file_handler)
    
    # Console handler
    if not quiet:
        console_handler = logging.StreamHandler(sys.stdout)
        
        if verbose >= 2:
            console_handler.setLevel(logging.DEBUG)
        elif verbose >= 1:
            console_handler.setLevel(logging.INFO)
        else:
            console_handler.setLevel(logging.WARNING)
        
        console_format = logging.Formatter(
            f'{Colors.CYAN}[%(levelname)s]{Colors.RESET} %(message)s'
        )
        console_handler.setFormatter(console_format)
        logger.addHandler(console_handler)
    
    return logger


def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from YAML file.
    
    Args:
        config_path: Path to config file
    
    Returns:
        Configuration dictionary
    """
    default_config = {
        "scan": {
            "timeout": 30,
            "max_retries": 3,
            "delay_between_requests": 0,
            "max_concurrent": 5,
            "user_agent": "MCPReconX/1.0 (Security Scanner)"
        },
        "fingerprint": {
            "probe_endpoints": [
                "/sse",
                "/mcp",
                "/mcp/v1",
                "/.well-known/mcp",
                "/capabilities"
            ],
            "version_signatures": {
                "langchain-mcp": ["langchain", "mcp-adapter"],
                "fastmcp": ["fastmcp", "python-mcp"],
                "mcp-typescript": ["@modelcontextprotocol/sdk"]
            }
        },
        "detection": {
            "hidden_instruction_patterns": [
                r"ignore\s+previous\s+instructions",
                r"disregard\s+(all\s+)?(prior|previous)\s+(instructions|directives)",
                r"system\s*:\s*you\s+are\s+now",
                r"\[system\s*\(|\<system\>|\{\{system\}\}",
                r"admin\s*mode\s*(enabled|activated)",
                r"debug\s*mode\s*(on|enabled)",
                r"override\s+(security|restrictions|constraints)"
            ],
            "suspicious_tool_patterns": [
                r"exec\s*\(",
                r"eval\s*\(",
                r"system\s*\(",
                r"subprocess",
                r"os\.system",
                r"shell",
                r"command"
            ]
        },
        "exploit_simulation": {
            "safe_payloads": {
                "file_read": ["/etc/passwd", "C:\\Windows\\system32\\drivers\\etc\\hosts"],
                "command_injection": [";echo 'MCP_TEST'", "| whoami", "`id`"],
                "path_traversal": ["../../../etc/passwd", "....//....//etc/passwd"]
            },
            "confirmation_required": True
        },
        "reporting": {
            "include_evidence": True,
            "max_evidence_length": 1000,
            "cvss_calculator": "standard"
        },
        "llm": {
            "enabled": False,
            "provider": "ollama",
            "model": "llama3.2",
            "api_url": "http://localhost:11434",
            "timeout": 60
        }
    }
    
    path = Path(config_path)
    if path.exists():
        try:
            with open(path, 'r') as f:
                user_config = yaml.safe_load(f)
                if user_config:
                    # Merge with defaults
                    def merge_dicts(base, override):
                        for key, value in override.items():
                            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                                merge_dicts(base[key], value)
                            else:
                                base[key] = value
                        return base
                    return merge_dicts(default_config, user_config)
        except Exception as e:
            print(f"Warning: Could not load config file: {e}")
    
    return default_config


def calculate_cvss_score(
    attack_vector: str = "network",
    attack_complexity: str = "low",
    privileges_required: str = "none",
    user_interaction: str = "none",
    scope: str = "unchanged",
    confidentiality: str = "none",
    integrity: str = "none",
    availability: str = "none"
) -> float:
    """
    Simplified CVSS v3.1 score calculator.
    
    Returns approximate CVSS base score (0.0 - 10.0).
    """
    # Simplified scoring - in production, use proper CVSS calculation
    scores = {
        "attack_vector": {"network": 0.85, "adjacent": 0.62, "local": 0.55, "physical": 0.2},
        "attack_complexity": {"low": 0.77, "high": 0.44},
        "privileges_required": {"none": 0.85, "low": 0.62, "high": 0.27},
        "user_interaction": {"none": 0.85, "required": 0.62},
        "scope": {"unchanged": 1.0, "changed": 1.0},
        "confidentiality": {"none": 0.0, "low": 0.22, "high": 0.56},
        "integrity": {"none": 0.0, "low": 0.22, "high": 0.56},
        "availability": {"none": 0.0, "low": 0.22, "high": 0.56}
    }
    
    av = scores["attack_vector"].get(attack_vector, 0.85)
    ac = scores["attack_complexity"].get(attack_complexity, 0.77)
    pr = scores["privileges_required"].get(privileges_required, 0.85)
    ui = scores["user_interaction"].get(user_interaction, 0.85)
    c = scores["confidentiality"].get(confidentiality, 0.0)
    i = scores["integrity"].get(integrity, 0.0)
    a = scores["availability"].get(availability, 0.0)
    
    # ISS (Impact Sub-Score)
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    
    # Impact
    if scope == "changed":
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    
    # Exploitability
    exploitability = 8.22 * av * ac * pr * ui
    
    # Base Score
    if impact <= 0:
        return 0.0
    
    if scope == "changed":
        score = min(1.08 * (impact + exploitability), 10)
    else:
        score = min(impact + exploitability, 10)
    
    return round(score, 1)


def severity_from_cvss(score: float) -> str:
    """Convert CVSS score to severity rating."""
    if score == 0:
        return "none"
    elif score < 4.0:
        return "low"
    elif score < 7.0:
        return "medium"
    elif score < 9.0:
        return "high"
    else:
        return "critical"


def sanitize_output(data: str, max_length: int = 500) -> str:
    """Sanitize and truncate output for safe display."""
    if not data:
        return ""
    
    # Remove control characters
    sanitized = ''.join(char for char in data if char.isprintable() or char in '\n\t')
    
    # Truncate if needed
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "... [truncated]"
    
    return sanitized


def format_timestamp(dt: Optional[datetime] = None) -> str:
    """Format timestamp for consistent output."""
    if dt is None:
        dt = datetime.now()
    return dt.strftime("%Y-%m-%d %H:%M:%S")


class ProgressBar:
    """Simple progress bar for CLI output."""
    
    def __init__(self, total: int, desc: str = "Progress"):
        self.total = total
        self.current = 0
        self.desc = desc
        self.width = 50
    
    def update(self, increment: int = 1):
        """Update progress bar."""
        self.current += increment
        self._draw()
    
    def _draw(self):
        """Draw the progress bar."""
        percent = min(100, int(100 * self.current / self.total))
        filled = int(self.width * self.current / self.total)
        bar = '█' * filled + '░' * (self.width - filled)
        
        sys.stdout.write(f'\r{Colors.CYAN}[{bar}]{Colors.RESET} {percent}% {self.desc}')
        sys.stdout.flush()
        
        if self.current >= self.total:
            sys.stdout.write('\n')
            sys.stdout.flush()


def validate_url(url: str) -> bool:
    """Basic URL validation."""
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        return parsed.scheme in ('http', 'https', 'ws', 'wss') and bool(parsed.netloc)
    except Exception:
        return False


def is_mcp_endpoint(response_data: Dict[str, Any]) -> bool:
    """Check if response indicates MCP endpoint."""
    mcp_indicators = [
        "modelcontextprotocol",
        "mcp",
        "tools",
        "resources",
        "capabilities",
        "jsonrpc",
        "2.0"
    ]
    
    response_str = str(response_data).lower()
    return any(indicator in response_str for indicator in mcp_indicators)
