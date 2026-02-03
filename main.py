#!/usr/bin/env python3
"""
MCPReconX v2.0 - Model Context Protocol Security Scanner
=========================================================
A comprehensive security assessment tool for MCP servers.

Features:
- CVE Detection (10+ known vulnerabilities)
- Attack Pattern Analysis (25+ patterns)
- GitHub MCP Server Discovery
- Internet MCP Server Scanning
- Working MCP Protocol Client
- Real Exploit PoCs

Author: Security Research Community
License: MIT
Version: 2.0.0

ETHICAL USE NOTICE:
This tool is intended for authorized security testing only.
"""

import argparse
import asyncio
import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

import yaml

# Import modules
from modules.fingerprint import FingerprintEngine
from modules.scanner import ActiveScanner
from modules.detect_poison import PoisonDetector
from modules.exploit_sim import ExploitSimulator
from modules.report import ReportGenerator
from modules.target import TargetValidator
from modules.utils import Colors, Banner, setup_logging, load_config
from modules.cve_detector import CVEDetector
from modules.attack_patterns import AttackPatternDetector
from modules.mcp_client import MCPClient
from modules.github_discovery import GitHubDiscovery
from modules.internet_discovery import InternetDiscovery


class MCPReconX:
    """Main orchestrator for MCP security scanning."""
    
    VERSION = "2.0.0"
    SAFE_MODE = True
    
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.session_id = str(uuid.uuid4())[:8]
        self.start_time = datetime.now()
        self.config = self._load_configuration()
        self.logger = self._setup_logger()
        self.results = {
            "session_id": self.session_id,
            "target": args.target,
            "start_time": self.start_time.isoformat(),
            "version": self.VERSION,
            "safe_mode": not args.exploit,
            "findings": [],
            "vulnerabilities": [],
            "cve_findings": [],
            "attack_patterns": [],
            "metadata": {}
        }
        
    def _load_configuration(self) -> Dict[str, Any]:
        """Load configuration from config.yaml or use defaults."""
        config_path = self.args.config or "config.yaml"
        return load_config(config_path)
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logging with file and console handlers."""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / f"mcpreconx_{self.session_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        return setup_logging(
            log_file=str(log_file),
            verbose=self.args.verbose,
            quiet=self.args.quiet
        )
    
    async def run(self) -> int:
        """Main execution pipeline."""
        Banner.print(self.VERSION)
        
        # Handle discovery modes
        if self.args.discover_github:
            return await self._run_github_discovery()
        
        if self.args.discover_internet:
            return await self._run_internet_discovery()
        
        # Standard scanning mode
        if not self.args.target:
            self.logger.error("No target specified. Use --target or discovery modes.")
            return 1
        
        # Ethical check
        if not self._ethical_confirmation():
            self.logger.error("Ethical confirmation failed. Exiting.")
            return 1
        
        self.logger.info(f"Starting MCPReconX v{self.VERSION}")
        self.logger.info(f"Session ID: {self.session_id}")
        self.logger.info(f"Target: {self.args.target}")
        self.logger.info(f"Safe Mode: {not self.args.exploit}")
        
        try:
            # Phase 1: Target Validation
            if not await self._phase_validate():
                return 1
            
            # Phase 2: Fingerprinting
            await self._phase_fingerprint()
            
            # Phase 3: CVE Detection
            if self.args.cve_check:
                await self._phase_cve_detection()
            
            # Phase 4: Attack Pattern Detection
            if self.args.detect_patterns:
                await self._phase_attack_patterns()
            
            # Phase 5: Passive Reconnaissance
            await self._phase_passive_recon()
            
            # Phase 6: Active Scanning (Safe Mode)
            await self._phase_active_scan()
            
            # Phase 7: Exploitation Simulation (if enabled)
            if self.args.exploit:
                await self._phase_exploit_sim()
            
            # Phase 8: Reporting
            await self._phase_report()
            
            self.logger.info("Scan completed successfully.")
            return 0
            
        except KeyboardInterrupt:
            self.logger.warning("Scan interrupted by user.")
            await self._phase_report(interrupted=True)
            return 130
        except Exception as e:
            self.logger.error(f"Fatal error: {str(e)}", exc_info=self.args.verbose >= 2)
            return 1
    
    async def _run_github_discovery(self) -> int:
        """Run GitHub MCP server discovery."""
        self.logger.info("Starting GitHub MCP server discovery...")
        
        try:
            async with GitHubDiscovery(
                github_token=self.args.github_token,
                logger=self.logger
            ) as discovery:
                # Search for MCP servers
                servers = await discovery.search_mcp_servers(max_results=self.args.max_results or 50)
                
                # Also get known servers
                known_servers = await discovery.get_known_mcp_servers()
                
                all_servers = servers + known_servers
                
                # Remove duplicates
                seen = set()
                unique_servers = []
                for server in all_servers:
                    repo = server.get("repository", "")
                    if repo not in seen:
                        seen.add(repo)
                        unique_servers.append(server)
                
                self.logger.info(f"Discovered {len(unique_servers)} unique MCP servers on GitHub")
                
                # Save results
                output_file = Path(self.args.output_dir or "reports") / f"github_discovery_{self.session_id}.json"
                output_file.parent.mkdir(parents=True, exist_ok=True)
                
                with open(output_file, 'w') as f:
                    json.dump({
                        "discovery_type": "github",
                        "timestamp": datetime.now().isoformat(),
                        "servers": unique_servers
                    }, f, indent=2)
                
                self.logger.info(f"Results saved to: {output_file}")
                
                # Print summary
                print(f"\n{Colors.CYAN}{'='*70}{Colors.RESET}")
                print(f"{Colors.BOLD}GitHub Discovery Results{Colors.RESET}")
                print(f"{Colors.CYAN}{'='*70}{Colors.RESET}")
                print(f"Total servers discovered: {len(unique_servers)}")
                
                high_risk = [s for s in unique_servers if s.get("risk_level") == "high"]
                medium_risk = [s for s in unique_servers if s.get("risk_level") == "medium"]
                
                print(f"High risk: {len(high_risk)}")
                print(f"Medium risk: {len(medium_risk)}")
                
                print(f"\n{Colors.BOLD}Top MCP Servers:{Colors.RESET}")
                for server in sorted(unique_servers, key=lambda x: x.get("stars", 0), reverse=True)[:10]:
                    print(f"  - {server['repository']} ({server.get('stars', 0)} stars)")
                
                print(f"{Colors.CYAN}{'='*70}{Colors.RESET}\n")
                
                return 0
                
        except Exception as e:
            self.logger.error(f"GitHub discovery failed: {e}")
            return 1
    
    async def _run_internet_discovery(self) -> int:
        """Run internet MCP server discovery."""
        self.logger.info("Starting internet MCP server discovery...")
        
        if not self.args.target:
            self.logger.error("Internet discovery requires --target (host or network)")
            return 1
        
        # Ethical check for internet scanning
        if not self._ethical_confirmation():
            self.logger.error("Ethical confirmation failed. Exiting.")
            return 1
        
        try:
            async with InternetDiscovery(logger=self.logger) as discovery:
                discovered = []
                
                # Check if it's a network range
                if "/" in self.args.target:
                    async for endpoint in discovery.scan_network_range(self.args.target):
                        discovered.append(endpoint)
                        self.logger.info(f"Found MCP endpoint: {endpoint.get('url')}")
                else:
                    # Single host
                    discovered = await discovery.scan_host(self.args.target)
                
                self.logger.info(f"Discovered {len(discovered)} MCP endpoints")
                
                # Save results
                output_file = Path(self.args.output_dir or "reports") / f"internet_discovery_{self.session_id}.json"
                output_file.parent.mkdir(parents=True, exist_ok=True)
                
                report = discovery.generate_report(discovered)
                
                with open(output_file, 'w') as f:
                    json.dump(report, f, indent=2)
                
                self.logger.info(f"Results saved to: {output_file}")
                
                # Print summary
                print(f"\n{Colors.CYAN}{'='*70}{Colors.RESET}")
                print(f"{Colors.BOLD}Internet Discovery Results{Colors.RESET}")
                print(f"{Colors.CYAN}{'='*70}{Colors.RESET}")
                print(f"Total endpoints discovered: {len(discovered)}")
                
                for endpoint in discovered:
                    print(f"  {Colors.GREEN}[MCP]{Colors.RESET} {endpoint.get('url')} ({endpoint.get('transport')})")
                
                print(f"{Colors.CYAN}{'='*70}{Colors.RESET}\n")
                
                return 0
                
        except Exception as e:
            self.logger.error(f"Internet discovery failed: {e}")
            return 1
    
    def _ethical_confirmation(self) -> bool:
        """Display ethical use notice and require confirmation."""
        if self.args.batch:
            return True
            
        print(f"\n{Colors.YELLOW}{'='*70}")
        print("ETHICAL USE NOTICE - AUTHORIZED TESTING ONLY")
        print('='*70)
        print(f"""
You are about to scan: {self.args.target}

This tool is designed for authorized security testing ONLY. By proceeding,
you confirm that:

1. You have EXPLICIT WRITTEN PERMISSION to test this target
2. You understand the legal implications of unauthorized scanning
3. You will use this tool responsibly and ethically
4. You accept full responsibility for your actions

Unauthorized access to computer systems is illegal in most jurisdictions.
        """)
        print('='*70 + Colors.RESET)
        
        try:
            response = input(f"\n{Colors.CYAN}Do you have authorization to test this target? (yes/no): {Colors.RESET}").lower().strip()
            return response in ['yes', 'y']
        except (EOFError, KeyboardInterrupt):
            print()
            return False
    
    async def _phase_validate(self) -> bool:
        """Phase 1: Target validation and protocol detection."""
        self.logger.info("="*50)
        self.logger.info("PHASE 1: Target Validation")
        self.logger.info("="*50)
        
        validator = TargetValidator(self.config, self.logger)
        self.target_info = await validator.validate(self.args.target)
        
        if not self.target_info.valid:
            self.logger.error(f"Target validation failed: {self.target_info.error}")
            return False
        
        self.logger.info(f"Target validated: {self.target_info.protocol.upper()} transport detected")
        self.logger.info(f"MCP Version: {self.target_info.mcp_version or 'Unknown'}")
        self.results["target_info"] = self.target_info.to_dict()
        return True
    
    async def _phase_fingerprint(self):
        """Phase 2: Server fingerprinting."""
        self.logger.info("="*50)
        self.logger.info("PHASE 2: Fingerprinting")
        self.logger.info("="*50)
        
        fingerprinter = FingerprintEngine(self.config, self.logger, self.args)
        fingerprint = await fingerprinter.scan(self.target_info)
        
        self.results["fingerprint"] = fingerprint.to_dict()
        self.fingerprint = fingerprint  # Store for later use
        
        self.logger.info(f"Server implementation: {fingerprint.implementation or 'Unknown'}")
        self.logger.info(f"Authentication: {fingerprint.auth_method or 'None detected'}")
        self.logger.info(f"Tools discovered: {len(fingerprint.tools)}")
        self.logger.info(f"Resources discovered: {len(fingerprint.resources)}")
    
    async def _phase_cve_detection(self):
        """Phase 3: CVE detection."""
        self.logger.info("="*50)
        self.logger.info("PHASE 3: CVE Detection")
        self.logger.info("="*50)
        
        detector = CVEDetector(self.config, self.logger, self.args)
        cve_findings = await detector.detect_all(self.target_info, self.fingerprint)
        
        for finding in cve_findings:
            self.results["cve_findings"].append(finding.to_dict())
            self.logger.critical(f"[CVE] {finding.cve_id}: {finding.name} (CVSS: {finding.cvss_score})")
    
    async def _phase_attack_patterns(self):
        """Phase 4: Attack pattern detection."""
        self.logger.info("="*50)
        self.logger.info("PHASE 4: Attack Pattern Detection")
        self.logger.info("="*50)
        
        detector = AttackPatternDetector(self.config, self.logger)
        patterns = detector.detect_all(self.fingerprint)
        
        for pattern in patterns:
            self.results["attack_patterns"].append(pattern.to_dict())
            self.logger.warning(f"[PATTERN] {pattern.pattern_name} - {pattern.severity}")
    
    async def _phase_passive_recon(self):
        """Phase 5: Passive reconnaissance."""
        self.logger.info("="*50)
        self.logger.info("PHASE 5: Passive Reconnaissance")
        self.logger.info("="*50)
        
        detector = PoisonDetector(self.config, self.logger, self.args)
        passive_findings = await detector.passive_analysis(self.fingerprint)
        
        for finding in passive_findings:
            self.results["findings"].append(finding.to_dict())
            self.logger.warning(f"[PASSIVE] {finding.severity.upper()}: {finding.title}")
    
    async def _phase_active_scan(self):
        """Phase 6: Active scanning (safe mode only)."""
        self.logger.info("="*50)
        self.logger.info("PHASE 6: Active Scanning (Safe Mode)")
        self.logger.info("="*50)
        
        scanner = ActiveScanner(self.config, self.logger, self.args)
        vulns = await scanner.scan(self.target_info, self.fingerprint)
        
        for vuln in vulns:
            self.results["vulnerabilities"].append(vuln.to_dict())
            self.logger.warning(f"[{vuln.severity.upper()}] {vuln.name} - CVSS: {vuln.cvss_score}")
    
    async def _phase_exploit_sim(self):
        """Phase 7: Exploitation simulation (requires --exploit flag)."""
        self.logger.info("="*50)
        self.logger.info("PHASE 7: Exploitation Simulation")
        self.logger.info("="*50)
        
        if self.args.risk != "high":
            self.logger.info("High risk level required for exploitation simulation")
            return
        
        # Additional confirmation for exploit mode
        if not self.args.batch:
            print(f"\n{Colors.RED}WARNING: Exploitation simulation mode active!{Colors.RESET}")
            print("This may trigger security alerts on the target system.")
            try:
                confirm = input("Continue with exploitation simulation? (yes/no): ").lower().strip()
                if confirm not in ['yes', 'y']:
                    self.logger.info("Exploitation simulation cancelled by user.")
                    return
            except (EOFError, KeyboardInterrupt):
                print()
                return
        
        simulator = ExploitSimulator(self.config, self.logger, self.args)
        exploit_results = await simulator.run(
            self.target_info,
            self.fingerprint,
            self.results["vulnerabilities"]
        )
        
        self.results["exploit_simulation"] = exploit_results
        self.logger.info(f"Exploitation simulation completed: {len(exploit_results)} PoCs executed")
    
    async def _phase_report(self, interrupted: bool = False):
        """Phase 8: Generate reports."""
        self.logger.info("="*50)
        self.logger.info("PHASE 8: Report Generation")
        self.logger.info("="*50)
        
        self.results["end_time"] = datetime.now().isoformat()
        self.results["duration_seconds"] = (datetime.now() - self.start_time).total_seconds()
        self.results["interrupted"] = interrupted
        
        reporter = ReportGenerator(self.config, self.logger)
        
        # JSON report
        if self.args.json or self.args.report_all:
            json_path = await reporter.generate_json(self.results, self.session_id)
            self.logger.info(f"JSON report saved: {json_path}")
        
        # PDF report
        if self.args.pdf or self.args.report_all:
            pdf_path = await reporter.generate_pdf(self.results, self.session_id)
            self.logger.info(f"PDF report saved: {pdf_path}")
        
        # Console summary
        reporter.print_summary(self.results)


def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure argument parser."""
    parser = argparse.ArgumentParser(
        prog="mcpreconx",
        description="MCPReconX v2.0 - Model Context Protocol Security Scanner",
        epilog="""
Examples:
  # Basic scan
  %(prog)s --target http://localhost:3000/sse
  
  # Full security assessment
  %(prog)s -t http://target.com/mcp --cve-check --detect-patterns --report-all
  
  # GitHub discovery
  %(prog)s --discover-github --github-token YOUR_TOKEN
  
  # Internet discovery
  %(prog)s --discover-internet --target scanme.nmap.org
  
  # Network scan
  %(prog)s --discover-internet --target 192.168.1.0/24
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Target specification
    target_group = parser.add_argument_group("Target Specification")
    target_group.add_argument(
        "-t", "--target",
        help="Target MCP server URL (HTTP/SSE or WebSocket)"
    )
    target_group.add_argument(
        "--method",
        choices=["auto", "http", "websocket"],
        default="auto",
        help="Transport method (default: auto-detect)"
    )
    
    # Discovery modes
    discovery_group = parser.add_argument_group("Discovery Modes")
    discovery_group.add_argument(
        "--discover-github",
        action="store_true",
        help="Discover MCP servers on GitHub"
    )
    discovery_group.add_argument(
        "--discover-internet",
        action="store_true",
        help="Discover MCP servers on the internet"
    )
    discovery_group.add_argument(
        "--github-token",
        help="GitHub API token for GitHub discovery"
    )
    discovery_group.add_argument(
        "--max-results",
        type=int,
        default=50,
        help="Maximum results for discovery (default: 50)"
    )
    
    # Scan configuration
    scan_group = parser.add_argument_group("Scan Configuration")
    scan_group.add_argument(
        "--safe",
        action="store_true",
        default=True,
        help="Safe mode: detection only, no modification (default)"
    )
    scan_group.add_argument(
        "--exploit",
        action="store_true",
        help="Enable exploitation simulation mode (requires confirmation)"
    )
    scan_group.add_argument(
        "--cve-check",
        action="store_true",
        help="Enable CVE detection"
    )
    scan_group.add_argument(
        "--detect-patterns",
        action="store_true",
        help="Enable attack pattern detection"
    )
    scan_group.add_argument(
        "--risk",
        choices=["low", "medium", "high"],
        default="medium",
        help="Risk level for active tests (default: medium)"
    )
    scan_group.add_argument(
        "--level",
        type=int,
        choices=range(1, 6),
        default=3,
        help="Scan intensity level 1-5 (default: 3)"
    )
    scan_group.add_argument(
        "--fingerprint-only",
        action="store_true",
        help="Stop after fingerprinting phase"
    )
    scan_group.add_argument(
        "--tamper",
        help="Comma-separated tamper script names (e.g., base64,comment,case)"
    )
    
    # Authentication
    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument(
        "--auth-token",
        help="Bearer token for authentication"
    )
    auth_group.add_argument(
        "--api-key",
        help="API key for authentication"
    )
    auth_group.add_argument(
        "--oauth-token",
        help="OAuth access token"
    )
    
    # Output and reporting
    output_group = parser.add_argument_group("Output and Reporting")
    output_group.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Verbose output (use -vv for debug)"
    )
    output_group.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress non-essential output"
    )
    output_group.add_argument(
        "--json",
        action="store_true",
        help="Generate JSON report"
    )
    output_group.add_argument(
        "--pdf",
        action="store_true",
        help="Generate PDF report"
    )
    output_group.add_argument(
        "--report-all",
        action="store_true",
        help="Generate all report formats"
    )
    output_group.add_argument(
        "--output-dir",
        default="reports",
        help="Output directory for reports (default: reports)"
    )
    
    # Configuration
    config_group = parser.add_argument_group("Configuration")
    config_group.add_argument(
        "-c", "--config",
        help="Path to configuration file (default: config.yaml)"
    )
    config_group.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Request timeout in seconds (default: 30)"
    )
    config_group.add_argument(
        "--threads",
        type=int,
        default=5,
        help="Number of concurrent threads (default: 5)"
    )
    config_group.add_argument(
        "--delay",
        type=float,
        default=0,
        help="Delay between requests in seconds (default: 0)"
    )
    
    # LLM integration
    llm_group = parser.add_argument_group("LLM Integration")
    llm_group.add_argument(
        "--llm-provider",
        choices=["ollama", "openai", "anthropic", "none"],
        default="none",
        help="LLM provider for advanced analysis"
    )
    llm_group.add_argument(
        "--llm-model",
        default="llama3.2",
        help="LLM model name (default: llama3.2 for ollama)"
    )
    llm_group.add_argument(
        "--llm-api-key",
        help="API key for LLM provider"
    )
    
    # Miscellaneous
    misc_group = parser.add_argument_group("Miscellaneous")
    misc_group.add_argument(
        "--batch",
        action="store_true",
        help="Non-interactive mode (no prompts)"
    )
    misc_group.add_argument(
        "--update",
        action="store_true",
        help="Check for updates"
    )
    misc_group.add_argument(
        "--version",
        action="version",
        version="%(prog)s 2.0.0"
    )
    
    return parser


async def main():
    """Entry point."""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Handle safe/exploit flag relationship
    if args.exploit:
        args.safe = False
    
    tool = MCPReconX(args)
    exit_code = await tool.run()
    sys.exit(exit_code)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted by user{Colors.RESET}")
        sys.exit(130)
