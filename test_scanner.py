#!/usr/bin/env python3
"""
MCPReconX - Test Scanner
========================
Simple test script to verify the scanner works.

ETHICAL USE NOTICE:
This tool is intended for authorized security testing only.
"""

import asyncio
import sys
from pathlib import Path

# Add modules to path
sys.path.insert(0, str(Path(__file__).parent))

from modules.mcp_client import MCPClient
from modules.github_discovery import GitHubDiscovery
from modules.internet_discovery import InternetDiscovery
from modules.cve_detector import CVEDetector
from modules.attack_patterns import AttackPatternDetector
from modules.utils import setup_logging
import logging


async def test_mcp_client():
    """Test MCP client connection."""
    print("="*70)
    print("Testing MCP Client")
    print("="*70)
    
    # Test with a mock/local server
    test_urls = [
        "http://localhost:3000/sse",
        "ws://localhost:3001",
    ]
    
    for url in test_urls:
        print(f"\nTrying {url}...")
        try:
            async with MCPClient(url, timeout=5) as client:
                transport = await client.detect_transport()
                if transport:
                    print(f"  ✓ Detected transport: {transport}")
                    
                    if await client.initialize():
                        print(f"  ✓ Initialized successfully")
                        
                        info = client.get_server_info()
                        print(f"  Server info: {info.get('server_info', {})}")
                        
                        tools = await client.list_tools()
                        print(f"  ✓ Found {len(tools)} tools")
                    else:
                        print(f"  ✗ Initialization failed")
                else:
                    print(f"  ✗ No MCP transport detected")
        except Exception as e:
            print(f"  ✗ Error: {e}")


async def test_github_discovery():
    """Test GitHub discovery (without token)."""
    print("\n" + "="*70)
    print("Testing GitHub Discovery (limited without token)")
    print("="*70)
    
    logger = setup_logging("/dev/null", verbose=0, quiet=True)
    
    try:
        async with GitHubDiscovery(logger=logger) as discovery:
            # Get known MCP servers (doesn't require auth)
            servers = await discovery.get_known_mcp_servers()
            print(f"\n✓ Found {len(servers)} known MCP servers")
            
            for server in servers[:5]:
                print(f"  - {server['repository']} ({server.get('stars', 0)} stars)")
    except Exception as e:
        print(f"✗ Error: {e}")


async def test_cve_detector():
    """Test CVE detector."""
    print("\n" + "="*70)
    print("Testing CVE Detector")
    print("="*70)
    
    logger = setup_logging("/dev/null", verbose=0, quiet=True)
    
    # Create mock config
    config = {
        "scan": {"timeout": 30},
        "cve_detection": {"enabled": True}
    }
    
    # Create mock args
    class MockArgs:
        risk = "medium"
        level = 3
    
    detector = CVEDetector(config, logger, MockArgs())
    
    print(f"\n✓ CVE database loaded with {len(detector.CVE_DATABASE)} CVEs")
    
    for cve_id, cve_info in list(detector.CVE_DATABASE.items())[:5]:
        print(f"  - {cve_id}: {cve_info['name']} (CVSS: {cve_info.get('cvss_v4', 'N/A')})")


async def test_attack_patterns():
    """Test attack pattern detector."""
    print("\n" + "="*70)
    print("Testing Attack Pattern Detector")
    print("="*70)
    
    logger = setup_logging("/dev/null", verbose=0, quiet=True)
    
    config = {}
    detector = AttackPatternDetector(config, logger)
    
    print(f"\n✓ Loaded {len(detector.TOOL_POISONING_PATTERNS)} tool poisoning patterns")
    print(f"✓ Loaded {len(detector.EXCESSIVE_AGENCY_INDICATORS)} excessive agency indicators")


async def main():
    """Run all tests."""
    print("""
    ███╗   ███╗ ██████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
    ████╗ ████║██╔════╝██╔══██╗██╔════╝██╔═══██╗██╔══██╗████╗  ██║╚██╗██╔╝
    ██╔████╔██║██║     ██████╔╝█████╗  ██║   ██║██████╔╝██╔██╗ ██║ ╚███╔╝ 
    ██║╚██╔╝██║██║     ██╔══██╗██╔══╝  ██║   ██║██╔══██╗██║╚██╗██║ ██╔██╗ 
    ██║ ╚═╝ ██║╚██████╗██║  ██║██║     ╚██████╔╝██║  ██║██║ ╚████║██╔╝ ██╗
    ╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝
    
    MCPReconX Test Suite v2.0
    """)
    
    await test_mcp_client()
    await test_github_discovery()
    await test_cve_detector()
    await test_attack_patterns()
    
    print("\n" + "="*70)
    print("All tests completed!")
    print("="*70)


if __name__ == "__main__":
    asyncio.run(main())
