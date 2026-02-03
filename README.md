# MCPReconX v2.0 - Model Context Protocol Security Scanner

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/python-3.9+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/MCP-Security-red.svg" alt="MCP Security">
</p>

<p align="center">
  <b>Complete security assessment toolkit for Model Context Protocol (MCP) servers</b>
</p>

<p align="center">
  🔍 CVE Detection | 🌐 Internet Scanning | 📊 Attack Patterns | 🛠️ Working Exploits
</p>

---

## ⚠️ Ethical Use Notice

**MCPReconX is for authorized security testing only.** By using this tool, you agree to the [DISCLAIMER](DISCLAIMER.md). Unauthorized access to computer systems is illegal.

---

## Features

### 🔍 CVE Detection
Detects 10+ known MCP vulnerabilities:

| CVE | Description | CVSS |
|-----|-------------|------|
| CVE-2025-49596 | MCP Inspector Unauthenticated RCE | 9.4 |
| CVE-2025-6514 | mcp-remote OS Command Injection | 9.6 |
| CVE-2025-68143 | Git MCP Path Traversal | 8.8 |
| CVE-2025-68144 | Git MCP Argument Injection | 8.1 |
| CVE-2025-68145 | Git MCP Path Validation Bypass | 7.1 |
| CVE-2025-66416 | DNS Rebinding in Python SDK | 7.6 |
| CVE-2025-6515 | Session Hijacking (oatpp-mcp) | 8.2 |
| CVE-2025-65513 | fetch-mcp SSRF | 8.5 |
| CVE-2025-53967 | Framelink Figma RCE | 9.1 |
| CVE-2025-5276 | Markdownify SSRF | 7.5 |

### 🌐 Discovery Modes

- **GitHub Discovery**: Find MCP servers on GitHub repositories
- **Internet Scanning**: Scan hosts/networks for exposed MCP servers
- **Local Discovery**: Auto-detect local MCP servers

### 📊 Attack Pattern Detection

Based on [Adversa.ai's MCP Security Top 25](https://adversa.ai/mcp-security-top-25-mcp-vulnerabilities/):

- Tool Poisoning Attacks (TPA)
- Full Schema Poisoning (FSP)
- Advanced Tool Poisoning (ATPA)
- Confused Deputy attacks
- Token Passthrough
- Rug Pull attacks
- NeighborJack (0.0.0.0 Day)
- DNS Rebinding

### 🛠️ Working MCP Client

Full MCP protocol implementation:
- HTTP/SSE transport
- WebSocket transport
- Tool invocation
- Resource access
- Prompt handling

---

## Improvements & Feature Roadmap

MCPReconX provides a CLI-driven pipeline (discovery → fingerprinting → CVE checks → attack pattern detection → reporting) backed by modules in `modules/`, with configuration in `config.yaml` and reports/logs written to `reports/` and `logs/`. The repository includes a smoke test (`python test_scanner.py`) and an installer script (`install.sh`).

Improvements:
- Add CI to run `test_scanner.py` (and optional linting) automatically on PRs.
- Document test/runtime dependencies (e.g., `aiohttp`) and optional dev requirements in `requirements.txt`.
- Expand troubleshooting guidance for config/report locations (`config.yaml`, `reports/`, `logs/`).

Features to build/add:
- Add unit tests per module (discovery, fingerprinting, CVE detection) with fixtures.
- Extend `config.yaml` CVE signatures and map `exploits/` templates to findings.
- Add additional report formats (CSV/HTML) and scan-to-scan summary diffs.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/security/mcpreconx.git
cd mcpreconx

# Install dependencies
pip install -r requirements.txt

# Or use the installer
chmod +x install.sh
./install.sh
```

---

## Quick Start

### 1. Scan a Local MCP Server

```bash
# Basic scan
python main.py --target http://localhost:3000/sse

# Full security assessment
python main.py -t http://localhost:3000/sse --cve-check --detect-patterns --report-all

# With authentication
python main.py -t http://localhost:3000/sse --auth-token "Bearer YOUR_TOKEN"
```

### 2. Discover MCP Servers on GitHub

```bash
# Search GitHub for MCP servers
python main.py --discover-github

# With GitHub token (higher rate limits)
python main.py --discover-github --github-token YOUR_GITHUB_TOKEN

# Limit results
python main.py --discover-github --max-results 100
```

### 3. Scan Internet for Exposed MCP Servers

```bash
# Scan a single host
python main.py --discover-internet --target scanme.nmap.org

# Scan a network range
python main.py --discover-internet --target 192.168.1.0/24

# ⚠️ Only scan networks you own or have permission to test!
```

### 4. Test with MCP Client

```python
import asyncio
from modules.mcp_client import MCPClient

async def test_mcp():
    async with MCPClient("http://localhost:3000/sse") as client:
        # Initialize connection
        if await client.initialize():
            print("Connected to MCP server!")
            
            # List tools
            tools = await client.list_tools()
            print(f"Available tools: {len(tools)}")
            
            # Call a tool
            result = await client.call_tool("example_tool", {"param": "value"})
            print(f"Result: {result}")

asyncio.run(test_mcp())
```

---

## CLI Reference

### Target Specification

```
-t, --target          Target MCP server URL
--method              Transport: auto, http, websocket
```

### Discovery Modes

```
--discover-github     Discover MCP servers on GitHub
--discover-internet   Discover MCP servers on internet
--github-token        GitHub API token
--max-results         Maximum results (default: 50)
```

### Scan Options

```
--cve-check           Enable CVE detection
--detect-patterns     Enable attack pattern detection
--risk                Risk level: low, medium, high
--level               Scan intensity 1-5
--safe                Safe mode (default)
--exploit             Enable exploitation simulation
```

### Output Options

```
-v, --verbose         Verbose output (-vv for debug)
--json                Generate JSON report
--pdf                 Generate PDF report
--report-all          Generate all reports
--output-dir          Output directory (default: reports)
```

---

## Examples

### Full Security Assessment

```bash
# Comprehensive scan with all checks
python main.py \
  --target http://localhost:3000/sse \
  --cve-check \
  --detect-patterns \
  --risk high \
  --report-all \
  -v
```

### GitHub Research

```bash
# Find popular MCP servers
python main.py --discover-github --max-results 100

# Analyze specific repositories
python main.py --discover-github | jq '.servers[] | select(.stars > 100)'
```

### Network Scanning

```bash
# Scan your local network
python main.py --discover-internet --target 192.168.1.0/24

# Scan common MCP ports on a host
python main.py --discover-internet --target localhost
```

### Batch Scanning

```bash
# Scan multiple targets from file
for target in $(cat targets.txt); do
  python main.py --target "$target" --batch --json
done
```

---

## Architecture

```
MCPReconX/
├── main.py                    # CLI entry point
├── config.yaml               # Configuration with CVE signatures
├── requirements.txt          # Dependencies
├── install.sh               # Installation script
│
├── modules/                  # Core modules
│   ├── mcp_client.py        # Working MCP protocol client
│   ├── github_discovery.py  # GitHub MCP server discovery
│   ├── internet_discovery.py # Internet scanning
│   ├── cve_detector.py      # CVE detection engine
│   ├── attack_patterns.py   # Attack pattern detection
│   ├── scanner.py           # Active vulnerability scanning
│   ├── fingerprint.py       # Server fingerprinting
│   ├── detect_poison.py     # Tool poisoning detection
│   ├── exploit_sim.py       # Exploitation simulation
│   ├── report.py            # Report generation
│   └── utils.py             # Utilities
│
├── exploits/                 # PoC exploit templates
├── tampers/                  # Evasion scripts
├── logs/                     # Scan logs
└── reports/                  # Generated reports
```

---

## Scanning Pipeline

```
┌─────────────────┐
│  1. Discovery   │ → GitHub/Internet/Local
└────────┬────────┘
         ▼
┌─────────────────┐
│  2. Validation  │ → Protocol detection
└────────┬────────┘
         ▼
┌─────────────────┐
│  3. Fingerprint │ → Implementation, version
└────────┬────────┘
         ▼
┌─────────────────┐
│  4. CVE Check   │ → Match known CVEs
└────────┬────────┘
         ▼
┌─────────────────┐
│  5. Patterns    │ → Attack pattern detection
└────────┬────────┘
         ▼
┌─────────────────┐
│  6. Active Scan │ → Vulnerability testing
└────────┬────────┘
         ▼
┌─────────────────┐
│  7. Exploit Sim │ → PoC simulation
└────────┬────────┘
         ▼
┌─────────────────┐
│  8. Reporting   │ → JSON/PDF reports
└─────────────────┘
```

---

## Report Example

### Console Output

```
======================================================================
MCPReconX Security Assessment Report
======================================================================
Target: http://localhost:3000/sse
Risk Rating: CRITICAL
Duration: 45.23 seconds
Safe Mode: Yes

CVEs Detected:
  [CRITICAL] CVE-2025-49596: MCP Inspector Unauthenticated RCE (CVSS: 9.4)
  [HIGH] CVE-2025-66416: DNS Rebinding Vulnerability (CVSS: 7.6)

Attack Patterns:
  [CRITICAL] Tool Poisoning Attack (TPA)
  [HIGH] Full Schema Poisoning (FSP)
  [MEDIUM] Excessive Agency

Vulnerabilities:
  Critical: 2
  High: 3
  Medium: 2
  Low: 1

Top Issues:
  - CVE-2025-49596: Unauthenticated RCE in MCP Inspector
  - Tool Poisoning in 'execute_code' tool
  - SSRF vulnerability in 'fetch_url' tool
======================================================================
```

### JSON Report

```json
{
  "report_metadata": {
    "tool": "MCPReconX",
    "version": "2.0.0",
    "generated_at": "2024-01-15T10:30:00"
  },
  "executive_summary": {
    "overall_risk_rating": "CRITICAL",
    "cves_detected": 2,
    "attack_patterns": 3,
    "vulnerabilities_found": 7
  },
  "cve_findings": [
    {
      "cve_id": "CVE-2025-49596",
      "name": "MCP Inspector Unauthenticated RCE",
      "cvss_score": 9.4,
      "severity": "critical"
    }
  ],
  "attack_patterns": [
    {
      "pattern_name": "Tool Poisoning Attack (TPA)",
      "severity": "critical",
      "affected_component": "tool:execute_code"
    }
  ],
  "scan_details": { ... }
}
```

---

## Research Sources

- [Adversa.ai MCP Security Top 25](https://adversa.ai/mcp-security-top-25-mcp-vulnerabilities/)
- [Cyata Research](https://cyata.com)
- [Oligo Security](https://www.oligo.security)
- [JFrog Security](https://jfrog.com/blog)
- [Imperva Threat Research](https://www.imperva.com/blog)
- [NVD - National Vulnerability Database](https://nvd.nist.gov/)

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

---

## License

MIT License - See [LICENSE](LICENSE) file

---

<p align="center">
  <b>🔒 Secure MCP. Safe AI. Ethical Testing. 🔒</b>
</p>
