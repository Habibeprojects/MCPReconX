"""
MCPReconX - Report Generator Module
====================================
Generates JSON and PDF reports from scan results.

ETHICAL USE NOTICE:
This tool is intended for authorized security testing only.
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from .utils import Colors, format_timestamp, sanitize_output


class ReportGenerator:
    """Generates security assessment reports."""
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.output_dir = Path("reports")
        self.output_dir.mkdir(exist_ok=True)
    
    async def generate_json(self, results: Dict[str, Any], session_id: str) -> str:
        """
        Generate JSON report.
        
        Args:
            results: Complete scan results
            session_id: Session identifier
        
        Returns:
            Path to generated JSON file
        """
        filename = self.output_dir / f"mcpreconx_report_{session_id}.json"
        
        # Add metadata
        report = {
            "report_metadata": {
                "tool": "MCPReconX",
                "version": results.get("version"),
                "generated_at": datetime.now().isoformat(),
                "session_id": session_id,
                "report_type": "MCP Security Assessment"
            },
            "executive_summary": self._generate_executive_summary(results),
            "scan_details": results
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        self.logger.info(f"JSON report generated: {filename}")
        return str(filename)
    
    async def generate_pdf(self, results: Dict[str, Any], session_id: str) -> str:
        """
        Generate PDF report.
        
        Args:
            results: Complete scan results
            session_id: Session identifier
        
        Returns:
            Path to generated PDF file
        """
        filename = self.output_dir / f"mcpreconx_report_{session_id}.pdf"
        
        try:
            # Try to use fpdf2 (preferred)
            from fpdf import FPDF
            self._generate_pdf_fpdf(results, session_id, str(filename))
        except ImportError:
            try:
                # Fallback to reportlab
                from reportlab.lib import colors
                from reportlab.lib.pagesizes import letter
                from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
                from reportlab.lib.styles import getSampleStyleSheet
                self._generate_pdf_reportlab(results, session_id, str(filename))
            except ImportError:
                self.logger.warning("PDF libraries not available. Install fpdf2 or reportlab.")
                # Create a text-based "PDF" placeholder
                txt_filename = self.output_dir / f"mcpreconx_report_{session_id}.txt"
                self._generate_text_report(results, session_id, str(txt_filename))
                return str(txt_filename)
        
        self.logger.info(f"PDF report generated: {filename}")
        return str(filename)
    
    def _generate_pdf_fpdf(self, results: Dict[str, Any], session_id: str, filename: str):
        """Generate PDF using fpdf2."""
        from fpdf import FPDF
        
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        
        # Title page
        pdf.add_page()
        pdf.set_font("Arial", "B", 24)
        pdf.cell(0, 20, "MCPReconX Security Assessment Report", ln=True, align="C")
        pdf.set_font("Arial", "", 12)
        pdf.cell(0, 10, f"Session ID: {session_id}", ln=True, align="C")
        pdf.cell(0, 10, f"Generated: {format_timestamp()}", ln=True, align="C")
        pdf.cell(0, 10, f"Target: {results.get('target', 'N/A')}", ln=True, align="C")
        
        # Executive Summary
        pdf.add_page()
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "Executive Summary", ln=True)
        pdf.ln(5)
        
        summary = self._generate_executive_summary(results)
        pdf.set_font("Arial", "", 11)
        for key, value in summary.items():
            pdf.set_font("Arial", "B", 11)
            pdf.cell(0, 8, f"{key.replace('_', ' ').title()}:", ln=True)
            pdf.set_font("Arial", "", 11)
            if isinstance(value, list):
                for item in value:
                    pdf.cell(0, 6, f"  - {item}", ln=True)
            else:
                pdf.cell(0, 8, str(value), ln=True)
            pdf.ln(2)
        
        # Vulnerabilities
        pdf.add_page()
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "Vulnerability Details", ln=True)
        pdf.ln(5)
        
        vulns = results.get("vulnerabilities", [])
        for vuln in vulns:
            pdf.set_font("Arial", "B", 12)
            severity_color = {
                "critical": (200, 0, 0),
                "high": (255, 100, 0),
                "medium": (255, 200, 0),
                "low": (0, 150, 0),
                "info": (100, 100, 100)
            }.get(vuln.get("severity", ""), (0, 0, 0))
            
            pdf.set_text_color(*severity_color)
            pdf.cell(0, 8, f"[{vuln.get('severity', 'unknown').upper()}] {vuln.get('name', 'Unknown')}", ln=True)
            pdf.set_text_color(0, 0, 0)
            
            pdf.set_font("Arial", "", 10)
            pdf.cell(0, 6, f"ID: {vuln.get('id', 'N/A')}", ln=True)
            pdf.cell(0, 6, f"CVSS: {vuln.get('cvss_score', 'N/A')}", ln=True)
            pdf.multi_cell(0, 6, f"Description: {vuln.get('description', 'N/A')}")
            pdf.multi_cell(0, 6, f"Remediation: {vuln.get('remediation', 'N/A')}")
            pdf.ln(5)
        
        # Findings
        if results.get("findings"):
            pdf.add_page()
            pdf.set_font("Arial", "B", 16)
            pdf.cell(0, 10, "Security Findings", ln=True)
            pdf.ln(5)
            
            for finding in results.get("findings", []):
                pdf.set_font("Arial", "B", 12)
                pdf.cell(0, 8, finding.get("title", "Unknown"), ln=True)
                pdf.set_font("Arial", "", 10)
                pdf.cell(0, 6, f"Severity: {finding.get('severity', 'N/A')}", ln=True)
                pdf.cell(0, 6, f"Category: {finding.get('category', 'N/A')}", ln=True)
                pdf.multi_cell(0, 6, finding.get("description", "N/A"))
                pdf.ln(3)
        
        # Technical Details
        pdf.add_page()
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "Technical Details", ln=True)
        pdf.ln(5)
        
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 8, "Target Information", ln=True)
        pdf.set_font("Arial", "", 10)
        
        target_info = results.get("target_info", {})
        pdf.cell(0, 6, f"URL: {target_info.get('url', 'N/A')}", ln=True)
        pdf.cell(0, 6, f"Protocol: {target_info.get('protocol', 'N/A')}", ln=True)
        pdf.cell(0, 6, f"MCP Version: {target_info.get('mcp_version', 'N/A')}", ln=True)
        pdf.cell(0, 6, f"Transport: {target_info.get('transport_type', 'N/A')}", ln=True)
        
        pdf.ln(5)
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 8, "Fingerprinting Results", ln=True)
        pdf.set_font("Arial", "", 10)
        
        fingerprint = results.get("fingerprint", {})
        pdf.cell(0, 6, f"Implementation: {fingerprint.get('implementation', 'Unknown')}", ln=True)
        pdf.cell(0, 6, f"Version: {fingerprint.get('version', 'Unknown')}", ln=True)
        pdf.cell(0, 6, f"Authentication: {fingerprint.get('auth_method', 'None')}", ln=True)
        pdf.cell(0, 6, f"Tools Count: {fingerprint.get('tools_count', 0)}", ln=True)
        pdf.cell(0, 6, f"Resources Count: {fingerprint.get('resources_count', 0)}", ln=True)
        
        # Disclaimer
        pdf.add_page()
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Disclaimer", ln=True)
        pdf.ln(5)
        pdf.set_font("Arial", "", 10)
        disclaimer_text = """
This report was generated by MCPReconX, a security testing tool designed for authorized 
security assessments only. The testing performed was done with the explicit permission 
of the system owner.

The findings in this report represent potential security issues identified through 
automated scanning and should be verified through manual testing before remediation.

CVSS scores are approximate and should be validated in the context of your specific 
environment and threat model.

Unauthorized testing of systems without explicit permission is illegal and unethical.
        """
        pdf.multi_cell(0, 6, disclaimer_text)
        
        pdf.output(filename)
    
    def _generate_pdf_reportlab(self, results: Dict[str, Any], session_id: str, filename: str):
        """Generate PDF using reportlab (fallback)."""
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet
        
        doc = SimpleDocTemplate(filename, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        story.append(Paragraph("MCPReconX Security Assessment Report", styles['Title']))
        story.append(Spacer(1, 12))
        story.append(Paragraph(f"Session: {session_id}", styles['Normal']))
        story.append(Paragraph(f"Target: {results.get('target', 'N/A')}", styles['Normal']))
        story.append(Spacer(1, 24))
        
        # Vulnerabilities table
        story.append(Paragraph("Vulnerabilities", styles['Heading2']))
        story.append(Spacer(1, 12))
        
        vuln_data = [["ID", "Name", "Severity", "CVSS"]]
        for vuln in results.get("vulnerabilities", []):
            vuln_data.append([
                vuln.get("id", "N/A"),
                vuln.get("name", "N/A")[:40],
                vuln.get("severity", "N/A"),
                str(vuln.get("cvss_score", "N/A"))
            ])
        
        if len(vuln_data) > 1:
            vuln_table = Table(vuln_data)
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(vuln_table)
        else:
            story.append(Paragraph("No vulnerabilities detected.", styles['Normal']))
        
        doc.build(story)
    
    def _generate_text_report(self, results: Dict[str, Any], session_id: str, filename: str):
        """Generate text report (fallback when PDF libs unavailable)."""
        with open(filename, 'w') as f:
            f.write("="*70 + "\n")
            f.write("MCPReconX Security Assessment Report\n")
            f.write("="*70 + "\n")
            f.write(f"Session ID: {session_id}\n")
            f.write(f"Generated: {format_timestamp()}\n")
            f.write(f"Target: {results.get('target', 'N/A')}\n")
            f.write("="*70 + "\n\n")
            
            # Executive Summary
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-"*70 + "\n")
            summary = self._generate_executive_summary(results)
            for key, value in summary.items():
                f.write(f"{key.replace('_', ' ').title()}: {value}\n")
            f.write("\n")
            
            # Vulnerabilities
            f.write("VULNERABILITIES\n")
            f.write("-"*70 + "\n")
            for vuln in results.get("vulnerabilities", []):
                f.write(f"\n[{vuln.get('severity', 'unknown').upper()}] {vuln.get('name')}\n")
                f.write(f"ID: {vuln.get('id')}\n")
                f.write(f"CVSS: {vuln.get('cvss_score')}\n")
                f.write(f"Description: {vuln.get('description')}\n")
                f.write(f"Remediation: {vuln.get('remediation')}\n")
            
            if not results.get("vulnerabilities"):
                f.write("No vulnerabilities detected.\n")
            
            f.write("\n" + "="*70 + "\n")
            f.write("End of Report\n")
    
    def _generate_executive_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary from results."""
        vulns = results.get("vulnerabilities", [])
        findings = results.get("findings", [])
        
        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in vulns:
            sev = vuln.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        # Overall risk
        if severity_counts["critical"] > 0:
            overall_risk = "CRITICAL"
        elif severity_counts["high"] > 0:
            overall_risk = "HIGH"
        elif severity_counts["medium"] > 0:
            overall_risk = "MEDIUM"
        elif severity_counts["low"] > 0:
            overall_risk = "LOW"
        else:
            overall_risk = "MINIMAL"
        
        # Top issues
        top_issues = []
        for vuln in sorted(vulns, key=lambda x: x.get("cvss_score", 0), reverse=True)[:5]:
            top_issues.append(f"{vuln.get('id')}: {vuln.get('name')}")
        
        fingerprint = results.get("fingerprint", {})
        
        return {
            "scan_target": results.get("target"),
            "scan_duration": f"{results.get('duration_seconds', 0):.2f} seconds",
            "overall_risk_rating": overall_risk,
            "vulnerabilities_found": len(vulns),
            "findings_identified": len(findings),
            "severity_breakdown": severity_counts,
            "critical_issues": severity_counts["critical"],
            "high_issues": severity_counts["high"],
            "server_implementation": fingerprint.get("implementation", "Unknown"),
            "authentication_required": fingerprint.get("auth_required", False),
            "top_issues": top_issues if top_issues else ["None"],
            "safe_mode": results.get("safe_mode", True)
        }
    
    def print_summary(self, results: Dict[str, Any]):
        """Print console summary of results."""
        summary = self._generate_executive_summary(results)
        
        print(f"\n{Colors.CYAN}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}SCAN SUMMARY{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*70}{Colors.RESET}")
        
        # Risk rating with color
        risk = summary["overall_risk_rating"]
        risk_color = {
            "CRITICAL": Colors.RED,
            "HIGH": Colors.YELLOW,
            "MEDIUM": Colors.CYAN,
            "LOW": Colors.GREEN,
            "MINIMAL": Colors.GREEN
        }.get(risk, Colors.WHITE)
        
        print(f"Target: {summary['scan_target']}")
        print(f"Risk Rating: {risk_color}{risk}{Colors.RESET}")
        print(f"Duration: {summary['scan_duration']}")
        print(f"Safe Mode: {'Yes' if summary['safe_mode'] else 'No'}")
        
        print(f"\n{Colors.BOLD}Vulnerabilities:{Colors.RESET}")
        sev = summary["severity_breakdown"]
        print(f"  {Colors.RED}Critical: {sev['critical']}{Colors.RESET}")
        print(f"  {Colors.YELLOW}High: {sev['high']}{Colors.RESET}")
        print(f"  {Colors.CYAN}Medium: {sev['medium']}{Colors.RESET}")
        print(f"  {Colors.GREEN}Low: {sev['low']}{Colors.RESET}")
        print(f"  Info: {sev['info']}")
        
        if summary["top_issues"] and summary["top_issues"] != ["None"]:
            print(f"\n{Colors.BOLD}Top Issues:{Colors.RESET}")
            for issue in summary["top_issues"]:
                print(f"  - {issue}")
        
        print(f"{Colors.CYAN}{'='*70}{Colors.RESET}\n")
