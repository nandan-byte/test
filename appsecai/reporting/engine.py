"""
Report Generator for Caze AppSecAI CLI

Generates comprehensive security reports in multiple formats (HTML, PDF, CSV, JSON).
This module leverages existing reporting logic from the Streamlit application.
"""

import os
import json
import csv
import logging
from typing import Dict, Any, List, Optional, Union
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class ReportData:
    """Container for report data."""
    scan_results: List[Dict[str, Any]]
    remediation_results: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None
    summary: Optional[Dict[str, Any]] = None

class ReportGenerator:
    """Multi-format report generator for security scan results."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize report generator with configuration.
        
        Args:
            config: Reporting configuration
        """
        self.config = config
        self.template_dir = config.get('template_dir', './templates')
        self.include_executive_summary = config.get('include_executive_summary', True)
        
    def generate_report(self, data: ReportData, formats: List[str], output_dir: str) -> List[str]:
        """
        Generate reports in specified formats.
        
        Args:
            data: Report data container
            formats: List of formats to generate ('html', 'pdf', 'csv', 'json')
            output_dir: Output directory for reports
            
        Returns:
            List of generated report file paths
        """
        logger.info(f"Generating reports in formats: {', '.join(formats)}")
        
        # Create output directory
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        generated_files = []
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Generate summary if not provided
        if not data.summary:
            data.summary = self._generate_summary(data)
        
        # Generate each requested format
        for format_type in formats:
            try:
                if format_type.lower() == 'html':
                    file_path = self._generate_html_report(data, output_dir, timestamp)
                elif format_type.lower() == 'pdf':
                    file_path = self._generate_pdf_report(data, output_dir, timestamp)
                elif format_type.lower() == 'csv':
                    file_path = self._generate_csv_report(data, output_dir, timestamp)
                elif format_type.lower() == 'json':
                    file_path = self._generate_json_report(data, output_dir, timestamp)
                else:
                    logger.warning(f"Unsupported report format: {format_type}")
                    continue
                
                if file_path:
                    generated_files.append(file_path)
                    logger.info(f"Generated {format_type.upper()} report: {file_path}")
                
            except Exception as e:
                logger.error(f"Failed to generate {format_type} report: {e}")
        
        return generated_files
    
    def _generate_summary(self, data: ReportData) -> Dict[str, Any]:
        """Generate summary statistics from scan results."""
        summary = {
            'total_vulnerabilities': 0,
            'severity_counts': {
                'Critical': 0,
                'High': 0,
                'Medium': 0,
                'Low': 0
            },
            'scan_types': set(),
            'files_affected': set(),
            'scan_timestamp': datetime.now().isoformat(),
            'remediation_stats': {}
        }
        
        # Process scan results
        for result in data.scan_results:
            vulnerabilities = result.get('vulnerabilities', [])
            summary['total_vulnerabilities'] += len(vulnerabilities)
            summary['scan_types'].add(result.get('scan_type', 'unknown'))
            
            for vuln in vulnerabilities:
                # Count by severity
                severity = vuln.get('severity', 'Low')
                if severity in summary['severity_counts']:
                    summary['severity_counts'][severity] += 1
                
                # Track affected files
                file_path = vuln.get('file_path') or vuln.get('url', '')
                if file_path:
                    summary['files_affected'].add(file_path)
        
        # Process remediation results if available
        if data.remediation_results:
            remediation_summary = data.remediation_results.get('summary', {})
            summary['remediation_stats'] = {
                'total_processed': remediation_summary.get('total_vulnerabilities', 0),
                'successfully_fixed': remediation_summary.get('status_counts', {}).get('success', 0),
                'failed_fixes': remediation_summary.get('status_counts', {}).get('failed', 0),
                'success_rate': remediation_summary.get('success_rate', 0.0),
                'pull_requests_created': remediation_summary.get('pull_requests_created', 0)
            }
        
        # Convert sets to lists for JSON serialization
        summary['scan_types'] = list(summary['scan_types'])
        summary['files_affected'] = list(summary['files_affected'])
        
        return summary
    
    def _generate_html_report(self, data: ReportData, output_dir: str, timestamp: str) -> str:
        """Generate HTML report."""
        output_file = Path(output_dir) / f"security_report_{timestamp}.html"
        
        try:
            # Generate HTML content
            html_content = self._create_html_content(data)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            return str(output_file)
            
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")
            return ""
    
    def _create_html_content(self, data: ReportData) -> str:
        """Create HTML report content."""
        summary = data.summary
        
        # Create severity chart data
        severity_data = summary['severity_counts']
        chart_data = json.dumps([
            {'name': k, 'value': v} for k, v in severity_data.items() if v > 0
        ])
        
        html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Caze AppSecAI Security Report</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 30px; border-bottom: 2px solid #0078D7; padding-bottom: 20px; }}
        .header h1 {{ color: #0078D7; margin: 0; font-size: 2.5rem; }}
        .header p {{ color: #666; margin: 10px 0 0 0; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }}
        .summary-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #0078D7; }}
        .summary-card h3 {{ margin: 0 0 10px 0; color: #333; }}
        .summary-card .value {{ font-size: 2rem; font-weight: bold; color: #0078D7; }}
        .section {{ margin: 30px 0; }}
        .section h2 {{ color: #333; border-bottom: 1px solid #ddd; padding-bottom: 10px; }}
        .vulnerability-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        .vulnerability-table th, .vulnerability-table td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        .vulnerability-table th {{ background-color: #f8f9fa; font-weight: 600; }}
        .severity-critical {{ color: #dc3545; font-weight: bold; }}
        .severity-high {{ color: #fd7e14; font-weight: bold; }}
        .severity-medium {{ color: #ffc107; font-weight: bold; }}
        .severity-low {{ color: #28a745; font-weight: bold; }}
        .chart-container {{ margin: 20px 0; height: 400px; }}
        .remediation-stats {{ background: #e8f5e8; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .footer {{ text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Caze AppSecAI Security Report</h1>
            <p>Generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</p>
        </div>
        
        <div class="summary-grid">
            <div class="summary-card">
                <h3>Total Vulnerabilities</h3>
                <div class="value">{summary['total_vulnerabilities']}</div>
            </div>
            <div class="summary-card">
                <h3>Critical & High</h3>
                <div class="value">{summary['severity_counts']['Critical'] + summary['severity_counts']['High']}</div>
            </div>
            <div class="summary-card">
                <h3>Files Affected</h3>
                <div class="value">{len(summary['files_affected'])}</div>
            </div>
            <div class="summary-card">
                <h3>Scan Types</h3>
                <div class="value">{', '.join(summary['scan_types'])}</div>
            </div>
        </div>
        
        <div class="section">
            <h2>📊 Vulnerability Distribution</h2>
            <div id="severityChart" class="chart-container"></div>
        </div>
        
        {self._generate_remediation_section(data) if data.remediation_results else ''}
        
        <div class="section">
            <h2>🔍 Detailed Vulnerabilities</h2>
            {self._generate_vulnerability_table(data)}
        </div>
        
        <div class="footer">
            <p>Report generated by Caze AppSecAI CLI • <a href="https://github.com/yourusername/cazeAppSecAI">GitHub</a></p>
        </div>
    </div>
    
    <script>
        // Create severity distribution chart
        var chartData = {chart_data};
        var layout = {{
            title: 'Vulnerability Severity Distribution',
            showlegend: true,
            height: 350,
            margin: {{ t: 50, b: 50, l: 50, r: 50 }}
        }};
        
        if (chartData.length > 0) {{
            var trace = {{
                labels: chartData.map(d => d.name),
                values: chartData.map(d => d.value),
                type: 'pie',
                marker: {{
                    colors: ['#dc3545', '#fd7e14', '#ffc107', '#28a745']
                }}
            }};
            Plotly.newPlot('severityChart', [trace], layout);
        }} else {{
            document.getElementById('severityChart').innerHTML = '<p style="text-align: center; color: #666;">No vulnerabilities found</p>';
        }}
    </script>
</body>
</html>
        """
        
        return html_template
    
    def _generate_remediation_section(self, data: ReportData) -> str:
        """Generate remediation results section for HTML report."""
        if not data.remediation_results:
            return ""
        
        stats = data.remediation_results.get('summary', {}).get('remediation_stats', {})
        
        return f"""
        <div class="section">
            <h2>🤖 AI Remediation Results</h2>
            <div class="remediation-stats">
                <div class="summary-grid">
                    <div class="summary-card">
                        <h3>Processed</h3>
                        <div class="value">{stats.get('total_processed', 0)}</div>
                    </div>
                    <div class="summary-card">
                        <h3>Successfully Fixed</h3>
                        <div class="value">{stats.get('successfully_fixed', 0)}</div>
                    </div>
                    <div class="summary-card">
                        <h3>Success Rate</h3>
                        <div class="value">{stats.get('success_rate', 0):.1%}</div>
                    </div>
                    <div class="summary-card">
                        <h3>Pull Requests</h3>
                        <div class="value">{stats.get('pull_requests_created', 0)}</div>
                    </div>
                </div>
            </div>
        </div>
        """
    
    def _generate_vulnerability_table(self, data: ReportData) -> str:
        """Generate vulnerability table for HTML report."""
        table_rows = []
        
        for result in data.scan_results:
            vulnerabilities = result.get('vulnerabilities', [])
            
            for vuln in vulnerabilities[:50]:  # Limit to first 50 for readability
                severity = vuln.get('severity', 'Low')
                severity_class = f"severity-{severity.lower()}"
                
                file_or_url = vuln.get('file_path') or vuln.get('url', 'N/A')
                
                table_rows.append(f"""
                <tr>
                    <td class="{severity_class}">{severity}</td>
                    <td>{vuln.get('title', 'Unknown')}</td>
                    <td>{file_or_url}</td>
                    <td>{vuln.get('description', 'No description')[:100]}...</td>
                </tr>
                """)
        
        if not table_rows:
            return "<p>No vulnerabilities found.</p>"
        
        return f"""
        <table class="vulnerability-table">
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Title</th>
                    <th>File/URL</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                {''.join(table_rows)}
            </tbody>
        </table>
        """
    
    def _generate_pdf_report(self, data: ReportData, output_dir: str, timestamp: str) -> str:
        """Generate PDF report using existing FPDF functionality."""
        output_file = Path(output_dir) / f"security_report_{timestamp}.pdf"
        
        try:
            from fpdf import FPDF
            
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font('Arial', 'B', 16)
            
            # Title
            pdf.cell(0, 10, 'Caze AppSecAI Security Report', 0, 1, 'C')
            pdf.ln(10)
            
            # Summary
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 10, 'Executive Summary', 0, 1)
            pdf.set_font('Arial', '', 12)
            
            summary = data.summary
            pdf.cell(0, 8, f"Total Vulnerabilities: {summary['total_vulnerabilities']}", 0, 1)
            pdf.cell(0, 8, f"Critical: {summary['severity_counts']['Critical']}", 0, 1)
            pdf.cell(0, 8, f"High: {summary['severity_counts']['High']}", 0, 1)
            pdf.cell(0, 8, f"Medium: {summary['severity_counts']['Medium']}", 0, 1)
            pdf.cell(0, 8, f"Low: {summary['severity_counts']['Low']}", 0, 1)
            pdf.ln(10)
            
            # Vulnerability details
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 10, 'Vulnerability Details', 0, 1)
            pdf.set_font('Arial', '', 10)
            
            for result in data.scan_results:
                vulnerabilities = result.get('vulnerabilities', [])
                
                for vuln in vulnerabilities[:20]:  # Limit for PDF space
                    pdf.cell(0, 6, f"[{vuln.get('severity', 'Low')}] {vuln.get('title', 'Unknown')}", 0, 1)
                    file_or_url = vuln.get('file_path') or vuln.get('url', 'N/A')
                    pdf.cell(0, 6, f"Location: {file_or_url}", 0, 1)
                    pdf.ln(2)
            
            pdf.output(str(output_file))
            return str(output_file)
            
        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")
            return ""
    
    def _generate_csv_report(self, data: ReportData, output_dir: str, timestamp: str) -> str:
        """Generate CSV report."""
        output_file = Path(output_dir) / f"security_report_{timestamp}.csv"
        
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'scan_type', 'severity', 'title', 'description', 
                    'file_path', 'url', 'line_number', 'risk_score'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for result in data.scan_results:
                    scan_type = result.get('scan_type', 'unknown')
                    vulnerabilities = result.get('vulnerabilities', [])
                    
                    for vuln in vulnerabilities:
                        writer.writerow({
                            'scan_type': scan_type,
                            'severity': vuln.get('severity', ''),
                            'title': vuln.get('title', ''),
                            'description': vuln.get('description', ''),
                            'file_path': vuln.get('file_path', ''),
                            'url': vuln.get('url', ''),
                            'line_number': vuln.get('line_number', ''),
                            'risk_score': vuln.get('risk_score', 0)
                        })
            
            return str(output_file)
            
        except Exception as e:
            logger.error(f"Failed to generate CSV report: {e}")
            return ""
    
    def _generate_json_report(self, data: ReportData, output_dir: str, timestamp: str) -> str:
        """Generate JSON report."""
        output_file = Path(output_dir) / f"security_report_{timestamp}.json"
        
        try:
            report_data = {
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'generator': 'Caze AppSecAI CLI',
                    'version': '1.0.0'
                },
                'summary': data.summary,
                'scan_results': data.scan_results,
                'remediation_results': data.remediation_results
            }
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, default=str)
            
            return str(output_file)
            
        except Exception as e:
            logger.error(f"Failed to generate JSON report: {e}")
            return ""