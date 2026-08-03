#!/usr/bin/env python3
"""
Enhanced Security Posture Report Generator

Generates comprehensive security posture reports in both JSON and PDF formats.
Consolidates data from ZAP (DAST), SonarQube (SAST), and compliance configurations.

Features:
- Executive summary with risk assessment
- Detailed vulnerability analysis
- Security controls evaluation
- Remediation recommendations
- Risk scoring and prioritization
- Professional PDF output with charts

Usage:
    python generate_security_posture_report.py [--format pdf|json|both] [--output-dir DIR]
"""

import os
import sys
import json
import csv
import glob
import argparse
import time
from datetime import datetime
import logging
from typing import List, Dict, Optional, Any
from pathlib import Path
from dotenv import load_dotenv
import html
import re

# Load environment variables from .env file
# Use explicit path to ensure .env is found regardless of working directory
env_path = Path(__file__).parent / '.env'
load_dotenv(env_path)


from appsecai.common.utils import get_resource_path, load_appsec_json_data

# PDF generation imports
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.colors import HexColor, black, white, red, orange, yellow, green
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
    from reportlab.platypus import Image as RLImage
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
    from reportlab.graphics.shapes import Drawing, Rect
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics.charts.legends import Legend
    from reportlab.lib import colors
    from reportlab.platypus.tableofcontents import TableOfContents
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    print("⚠️  PDF generation not available. Install reportlab: pip install reportlab")

# Configure logging - only show warnings and errors to users
logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


if PDF_AVAILABLE:
    class ReportDocTemplate(SimpleDocTemplate):
        def afterFlowable(self, flowable):
            "Registers TOC entries."
            if flowable.__class__.__name__ == 'Paragraph':
                text = flowable.getPlainText()
                style = flowable.style.name
                if style == 'CustomHeading':
                    self.notify('TOCEntry', (0, text, self.page))
                elif style == 'CustomSubHeading':
                    self.notify('TOCEntry', (1, text, self.page))
else:
    class ReportDocTemplate:
        """Fallback empty class when reportlab is not available."""
        def __init__(self, *args, **kwargs):
            pass


class SecurityPostureReportGenerator:
    """Enhanced security posture report generator with PDF support."""
    

    def _get_deployment_controls_summary(self, controls_data: Dict[str, Any], header_style: Any, normal_style: Any, primary_color: Any, white: Any, neutral_gray: Any) -> Table:
        """Create a summary table for deployment controls."""
        implemented = controls_data.get('implemented_controls', 0)
        total = controls_data.get('total_controls', 0)
        missing = total - implemented
        
        data = [
            [Paragraph("<b>Deployment Controls</b>", header_style), Paragraph("<b>Status</b>", header_style)],
            [Paragraph("Implemented Controls", normal_style), Paragraph(f"{implemented} / {total}", normal_style)],
            [Paragraph("Missing Controls", normal_style), Paragraph(f"{missing} / {total}", normal_style)]
        ]
        
        summary_table = Table(data, colWidths=[3.0*inch, 3.0*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), primary_color),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 0.5, neutral_gray),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('TOPPADDING', (0, 1), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
        ]))
        
        return summary_table

    def __init__(self, input_dir: str = "AppSecAI_output", output_dir: str = "generated_reports", force_report_type: str = None):
        # Get the base directory where reports should be saved
        if getattr(sys, 'frozen', False):
            # Running as EXE - use get_base_directory to find correct location
            # Import here to avoid circular dependency
            try:
                from appsecai.cli.menu import get_base_directory
                base_dir = get_base_directory()
            except ImportError:
                # Fallback if import fails
                exe_path = Path(sys.executable)
                exe_dir = exe_path.parent
                if '_MEI' in str(exe_dir):
                    base_dir = Path.home() / "Desktop" / "CazeAppSecReport"
                else:
                    base_dir = exe_dir / "CazeAppSecReport"
                base_dir.mkdir(exist_ok=True)
        else:
            # Running as Python - use current working directory
            base_dir = Path.cwd()
        
        # Make paths absolute relative to base directory
        # If input_dir is already absolute, use it as-is
        if Path(input_dir).is_absolute():
            self.input_dir = Path(input_dir)
        else:
            self.input_dir = base_dir / input_dir
        
        # Same for output_dir
        if Path(output_dir).is_absolute():
            self.output_dir = Path(output_dir)
        else:
            self.output_dir = base_dir / output_dir
        
        # Create output directory if it doesn't exist
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Log the paths being used
        logger.info(f"📂 Report Generator initialized:")
        logger.info(f"   Input directory: {self.input_dir}")
        logger.info(f"   Output directory: {self.output_dir}")
        logger.info(f"   Base directory: {base_dir}")
        
        # Force specific report type (dast_only, sast_only, comprehensive, or None for auto-detect)
        self.force_report_type = force_report_type
        
        # Report data
        self.zap_data = []
        self.sonar_data = []  # Filtered data for top vulnerabilities
        self.sonar_raw_data = []  # Raw data for original counts
        self.sca_data = []  # Trivy SCA prioritized findings
        self.sca_original_count = 0  # Original total count from Trivy before prioritization
        self.compliance_data = {}
        self.report_data = {}
        self.target_url = "Not specified"  # Target URL from ZAP scan
    
    def _get_repositories_display(self) -> str:
        """Get summary of configured repositories and their Sonar project keys from environment."""
        repos_str = os.environ.get('GITHUB_REPOSITORIES', '')
        if not repos_str:
            repo = os.environ.get('GITHUB_REPO', 'Not specified')
            pk = os.environ.get('SONAR_PROJECT_KEY', '')
            if pk:
                return f"{repo} (Sonar: {pk})"
            return repo
        
        try:
            repos = []
            for item in repos_str.split(';'):
                if not item.strip(): continue
                parts = [p.strip() for p in item.split('|')]
                repo_name = parts[0]
                if len(parts) > 2 and parts[2]:
                    repos.append(f"{repo_name} ({parts[2]})")
                else:
                    repos.append(repo_name)
            
            if not repos:
                return os.environ.get('GITHUB_REPO', 'Not specified')
            
            summary = ", ".join(repos[:3])
            if len(repos) > 3:
                summary += f" (+{len(repos) - 3} more)"
            return summary
        except:
            return os.environ.get('GITHUB_REPO', 'Not specified')
        
    def discover_and_load_data(self):
        """Discover and load all available security scan data."""
        print("[*] Discovering security scan data...")
        
        # Load data based on report type
        if self.force_report_type == "dast_only":
            print("[TARGET] DAST-only report requested - loading only ZAP data")
            self._load_zap_data()
            self._load_compliance_data()
            # Explicitly skip SonarQube data for DAST-only reports
            self.sonar_data = []
            self.sonar_raw_data = []
            self.sca_data = []
        elif self.force_report_type == "sast_only":
            print("[TARGET] SAST-only report requested - loading only SonarQube data")
            self._load_sonar_data()
            self._load_compliance_data()
            # Explicitly skip ZAP data for SAST-only reports
            self.zap_data = []
            self.sca_data = []
        elif self.force_report_type == "sca_only":
            print("[TARGET] SCA-only report requested - loading only Trivy SCA data")
            self._load_sca_data()
            self._load_compliance_data()
            # Explicitly skip ZAP and SonarQube data for SCA-only reports
            self.zap_data = []
            self.sonar_data = []
            self.sonar_raw_data = []
        else:
            # Load all available data (comprehensive or auto-detect)
            self._load_zap_data()
            self._load_sonar_data()
            self._load_sca_data()
            self._load_compliance_data()
            
            # Clean and harmonize loaded data
            self._clean_vulnerability_data()
        
        logger.info(
            f"📊 Data loaded: {len(self.zap_data)} ZAP findings, "
            f"{len(self.sonar_data)} SonarQube findings, "
            f"{len(self.sca_data)} Trivy SCA findings"
        )
        
        # Print focused summary based on report type
        if self.force_report_type == "sca_only":
            print(f"[OK] Loaded SCA scan data: {len(self.sca_data)} vulnerabilities")
        elif self.force_report_type == "dast_only":
            print(f"[OK] Loaded DAST scan data: {len(self.zap_data)} vulnerabilities")
        elif self.force_report_type == "sast_only":
            print(f"[OK] Loaded SAST scan data: {len(self.sonar_data)} vulnerabilities")
        else:
            print(f"[OK] Data loaded: {len(self.zap_data)} ZAP findings, {len(self.sonar_data)} SonarQube findings, {len(self.sca_data)} Trivy SCA findings")
        
        if self.force_report_type:
            logger.info(f"🎯 Forced report type: {self.force_report_type}")
        
    def _load_zap_data(self):
        """Load ZAP scan results from various file formats, supporting multiple URLs."""
        # Try security_recommendations.json first (enhanced format)
        # Check if there's a session manifest for multi-URL scans
        
        session_manifest_path = self.input_dir / "dast_scan_session.json"
        main_file = self.input_dir / "security_recommendations.json"
        
        zap_json_files = []
        session_urls = []
        
        # Strategy 1: Use session manifest if available (for multi-URL scans)
        if session_manifest_path.exists():
            try:
                with open(session_manifest_path, 'r', encoding='utf-8') as f:
                    manifest = json.load(f)
                
                session_urls = manifest.get('successful_urls', [])
                session_timestamp = manifest.get('session_timestamp', '')
                logger.info(f"📋 Found session manifest with {len(session_urls)} URLs (session: {session_timestamp})")
                
                # Normalize session URLs (remove trailing slashes for comparison)
                normalized_session_urls = {url.rstrip('/'): url for url in session_urls}
                logger.info(f"🔍 Normalized session URLs: {list(normalized_session_urls.keys())}")
                
                # Get all JSON files sorted by modification time (newest first)
                all_json_files = sorted(
                    self.input_dir.glob("security_recommendations*.json"),
                    key=lambda p: p.stat().st_mtime,
                    reverse=True
                )
                
                logger.info(f"🔍 Found {len(all_json_files)} total security_recommendations*.json files")
                
                url_to_file = {}  # Map each URL to its most recent file
                
                # IMPROVED LOGIC: Check ALL files, not just until we find matches
                # This ensures we don't miss files due to ordering issues
                for json_file in all_json_files:
                    if json_file.name == "dast_scan_session.json":
                        continue
                    try:
                        with open(json_file, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                        target_url = data.get('target_url', '')
                        
                        # Try multiple normalization strategies
                        normalized_target = target_url.rstrip('/')
                        
                        # Also try without protocol for matching
                        normalized_target_no_protocol = normalized_target.replace('https://', '').replace('http://', '')
                        
                        logger.debug(f"🔍 Checking file {json_file.name}:")
                        logger.debug(f"   target='{target_url}'")
                        logger.debug(f"   normalized='{normalized_target}'")
                        logger.debug(f"   no_protocol='{normalized_target_no_protocol}'")
                        
                        # Check if this URL matches any session URL
                        matched = False
                        for session_url_normalized, session_url_original in normalized_session_urls.items():
                            session_url_no_protocol = session_url_normalized.replace('https://', '').replace('http://', '')
                            
                            # Try exact match first
                            if normalized_target == session_url_normalized:
                                matched = True
                                match_key = session_url_normalized
                            # Try without protocol
                            elif normalized_target_no_protocol == session_url_no_protocol:
                                matched = True
                                match_key = session_url_normalized
                            # Try with original URL
                            elif target_url.rstrip('/') == session_url_original.rstrip('/'):
                                matched = True
                                match_key = session_url_normalized
                            
                            if matched:
                                # Only add if we haven't found a file for this URL yet (keep most recent)
                                if match_key not in url_to_file:
                                    url_to_file[match_key] = json_file
                                    logger.info(f"✅ Matched {json_file.name} to URL: {match_key}")
                                else:
                                    logger.debug(f"⏭️  Skipping {json_file.name} - already have file for {match_key}")
                                break
                        
                        if not matched:
                            logger.debug(f"⏭️  File {json_file.name} doesn't match any session URL")
                            
                    except Exception as e:
                        logger.debug(f"⚠️  Error reading {json_file.name}: {e}")
                        pass
                
                zap_json_files = list(url_to_file.values())
                logger.info(f"🔍 Matched {len(zap_json_files)} files for {len(session_urls)} session URLs")
                
                # DIAGNOSTIC: Show which URLs were matched and which weren't
                if len(zap_json_files) < len(session_urls):
                    logger.warning(f"⚠️  Only found {len(zap_json_files)} files for {len(session_urls)} URLs!")
                    logger.warning(f"⚠️  Missing files for: {set(normalized_session_urls.keys()) - set(url_to_file.keys())}")
                    print(f"⚠️  WARNING: Only found scan results for {len(zap_json_files)} of {len(session_urls)} URLs")
                    print(f"💡 Missing results for: {', '.join(set(normalized_session_urls.keys()) - set(url_to_file.keys()))}")
                
            except Exception as e:
                logger.warning(f"⚠️  Could not load session manifest: {e}")
                session_manifest_path = None
        
        # Strategy 2: Fallback to main file only (single-URL scan or no manifest)
        if not zap_json_files and main_file.exists():
            zap_json_files = [main_file]
            logger.info(f"🔍 Using main security_recommendations.json file")
        
        # Remove duplicates while preserving order
        zap_json_files = list(dict.fromkeys(zap_json_files))
        
        logger.info(f"🔍 Searching for ZAP data in: {self.input_dir}")
        logger.info(f"🔍 Found {len(zap_json_files)} ZAP JSON files")
        
        target_urls = []
        files_loaded = 0
        zap_json_loaded = False
        
        for file_path in zap_json_files:
            if file_path.exists():
                try:
                    logger.info(f"📂 Trying to load: {file_path}")
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    
                    if 'vulnerabilities' in data:
                        # Extract target URL from this scan
                        scan_target_url = data.get('target_url', 'Not specified')
                        
                        # Add source URL to each vulnerability for tracking
                        for vuln in data['vulnerabilities']:
                            if 'source_url' not in vuln:
                                vuln['source_url'] = scan_target_url
                        
                        self.zap_data.extend(data['vulnerabilities'])
                        target_urls.append(scan_target_url)
                        files_loaded += 1
                        zap_json_loaded = True
                        
                        logger.info(f"📋 Loaded {len(data['vulnerabilities'])} ZAP findings from {file_path.name}")
                        logger.info(f"🎯 Target URL: {scan_target_url}")
                        print(f"[OK] Loaded DAST scan data: {len(data['vulnerabilities'])} vulnerabilities from {file_path.name} (URL: {scan_target_url})")
                        
                        # Don't break - continue loading from other files for multi-URL support
                except Exception as e:
                    logger.warning(f"⚠️  Could not load {file_path}: {e}")
        
        # Set target URL(s) - if multiple, join them
        # Deduplicate URLs to avoid showing the same URL multiple times
        if target_urls:
            logger.info(f"🔍 Raw target_urls before deduplication: {target_urls}")
            unique_urls = list(dict.fromkeys(target_urls))  # Preserve order while removing duplicates
            logger.info(f"🔍 Unique URLs after deduplication: {unique_urls}")
            
            # POST-PROCESSING FIX: Check if target URL is a reference/CDN URL and correct it
            reference_domains = [
                'firefox.settings.services.mozilla.com',
                'firefox-settings-attachments.cdn.mozilla.net',
                'checkmarx.com',
                'mozilla.net',
                'mozilla.org',
                'mozilla.com',
                'owasp.org',
                'cwe.mitre.org'
            ]
            
            # Check if the extracted URL is a reference URL
            corrected_urls = []
            for url in unique_urls:
                is_reference = any(domain in url.lower() for domain in reference_domains)
                
                if is_reference:
                    logger.warning(f"⚠️  Detected reference/CDN URL: {url}")
                    logger.info(f"🔧 Attempting to extract correct target URL from vulnerability instances...")
                    
                    # Extract actual target URL from vulnerability instances
                    from collections import Counter
                    from urllib.parse import urlparse
                    
                    instance_urls = []
                    for vuln in self.zap_data:
                        instances = vuln.get('instances', [])
                        for instance in instances:
                            inst_url = instance.get('URL', '')
                            if inst_url and inst_url.startswith('http'):
                                parsed = urlparse(inst_url)
                                base_url = f"{parsed.scheme}://{parsed.netloc}/"
                                
                                # Skip if this is also a reference URL
                                if not any(domain in base_url.lower() for domain in reference_domains):
                                    instance_urls.append(base_url)
                    
                    if instance_urls:
                        # Get the most common URL (the actual scan target)
                        url_counts = Counter(instance_urls)
                        corrected_url = url_counts.most_common(1)[0][0]
                        logger.info(f"✅ Corrected target URL from instances: {corrected_url}")
                        print(f"🔧 Corrected target URL: {url} → {corrected_url}")
                        corrected_urls.append(corrected_url)
                    else:
                        logger.warning(f"⚠️  Could not find valid target URL in instances, keeping: {url}")
                        corrected_urls.append(url)
                else:
                    corrected_urls.append(url)
            
            unique_urls = corrected_urls
            
            if len(unique_urls) == 1:
                self.target_url = unique_urls[0]
            else:
                self.target_url = f"Multiple URLs ({len(unique_urls)}): " + ", ".join(unique_urls[:3])
                if len(unique_urls) > 3:
                    self.target_url += f" and {len(unique_urls) - 3} more"
            logger.info(f"📊 Loaded {files_loaded} ZAP scan file(s) with {len(self.zap_data)} total vulnerabilities from {len(unique_urls)} unique URL(s)")
            print(f"[STATS] Total DAST vulnerabilities from {files_loaded} scan(s): {len(self.zap_data)}")
            print(f"[TARGET] Final Target URL: {self.target_url}")
        
        # Also try CSV summaries
        # Search recursively in subdirectories (scans create subdirectories)
        csv_files = list(self.input_dir.glob("**/security_recommendations_summary_*.csv"))
        logger.info(f"🔍 Found {len(csv_files)} potential CSV files")
        
        if csv_files and not zap_json_loaded and not self.zap_data:
            latest_csv = max(csv_files, key=os.path.getmtime)
            try:
                logger.info(f"📂 Trying to load CSV: {latest_csv}")
                with open(latest_csv, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    self.zap_data = list(reader)
                logger.info(f"📋 Loaded {len(self.zap_data)} ZAP findings from {latest_csv.name}")
                print(f"[OK] Loaded DAST scan data: {len(self.zap_data)} vulnerabilities from {latest_csv.name}")
            except Exception as e:
                logger.warning(f"⚠️  Could not load {latest_csv}: {e}")
        
        if not self.zap_data:
            logger.warning(f"⚠️  No ZAP data found in {self.input_dir}")
            logger.warning(f"⚠️  Searched for: security_recommendations.json and security_recommendations_summary_*.csv")
            print(f"[WARN] No DAST scan data found in {self.input_dir}")
            print(f"[TIP] Make sure DAST scan completed successfully and generated output files")
    
    def _load_sonar_data(self):
        """Load SonarQube scan results - both raw and filtered data."""
        
        # 1. Load RAW data for original vulnerability counts
        # Try JSON first (preserves complex data structures), then CSV
        raw_json_patterns = [
            "sonarqube_complete_*.json",  # Complete/raw JSON data files
            "sonarqube_hotspots_*.json",  # Hotspot JSON files
            "complete_enhanced_vulnerabilities_*.json" # New: SAST enhanced data files
        ]
        
        all_raw_json_files = []
        for pattern in raw_json_patterns:
            # Search recursively in subdirectories (scans create subdirectories)
            all_raw_json_files.extend(list(self.input_dir.glob(f"**/{pattern}")))
        
        raw_json_loaded = False
        if all_raw_json_files:
            # Group files by project to avoid loading duplicate history
            import re
            project_files = {}
            for json_file in all_raw_json_files:
                # Extract project name, ignoring prefixes and the _YYYYMMDD_HHMMSS timestamp
                # e.g., sonarqube_complete_caze-core_20260226_154005.json -> caze-core
                basename = json_file.stem
                
                # Remove common prefixes
                clean_name = re.sub(r'^(?:sonarqube_complete_|sonarqube_hotspots_|complete_enhanced_vulnerabilities_|filtered_vulnerabilities_|sonarqube_filtered_|hotspots_with_code_)', '', basename)
                
                # Remove timestamp suffix
                match = re.match(r'(.+)_\d{8}_\d{6}$', clean_name)
                project_name = match.group(1) if match else clean_name
                
                if project_name not in project_files:
                    project_files[project_name] = []
                project_files[project_name].append(json_file)
                
            if len(project_files) > 1:
                # Strict isolation: Only process the single project that was most recently scanned
                latest_proj = max(project_files.keys(), key=lambda p: max(os.path.getmtime(f) for f in project_files[p]))
                project_files = {latest_proj: project_files[latest_proj]}
                
            # For each project, only load the most recent file
            for project_name, files in project_files.items():
                # Prefer 'complete' over 'hotspots' over others if they exist for the same project
                def sort_key(f):
                    score = 0
                    if 'complete_enhanced_vulnerabilities' in f.name: score = 3
                    elif 'sonarqube_complete' in f.name: score = 2
                    elif 'hotspots' in f.name: score = 1
                    return (score, os.path.getmtime(f))
                latest_file = max(files, key=sort_key)
                
                try:
                    with open(latest_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        
                    if isinstance(data, list):
                        self.sonar_raw_data.extend(data)
                        raw_json_loaded = True
                        logger.info(f"📋 Appended {len(data)} RAW findings from {latest_file.name}")
                    else:
                        logger.warning(f"⚠️ Unexpected data format in {latest_file.name}")
                except Exception as e:
                    logger.warning(f"⚠️ Could not load raw JSON data {latest_file}: {e}")
        
        # Fallback to CSV if JSON not found
        if not raw_json_loaded and not self.sonar_raw_data:
            raw_csv_patterns = [
                "sonarqube_complete_*.csv",  # Complete/raw data files
                "sonarqube_hotspots_*.csv",  # Hotspot files  
                "sonarqube_*.csv",           # Generic sonarqube files
                "complete_enhanced_vulnerabilities_*.csv", # New: SAST enhanced data files
                "hotspots_with_code_*.csv"   # Used as fallback raw data
            ]
            
            all_raw_csv_files = []
            for pattern in raw_csv_patterns:
                all_raw_csv_files.extend(list(self.input_dir.glob(f"**/{pattern}")))
                
            if all_raw_csv_files and not self.sonar_raw_data:
                # Group files by project to avoid loading duplicate history
                import re
                project_files = {}
                for csv_file in all_raw_csv_files:
                    basename = csv_file.stem
                    
                    # Remove common prefixes
                    clean_name = re.sub(r'^(?:sonarqube_complete_|sonarqube_hotspots_|complete_enhanced_vulnerabilities_|filtered_vulnerabilities_|sonarqube_filtered_|hotspots_with_code_)', '', basename)
                    
                    # Remove timestamp suffix
                    match = re.match(r'(.+)_\d{8}_\d{6}$', clean_name)
                    project_name = match.group(1) if match else clean_name
                    
                    if project_name not in project_files:
                        project_files[project_name] = []
                    project_files[project_name].append(csv_file)
                    
                if len(project_files) > 1:
                    # Strict isolation: Only process the single project that was most recently scanned
                    latest_proj = max(project_files.keys(), key=lambda p: max(os.path.getmtime(f) for f in project_files[p]))
                    project_files = {latest_proj: project_files[latest_proj]}
                    
                # For each project, pick the best file:
                # Priority: complete_enhanced > sonarqube_complete > hotspots > others
                # This prevents filtered_vulnerabilities files from being selected as raw data.
                def csv_sort_key(f):
                    score = 0
                    if 'complete_enhanced_vulnerabilities' in f.name: score = 4
                    elif 'sonarqube_complete' in f.name: score = 3
                    elif 'hotspots_with_code' in f.name: score = 2
                    elif 'sonarqube_hotspots' in f.name: score = 2
                    elif 'sonarqube_' in f.name: score = 1
                    # filtered_vulnerabilities gets score 0 — lowest priority as raw source
                    return (score, os.path.getmtime(f))
                best_file = max(files, key=csv_sort_key)
                try:
                    with open(best_file, 'r', encoding='utf-8') as f:
                        reader = csv.DictReader(f)
                        data = list(reader)
                        self.sonar_raw_data.extend(data)
                    logger.info(f"📋 Appended {len(data)} RAW findings from {best_file.name}")
                except Exception as e:
                    logger.warning(f"⚠️ Could not load raw data {best_file}: {e}")
        
        # 2. Load FILTERED data for top vulnerabilities display
        # Try JSON first (preserves framework_justification and other complex fields), then CSV
        filtered_json_patterns = [
            "sonarqube_filtered_*.json",     # Filtered JSON data files
            "filtered_vulnerabilities_*.json" # Legacy/Batch filtered JSON files
        ]
        
        all_filtered_json_files = []
        for pattern in filtered_json_patterns:
            # Search recursively in subdirectories (scans create subdirectories)
            all_filtered_json_files.extend(list(self.input_dir.glob(f"**/{pattern}")))
        
        filtered_data_loaded = False
        if all_filtered_json_files:
            # Group files by project to avoid loading duplicate history
            import re
            project_files = {}
            for json_file in all_filtered_json_files:
                basename = json_file.stem
                
                # Remove common prefixes
                clean_name = re.sub(r'^(?:sonarqube_complete_|sonarqube_hotspots_|complete_enhanced_vulnerabilities_|filtered_vulnerabilities_|sonarqube_filtered_|hotspots_with_code_)', '', basename)
                
                # Remove timestamp suffix
                match = re.match(r'(.+)_\d{8}_\d{6}$', clean_name)
                project_name = match.group(1) if match else clean_name
                
                if project_name not in project_files:
                    project_files[project_name] = []
                project_files[project_name].append(json_file)
                
            if len(project_files) > 1:
                # Strict isolation: Only process the single project that was most recently scanned
                latest_proj = max(project_files.keys(), key=lambda p: max(os.path.getmtime(f) for f in project_files[p]))
                project_files = {latest_proj: project_files[latest_proj]}
                
            # For each project, only load the most recent file
            for project_name, files in project_files.items():
                latest_file = max(files, key=os.path.getmtime)
                try:
                    with open(latest_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            self.sonar_data.extend(data)
                            filtered_data_loaded = True
                            logger.info(f"📋 Appended {len(data)} FILTERED findings from {latest_file.name}")
                except Exception as e:
                    logger.warning(f"⚠️ Could not load filtered JSON data {latest_file}: {e}")
        
        # Fallback to CSV if JSON not found
        if not filtered_data_loaded and not self.sonar_data:
            filtered_csv_patterns = [
                "sonarqube_filtered_*.csv",     # Filtered data files
                "filtered_vulnerabilities_*.csv" # Legacy filtered files
            ]
            
            all_filtered_csv_files = []
            for pattern in filtered_csv_patterns:
                all_filtered_csv_files.extend(list(self.input_dir.glob(f"**/{pattern}")))
                
            if all_filtered_csv_files and not self.sonar_data:
                # Group files by project to avoid loading duplicate history
                import re
                project_files = {}
                for csv_file in all_filtered_csv_files:
                    basename = csv_file.stem
                    
                    # Remove common prefixes
                    clean_name = re.sub(r'^(?:sonarqube_complete_|sonarqube_hotspots_|complete_enhanced_vulnerabilities_|filtered_vulnerabilities_|sonarqube_filtered_|hotspots_with_code_)', '', basename)
                    
                    # Remove timestamp suffix
                    match = re.match(r'(.+)_\d{8}_\d{6}$', clean_name)
                    project_name = match.group(1) if match else clean_name
                    
                    if project_name not in project_files:
                        project_files[project_name] = []
                    project_files[project_name].append(csv_file)
                    
                if len(project_files) > 1:
                    # Strict isolation: Only process the single project that was most recently scanned
                    latest_proj = max(project_files.keys(), key=lambda p: max(os.path.getmtime(f) for f in project_files[p]))
                    project_files = {latest_proj: project_files[latest_proj]}
                    
                # For each project, only load the most recent file
                for project_name, files in project_files.items():
                    latest_file = max(files, key=os.path.getmtime)
                    try:
                        with open(latest_file, 'r', encoding='utf-8') as f:
                            reader = csv.DictReader(f)
                            data = list(reader)
                            self.sonar_data.extend(data)
                            filtered_data_loaded = True
                        logger.info(f"📋 Appended {len(data)} FILTERED findings from {latest_file.name}")
                    except Exception as e:
                        logger.warning(f"⚠️ Could not load filtered data {latest_file}: {e}")
        
        # Fallback: if no filtered data, use raw data for both
        if not filtered_data_loaded and not self.sonar_data and self.sonar_raw_data:
            self.sonar_data = self.sonar_raw_data.copy()
            logger.info("📋 Using raw data for both original counts and top vulnerabilities")

    def _load_sca_data(self):
        """Load Trivy SCA prioritized results produced by the CLI (`sca_trivy_prioritized_*.json`)."""
        sca_patterns = [
            "sca_trivy_prioritized_*.json",
            "sca_trivy_prioritized_*.JSON",
            "sca_trivy_prioritized_*.json",  # keep legacy-compatible
            "sca_trivy_prioritized_*.json",
        ]

        sca_files = []
        for pattern in sca_patterns:
            sca_files.extend(list(self.input_dir.glob(f"**/{pattern}")))

        # Also accept the older naming used by earlier versions if present
        sca_files.extend(list(self.input_dir.glob("**/sca_trivy_prioritized_*.json")))

        if not sca_files:
            # Accept generic SCA output naming, if user renamed it
            sca_files.extend(list(self.input_dir.glob("**/*sca*trivy*prioritized*.json")))

        if not sca_files:
            logger.info(f"ℹ️  No SCA (Trivy) data found in {self.input_dir}")
            return

        latest_file = max(sca_files, key=os.path.getmtime)
        try:
            with open(latest_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            vulns = data.get("vulnerabilities", [])
            meta = data.get("scan_metadata", {})
            artifact = meta.get("artifact") or meta.get("scan_type") or "Trivy SCA"
            
            # Store the original total count from metadata
            self.sca_original_count = meta.get("total_vulnerabilities", len(vulns))

            mapped: List[Dict[str, Any]] = []
            for v in vulns:
                # Normalize into a shape compatible with existing posture report functions
                name = v.get("title") or v.get("source_id") or v.get("id") or "Unknown"
                pkg = v.get("package_name") or ""
                src_id = v.get("source_id") or ""
                if pkg and src_id:
                    name = f"{pkg}: {src_id}"

                risk_level = v.get("risk_level") or v.get("severity") or "Low"
                original = v.get("severity") or risk_level
                score = v.get("risk_score") or 0

                mapped.append(
                    {
                        "name": name,
                        "type": "SCA",
                        "risk": original,
                        "original_risk_level": original,
                        "enhanced_risk_level": risk_level,
                        "enhanced_score": score,
                        "score": score,
                        "enhanced_category": v.get("category", "Dependency Vulnerability"),
                        "category": v.get("category", "Dependency Vulnerability"),
                        "package_name": v.get("package_name"),
                        "installed_version": v.get("installed_version"),
                        "fixed_version": v.get("fixed_version"),
                        "description": v.get("description") or "",
                        "artifact": v.get("artifact") or artifact,
                        "primary_url": v.get("primary_url"),
                        "references": v.get("references", []),
                        "framework_justification": "",
                        "enhanced_justifications": v.get("enhanced_justifications")
                        or v.get("enhanced_justifications".lower(), [])
                        or v.get("enhanced_justifications", []),
                        "ai_justification": v.get("ai_justification"),
                        "raw_data": v.get("raw_data", {}),
                    }
                )

            self.sca_data = mapped
            logger.info(f"📦 Loaded {len(self.sca_data)} Trivy SCA findings from {latest_file.name}")
            print(f"[OK] Loaded SCA scan data: {len(self.sca_data)} vulnerabilities from {latest_file.name}")

        except Exception as e:
            logger.warning(f"⚠️  Could not load SCA data {latest_file}: {e}")
    
    def _deep_merge_dict(self, default_dict: Dict, override_dict: Dict) -> Dict:
        """Deep merge two dictionaries, overriding the first with the second."""
        result = default_dict.copy()
        for k, v in override_dict.items():
            if k in result and isinstance(result[k], dict) and isinstance(v, dict):
                result[k] = self._deep_merge_dict(result[k], v)
            else:
                result[k] = v
        return result

    def _load_compliance_data(self):
        """Load compliance and environment configuration."""
        compliance_path_str = get_resource_path("appsecai/risk_profiles/context_modifiers/risk_context_template.json")
        compliance_file = Path(compliance_path_str)
        print(f"[DEBUG] Looking for risk_context_template.json at: {compliance_file.absolute()}")
        if compliance_file.exists():
            print(f"[DEBUG] Found risk_context_template.json!")
            try:
                with open(compliance_file, 'r', encoding='utf-8') as f:
                    self.compliance_data = json.load(f)
                print(f"[DEBUG] Loaded compliance data. Keys: {list(self.compliance_data.keys())}")
            except Exception as e:
                print(f"[DEBUG] Error loading compliance data: {e}")
        else:
            print(f"[DEBUG] ERROR: risk_context_template.json not found at {compliance_file.absolute()}")
                
        # Support dynamic overrides from appsec_config.json if it exists
        if getattr(sys, 'frozen', False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.getcwd()
            
        appsec_json_path = os.path.join(base_dir, "appsec_config.json")
        print(f"[DEBUG] Looking for appsec_config.json at: {appsec_json_path}")
        if os.path.exists(appsec_json_path):
            print(f"[DEBUG] Found appsec_config.json!")
            try:
                custom_config = load_appsec_json_data(appsec_json_path)
                
                if "vulnerability_threshold" in custom_config:
                    os.environ['VULNERABILITY_THRESHOLD'] = str(custom_config["vulnerability_threshold"])
                    
                if "AppSecAI" in custom_config:
                    print("[DEBUG] AppSecAI key found in appsec_config.json!")
                    if "AppSecAI" in self.compliance_data:
                        print("[DEBUG] Merging custom config into compliance_data!")
                        self.compliance_data["AppSecAI"] = self._deep_merge_dict(
                            self.compliance_data["AppSecAI"],
                            custom_config["AppSecAI"]
                        )
                    else:
                        print("[DEBUG] ERROR: AppSecAI key NOT found in self.compliance_data! Cannot merge.")
                        self.compliance_data["AppSecAI"] = custom_config["AppSecAI"]
            except Exception as e:
                print(f"[DEBUG] Error loading or merging appsec_config.json: {e}")
        
        # Also load framework data for risk thresholds
        framework_file = Path(get_resource_path("appsecai/risk_profiles/context_modifiers/vulnerability_framework.json"))
        # Default to the new multiplicative scale in case file loading fails
        self.risk_thresholds = {"critical": 8.5, "high": 7.5, "medium": 5.0, "low": 2.5, "informational": 1.0}
        if framework_file.exists():
            try:
                with open(framework_file, 'r', encoding='utf-8') as f:
                    framework_data = json.load(f)
                    methodology = framework_data.get('vulnerability_scoring_framework', {}).get('scoring_methodology', {})
                    if 'risk_thresholds' in methodology:
                        self.risk_thresholds = methodology['risk_thresholds']
                        logger.info(f"📋 Loaded risk thresholds: {self.risk_thresholds}")
            except Exception as e:
                logger.warning(f"⚠️  Could not load framework thresholds: {e}")


    def _clean_vulnerability_data(self):
        """Clean and harmonize all loaded vulnerability data."""
        # Clean ZAP data
        for vuln in self.zap_data:
            # Clean framework justification
            just = vuln.get('framework_justification', '')
            if just and 'separation model' in just.lower():
                vuln['framework_justification'] = ""
            
            # Ensure enhanced_justifications is a list
            if isinstance(vuln.get('enhanced_justifications'), str):
                try:
                    # Try to parse if it's a string representation of a list
                    vuln['enhanced_justifications'] = eval(vuln['enhanced_justifications'])
                except:
                    vuln['enhanced_justifications'] = [vuln['enhanced_justifications']]
            
            # Clean multipliers from justifications
            if vuln.get('enhanced_justifications'):
                vuln['enhanced_justifications'] = [self._clean_justification_text(j) for j in vuln['enhanced_justifications'] if j]

        # Clean SonarQube data
        for vuln in self.sonar_data:
            just = vuln.get('framework_justification', '')
            if just and 'separation model' in just.lower():
                vuln['framework_justification'] = ""
            
            # Ensure enhanced_justifications is a list
            if isinstance(vuln.get('enhanced_justifications'), str):
                try:
                    vuln['enhanced_justifications'] = eval(vuln['enhanced_justifications'])
                except:
                    vuln['enhanced_justifications'] = [vuln['enhanced_justifications']]

            if vuln.get('enhanced_justifications'):
                vuln['enhanced_justifications'] = [self._clean_justification_text(j) for j in vuln['enhanced_justifications'] if j]

        # Clean SCA data
        for vuln in self.sca_data:
            # Ensure enhanced_justifications is a list
            if isinstance(vuln.get('enhanced_justifications'), str):
                try:
                    vuln['enhanced_justifications'] = eval(vuln['enhanced_justifications'])
                except Exception:
                    vuln['enhanced_justifications'] = [vuln['enhanced_justifications']]

            if vuln.get('enhanced_justifications'):
                vuln['enhanced_justifications'] = [
                    self._clean_justification_text(j) for j in vuln['enhanced_justifications'] if j
                ]
    
    def _determine_report_focus(self) -> str:
        """Determine report focus based on available data and configuration."""
        # Check if forced
        if self.force_report_type:
            if self.force_report_type == 'auto':
                pass # Continue to auto-detection
            elif self.force_report_type == 'sast_only':
                return 'sast_focused'
            elif self.force_report_type == 'dast_only':
                return 'dast_focused'
            elif self.force_report_type == 'sca_only':
                return 'sca_focused'
            else:
                return self.force_report_type
        
        # Auto-detection logic
        has_zap = len(self.zap_data) > 0
        has_sonar = len(self.sonar_data) > 0 or len(self.sonar_raw_data) > 0
        has_sca = len(self.sca_data) > 0
        
        if has_zap and has_sonar:
            return 'unified'
        elif has_sca and not has_zap and not has_sonar:
            return 'sca_focused'
        elif has_zap:
            return 'dast_focused'
        elif has_sonar:
            return 'sast_focused'
        else:
            return 'comprehensive' # Default if no data found

    def analyze_security_posture(self):
        """Analyze the overall security posture based on collected data."""
        print("[*] Analyzing security posture...")
        
        # Get product information
        app_config = self.compliance_data.get('AppSecAI', {})
        product_name = app_config.get('product', 'Unknown Product')
        version = app_config.get('version', '1.0.0')
        # Use target_url from ZAP data (extracted from HTML report)
        target_url = self.target_url
        environment = app_config.get('environment', {})
        
        # Determine report focus based on available data
        report_focus = self._determine_report_focus()
        logger.info(f"📊 Report focus determined: {report_focus} (force_type: {self.force_report_type})")
        
        # Get artifact from SCA data if available
        artifact = "Not specified"
        if self.sca_data and len(self.sca_data) > 0:
            artifact = self.sca_data[0].get('artifact', 'Not specified')
        
        # Analyze vulnerability distribution
        original_severity_counts = self._analyze_original_severity_distribution()  # For Vulnerability Assessment
        severity_counts = self._analyze_severity_distribution()  # For Top Vulnerabilities
        
        # Calculate risk scores
        risk_assessment = self._calculate_risk_assessment(severity_counts)
        
        # Analyze security controls
        controls_analysis = self._analyze_security_controls()
        
        # Generate recommendations
        recommendations = self._generate_recommendations()
        
        # Analyze scan correlation
        scan_correlation = self._analyze_scan_correlation()
        
        # Build comprehensive report data
        self.report_data = {
            'metadata': {
                'product_name': product_name,
                'version': version,
                'target_url': target_url,
                'repository': self._get_repositories_display(),
                'branch': os.environ.get('GITHUB_BASE_BRANCH', 'main'),
                'report_date': datetime.now().isoformat(),
                'report_focus': report_focus,
                'artifact': artifact,
                'scan_summary': {
                    'zap_findings': len(self.zap_data),
                    'sonar_findings': len(self.sonar_data),
                    'sca_findings': len(self.sca_data),
                    'total_findings': len(self.zap_data) + len(self.sonar_data) + len(self.sca_data),
                    'scan_correlation': scan_correlation
                }
            },
            'executive_summary': {
                'overall_risk_level': risk_assessment['overall_risk'],
                'risk_score': risk_assessment['risk_score'],
                'key_concerns': risk_assessment['key_concerns'],
                'security_posture': self._assess_security_posture(controls_analysis, severity_counts)
            },
            'vulnerability_analysis': {
                'severity_distribution': original_severity_counts,  # Original counts before prioritization
                'by_category': self._analyze_by_category(),
                'top_vulnerabilities': self._get_top_vulnerabilities(),  # Uses prioritized data
                'below_threshold_vulnerabilities': self._get_below_threshold_vulnerabilities(), # V4: New table
                'trend_analysis': self._analyze_trends()
            },
            'security_controls': controls_analysis,
            'risk_assessment': risk_assessment,
            'recommendations': recommendations,
            'detailed_findings': {
                'zap_findings': self.zap_data[:20],  # Top 20 for report
                'sonar_findings': self.sonar_data[:20],
                'sca_findings': self.sca_data[:20]
            },
            'appendix': {
                'methodology': self._get_methodology(),
                'risk_matrix': self._get_risk_matrix(),
                'compliance_framework': environment
            }
        }
    
    def _analyze_original_severity_distribution(self) -> Dict[str, int]:
        """Analyze ORIGINAL vulnerability severity distribution (before prioritization)."""
        counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
        
        # Analyze ZAP findings - use ORIGINAL risk levels (before enhancement)
        for finding in self.zap_data:
            # Use original_risk field for true original ZAP risk, fallback to risk field
            risk = finding.get('original_risk', finding.get('risk', finding.get('Risk', 'Low')))
            risk = str(risk).title()
            if risk in counts:
                counts[risk] += 1
            else:
                counts['Informational'] += 1
        
        # Analyze SonarQube findings - use RAW data for ORIGINAL severity counts
        if self.force_report_type != "dast_only":
            # Use raw data if available, otherwise fall back to filtered data
            sonar_data_for_counts = self.sonar_raw_data if self.sonar_raw_data else self.sonar_data
            for finding in sonar_data_for_counts:
                severity = finding.get('vulnerabilityProbability', 'LOW').upper()  # Original severity only
                severity_mapping = {
                    'HIGH': 'High',
                    'MEDIUM': 'Medium', 
                    'LOW': 'Low'
                }
                mapped_severity = severity_mapping.get(severity, 'Low')
                counts[mapped_severity] += 1

        # Analyze Trivy SCA findings - use ORIGINAL Trivy severity
        if self.force_report_type not in ["dast_only", "sast_only"]:
            for finding in self.sca_data:
                sev = finding.get('original_risk_level', finding.get('risk', 'Low'))
                sev = str(sev).title()
                if sev in counts:
                    counts[sev] += 1
                else:
                    counts['Informational'] += 1
        
        return counts

    def _analyze_severity_distribution(self) -> Dict[str, int]:
        """Analyze PRIORITIZED vulnerability severity distribution (after scoring) with threshold upgrading."""
        counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
        
        # Get threshold score for upgrading
        threshold_score = self._get_threshold_score()
        
        # Analyze ZAP findings (always include if available)
        for finding in self.zap_data:
            # Get original risk level and score
            original_risk = finding.get('enhanced_risk_level', finding.get('risk', finding.get('Risk', 'Low')))
            score = finding.get('enhanced_score', finding.get('score', 0))
            
            # Apply threshold-based upgrading for report display
            display_risk = self._upgrade_risk_for_report(original_risk, score, threshold_score)
            display_risk = str(display_risk).title()
            
            if display_risk in counts:
                counts[display_risk] += 1
            else:
                counts['Informational'] += 1
        
        # Analyze SonarQube findings (only if not DAST-only report)
        if self.force_report_type != "dast_only":
            for finding in self.sonar_data:
                # Get original risk level and score
                original_severity = finding.get('vulnerabilityProbability', finding.get('enhanced_risk_level', 'LOW')).upper()
                score = finding.get('enhanced_score', finding.get('vulnerability_score', 0))
                
                # Map SonarQube severity to risk level
                severity_mapping = {
                    'BLOCKER': 'Critical',
                    'HIGH': 'High',
                    'MEDIUM': 'Medium',
                    'LOW': 'Low'
                }
                original_risk = severity_mapping.get(original_severity, 'Low')
                
                # Apply threshold-based upgrading for report display
                display_risk = self._upgrade_risk_for_report(original_risk, score, threshold_score)
                
                if display_risk in counts:
                    counts[display_risk] += 1
                else:
                    counts['Informational'] += 1

        # Analyze SCA findings (only if included)
        if self.force_report_type not in ["dast_only", "sast_only"]:
            for finding in self.sca_data:
                original_risk = finding.get('enhanced_risk_level', finding.get('risk', 'Low'))
                score = finding.get('enhanced_score', finding.get('score', 0))

                # FIX: Do not artificially upgrade SCA risk levels based on numeric thresholds.
                # The EnhancedVulnerabilityScorer already strictly capped the sca_data risk level.
                # We must blindly trust `enhanced_risk_level`.
                display_risk = original_risk
                display_risk = str(display_risk).title()

                if display_risk in counts:
                    counts[display_risk] += 1
                else:
                    counts['Informational'] += 1
        return counts
    
 
    def _calculate_risk_assessment(self, severity_counts: Dict[str, int]) -> Dict[str, Any]:
        """Calculate overall risk assessment."""
        # Calculate weighted risk score
        weights = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 2, 'Informational': 1}
        total_score = sum(counts * weights[severity] for severity, counts in severity_counts.items())
        total_findings = sum(severity_counts.values())
        
        if total_findings == 0:
            risk_score = 0
            overall_risk = 'Low'
        else:
            risk_score = total_score / total_findings
            if risk_score >= 8:
                overall_risk = 'Critical'
            elif risk_score >= 6:
                overall_risk = 'High'
            elif risk_score >= 4:
                overall_risk = 'Medium'
            else:
                overall_risk = 'Low'
        
        # Identify key concerns
        key_concerns = []
        if severity_counts['Critical'] > 0:
            key_concerns.append(f"Found {severity_counts['Critical']}  vulnerabilities require immediate attention")
        if severity_counts['High'] > 5:
            key_concerns.append(f"{severity_counts['High']} high-severity vulnerabilities present significant risk")
        if total_findings > 50:
            key_concerns.append(f"High volume of findings ({total_findings}) indicates systemic security issues")
        
        return {
            'risk_score': round(risk_score, 2),
            'overall_risk': overall_risk,
            'key_concerns': key_concerns,
            'total_findings': total_findings
        }
    
    def _analyze_security_controls(self) -> Dict[str, Any]:
        """Analyze implemented security controls."""
        app_config = self.compliance_data.get('AppSecAI', {})
        controls = app_config.get('security_controls', {})
        environment = app_config.get('environment', {})
        
        # Count implemented controls
        implemented = sum(1 for v in controls.values() if v is True)
        total_controls = len(controls)
        
        # Get ALL missing controls (not just hardcoded critical ones)
        missing_controls = [
            control for control, value in controls.items() 
            if value is False
        ]
        
        # Environment risk factors
        risk_factors = []
        if environment.get('internet_exposure') == 'public':
            risk_factors.append('Public internet exposure increases attack surface')
        if not environment.get('https_enabled', True):
            risk_factors.append('HTTPS not enabled - data in transit at risk')
        if environment.get('pii_present', False):
            risk_factors.append('PII present - requires enhanced protection')
        
        return {
            'implementation_rate': round((implemented / total_controls * 100), 1) if total_controls > 0 else 0,
            'implemented_controls': implemented,
            'total_controls': total_controls,
            'missing_critical_controls': missing_controls,
            'environment_risk_factors': risk_factors,
            'environment': environment,
            'runtime': app_config.get('runtime', {}),
            'service': app_config.get('service', {}),
            'security_controls': controls,
            'sca_context': app_config.get('sca_context', {})
        }
    
    def _assess_security_posture(self, controls_analysis: Dict, severity_counts: Dict) -> str:
        """Generate professional executive summary using template-based approach."""
        # For SCA-only reports we do NOT require or use LLM; always use template.
        if self._determine_report_focus() == 'sca_focused':
            return self._generate_template_summary(controls_analysis, severity_counts)
        try:
            return self._generate_llm_executive_summary(controls_analysis, severity_counts)
        except Exception as e:
            logger.error(f"LLM executive summary failed: {e}")
            # Fallback to template-based summary
            return self._generate_template_summary(controls_analysis, severity_counts)
    
    def _generate_llm_executive_summary(self, controls_analysis: Dict, severity_counts: Dict) -> str:
        """Generate executive summary using template-based approach with LLM enhancement."""
        import requests
        import json
        import os
        import re
        
        # Get product information
        app_config = self.compliance_data.get('AppSecAI', {})
        product_name = app_config.get('product', 'The Application')
        
        # Build tools list dynamically
        tools_used = []
        if self.zap_data:
            tools_used.append("ZAP (DAST)")
        if self.sonar_data:
            tools_used.append("SonarQube (SAST)")
        if self.sca_data:
            tools_used.append("Trivy (SCA)")
        
        tools_string = " and ".join(tools_used) if len(tools_used) > 1 else (tools_used[0] if tools_used else "security scanning tools")
        
        # Calculate final risk rating based on adjusted vulnerabilities
        critical_count = severity_counts.get('Critical', 0)
        high_count = severity_counts.get('High', 0)
        total_vulns = sum(severity_counts.values())
        implementation_rate = controls_analysis.get('implementation_rate', 0)
        deployment_type = controls_analysis.get('deployment_type', 'unknown')
        internet_exposure = controls_analysis.get('internet_exposure', 'unknown')
        
        # Determine final risk rating
        if critical_count > 5 or high_count > 15:
            final_risk = "High"
        elif critical_count > 0 or high_count > 10:
            final_risk = "Moderate-High"
        elif high_count > 0 or total_vulns > 20:
            final_risk = "Moderate"
        elif total_vulns > 5:
            final_risk = "Low-Moderate"
        else:
            final_risk = "Low"
        
        # Build template-based summary
        template = f"""The {product_name} underwent a detailed vulnerability assessment to evaluate its security posture across code, dependencies, and deployment configurations. Based on {tools_string} analyses, and subsequent contextualization with real deployment data ({deployment_type} deployment, {internet_exposure} exposure, {implementation_rate}% security controls implemented), the overall residual risk rating is now {final_risk}."""
        
        # Try to enhance with LLM, but use template as fallback
        try:
            # Create structured prompt for LLM
            prompt = f"""Write an executive summary following this EXACT structure and style:

"The [Product Name] underwent a detailed vulnerability assessment to evaluate its security posture across code, dependencies, and deployment configurations. Based on [Tools] analyses, and subsequent contextualization with real deployment data ([deployment context]), the overall residual risk rating is now [Risk Level]."

Data:
- Product: {product_name}
- Tools: {tools_string}
- Total vulnerabilities: {total_vulns} ({critical_count} critical, {high_count} high)
- Deployment: {deployment_type} deployment, {internet_exposure} exposure
- Security controls: {implementation_rate}% implemented
- Calculated risk: {final_risk}

Write ONLY the summary paragraph following the template structure above. Start with the product name. End with the risk rating. Use professional, executive-level language. 60-100 words. No meta-commentary."""

            # Get LLM configuration
            llm_url = os.environ.get('LLM_URL', 'http://4.247.140.236:11434')
            llm_model = os.environ.get('LLM_MODEL', 'qwen2.5-coder:7b-instruct')
            
            # Call LLM
            payload = {
                "model": llm_model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "num_predict": 250,
                    "temperature": 0.5,  # Lower temperature for more consistent output
                    "top_p": 0.85
                }
            }
            
            response = requests.post(f"{llm_url}/api/generate", json=payload, timeout=60)
            response.raise_for_status()
            
            result = response.json()
            summary = result.get('response', '').strip()
            
            # Clean up the response
            summary = summary.replace('**Executive Summary:**', '').replace('Executive Summary:', '').strip()
            summary = re.sub(r'^Here is.*?:', '', summary, flags=re.IGNORECASE).strip()
            summary = re.sub(r'^Based on.*?:', '', summary, flags=re.IGNORECASE).strip()
            summary = re.sub(r'^\*\*.*?\*\*:?\s*', '', summary).strip()
            summary = re.sub(r'^\"', '', summary).strip()
            summary = re.sub(r'\"$', '', summary).strip()
            summary = re.sub(r'\s+', ' ', summary)
            summary = summary.strip()
            
            # Validate that summary follows expected format
            if summary and summary.startswith(product_name) and final_risk in summary:
                # LLM produced good output
                words = summary.split()
                if 50 <= len(words) <= 120:
                    return summary
            
            # LLM output doesn't match format, use template
            logger.warning("LLM summary didn't match expected format, using template")
            return template
            
        except Exception as e:
            logger.warning(f"LLM enhancement failed: {e}, using template")
            return template
    
    def _generate_template_summary(self, controls_analysis: Dict, severity_counts: Dict) -> str:
        """Generate executive summary using pure template (fallback when LLM fails)."""
        # Get product information
        app_config = self.compliance_data.get('AppSecAI', {})
        product_name = app_config.get('product', 'The Application')
        
        # Build tools list dynamically
        tools_used = []
        if self.zap_data:
            tools_used.append("ZAP (DAST)")
        if self.sonar_data:
            tools_used.append("SonarQube (SAST)")
        if self.sca_data:
            tools_used.append("Trivy (SCA)")
        
        tools_string = " and ".join(tools_used) if len(tools_used) > 1 else (tools_used[0] if tools_used else "security scanning tools")
        
        # Calculate final risk rating
        critical_count = severity_counts.get('Critical', 0)
        high_count = severity_counts.get('High', 0)
        total_vulns = sum(severity_counts.values())
        implementation_rate = controls_analysis.get('implementation_rate', 0)
        deployment_type = controls_analysis.get('deployment_type', 'unknown')
        internet_exposure = controls_analysis.get('internet_exposure', 'unknown')
        
        # Determine final risk rating
        if critical_count > 5 or high_count > 15:
            final_risk = "High"
        elif critical_count > 0 or high_count > 10:
            final_risk = "Moderate-High"
        elif high_count > 0 or total_vulns > 20:
            final_risk = "Moderate"
        elif total_vulns > 5:
            final_risk = "Low-Moderate"
        else:
            final_risk = "Low"
        
        # Return template-based summary
        return f"""The {product_name} underwent a detailed vulnerability assessment to evaluate its security posture across code, dependencies, and deployment configurations. Based on {tools_string} analyses, and subsequent contextualization with real deployment data ({deployment_type} deployment, {internet_exposure} exposure, {implementation_rate}% security controls implemented), the overall residual risk rating is now {final_risk}."""
    
    def _analyze_by_category(self) -> Dict[str, int]:
        """Analyze vulnerabilities by category."""
        categories = {}
        
        # ZAP categories
        for finding in self.zap_data:
            category = finding.get('enhanced_category', finding.get('mapped_type', 'Other'))
            categories[category] = categories.get(category, 0) + 1
        
        # SonarQube categories  
        for finding in self.sonar_data:
            category = finding.get('enhanced_category', 'Code Quality')
            categories[category] = categories.get(category, 0) + 1

        # SCA categories
        for finding in self.sca_data:
            category = finding.get('enhanced_category', finding.get('category', 'Dependency Vulnerability'))
            categories[category] = categories.get(category, 0) + 1
        
        return dict(sorted(categories.items(), key=lambda x: x[1], reverse=True))
    
    def _get_display_risk_from_severity(self, vuln_data: Dict) -> str:
        """Get display risk level based on adjusted severity for DAST vulnerabilities only."""
        # Only apply severity-based risk for DAST vulnerabilities
        if vuln_data.get('type') != 'DAST':
            return vuln_data.get('risk', 'Unknown')
        
        try:
            # Get the adjusted severity from enhanced scoring
            base_severity = vuln_data.get('base_severity')
            if base_severity is not None:
                severity = float(base_severity)
                if severity >= 5:
                    return "Critical"
                elif severity >= 4:
                    return "High" 
                elif severity >= 3:
                    return "Medium"
                elif severity >= 2:
                    return "Low"
                else:
                    return "Informational"
        except (ValueError, TypeError):
            pass
        
        # Fallback: Calculate adjusted severity from context
        # If we have context adjustments, apply them to estimate adjusted severity
        try:
            original_risk = vuln_data.get('risk', 'Medium')
            # Map original risk to base severity
            risk_to_severity = {'High': 4, 'Medium': 3, 'Low': 2, 'Informational': 1}
            base_sev = risk_to_severity.get(original_risk, 3)
            
            # Apply context reduction (assuming -1 for internal_only environment)
            # This matches your configuration: environment.internet_exposure == 'internal_only'
            adjusted_sev = base_sev - 1
            
            if adjusted_sev >= 5:
                return "Critical"
            elif adjusted_sev >= 4:
                return "High" 
            elif adjusted_sev >= 3:
                return "Medium"
            elif adjusted_sev >= 2:
                return "Low"
            else:
                return "Informational"
        except:
            pass
        
        # Final fallback to original risk level
        return vuln_data.get('risk', 'Unknown')

    def _get_below_threshold_vulnerabilities(self) -> List[Dict]:
        """Get vulnerabilities that did not meet the prioritization threshold."""
        below_vulns = []
        threshold_score = self._get_threshold_score()
        report_focus = self._determine_report_focus()
        
        # ZAP Data
        for vuln in self.zap_data:
            score = float(vuln.get('enhanced_score', vuln.get('score', 0)))
            if score < threshold_score:
                below_vulns.append({
                    'name': vuln.get('name', vuln.get('Alert', 'Unknown')),
                    'type': 'DAST',
                    'risk': str(vuln.get('enhanced_risk_level', vuln.get('risk', 'Low'))).title(),
                    'score': score,
                    'category': vuln.get('enhanced_category', 'Other'),
                    'original_risk_level': vuln.get('original_risk', vuln.get('risk', 'Unknown')),
                    'original_risk': vuln.get('original_risk', vuln.get('risk', 'Unknown')),
                    'source_url': vuln.get('url', vuln.get('URL', '')),
                    'instances': vuln.get('instances', []),
                    'original_message': vuln.get('description', ''),
                    'solution': vuln.get('solution', ''),
                    'framework_justification': vuln.get('framework_justification', ''),
                    'enhanced_justifications': vuln.get('enhanced_justifications', []),
                    'ai_justification': vuln.get('ai_justification')
                })
                
        # Sonar Data
        if report_focus not in ['dast_focused']:
            source_data = self.sonar_raw_data if hasattr(self, 'sonar_raw_data') and self.sonar_raw_data else self.sonar_data
            for vuln in source_data:
                # Try getting enhanced score, then vulnerability_score, then basic_score
                score = vuln.get('enhanced_score', vuln.get('vulnerability_score', vuln.get('basic_score', 0)))
                score = float(score) if score else 0
                
                if score < threshold_score:
                    original_risk = vuln.get('vulnerabilityProbability', 'Low')
                    below_vulns.append({
                        'name': vuln.get('ruleKey', 'Unknown'),
                        'type': 'SAST',
                        'risk': str(vuln.get('enhanced_risk_level', original_risk)).title(),
                        'score': score,
                        'category': vuln.get('enhanced_category', 'Code Quality'),
                        'original_risk_level': self._map_sonar_severity(vuln.get('vulnerabilityProbability', 'Unknown')),
                        'original_risk': self._map_sonar_severity(vuln.get('vulnerabilityProbability', 'Unknown')),
                        'ai_justification': vuln.get('ai_justification')
                    })

        # SCA Data
        for vuln in self.sca_data:
            score = float(vuln.get('enhanced_score', vuln.get('score', 0)) or 0)
            if score < threshold_score:
                below_vulns.append({
                    'name': vuln.get('name', 'Unknown'),
                    'type': 'SCA',
                    'risk': vuln.get('enhanced_risk_level', vuln.get('risk', 'Low')),
                    'score': score,
                    'category': vuln.get('enhanced_category', 'Dependency Vulnerability'),
                    'original_risk_level': vuln.get('original_risk_level', vuln.get('risk', 'Unknown')),
                    'original_risk': vuln.get('original_risk_level', vuln.get('risk', 'Unknown')),
                    'package_name': vuln.get('package_name', 'Unknown'),
                    'installed_version': vuln.get('installed_version', 'N/A'),
                    'fixed_version': vuln.get('fixed_version', 'N/A'),
                    'description': vuln.get('description', ''),
                    'artifact': vuln.get('artifact', 'Unknown'),
                    'primary_url': vuln.get('primary_url'),
                    'references': vuln.get('references', []),
                    'enhanced_justifications': vuln.get('enhanced_justifications', []),
                    'ai_justification': vuln.get('ai_justification')
                })
        
        # Sort by score descending
        return sorted(below_vulns, key=lambda x: x['score'], reverse=True)

    def _get_top_vulnerabilities(self) -> List[Dict]:
        """Get top vulnerabilities by risk score, filtered by threshold."""
        all_vulns = []
        
        # Get threshold score from config (default to 10 if not found)
        threshold_score = self._get_threshold_score()
        
        # Determine report focus to filter vulnerabilities appropriately
        report_focus = self._determine_report_focus()
        
        # Add ZAP vulnerabilities
        for vuln in self.zap_data:
            enhanced_score = vuln.get('enhanced_score', vuln.get('score', 0))
            enhanced_risk = vuln.get('enhanced_risk_level', vuln.get('risk', 'Low'))
            score = float(enhanced_score) if enhanced_score else 0
            
            # Only include vulnerabilities that meet the threshold
            if score >= threshold_score:
                # FIX: Trust the AI's enhanced_risk_level explicitly
                display_risk = str(enhanced_risk).title()
                
                all_vulns.append({
                    'name': vuln.get('name', vuln.get('Alert', 'Unknown')),
                    'type': 'DAST',
                    'risk': display_risk,  # Use upgraded risk for display
                    'score': score,
                    'category': vuln.get('enhanced_category', 'Other'),
                    'enhanced_risk_level': display_risk,  # Use upgraded risk for filtering
                    'original_risk_level': vuln.get('original_risk', vuln.get('risk', 'Unknown')),  # Keep original for reference
                    'base_severity': vuln.get('base_severity'),  # Add adjusted severity for display
                    'context_adjustments': vuln.get('context_adjustments', {}),  # Add context adjustments for DAST calculation
                    'original_risk': vuln.get('original_risk', vuln.get('risk', 'Unknown')),  # Add original risk for DAST calculation
                    'framework_justification': vuln.get('framework_justification', ''),  # Add framework justification from ZAP data
                    'original_message': vuln.get('description', ''),  # Add Issue Description from ZAP HTML
                    'instances': vuln.get('instances', []),  # Add instances for displaying URLs in PDF
                    'source_url': vuln.get('source_url', 'Not specified'),  # Add source URL for multi-URL support
                    'solution': vuln.get('solution', ''),  # Add solution/recommendations from ZAP data
                    'enhanced_justifications': vuln.get('enhanced_justifications', []),  # DAST: Include enhanced justifications list
                    'ai_justification': vuln.get('ai_justification')
                })
        
        if report_focus not in ['dast_focused', 'sca_focused']:
            logger.info(f"🔍 SAST Filtering - Threshold: {threshold_score}")
            for vuln in self.sonar_data:
                # Try multiple score fields for robust extraction
                score = vuln.get('enhanced_score', vuln.get('vulnerability_score', vuln.get('basic_score', 0)))
                score = float(score) if score else 0
                
                # Only include vulnerabilities that meet the threshold
                if score >= threshold_score:
                    # Create a more readable name using rule and category
                    category = vuln.get('enhanced_category', 'Code Quality')
                    rule_key = vuln.get('ruleKey', 'Unknown')
                    readable_name = f"{rule_key}"  # Just use rule key, category will be added later
                    
                    # Get original risk level
                    original_risk = vuln.get('enhanced_risk_level', vuln.get('vulnerabilityProbability', 'LOW'))
                    
                    # FIX: Trust the AI's enhanced_risk_level explicitly
                    display_risk = str(original_risk).title()
                    
                    all_vulns.append({
                        'name': readable_name,
                        'type': 'SAST',
                        'risk': display_risk,  # Use upgraded risk for display
                        'score': score,
                        'category': category,
                        'enhanced_risk_level': display_risk,  # Use upgraded risk for filtering
                        'original_risk_level': self._map_sonar_severity(original_risk),  # Keep original for reference
                        'original_message': vuln.get('message', ''),  # Keep original for reference
                        'rule_key': rule_key,
                        'original_risk': self._map_sonar_severity(vuln.get('vulnerabilityProbability', 'Unknown')),  # Original SonarQube risk
                        'vulnerabilityProbability': self._map_sonar_severity(vuln.get('vulnerabilityProbability', 'Unknown')),  # For backward compatibility
                        'context_adjustments': vuln.get('context_adjustments', {}),  # Add context adjustments for severity calculation
                        'framework_justification': vuln.get('framework_justification', ''),  # Add framework justification from SonarQube data
                        'enhanced_justifications': vuln.get('enhanced_justifications', []),  # SAST: Include enhanced justifications list
                        'ai_justification': vuln.get('ai_justification'),
                        'component': vuln.get('component', ''),  # SAST: Component path for detail display
                        'start_line': vuln.get('start_line', ''),  # SAST: Start line number
                        'end_line': vuln.get('end_line', ''),  # SAST: End line number
                        'line': vuln.get('line', '')  # SAST: Single line number (fallback)
                    })

        # Add SCA vulnerabilities
        if report_focus in ['sca_focused', 'unified', 'comprehensive']:
            logger.info(f"🔍 SCA Filtering - Threshold: {threshold_score}")
            for vuln in self.sca_data:
                score = float(vuln.get('enhanced_score', vuln.get('score', 0)) or 0)
                if score >= threshold_score:
                    original_risk = vuln.get('enhanced_risk_level', vuln.get('risk', 'Low'))
                    # FIX: Do not artificially upgrade SCA risk levels based on numeric thresholds.
                    # The EnhancedVulnerabilityScorer already strictly capped the sca_data risk level.
                    # We must blindly trust `enhanced_risk_level`.
                    display_risk = str(original_risk).title()

                    all_vulns.append({
                        'name': vuln.get('name', 'Unknown'),
                        'type': 'SCA',
                        'risk': display_risk,
                        'score': score,
                        'category': vuln.get('enhanced_category', 'Dependency Vulnerability'),
                        'enhanced_risk_level': display_risk,
                        'original_risk_level': vuln.get('original_risk_level', vuln.get('risk', 'Unknown')),
                        'original_risk': vuln.get('original_risk_level', vuln.get('risk', 'Unknown')),
                        'package_name': vuln.get('package_name', ''),
                        'installed_version': vuln.get('installed_version', ''),
                        'fixed_version': vuln.get('fixed_version', ''),
                        'description': vuln.get('description', ''),
                        'artifact': vuln.get('artifact', ''),
                        'primary_url': vuln.get('primary_url', ''),
                        'framework_justification': vuln.get('framework_justification', ''),
                        'enhanced_justifications': vuln.get('enhanced_justifications', []),
                        'ai_justification': vuln.get('ai_justification'),
                    })
        
        # Sort by score and return filtered vulnerabilities
        return sorted(all_vulns, key=lambda x: x['score'], reverse=True)
    
    def _get_pr_links(self) -> List[tuple]:
        """
        Get simple list of PR links from fix reports (for SAST scans).
        
        Returns:
            List of tuples: [(pr_number, pr_url), ...]
        """
        pr_links = []
        
        # Only look for PRs if we have SAST data
        if not self.sonar_data:
            logger.debug("No SAST data found - skipping PR link search")
            return []
        
        logger.info(f"🔍 Searching for PR links from fix reports")
        
        # Get current repository from environment to filter PRs
        current_repo = os.environ.get('GITHUB_REPO', '')
        
        # Extract timestamp from the scan data being used
        scan_timestamp = None
        if self.sonar_data:
            # Try to get timestamp from the loaded data file
            filtered_patterns = ["sonarqube_filtered_*.json", "sonarqube_filtered_*.csv", "filtered_vulnerabilities_*.csv"]
            for pattern in filtered_patterns:
                files = list(self.input_dir.glob(pattern))
                if files:
                    latest_file = max(files, key=os.path.getmtime)
                    # Extract timestamp from filename: sonarqube_filtered_20251111_063951.csv
                    import re
                    timestamp_match = re.search(r'(\d{8}_\d{6})', latest_file.name)
                    if timestamp_match:
                        scan_timestamp = timestamp_match.group(1)
                        logger.debug(f"Scan timestamp: {scan_timestamp}")
                    break
        
        # Try to find PR report file
        try:
            import glob
            import re
            
            # Find PR report file matching the scan timestamp
            pr_report_file = None
            if scan_timestamp:
                matching_pr_file = f"vulnerability-fixes/fix_report_{scan_timestamp}.md"
                logger.info(f"🔍 Looking for PR report: {matching_pr_file}")
                if os.path.exists(matching_pr_file):
                    pr_report_file = matching_pr_file
                    logger.info(f"✅ Found matching PR report for scan: {matching_pr_file}")
            
            # Fallback: use most recent PR report if no timestamp match
            if not pr_report_file:
                pr_report_files = glob.glob("vulnerability-fixes/fix_report_*.md")
                if pr_report_files:
                    pr_report_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
                    most_recent = pr_report_files[0]
                    # Increased time window to 24 hours for better matching
                    if os.path.getmtime(most_recent) > (time.time() - 86400):  # Within 24 hours
                        pr_report_file = most_recent
                        logger.info(f"✅ Using most recent PR report (within 24h): {most_recent}")
            
            # Second fallback: If still no match, try to find PR report with closest timestamp
            if not pr_report_file and scan_timestamp:
                pr_report_files = glob.glob("vulnerability-fixes/fix_report_*.md")
                if pr_report_files:
                    # Extract timestamps and find closest match
                    from datetime import datetime
                    
                    scan_dt = datetime.strptime(scan_timestamp, '%Y%m%d_%H%M%S')
                    closest_file = None
                    min_diff = float('inf')
                    
                    for pr_file in pr_report_files:
                        pr_timestamp_match = re.search(r'fix_report_(\d{8}_\d{6})\.md', pr_file)
                        if pr_timestamp_match:
                            pr_timestamp = pr_timestamp_match.group(1)
                            try:
                                pr_dt = datetime.strptime(pr_timestamp, '%Y%m%d_%H%M%S')
                                diff = abs((pr_dt - scan_dt).total_seconds())
                                
                                # If within 4 hours, consider it a match
                                if diff < 14400 and diff < min_diff:
                                    min_diff = diff
                                    closest_file = pr_file
                            except:
                                continue
                    
                    if closest_file:
                        pr_report_file = closest_file
                        logger.info(f"✅ Found PR report with closest timestamp: {closest_file} (diff: {min_diff/60:.1f} minutes)")
            
            if not pr_report_file:
                logger.debug("No PR report file found")
                return []
            
            # Extract PR URLs from the report
            pr_pattern = r'- PR #(\d+): (https://github\.com/[^/]+/[^/]+/pull/\d+)'
            
            with open(pr_report_file, 'r', encoding='utf-8') as f:
                content = f.read()
                matches = re.findall(pr_pattern, content)
                for pr_num, pr_url in matches:
                    # Filter by repository if GITHUB_REPO is set
                    if current_repo:
                        pr_repo_match = re.search(r'github\.com/([^/]+/[^/]+)/pull', pr_url)
                        if pr_repo_match and pr_repo_match.group(1) != current_repo:
                            continue
                    pr_links.append((pr_num, pr_url))
            
            if pr_links:
                logger.info(f"✅ Found {len(pr_links)} PR link(s)")
            else:
                logger.debug("No PR URLs found in report")
                    
        except Exception as e:
            logger.debug(f"Could not search for PR data: {e}")
        
        return pr_links
    
    def _get_sast_adjusted_severity(self, vuln: Dict) -> str:
        """Get adjusted severity for SAST vulnerabilities - now uses threshold-upgraded risk level."""
        # Use the upgraded risk level that was calculated in _get_top_vulnerabilities
        upgraded_risk = vuln.get('risk', vuln.get('enhanced_risk_level', 'Medium'))
        return str(upgraded_risk).title()
    
    def _get_dast_adjusted_severity(self, vuln: Dict) -> str:
        """Get adjusted severity for DAST vulnerabilities - now uses threshold-upgraded risk level."""
        # Use the upgraded risk level that was calculated in _get_top_vulnerabilities
        upgraded_risk = vuln.get('risk', vuln.get('enhanced_risk_level', 'Medium'))
        return str(upgraded_risk).title()
    
    def _get_threshold_score(self) -> float:
        """Get the threshold score from configuration."""
        try:
            # Try to get from appsecai/risk_profiles/app_config.yaml or environment
            import os
            threshold = os.environ.get('VULNERABILITY_THRESHOLD')
            if not threshold:
                # Use default threshold of 0 to include all vulnerabilities
                logger.warning("VULNERABILITY_THRESHOLD not set, using default value of 0 (include all vulnerabilities)")
                return 0.0
            return float(threshold)
        except ValueError as e:
            logger.error(f"Invalid VULNERABILITY_THRESHOLD value: {threshold}, using default 0")
            return 0.0
        except Exception as e:
            logger.error(f"Error reading VULNERABILITY_THRESHOLD: {e}, using default 0")
            return 0.0
    
    def _upgrade_risk_for_report(self, original_risk: str, score: float, threshold: float) -> str:
        """
        Determine risk level for report display based on score thresholds.
        
        This method replaces artificial upgrades with threshold-based classification.
        
        Args:
            original_risk: Original risk level (used as fallback or for comparison)
            score: Vulnerability score
            threshold: Minimum threshold to include in summary counts
            
        Returns:
            Risk level for report display
        """
        # Convert score to float if it's not already
        try:
            score_value = float(score) if score else 0.0
        except (ValueError, TypeError):
            score_value = 0.0
            
        # Get thresholds (using previously loaded self.risk_thresholds)
        rt = getattr(self, 'risk_thresholds', {"critical": 8.5, "high": 7.5, "medium": 5.0, "low": 2.5, "informational": 0.0})
        
        # Classification based on thresholds
        if score_value >= rt.get('critical', 8.5):
            risk = 'Critical'
        elif score_value >= rt.get('high', 7.5):
            risk = 'High'
        elif score_value >= rt.get('medium', 5.0):
            risk = 'Medium'
        elif score_value >= rt.get('low', 2.5):
            risk = 'Low'
        else:
            risk = 'Informational'
            
        # Log if there was a classification change from original
        orig_title = str(original_risk).title()
        if risk != orig_title and score_value > 0:
            logger.debug(f"📊 [REPORT CLASSIFY] Score {score_value}: {orig_title} → {risk}")
            
        return risk
    
    def _clean_justification_text(self, text: str) -> str:
        """Clean justification text by removing multipliers and extra formatting.
        Also escapes XML special characters to prevent ReportLab paraparser crashes.
        """
        if not text:
            return ""
            
        # Remove multipliers like (x1.2), (x0.75), (x1.3), etc.
        text = re.sub(r'\s*\(\s*x\d+(\.\d+)?\s*\)\s*$', '', text)
        text = re.sub(r'\s*\(\s*x\d+(\.\d+)?\s*\)', '', text)
        
        # Clean up any remaining artifacts from regex
        text = text.replace('  ', ' ').strip()
        
        # Escape XML special characters so ReportLab Paragraph doesn't crash
        # on CVE descriptions or LLM text containing < > & characters
        import html
        text = html.escape(text, quote=False)
        
        return text

    def _calculate_workload_optimization(self) -> Dict:
        """
        Calculate workload optimization and cost impact based on prioritization.
        
        Logic provided by User:
        - T_total = Total findings
        - T_prioritized = Vulnerabilities after prioritization (High/Critical)
        - H_triage = 0.5 hr (Average time to review 1 vuln)
        - H_fix = 2 hrs (Average time to fix 1 vuln)
        - Automation Efficiency = 60% (0.6)
        - C_dev = $50/hr (Developer hourly cost)
        """
        zap_findings = len(self.zap_data)
        
        # Access raw data for accurate total before threshold filtering
        sonar_source = self.sonar_raw_data if hasattr(self, 'sonar_raw_data') and self.sonar_raw_data else self.sonar_data
        sonar_findings = len(sonar_source)
        
        # Include SCA data
        sca_findings = self.sca_original_count if getattr(self, 'sca_original_count', 0) > 0 else len(self.sca_data)
        
        t_total = zap_findings + sonar_findings + sca_findings
        
        # Get prioritized findings (sum of all findings that passed the threshold)
        top_vulns = self.report_data.get('vulnerability_analysis', {}).get('top_vulnerabilities', [])
        
        # Determine actionable counts based on report focus
        report_focus = self.report_data.get('metadata', {}).get('report_focus', 'comprehensive')
        if report_focus == 'sast_focused':
            t_prioritized = sum(1 for v in top_vulns if v.get('type') == 'SAST')
        elif report_focus == 'dast_focused':
            t_prioritized = sum(1 for v in top_vulns if v.get('type') == 'DAST')
        elif report_focus == 'sca_focused':
            t_prioritized = sum(1 for v in top_vulns if v.get('type') == 'SCA')
        else:
            t_prioritized = len(top_vulns)
        
        # Variables
        h_triage = 0.5
        h_fix = 2.0
        automation_efficiency = 0.6
        c_dev = 50
        
        # Triage Effort
        triage_before = t_total * h_triage
        triage_after = t_prioritized * h_triage
        triage_saved = triage_before - triage_after
        
        # Remediation Effort
        h_fix_ai = h_fix * (1 - automation_efficiency)
        fix_before = t_prioritized * h_fix
        fix_after = t_prioritized * h_fix_ai
        fix_saved = fix_before - fix_after
        
        # Totals
        total_effort_before = triage_before + fix_before
        total_effort_after = triage_after + fix_after
        total_saved = triage_saved + fix_saved
        
        cost_before = total_effort_before * c_dev
        cost_after = total_effort_after * c_dev
        cost_saved = total_saved * c_dev
        
        # Reduction percentage for findings
        reduction_pct = 0
        if t_total > 0:
            reduction_pct = ((t_total - t_prioritized) / t_total) * 100
            
        return {
            't_total': t_total,
            't_prioritized': t_prioritized,
            'reduction_pct': reduction_pct,
            'triage_before': triage_before,
            'triage_after': triage_after,
            'triage_saved': triage_saved,
            'fix_before': fix_before,
            'fix_after': fix_after,
            'fix_saved': fix_saved,
            'total_effort_before': total_effort_before,
            'total_effort_after': total_effort_after,
            'total_saved': total_saved,
            'cost_before': cost_before,
            'cost_after': cost_after,
            'cost_saved': cost_saved
        }

    def _get_vulnerability_justifications(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Get framework-based justifications for vulnerabilities with category information."""
        justifications = []
        justifications_map = {}  # Track unique vulnerability types to avoid duplicates
        
        logger.info(f"🔍 Processing {len(vulnerabilities)} vulnerabilities for justifications")
        
        for vuln in vulnerabilities:
            vuln_name = vuln['name'][:60] + '...' if len(vuln['name']) > 60 else vuln['name']
            category = vuln.get('category', 'Other')
            vuln_type = vuln.get('type', 'Unknown')
            
            # Create unique key based on vulnerability name and category
            unique_key = f"{vuln_name}|{category}"
            
            # Skip if we've already processed this vulnerability type
            if unique_key in justifications_map:
                continue
            
            # Get all applied justifications
            applied_justifications = []
            
            # Check for framework_justification field (now cleaned in _clean_vulnerability_data)
            framework_justification = vuln.get('framework_justification', '')
            if framework_justification:
                if 'vulnerability prioritized due to:' in framework_justification:
                    context_part = framework_justification.split('vulnerability prioritized due to:')[1].strip()
                    applied_justifications.append(context_part.rstrip('.'))
                else:
                    applied_justifications.append(framework_justification)
            
            # Process enhanced_justifications (already cleaned in _clean_vulnerability_data)
            enhanced_justifications = vuln.get('enhanced_justifications', [])
            if enhanced_justifications:
                technical_prefixes = [
                    'Category:', 'Base severity:', 'Potential impact:', 'Ease of exploitation:',
                    'Context adjustments:', 'PotentialImpact:', 'EaseOfExploitation:', 
                    'Severity:', 'Final score:', 'Base Severity Component:', 'Effective Impact:',
                    'Effective Exploitability:', 'Exposure Multiplier:', 'Input Sev:', 'Applied Modifiers:'
                ]
                for just in enhanced_justifications:
                    # Only include relevant risk factors or bullet points
                    is_relevant = any(p in just for p in ['Risk Increasing Factors:', 'Risk Decreasing Factors:', '•'])
                    if is_relevant or not any(just.strip().startswith(prefix) for prefix in technical_prefixes):
                        clean_just = self._clean_justification_text(just)
                        if clean_just and clean_just not in applied_justifications:
                            applied_justifications.append(clean_just)
            
            if applied_justifications:
                # Remove duplicates while preserving order
                unique_justifications = []
                seen = set()
                for just in applied_justifications:
                    if just and just not in seen:
                        unique_justifications.append(just)
                        seen.add(just)
                
                justification_entry = {
                    'name': vuln_name,
                    'category': category,
                    'justifications': unique_justifications
                }
                
                justifications.append(justification_entry)
                justifications_map[unique_key] = justification_entry
            elif vuln_type == 'DAST':
                # Use category fallback for DAST if no detailed justifications found
                category_justification = self._get_category_justification(vuln)
                justifications.append({
                    'name': vuln_name,
                    'category': category,
                    'justifications': [category_justification]
                })
        
        return justifications
    
    def _get_category_justification(self, vuln: Dict) -> str:
        """Get justification based on vulnerability category."""
        category = vuln.get('category', 'Other')
        vuln_type = vuln.get('type', 'Unknown')
        
        # Category-based justifications from the comprehensive framework
        category_justifications = {
            'Injection': 'High-impact vulnerability that can lead to data breaches and system compromise through malicious input',
            'HTTP Security Headers': 'Missing security headers weaken browser protections against client-side attacks and data exposure',
            'API Security': 'Exposes application data and functionality to unauthorized access and manipulation',
            'Transport Security': 'Compromises data confidentiality and integrity during transmission between client and server',
            'Authentication & Session Management': 'Enables unauthorized access and session hijacking, compromising user accounts',
            'Infrastructure Security': 'Reveals sensitive system information that aids attackers in reconnaissance and exploitation',
            'Input Validation': 'Allows malicious input to compromise application logic and potentially execute arbitrary code',
            'Cryptography': 'Weakens data protection mechanisms and enables cryptographic attacks on sensitive information',
            'Session Management': 'Improper session handling can lead to session hijacking and unauthorized access'
        }
        
        base_justification = category_justifications.get(category, 'Security vulnerability requiring attention based on risk assessment')
        
        # Add context for DAST vulnerabilities with adjusted risk
        if vuln_type == 'DAST':
            # Check if this vulnerability had its risk adjusted down due to context
            original_risk = vuln.get('risk', 'Medium')
            display_risk = self._get_display_risk_from_severity(vuln)
            
            if original_risk != display_risk:
                base_justification += f" (Risk adjusted from {original_risk} to {display_risk} based on deployment context)"
        
        return base_justification
    

    
    def _get_methodology(self) -> str:
        """Get scan methodology description."""
        return "AppSecAI combines SAST and DAST techniques to identify vulnerabilities. SAST analyzes code, while DAST evaluates the running application for logical and configuration flaws. Results are then scored and prioritized based on contextual risk."

    def _get_risk_matrix(self) -> List[List[str]]:
        """Get the risk assessment matrix."""
        return [
            ['Impact / Likelihood', 'Low', 'Medium', 'High'],
            ['High', 'Medium', 'High', 'Critical'],
            ['Medium', 'Low', 'Medium', 'High'],
            ['Low', 'Informational', 'Low', 'Medium']
        ]

    def _map_risk_to_priority(self, risk: str) -> str:
        """Map risk level string to priority."""
        risk_map = {
            'Critical': 'High',
            'High': 'High',
            'Medium': 'Medium',
            'Low': 'Low',
            'Informational': 'Low'
        }
        return risk_map.get(str(risk).title(), 'Medium')


    def _map_sonar_severity(self, raw_severity: str) -> str:
        """Map SonarQube's specific severities (e.g., MAJOR, MINOR) to standard AppSecAI risk levels."""
        if not raw_severity:
            return 'Low'
            
        sonar_to_standard = {
            'BLOCKER': 'Critical',
            'CRITICAL': 'Critical',
            'HIGH': 'High',
            'MAJOR': 'High',
            'MEDIUM': 'Medium',
            'MINOR': 'Low',
            'LOW': 'Low',
            'INFO': 'Informational'
        }
        return sonar_to_standard.get(str(raw_severity).upper(), 'Low')


    def _generate_llm_recommendations(self) -> List[Dict]:
        """Generate recommendations using LLM (Placeholder)."""
        return [{
            "priority": "High",
            "title": "Implement Continuous Security Monitoring",
            "description": "Regular scans and automated monitoring should be integrated into the CI/CD pipeline.",
            "impact": "Reduces time to detect and resolve vulnerabilities",
            "effort": "Medium",
            "category": "Security Processes",
            "fix_details": "Integrate AppSecAI into your GitHub Actions or Jenkins pipelines.",
            "justification": "Continuous scanning provides real-time visibility into security posture."
        }]

    def _analyze_trends(self) -> Dict[str, str]:
        """Analyze trends (placeholder for future enhancement)."""
        return {
            'trend_analysis': 'Trend analysis requires historical data from multiple scans',
            'recommendation': 'Implement regular scanning to track security posture over time'
        }
    
    def _analyze_scan_correlation(self) -> Dict[str, Any]:
        """Analyze correlation between SAST and DAST findings."""
        # Placeholder implementation to unblock report generation
        correlation = {
            'common_components': [],
            'verified_findings': [],
            'correlation_score': 0.0
        }
        
        # Simple correlation: count if any SAST component appears in DAST URLs
        if self.zap_data and self.sonar_data:
            dast_urls = set()
            for vuln in self.zap_data:
                instances = vuln.get('instances', [])
                for inst in instances:
                    url = inst.get('URL', '')
                    if url:
                        dast_urls.add(url)
            
            sast_components = set()
            for vuln in self.sonar_data:
                comp = vuln.get('component', '')
                if comp:
                    sast_components.add(comp)
            
            # This is very basic matching, but sufficient for report generation
            match_count = 0
            # Logic here is just placeholder
            
        return correlation

    def _generate_recommendations(self) -> List[Dict]:
        """Generate recommendations - first try CSV, then LLM fallback."""
        try:
            # First try to load from existing CSV file
            csv_recommendations = self._load_recommendations_from_csv()
            if csv_recommendations:
                logger.info(f"✅ Loaded {len(csv_recommendations)} recommendations from CSV")
                return csv_recommendations
            
            # Fallback to LLM generation if CSV not available
            logger.info("📝 CSV not found, generating new LLM recommendations...")
            return self._generate_llm_recommendations()
        except Exception as e:
            logger.error(f"Recommendations failed: {e}")
            return [{"priority": "High", "title": "Recommendation Error", "description": "Could not load or generate recommendations", "impact": "Unable to generate recommendations"}]
    
    def _extract_fix_section(self, text: str) -> str:
        """Extract only the Fix section from mixed content."""
        import re
        
        if not text:
            return 'No fix details available'
        
        # Try to find the Fix section specifically
        fix_match = re.search(r'#\s*Fix:\s*(.*?)(?=#\s*(?:Impact|Justification):|```|$)', text, re.DOTALL | re.IGNORECASE)
        if fix_match:
            fix_text = fix_match.group(1).strip()
        else:
            # If no Fix section marker found, try to extract content before Impact/Justification markers
            fix_text = re.sub(r'#\s*(?:Impact|Justification):.*', '', text, flags=re.DOTALL | re.IGNORECASE).strip()
        
        # Remove markdown code blocks
        fix_text = re.sub(r'```\w*\n?', '', fix_text)
        fix_text = re.sub(r'```', '', fix_text)
        
        # Remove common LLM closing phrases
        fix_text = re.sub(r'Please let me know.*$', '', fix_text, flags=re.DOTALL | re.IGNORECASE)
        fix_text = re.sub(r"I'm here to assist.*$", '', fix_text, flags=re.DOTALL | re.IGNORECASE)
        
        # Clean up extra whitespace
        fix_text = re.sub(r'\n\s*\n\s*\n+', '\n\n', fix_text)
        fix_text = fix_text.strip()
        
        return fix_text if fix_text else 'No fix details available'
    
    def _load_recommendations_from_csv(self) -> List[Dict]:
        """Load existing recommendations from CSV file (same source as CLI)."""
        import glob
        import csv
        
        # Find the most recent CSV summary file (same pattern as CLI)
        csv_pattern = str(self.input_dir / "security_recommendations_summary_*.csv")
        csv_files = glob.glob(csv_pattern)
        
        if not csv_files:
            return []
        
        # Get the most recent file
        latest_csv = max(csv_files, key=os.path.getmtime)
        
        try:
            with open(latest_csv, 'r', encoding='utf-8') as file:
                reader = csv.DictReader(file)
                csv_data = list(reader)
            
            # Transform CSV format to report format
            recommendations = []
            for row in csv_data:
                rec = {
                    "title": row.get('Title', 'Unknown'),
                    "description": f"Impact: {row.get('Impact', 'Not specified')}",
                    "priority": self._map_risk_to_priority(row.get('Risk', 'Medium')),
                    "impact": row.get('Risk', 'Medium'),
                    "effort": "Medium",  # Default since not in CSV
                    "category": row.get('MappedType', 'Security'),
                    "fix_details": self._extract_fix_section(row.get('Fix', '')),
                    "justification": self._clean_justification_text(row.get('Justification', 'No justification available'))
                }
                
                # Better justification handling: if it's just a header or too short, try to synthesize from vulnerability data
                just = rec['justification']
                if just and (just.endswith(':') or len(just) < 30):
                    # Try to find the vulnerability in our loaded data (ZAP or SAST)
                    vuln_match = None
                    # Search ZAP data
                    for v in self.zap_data:
                         if v.get('name') == rec['title'] or v.get('Alert') == rec['title']:
                             vuln_match = v
                             break
                    # Search SAST data if not found
                    if not vuln_match:
                        for v in self.sonar_data:
                            if v.get('ruleKey') == rec['title'] or v.get('message') == rec['title']:
                                vuln_match = v
                                break
                    
                    if vuln_match and vuln_match.get('enhanced_justifications'):
                        # Filter to relevant modifiers
                        relevant = [self._clean_justification_text(j) for j in vuln_match['enhanced_justifications'] if 'Risk Increasing Factors:' in j or 'Risk Decreasing Factors:' in j or 'Applied Modifiers:' in j or '•' in j]
                        if relevant:
                            rec['justification'] = "\n".join(relevant)
                
                recommendations.append(rec)
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Failed to load CSV recommendations: {e}")
            return []
    
    def _map_risk_to_priority(self, risk: str) -> str:
        """Map CSV risk levels to report priority levels."""
        risk_mapping = {
            'High': 'High',
            'Medium': 'Medium', 
            'Low': 'Low',
            'Informational': 'Low'
        }
        return risk_mapping.get(risk, 'Medium')

    def _generate_llm_recommendations(self) -> List[Dict]:
        """Generate specific recommendations using LLM based on actual vulnerabilities."""
        import requests
        import json
        import os
        
        # Get the actual vulnerabilities that are above threshold
        top_vulns = self._get_top_vulnerabilities()
        if not top_vulns:
            return []
        
        # Prepare vulnerability context for LLM
        vuln_context = []
        for vuln in top_vulns[:5]:  # Top 5 vulnerabilities
            vuln_context.append({
                'name': vuln['name'],
                'original_risk': vuln.get('risk', vuln.get('vulnerabilityProbability', 'Unknown')),
                'adjusted_severity': vuln.get('enhanced_risk_level', vuln.get('risk', 'Unknown')),
                'score': vuln['score'],
                'category': vuln.get('category', 'Unknown')
            })
        
        # Create LLM prompt
        prompt = f"""Generate 3-4 specific security recommendations based on these actual vulnerabilities found:

{json.dumps(vuln_context, indent=2)}

Deployment Context: Internal-only application with limited internet exposure

Requirements:
- Focus on the SPECIFIC vulnerabilities listed above
- Consider that risks are reduced due to internal deployment
- Provide actionable, technical recommendations
- Format as JSON array with: title, description, priority (1-3), impact (High/Medium/Low), effort (High/Medium/Low), justification
- Be specific about the vulnerability names mentioned
- Prioritize based on scores and business impact
- Keep descriptions concise but actionable

Return only valid JSON array, no other text.
"""

        # Get LLM configuration
        llm_url = os.environ.get('LLM_URL', 'http://4.247.140.236:11434')
        llm_model = os.environ.get('LLM_MODEL', 'qwen2.5-coder:7b-instruct')
        
        # Call LLM
        payload = {
            "model": llm_model,
            "prompt": prompt,
            "stream": False,
            "options": {"num_predict": 500}
        }
        
        response = requests.post(f"{llm_url}/api/generate", json=payload, timeout=60)
        response.raise_for_status()
        
        result = response.json()
        llm_response = result.get('response', '').strip()
        
        # Parse JSON response
        try:
            recommendations = json.loads(llm_response)
            return recommendations if isinstance(recommendations, list) else []
        except json.JSONDecodeError:
            logger.error("LLM returned invalid JSON for recommendations")
            return [{"priority": "High", "title": "LLM Response Error", "description": "Recommendations generation returned invalid format. Please check LLM configuration.", "impact": "Unable to parse recommendations"}]
    

    
    def _generate_vulnerability_explanations(self) -> List[Dict]:
        """Generate brief LLM explanations for each unique vulnerability type."""
        import requests
        import json
        import os
        
        explanations = []
        seen_vulnerabilities = set()
        
        # Process SAST vulnerabilities
        for vuln in self.sonar_data[:30]:  # Limit to top 30 to avoid excessive LLM calls
            rule_key = vuln.get('ruleKey', 'Unknown')
            
            # Skip duplicates
            if rule_key in seen_vulnerabilities:
                continue
            seen_vulnerabilities.add(rule_key)
            
            # Extract vulnerability details
            message = vuln.get('message', 'No description available')
            category = vuln.get('enhanced_category', 'Code Quality')
            severity = vuln.get('vulnerabilityProbability', 'MEDIUM')
            
            # Create LLM prompt for brief explanation
            prompt = f"""Provide a brief 2-3 sentence explanation for this security vulnerability:

Vulnerability Type: {rule_key}
Category: {category}
Message: {message}
Severity: {severity}

Explain: What it is, why it's a security risk, and potential impact.
Keep it concise and clear for technical audiences. No markdown formatting."""

            try:
                # Get LLM configuration
                llm_url = os.environ.get('LLM_URL', 'http://4.247.140.236:11434')
                llm_model = os.environ.get('LLM_MODEL', 'qwen2.5-coder:7b-instruct')
                
                # Call LLM
                payload = {
                    "model": llm_model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "num_predict": 150,
                        "temperature": 0.7
                    }
                }
                
                response = requests.post(f"{llm_url}/api/generate", json=payload, timeout=30)
                response.raise_for_status()
                
                result = response.json()
                explanation_text = result.get('response', '').strip()
                
                # Clean up the response
                explanation_text = explanation_text.replace('**', '').strip()
                
                explanations.append({
                    'name': rule_key,
                    'category': category,
                    'brief_explanation': explanation_text
                })
                
            except Exception as e:
                logger.warning(f"Failed to generate explanation for {rule_key}: {e}")
                # Fallback explanation
                explanations.append({
                    'name': rule_key,
                    'category': category,
                    'brief_explanation': f"Security vulnerability in {category} category. {message}"
                })
        
        return explanations
    
    def generate_json_report(self) -> str:
        """Generate the security posture report in JSON format."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = Path(self.output_dir) / f"security_posture_report_{timestamp}.json"
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.report_data, f, indent=4, default=str)
            print(f"✅ Security posture JSON created: {output_file}")
            return str(output_file)
        except Exception as e:
            print(f"Failed to generate JSON report: {e}")
            return ""

    def generate_pdf_report(self) -> str:
        """Generate the main Security Posture Report (PDF)."""
        if not PDF_AVAILABLE:
            logger.error("❌ PDF generation not available")
            return ""
        
        import requests
        import json
        import os
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = self.output_dir / f"security_posture_report_{timestamp}.pdf"
        
        # Create PDF document
        doc = ReportDocTemplate(str(output_file), pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Professional styles and colors
        primary_color = HexColor('#1A237E')  # Dark Indigo
        secondary_color = HexColor('#2E86AB') # Steel Blue
        neutral_gray = HexColor('#757575')
        light_gray = HexColor('#F5F5F5')
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=28,
            spaceAfter=40,
            alignment=TA_CENTER,
            textColor=primary_color,
            fontName='Helvetica-Bold',
            leading=34
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=18,
            spaceBefore=20,
            spaceAfter=15,
            textColor=primary_color,
            fontName='Helvetica-Bold',
            leading=22
        )
        
        subheading_style = ParagraphStyle(
            'CustomSubHeading',
            parent=styles['Heading3'],
            fontSize=14,
            spaceBefore=15,
            spaceAfter=10,
            textColor=secondary_color,
            fontName='Helvetica-Bold'
        )
        
        normal_style = styles['Normal']
        normal_style.fontSize = 10
        normal_style.leading = 14
        
        metadata_label_style = ParagraphStyle(
            'MetadataLabel',
            parent=styles['Normal'],
            fontSize=10,
            fontName='Helvetica-Bold',
            textColor=white
        )

        header_cell_style = ParagraphStyle(
            'HeaderCell',
            parent=styles['Normal'],
            fontSize=10,
            fontName='Helvetica-Bold',
            textColor=white,
            alignment=TA_LEFT
        )

        # Helper for header/footer
                # Helper for header/footer
        def draw_header_footer(canvas, doc):
            canvas.saveState()
            
            # --- Corner Decorations ---
            # Top Right Corner
            path = canvas.beginPath()
            path.moveTo(A4[0], A4[1] - 80)
            path.lineTo(A4[0] - 80, A4[1])
            path.lineTo(A4[0], A4[1])
            path.close()
            canvas.setFillColor(HexColor('#304654')) # AppSecAI Blue
            canvas.drawPath(path, fill=1, stroke=0)
            
            # Bottom Left Corner
            path = canvas.beginPath()
            path.moveTo(0, 80)
            path.lineTo(80, 0)
            path.lineTo(0, 0)
            path.close()
            canvas.setFillColor(HexColor('#be232f')) # Caze Red
            canvas.drawPath(path, fill=1, stroke=0)

            # --- Header ---
            logo_path = get_resource_path('Caze_Logo_transparent.png')
            if os.path.exists(logo_path):
                canvas.drawImage(logo_path, A4[0] - 2.5*inch, A4[1] - 1.2*inch, width=1.5*inch, preserveAspectRatio=True, mask='auto')
            
            # --- Footer ---
            canvas.setStrokeColor(light_gray)
            canvas.line(1*inch, 0.8*inch, A4[0] - 1*inch, 0.8*inch)
            
            # Confidentiality notice
            canvas.setFont('Helvetica-Bold', 8)
            canvas.setFillColor(HexColor('#B71C1C')) # Dark Red
            canvas.drawCentredString(A4[0]/2, 0.3*inch, "INTERNAL USE ONLY - PROPRIETARY AND CONFIDENTIAL")
            
            # Branding: Caze (Red) AppSecAI (Blue)
            canvas.setFont('Helvetica-Bold', 8)
            
            # Caze
            canvas.setFillColor(HexColor('#be232f'))
            canvas.drawString(1*inch, 0.5*inch, "Caze")
            
            # AppSecAI
            canvas.setFillColor(HexColor('#304654'))
            canvas.drawString(1*inch + 22, 0.5*inch, "AppSecAI") # Offset manually
            
            # Page number
            page_num = canvas.getPageNumber()
            canvas.setFillColor(neutral_gray)
            canvas.setFont('Helvetica', 8)
            canvas.drawRightString(A4[0] - 1*inch, 0.5*inch, f"Page {page_num}")
            
            canvas.restoreState()

        # Get metadata and report focus
        metadata = self.report_data['metadata']
        report_focus = metadata.get('report_focus', 'comprehensive')
        vuln_analysis = self.report_data.get('vulnerability_analysis', {})
        controls_data = self.report_data.get('security_controls', {})

        # Title page and Logo
                # --- Cover Page ---
        story.append(Spacer(1, 1*inch))
        
        # Title (Top)
        # CazeLabs AppSecAI Security Assessment Report
        title_text = "CazeLabs AppSecAI Security Assessment Report"
        story.append(Paragraph(title_text, title_style))
        story.append(Spacer(1, 1.5*inch)) # Push date to middle
        
        # Date (Middle)
        date_style = ParagraphStyle('DateStyle', parent=styles['Normal'], alignment=1, fontSize=14)
        scan_date_str = datetime.now().strftime('%B %d, %Y')
        story.append(Paragraph(scan_date_str, date_style))
        story.append(Spacer(1, 4*inch)) # Push logo/footer to bottom
        
        
        # Table of Contents
        story.append(PageBreak())
        story.append(Paragraph("Table of Contents", title_style))
        toc = TableOfContents()
        toc.dotsMinLevel = 0
        toc.levelStyles = [
            ParagraphStyle(fontName='Helvetica-Bold', fontSize=12, name='TOCHeading1', leftIndent=20, firstLineIndent=-20, spaceBefore=5, leading=14),
            ParagraphStyle(fontName='Helvetica', fontSize=10, name='TOCHeading2', leftIndent=40, firstLineIndent=-20, spaceBefore=0, leading=12),
        ]
        story.append(toc)
        story.append(PageBreak())

        # --- Prepare Data for Executive Summary and Tables ---
        all_vulns = vuln_analysis.get('top_vulnerabilities', []) + vuln_analysis.get('below_threshold_vulnerabilities', [])
        
        # Initialize counts
        dast_stats = {'total': 0, 'high': 0, 'medium': 0, 'low': 0, 'informational': 0}
        sast_stats = {'total': 0, 'high': 0, 'medium': 0, 'low': 0, 'informational': 0}
        sca_stats = {'total': 0, 'high': 0, 'medium': 0, 'low': 0, 'informational': 0}
        
        for v in all_vulns:
            v_type = str(v.get('type', 'SAST')).upper()  # Default to SAST if not specified
            risk = v.get('enhanced_risk_level', v.get('risk', 'Low')).title()
            if risk == 'Info': risk = 'Informational'
            
            if v_type == 'DAST':
                dast_stats['total'] += 1
                if risk in ['Critical', 'High']: dast_stats['high'] += 1
                elif risk == 'Medium': dast_stats['medium'] += 1
                elif risk == 'Low': dast_stats['low'] += 1
                elif risk == 'Informational': dast_stats['informational'] += 1
            elif v_type == 'SCA':
                sca_stats['total'] += 1
                if risk in ['Critical', 'High']: sca_stats['high'] += 1
                elif risk == 'Medium': sca_stats['medium'] += 1
                elif risk == 'Low': sca_stats['low'] += 1
                elif risk == 'Informational': sca_stats['informational'] += 1
            else:
                sast_stats['total'] += 1
                if risk in ['Critical', 'High']: sast_stats['high'] += 1
                elif risk == 'Medium': sast_stats['medium'] += 1
                elif risk == 'Low': sast_stats['low'] += 1
                elif risk == 'Informational': sast_stats['informational'] += 1

        pr_links = self._get_pr_links()
        pr_count = len(pr_links)

        # 1. Introduction
        story.append(Paragraph("1. Introduction", heading_style))
        
        if report_focus == 'dast_focused':
            intro_text = """
            AppSecAI is an advanced security posture management platform designed to identify, prioritize, and remediate vulnerabilities in your applications. This report outlines the security health of your application, highlighting critical risks and providing actionable recommendations for remediation. It presents the results of a Dynamic Application Security Testing (DAST) assessment conducted using OWASP ZAP, with additional risk-based prioritization performed by CazeAppSecAI.
            <br/><br/>
            The objective of this assessment is to:<br/>
            • Identify security vulnerabilities in the running application<br/>
            • Prioritize findings based on exposure and application context<br/>
            • Provide actionable remediation recommendations<br/>
            • Improve runtime security posture<br/>
            <br/>
            CazeAppSecAI enhances traditional DAST outputs by applying a context-aware prioritization model. This report includes DAST findings.
            """
        elif report_focus == 'sast_focused':
            intro_text = """
            AppSecAI is an advanced security posture management platform designed to identify, prioritize, and remediate vulnerabilities in your applications. This report outlines the security health of your application, highlighting critical risks and providing actionable recommendations for remediation. It presents the results of a Static Application Security Testing (SAST) assessment conducted using SonarQube, with additional risk-based prioritization performed by CazeAppSecAI.
            <br/><br/>
            The objective of this assessment is to:<br/>
            • Identify security vulnerabilities in the application source code<br/>
            • Prioritize findings based on application context and risk factors<br/>
            • Provide actionable remediation guidance<br/>
            • Generate automated Pull Requests (where applicable) for high-risk findings<br/>
            <br/>
            CazeAppSecAI enhances traditional SAST outputs by applying a context-aware prioritization model. This report includes SAST findings.
            """
        elif report_focus == 'sca_focused':
            intro_text = """
            AppSecAI is an advanced security posture management platform designed to identify, prioritize, and remediate vulnerabilities in your applications. This report outlines the security health of your application, highlighting critical risks and providing actionable recommendations for remediation. It presents the results of a Software Composition Analysis (SCA) assessment based on a Trivy report, with additional risk-based prioritization performed by CazeAppSecAI.
            <br/><br/>
            The objective of this assessment is to:<br/>
            • Identify vulnerabilities in third-party dependencies and packages<br/>
            • Prioritize findings based on real deployment context (exposure, controls, runtime)<br/>
            • Provide actionable remediation guidance (upgrade/fix versions, risk rationale)<br/>
            • Improve overall dependency security posture<br/>
            <br/>
            CazeAppSecAI enhances traditional SCA outputs by applying a context-aware prioritization model. This report includes SCA findings from Trivy.
            """
        else:
            # Unified or Comprehensive - Combine objectives professionally
            intro_text = """
            AppSecAI is an advanced security posture management platform designed to identify, prioritize, and remediate vulnerabilities in your applications. This report outlines the security health of your application, highlighting critical risks and providing actionable recommendations for remediation. It presents the combined results of Static Application Security Testing (SAST) conducted using SonarQube and Dynamic Application Security Testing (DAST) conducted using OWASP ZAP, with additional risk-based prioritization performed by CazeAppSecAI.
            <br/><br/>
            The objective of this assessment is to:<br/>
            • Identify security vulnerabilities in both the application source code and the running application<br/>
            • Prioritize findings based on application context, exposure, and risk factors<br/>
            • Provide actionable remediation guidance and recommendations<br/>
            • Generate automated Pull Requests (where applicable) for high-risk findings<br/>
            • Improve overall security posture and runtime protection<br/>
            <br/>
            CazeAppSecAI enhances traditional SAST and DAST outputs by applying a context-aware prioritization model. This report includes both SAST and DAST findings.
            """

        story.append(Paragraph(intro_text, normal_style))
        story.append(Spacer(1, 20))
        
        # 2. Executive Summary Overhaul
        story.append(Paragraph("2. AppSecAI Executive Summary", heading_style))
        story.append(Spacer(1, 10))
        
        # 2.1 Assessment Overview
        story.append(Paragraph("2.1 Assessment Overview", subheading_style))
        overview_bullets = []
        
        # Populate Assessment Overview details carefully based on report type
        if report_focus == 'dast_focused':
             target_url = metadata.get('target_url', 'Not specified')
             overview_bullets.append(f"• Application URL: {target_url}")
             
        elif report_focus == 'sast_focused':
             # For SAST, prioritize App Name, Repo, Branch
             app_name = metadata.get('product_name', 'The Application')
             repo_name = metadata.get('repository', 'Not specified')
             branch_name = metadata.get('branch', 'main')
             
             overview_bullets.append(f"• Application Name: {app_name}")
             overview_bullets.append(f"• Repository: {repo_name}")
             overview_bullets.append(f"• Branch / Commit: {branch_name}")
             
        elif report_focus == 'sca_focused':
             # For SCA, show artifact/package information
             app_name = metadata.get('product_name', 'The Application')
             artifact = metadata.get('artifact', 'Not specified')
             
             overview_bullets.append(f"• Application Name: {app_name}")
             overview_bullets.append(f"• Artifact: {artifact}")
             
        else: # Unified/Comprehensive
             app_name = metadata.get('product_name', 'The Application')
             target_url = metadata.get('target_url', 'Not specified')
             repo_name = metadata.get('repository', 'Not specified')
             
             overview_bullets.append(f"• Application Name: {app_name}")
             overview_bullets.append(f"• Application URL: {target_url}")
             overview_bullets.append(f"• Repository: {repo_name}")

        scan_date_formatted = datetime.now().strftime('%B %d, %Y')
        overview_bullets.append(f"• Scan Date: {scan_date_formatted}")
        
        if report_focus == 'dast_focused':
            overview_bullets.append("• Tool Used: OWASP ZAP")
        elif report_focus == 'sast_focused':
            overview_bullets.append("• Tool Used: SonarQube")
        elif report_focus == 'sca_focused':
            overview_bullets.append("• Tool Used: Trivy")
        else:
            overview_bullets.append("• Tools Used: OWASP ZAP, SonarQube")
            
        overview_bullets.append("• Prioritization Engine: CazeAppSecAI")
        
        for bullet in overview_bullets:
            story.append(Paragraph(bullet, normal_style))
        story.append(Spacer(1, 15))
        
        # 2.2 Findings Summary
        story.append(Paragraph("2.2 Findings Summary", subheading_style))
        TABLE_WIDTH = 6.0*inch
        
        if report_focus == 'dast_focused':
            findings_data = [
                [Paragraph("<b>Metric</b>", normal_style), Paragraph("<b>Count</b>", normal_style)],
                ["Total DAST Findings", str(dast_stats['total'])],
                ["High / Critical (Post-Prioritization)", str(dast_stats['high'])],
                ["Medium", str(dast_stats['medium'])],
                ["Low", str(dast_stats['low'])],
                ["Informational", str(dast_stats['informational'])]
            ]
        elif report_focus == 'sast_focused':
            findings_data = [
                [Paragraph("<b>Metric</b>", normal_style), Paragraph("<b>Count</b>", normal_style)],
                ["Total Findings", str(sast_stats['total'])],
                ["High / Critical", str(sast_stats['high'])],
                ["Medium", str(sast_stats['medium'])],
                ["Low", str(sast_stats['low'])],
                ["Informational", str(sast_stats['informational'])],
                ["Pull Requests Generated", str(pr_count)]
            ]
        elif report_focus == 'sca_focused':
            # Get SCA stats - use original count for total, severity distribution for breakdown
            sca_severity = self._analyze_severity_distribution()
            # Use original count if available, otherwise fall back to loaded data count
            sca_total_original = self.sca_original_count if self.sca_original_count > 0 else len(self.sca_data)
            sca_high = sca_severity.get('Critical', 0) + sca_severity.get('High', 0)
            sca_medium = sca_severity.get('Medium', 0)
            sca_low = sca_severity.get('Low', 0)
            sca_info = sca_severity.get('Informational', 0)
            
            findings_data = [
                [Paragraph("<b>Metric</b>", normal_style), Paragraph("<b>Count</b>", normal_style)],
                ["Total SCA Findings (Original)", str(sca_total_original)],
                ["High / Critical (Post-Prioritization)", str(sca_high)],
                ["Medium", str(sca_medium)],
                ["Low", str(sca_low)],
                ["Informational", str(sca_info)]
            ]
        else:
            # Unified/Comprehensive Table - Combine both
            findings_data = [
                [Paragraph("<b>Metric</b>", normal_style), Paragraph("<b>Count</b>", normal_style)],
                ["Total Findings (Combined)", str(dast_stats['total'] + sast_stats['total'])],
                ["High / Critical (Post-Prioritization)", str(dast_stats['high'] + sast_stats['high'])],
                ["Medium (Combined)", str(dast_stats['medium'] + sast_stats['medium'])],
                ["Low (Combined)", str(dast_stats['low'] + sast_stats['low'])],
                ["Informational (Combined)", str(dast_stats['informational'] + sast_stats['informational'])],
                ["Pull Requests Generated", str(pr_count)]
            ]
            
        findings_table = Table(findings_data, colWidths=[4.0*inch, 2.0*inch])
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), primary_color),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 0.5, neutral_gray),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(findings_table)
        story.append(Spacer(1, 20))
        
        # LLM Summary - Removed as per user feedback in V14
        # exec_summary = self.report_data['executive_summary']
        # story.append(Paragraph("<b>Security Posture Assessment:</b>", normal_style))
        # story.append(Paragraph(exec_summary['security_posture'], normal_style))
        # story.append(Spacer(1, 20))
        
        # Key Concerns
        # Key Concerns - Disabled as per user feedback
        # if report_focus != 'unified' and exec_summary['key_concerns']:
        #     story.append(Paragraph("Key Concerns:", subheading_style))
        #     for concern in exec_summary['key_concerns']:
        #         story.append(Paragraph(f"• {concern}", normal_style))
        #     story.append(Spacer(1, 20))
        # Vulnerability Analysis - Handle unified reports differently
        # 3. AppSecAI scoring methodology & framework
        story.append(Paragraph("3. AppSecAI scoring methodology & framework", heading_style))
        scoring_text = "To provide a clear and actionable security assessment, AppSecAI applies a contextual prioritization framework to all identified vulnerabilities. This process converts raw scanner data into a prioritized roadmap for remediation."
        story.append(Paragraph(scoring_text, normal_style))
        story.append(Spacer(1, 10))

        risk_header = "ZAP/SONAR Severity"
        if report_focus == 'sast_focused': risk_header = "SonarQube Severity"
        elif report_focus == 'dast_focused': risk_header = "ZAP Severity"
        elif report_focus == 'sca_focused': risk_header = "Trivy Severity"

        # Terminology Table
        term_data = [
            [Paragraph("<b>Terminology</b>", header_cell_style), Paragraph("<b>Description</b>", header_cell_style)],
            [Paragraph(f"<b>{risk_header}</b>", normal_style), Paragraph("The original risk level identified by the scanning engine based on standard vulnerability signatures.", normal_style)],
            [Paragraph("<b>AppSecAI Severity</b>", normal_style), Paragraph("The reassessed severity after analyses vulnerabilities using application context, runtime exposure, exploitability and business risk.", normal_style)]
            # [Paragraph("<b>AppSecAI Score</b>", normal_style), Paragraph("A numerical priority index (0.00-10.00) used for precise remediation ordering.", normal_style)]
        ]
        # Methodology Table Style
        methodology_table_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), primary_color),
            ('GRID', (0, 0), (-1, -1), 0.5, neutral_gray),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('TOPPADDING', (0, 1), (-1, -1), 8),
        ])

        # Terminology Table
        term_table = Table(term_data, colWidths=[2.3*inch, 3.7*inch])
        term_table.setStyle(methodology_table_style)
        story.append(term_table)
        story.append(Spacer(1, 15))

        # Scoring Range Legend
        # story.append(Paragraph("<b>AppSecAI Scoring Legend:</b>", subheading_style))
        legend_data = [
            [Paragraph("<b>Risk Level</b>", header_cell_style), Paragraph("<b>AppSecAI Score Range</b>", header_cell_style)],
            [Paragraph("Critical", normal_style), "8.50 - 10.00"],
            [Paragraph("High", normal_style), "7.50 - 8.49"],
            [Paragraph("Medium", normal_style), "5.00 - 7.49"],
            [Paragraph("Low", normal_style), "2.50 - 4.99"],
            [Paragraph("Informational", normal_style), "< 2.50"]
        ]
        legend_table = Table(legend_data, colWidths=[2.3*inch, 3.7*inch])
        legend_table.setStyle(methodology_table_style)
        # story.append(legend_table)
        # story.append(Spacer(1, 15))

        # Scoring Methodology
        story.append(Paragraph("<b>Prioritization Methodology:</b>", subheading_style))
        methodology_text = "Vulnerabilities are analyzed against the application's specific risk context. A finding is classified as 'Actionable' and included in the Top Findings if it meets the defined prioritization threshold, ensuring focus on issues with the highest potential impact and likelihood of exploitation."
        story.append(Paragraph(methodology_text, normal_style))
        
        bullets = [
            "• <b>Internet Exposure & Network Placement:</b> Vulnerabilities in public or DMZ zones are prioritized.",
            "• <b>Data Classification:</b> Findings affecting PII or Confidential data receive higher scores.",
            "• <b>Business Criticality:</b> Critical business logic components are prioritized over auxiliary services.",
            "• <b>Defense-in-Depth:</b> Scores are adjusted based on the presence (or absence) of mitigating controls like WAF or MFA."
        ]
        for b in bullets:
            story.append(Paragraph(b, normal_style))
        story.append(Spacer(1, 25))


        # ==========================================
        # SECTION 4: Vulnerability Analysis
        # Setup element buffers for conditional layout
        # ==========================================
        top_vulns = self.report_data.get('vulnerability_analysis', {}).get('top_vulnerabilities', [])
        below_threshold_vulns = self.report_data.get('vulnerability_analysis', {}).get('below_threshold_vulnerabilities', [])
        has_top_vulns = len(top_vulns) > 0


        opt_elements = []
        if has_top_vulns:
            # 4. AppSecAI Vulnerability Analysis & Top Findings (prioritized)
            opt_elements.append(Paragraph("4. AppSecAI Vulnerability Analysis & Top Findings (prioritized)", heading_style))
            opt_elements.append(Spacer(1, 10))


            # V15: Workload Optimization & Cost Impact
            optimization_stats = self._calculate_workload_optimization()
            
            opt_elements.append(Paragraph("<b>Workload Optimization & Cost Impact:</b>", subheading_style))
            opt_elements.append(Paragraph("The following table quantifies the productivity gains and cost savings achieved by applying the AppSecAI prioritization framework. By filtering out low-impact findings and automating remediation paths, organizations can significantly reduce manual triage and fix efforts.", normal_style))
            opt_elements.append(Spacer(1, 10))
            
            opt_data = [
                [Paragraph("<b>Metric</b>", header_cell_style), Paragraph("<b>Before</b>", header_cell_style), Paragraph("<b>After (With AppSecAI)</b>", header_cell_style), Paragraph("<b>Reduction/Savings</b>", header_cell_style)],
                ["Total Findings", str(optimization_stats['t_total']), str(optimization_stats['t_prioritized']), f"{optimization_stats['reduction_pct']:.0f}%"],
                ["Triage Hours", f"{optimization_stats['triage_before']:.1f} hrs", f"{optimization_stats['triage_after']:.1f} hrs", f"{optimization_stats['triage_saved']:.1f} hrs saved"],
                ["Fix Hours", f"{optimization_stats['fix_before']:.1f} hrs", f"{optimization_stats['fix_after']:.1f} hrs", f"{optimization_stats['fix_saved']:.1f} hrs saved"],
                [Paragraph("<b>Total Effort</b>", normal_style), f"{optimization_stats['total_effort_before']:.1f} hrs", f"{optimization_stats['total_effort_after']:.1f} hrs", Paragraph(f"<b>{optimization_stats['total_saved']:.1f} hrs saved</b>", normal_style)],
                [Paragraph("<b>Estimated Cost</b>", normal_style), f"${optimization_stats['cost_before']:,.0f}", f"${optimization_stats['cost_after']:,.0f}", Paragraph(f"<b>${optimization_stats['cost_saved']:,.0f} saved</b>", normal_style)]
            ]
        
            opt_table = Table(opt_data, colWidths=[1.8*inch, 1.2*inch, 1.2*inch, 1.8*inch])
            opt_table.setStyle(methodology_table_style)
            opt_elements.append(opt_table)
            opt_elements.append(Spacer(1, 20))
        
        # Create a side-by-side Severity Distribution with a Chart
        severity_elements_list = []
        top_findings_elements = []
        bt_elements = []
        pr_elements = []


        severity_dist = vuln_analysis['severity_distribution']
        total_vulns = sum(severity_dist.values())
        
        if total_vulns > 0:

            
            top_vulns = self.report_data.get('vulnerability_analysis', {}).get('top_vulnerabilities', [])
            below_vulns = self.report_data.get('vulnerability_analysis', {}).get('below_threshold_vulnerabilities', [])
            all_vulns_for_stats = top_vulns + below_vulns
            
            # Determine how many sections to render
            sections_to_render = []
            if report_focus == 'unified':
                # Separate DAST and SAST explicitly for unified reports
                dast_vulns = [v for v in all_vulns_for_stats if v.get('type') == 'DAST']
                sast_vulns = [v for v in all_vulns_for_stats if v.get('type') == 'SAST']
                sections_to_render.append({'title': 'ZAP', 'vulns': dast_vulns, 'header': 'ZAP Count', 'chart_label': 'Original (ZAP)'})
                sections_to_render.append({'title': 'SonarQube', 'vulns': sast_vulns, 'header': 'SonarQube Count', 'chart_label': 'Original (Sonar)'})
            else:
                # Run once for specific reports
                if report_focus == 'dast_focused':
                    col_header = "ZAP Count"
                    chart_label = "Original (ZAP)"
                elif report_focus == 'sast_focused':
                    col_header = "SonarQube Count"
                    chart_label = "Original (SonarQube)"
                elif report_focus == 'sca_focused':
                    col_header = "Trivy Count"
                    chart_label = "Original (Trivy)"
                else:
                    # Default for comprehensive/other reports
                    col_header = "Vulnerability Count"
                    chart_label = "Original"
                
                sections_to_render.append({'title': 'Findings', 'vulns': all_vulns_for_stats, 'header': col_header, 'chart_label': chart_label})


            for section in sections_to_render:
                vulns_to_process = section['vulns']
                if not vulns_to_process:
                    continue  # Skip if no findings for this section
                    
                severity_order = ['Critical', 'High', 'Medium', 'Low', 'Informational']
                before_counts = {s: 0 for s in severity_order}
                after_counts = {s: 0 for s in severity_order}
                
                for v in vulns_to_process:
                    # Before: Original Risk
                    orig = v.get('original_risk', v.get('risk', 'Low'))
                    if not orig or orig == 'Unknown': orig = 'Low'
                    orig = str(orig).title()
                    if orig == 'Info': orig = 'Informational'
                    if orig in before_counts:
                        before_counts[orig] += 1
                    
                    # After: Enhanced Risk (Only count if it passed threshold)
                    if v in top_vulns:
                        after = v.get('enhanced_risk_level', v.get('risk', 'Low'))
                        if not after: after = 'Low'
                        after = str(after).title()
                        if after == 'Info': after = 'Informational'
                        if after in after_counts:
                            after_counts[after] += 1
                
                # Table Data
                severity_table_data = [['Severity', section['header'], 'AppSecAI Count (Prioritized)']]
                
                # Chart Data
                before_chart_data = []
                before_chart_colors = []
                after_chart_data = []
                after_chart_colors = []
                
                color_map = {
                    'Critical': HexColor('#B71C1C'), # Dark Red
                    'High': HexColor('#E64A19'),     # Deep Orange
                    'Medium': HexColor('#FBC02D'),   # Yellow
                    'Low': HexColor('#388E3C'),      # Green
                    'Informational': HexColor('#1976D2') # Blue
                }


                for sev in severity_order:
                    b_count = before_counts[sev]
                    a_count = after_counts[sev]
                    
                    if b_count > 0 or a_count > 0:
                         severity_table_data.append([sev, str(b_count), str(a_count)])
                    
                    if b_count > 0:
                        before_chart_data.append(b_count)
                        before_chart_colors.append(color_map.get(sev, colors.gray))
                    if a_count > 0:
                        after_chart_data.append(a_count)
                        after_chart_colors.append(color_map.get(sev, colors.gray))


                # Severity table styling
                sev_table = Table(severity_table_data, colWidths=[1.8*inch, 2.0*inch, 2.4*inch])
                sev_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), primary_color),
                    ('TEXTCOLOR', (0, 0), (-1, 0), white),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('GRID', (0, 0), (-1, -1), 0.5, neutral_gray),
                    ('BACKGROUND', (0, 1), (-1, -1), white),
                ]))


                # Create Charts side-by-side
                d_before = Drawing(150, 150)
                pc_before = Pie()
                pc_before.x = 25; pc_before.y = 25; pc_before.width = 100; pc_before.height = 100
                pc_before.data = before_chart_data
                pc_before.labels = None
                for i, color in enumerate(before_chart_colors): pc_before.slices[i].fillColor = color
                d_before.add(pc_before)
                
                d_after = Drawing(150, 150)
                pc_after = Pie()
                pc_after.x = 25; pc_after.y = 25; pc_after.width = 100; pc_after.height = 100
                pc_after.data = after_chart_data
                pc_after.labels = None
                for i, color in enumerate(after_chart_colors): pc_after.slices[i].fillColor = color
                d_after.add(pc_after)
                
                # Create Legends with Percentages
                def get_percentage_text(counts):
                    total = sum(counts.values())
                    if total == 0: return "No data available"
                    lines = []
                    for sev in severity_order:
                        count = counts.get(sev, 0)
                        pct = (count / total * 100) if total > 0 else 0
                        lines.append(f"• {sev}: {pct:.1f}% ({count})")
                    return "<br/>".join(lines)
                
                before_pct_text = get_percentage_text(before_counts)
                after_pct_text = get_percentage_text(after_counts)
                
                legend_style = ParagraphStyle('LegendStyle', parent=styles['Normal'], fontSize=8, leading=10, alignment=TA_LEFT, leftIndent=25)
                legend_before = Paragraph(before_pct_text, legend_style)
                legend_after = Paragraph(after_pct_text, legend_style)
                
                label_before = Paragraph(f"<b>{section['chart_label']}</b>", styles['Normal'])
                label_after = Paragraph("<b>AppSecAI (Prioritized)</b>", styles['Normal'])
                
                chart_table = Table([
                    [label_before, label_after], 
                    [d_before, d_after],
                    [legend_before, legend_after]
                ], colWidths=[3*inch, 3*inch])
                chart_table.setStyle(TableStyle([
                    ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                    ('TOPPADDING', (0,2), (-1,2), 10),
                ]))


                # Build full section
                severity_elements = []
                if report_focus == 'unified':
                    severity_elements.append(Paragraph(f"<b>{section['title']} Severity Distribution:</b>", styles['Heading3']))
                    severity_elements.append(Spacer(1, 10))
                severity_elements.extend([sev_table, Spacer(1, 15), chart_table])
                
                severity_elements_list.append(KeepTogether(severity_elements))
                severity_elements_list.append(Spacer(1, 25))
        
        # Unified Report sections

        if report_focus == 'unified':
            # ROI section removed in V10
            
            if has_top_vulns:
                top_findings_elements.append(Paragraph("4.1 Top Vulnerabilities (prioritized)", subheading_style))
                top_findings_elements.append(Spacer(1, 10))
                top_findings_elements.append(Spacer(1, 10))
            
            # Get vulnerabilities
            all_vulns = vuln_analysis['top_vulnerabilities']
            sast_vulns = [v for v in all_vulns if v.get('type') == 'SAST']
            dast_vulns = [v for v in all_vulns if v.get('type') == 'DAST']
            
            if has_top_vulns:
                top_findings_elements.append(Paragraph(f"Showing {len(all_vulns)} vulnerabilities above threshold (SAST: {len(sast_vulns)}, DAST: {len(dast_vulns)}):", normal_style))
                top_findings_elements.append(Spacer(1, 10))
            
            # PR links will be displayed in a separate section after the vulnerability table
            # No need to map individual vulnerabilities to PRs
            
            # Create unified table with Type column
            if all_vulns:
                risk_header = "ZAP/SonarQube Severity"
                if report_focus == 'sast_focused':
                    risk_header = "SonarQube Severity"
                elif report_focus == 'dast_focused':
                    risk_header = "ZAP Severity"
                elif report_focus == 'sca_focused':
                    risk_header = "Trivy Severity"

                vuln_data = [[
                    Paragraph('Vulnerability', header_cell_style),
                    Paragraph('Type', header_cell_style),
                    Paragraph(risk_header, header_cell_style),
                    Paragraph('AppSecAI Severity', header_cell_style)
                    # Paragraph('AppSecAI Score', header_cell_style)
                ]]
                row_styles = []
                current_row = 1
                
                for vuln in all_vulns:
                    vuln_type = vuln.get('type', 'Unknown')
                    
                    # Get risks
                    if vuln_type == 'SAST':
                        adjusted_risk = self._get_sast_adjusted_severity(vuln)
                        # Extract the original unprioritized severity from SonarQube
                        raw_original = vuln.get('original_risk', vuln.get('vulnerabilityProbability', 'LOW'))
                        original_risk = self._map_sonar_severity(raw_original)
                    else:
                        adjusted_risk = self._get_dast_adjusted_severity(vuln)
                        original_risk = vuln.get('original_risk', vuln.get('risk', 'Unknown'))
                        original_risk = original_risk.title()


                    
                    # Create name
                    vuln_name = vuln['name']
                    category = vuln.get('category', '')
                    full_name = f"{html.escape(vuln_name, quote=True)} : {html.escape(category, quote=True)}" if category and category != 'Other' else html.escape(vuln_name, quote=True)
                    
                    vuln_style = ParagraphStyle('VulnStyle', parent=styles['Normal'], fontSize=10, leading=12)
                    
                    # Add main row with Type column
                    vuln_data.append([
                        Paragraph(full_name, vuln_style),
                        vuln_type,
                        original_risk,
                        adjusted_risk
                        # str(vuln['score'])
                    ])
                    current_row += 1
                    
                    # Add SAST details
                    if vuln_type == 'SAST':
                        details = []
                        
                        # Remove any 'links' field that might exist
                        if 'links' in vuln:
                            del vuln['links']
                        if 'pr_links' in vuln:
                            del vuln['pr_links']
                        
                        if vuln.get('component'):
                            details.append(f"<b>component:</b> {html.escape(str(vuln['component']), quote=True)}")
                        if vuln.get('start_line'):
                            details.append(f"<b>start_line:</b> {html.escape(str(vuln['start_line']), quote=True)}")
                        if vuln.get('end_line') and str(vuln.get('end_line')) != str(vuln.get('start_line')):
                            details.append(f"<b>end_line:</b> {html.escape(str(vuln['end_line']), quote=True)}")
                        if vuln.get('line'):
                            details.append(f"<b>line:</b> {html.escape(str(vuln['line']), quote=True)}")
                        if vuln.get('original_message'):
                            details.append(f"<b>message:</b> {html.escape(str(vuln['original_message']), quote=True)}")
                        
                        # Add PR link if available (accurately mapped)
                        pr_url = vuln.get('pr_url', '')
                        if pr_url:
                            if isinstance(pr_url, list):
                                pr_url = pr_url[0] if pr_url else ''
                            if pr_url and isinstance(pr_url, str):
                                details.append(f"<b>PR:</b> <link href='{pr_url}' color='blue'>{pr_url}</link>")
                        
                        # Add justification - prioritize AI justification if available
                        ai_just = vuln.get('ai_justification')
                        enhanced_justs = vuln.get('enhanced_justifications', [])
                        
                        if ai_just:
                            safe_ai_just = html.escape(str(ai_just), quote=True)
                            details.append(f"<b>Justification:</b> {safe_ai_just}")
                        elif enhanced_justs:
                            # Filter to show only the relevant modifiers
                            relevant_justs = [self._clean_justification_text(j) for j in enhanced_justs if 'Risk Increasing Factors:' in j or 'Risk Decreasing Factors:' in j or 'Applied Modifiers:' in j or '•' in j]
                            if relevant_justs:
                                justification = '\n'.join(relevant_justs)
                                import re
                                justification = re.sub(r'links?:\s*\n\s*\d+\..*', '', justification, flags=re.IGNORECASE | re.DOTALL)
                                justification = re.sub(r'https?://[^\s]+', '', justification)
                                justification = justification.strip()
                                
                                if len(justification) > 400:
                                    justification = justification[:397] + "..."
                                
                                # Escape HTML but keep our line breaks
                                safe_justification = html.escape(justification, quote=True).replace('\n', '<br/>')
                                
                                if safe_justification:
                                    details.append(f"<b>Justification:</b> {safe_justification}")
                        else:
                            # Fallback to framework_justification if enhanced not available
                            justification = vuln.get('framework_justification', '') or vuln.get('justification', '')
                            if justification:
                                import re
                                justification = re.sub(r'links?:\s*\n\s*\d+\..*', '', justification, flags=re.IGNORECASE | re.DOTALL)
                                justification = re.sub(r'https?://[^\s]+', '', justification)
                                justification = justification.strip()
                                
                                if len(justification) > 200:
                                    justification = justification[:197] + "..."
                                
                                # Escape HTML
                                safe_justification = html.escape(justification, quote=True)
                                
                                if safe_justification:
                                    details.append(f"<b>Justification:</b> {safe_justification}")
                        
                        if details:
                            detail_style = ParagraphStyle('DetailStyle', parent=styles['Normal'], fontSize=9, leading=11, leftIndent=10, textColor=HexColor('#2E86AB'))
                            vuln_data.append([Paragraph("<br/>".join(details), detail_style), '', '', ''])
                            row_styles.append(current_row)
                            current_row += 1
                    
                    # Add DAST instances, justification, and recommendations
                    if vuln_type == 'DAST':
                        # Add source URL for DAST vulnerabilities (multi-URL support)
                        source_url = vuln.get('source_url')
                        if source_url:
                            safe_source_url = html.escape(source_url, quote=True)
                            source_text = f"<b>Scanned URL:</b> {safe_source_url}"
                            source_style = ParagraphStyle('SourceStyle', parent=styles['Normal'], fontSize=9, leading=11, leftIndent=10, textColor=HexColor('#666666'))
                            vuln_data.append([Paragraph(source_text, source_style), '', '', ''])
                            row_styles.append(current_row)
                            current_row += 1
                        
                        dast_details = []
                        
                        # Add Issue Description
                        message = vuln.get('original_message', '')
                        if message:
                            if len(message) > 400:
                                message = message[:397] + "..."
                            safe_message = html.escape(message, quote=True).replace('\n', '<br/>')
                            dast_details.append(f"<b>Issue Description:</b> {safe_message}")
                            
                        # Add instances
                        if vuln.get('instances'):
                            urls = list(set([inst.get('URL', '') for inst in vuln['instances'] if inst.get('URL')]))
                            if urls:
                                # Limit instances to prevent PDF layout errors
                                MAX_INSTANCES = 10
                                MAX_CONTENT_LENGTH = 1500  # Additional safety limit
                                inst_text = f"<b>Instances ({len(urls)}):</b>"
                                
                                # Display limited number of instances
                                displayed_urls = urls[:MAX_INSTANCES]
                                for url in displayed_urls:
                                    # Truncate long URLs to prevent horizontal overflow
                                    display_url = url if len(url) <= 80 else url[:77] + "..."
                                    inst_text += f"<br/>• {display_url}"
                                
                                # Add overflow indicator if there are more instances
                                if len(urls) > MAX_INSTANCES:
                                    inst_text += f"<br/>• ...and {len(urls) - MAX_INSTANCES} more instances"
                                
                                # Additional safety: truncate if content is still too long
                                if len(inst_text) > MAX_CONTENT_LENGTH:
                                    inst_text = inst_text[:MAX_CONTENT_LENGTH-3] + "..."
                                
                                dast_details.append(inst_text)
                        
                        # Add justification - prioritize AI justification if available
                        ai_just = vuln.get('ai_justification')
                        enhanced_justs = vuln.get('enhanced_justifications', [])
                        
                        if ai_just:
                            safe_ai_just = html.escape(str(ai_just), quote=True)
                            dast_details.append(f"<b>Justification:</b> {safe_ai_just}")
                        elif enhanced_justs:
                            # Filter to show only the relevant modifiers
                            relevant_justs = [self._clean_justification_text(j) for j in enhanced_justs if 'Risk Increasing Factors:' in j or 'Risk Decreasing Factors:' in j or 'Applied Modifiers:' in j or '•' in j]
                            if relevant_justs:
                                justification = '\n'.join(relevant_justs)
                                if len(justification) > 400:
                                    justification = justification[:397] + "..."
                                # Escape HTML but keep our line breaks
                                safe_justification = html.escape(justification, quote=True).replace('\n', '<br/>')
                                dast_details.append(f"<b>Justification:</b> {safe_justification}")
                        else:
                            # Fallback to framework_justification if enhanced not available
                            justification = vuln.get('framework_justification', '') or vuln.get('justification', '')
                            # Filter out generic/boilerplate justifications
                            if justification and 'separation model' in justification:
                                justification = ""
                                
                            if justification:
                                if len(justification) > 200:
                                    justification = justification[:197] + "..."
                                dast_details.append(f"<b>Justification:</b> {justification}")
                        
                        # Add security recommendation from DAST scan data
                        # Check the 'solution' field which comes from ZAP HTML report
                        recommendation = vuln.get('solution', '')
                        
                        if not recommendation:
                            # If no solution, check if there's a recommendation object from LLM
                            rec_obj = vuln.get('recommendation', {})
                            if isinstance(rec_obj, dict):
                                recommendation = rec_obj.get('fix', '') or rec_obj.get('solution', '')
                            elif isinstance(rec_obj, str):
                                recommendation = rec_obj
                        
                        if recommendation and isinstance(recommendation, str):
                            if len(recommendation) > 300:
                                recommendation = recommendation[:297] + "..."
                            safe_rec = html.escape(recommendation, quote=True).replace('\n', '<br/>')
                            dast_details.append(f"<b>Security Recommendation:</b> {safe_rec}")
                        
                        if dast_details:
                            dast_style = ParagraphStyle('DASTStyle', parent=styles['Normal'], fontSize=9, leading=11, leftIndent=10, textColor=HexColor('#2E86AB'))
                            # Use combined details directly as parts are already safely truncated
                            combined_details = "<br/>".join(dast_details)
                            vuln_data.append([Paragraph(combined_details, dast_style), '', '', ''])
                            row_styles.append(current_row)
                            current_row += 1
                    
                    # Add SCA details: Package, Version, Artifact, and Justification
                    if vuln_type == 'SCA':
                        sca_details = []
                        
                        # Add artifact and package info
                        artifact_name = vuln.get('artifact', 'Unknown Analysis Target')
                        package_name = vuln.get('package_name', 'Unknown Package')
                        installed = vuln.get('installed_version', 'N/A')
                        fixed = vuln.get('fixed_version', 'N/A')
                        
                        sca_details.append(f"<b>Artifact:</b> {html.escape(artifact_name, quote=True)}")
                        sca_details.append(f"<b>Package:</b> {html.escape(package_name, quote=True)} (Installed: {html.escape(installed, quote=True)})")
                        
                        # Add description from Trivy raw JSON if available
                        description = vuln.get('description', '')
                        if description:
                            description = str(description)
                            if len(description) > 300:
                                description = description[:297] + "..."
                            safe_desc = html.escape(description, quote=True)
                            sca_details.append(f"<b>Description:</b> {safe_desc}")
                        if fixed and fixed != 'N/A' and str(fixed).strip():
                            sca_details.append(f"<b>Recommendation:</b> Update to <font color='green'>{html.escape(fixed, quote=True)}</font>")
                        else:
                            sca_details.append(f"<b>Recommendation:</b> <font color='green'>Upgrade to latest version</font>")
                        
                        # Add justification - prioritize AI justification if available
                        ai_just = vuln.get('ai_justification')
                        enhanced_justs = vuln.get('enhanced_justifications', [])
                        
                        if ai_just:
                            safe_ai_just = html.escape(str(ai_just), quote=True)
                            sca_details.append(f"<b>Justification:</b> {safe_ai_just}")
                        elif enhanced_justs:
                            relevant_justs = [self._clean_justification_text(j) for j in enhanced_justs if 'Risk Increasing Factors:' in j or 'Risk Decreasing Factors:' in j or 'Applied Modifiers:' in j or '•' in j]
                            if relevant_justs:
                                justification = '\n'.join(relevant_justs)
                                if len(justification) > 400:
                                    justification = justification[:397] + "..."
                                safe_justification = html.escape(justification, quote=True).replace('\n', '<br/>')
                                sca_details.append(f"<b>Justification:</b> {safe_justification}")
                        
                        # Add recommendation / reference
                        primary_url = vuln.get('primary_url')
                        if primary_url:
                            safe_url = html.escape(str(primary_url), quote=True)
                            sca_details.append(f"<b>Reference:</b> <link href='{safe_url}' color='blue'>{safe_url}</link>")
                        
                        if sca_details:
                            sca_style = ParagraphStyle('SCAStyle', parent=styles['Normal'], fontSize=9, leading=11, leftIndent=10, textColor=HexColor('#2E86AB'))
                            vuln_data.append([Paragraph("<br/>".join(sca_details), sca_style), '', '', ''])
                            row_styles.append(current_row)
                            current_row += 1
                
                # Create table
                # Unified Table Alignment: Ensure headers do not overlap
                vuln_table = Table(vuln_data, colWidths=[3.0*inch, 0.6*inch, 1.1*inch, 1.3*inch], repeatRows=1)
                vuln_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), primary_color),
                    ('TEXTCOLOR', (0, 0), (-1, 0), white),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('FONTSIZE', (0, 1), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('TOPPADDING', (0, 1), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 0.5, neutral_gray),
                ]))

                # Stripe rows for better readability
                stripe_style = []
                for i in range(1, len(vuln_data)):
                    if i % 2 == 0:
                        stripe_style.append(('BACKGROUND', (0, i), (-1, i), light_gray))
                    else:
                        stripe_style.append(('BACKGROUND', (0, i), (-1, i), white))
                
                # Apply row stripes
                vuln_table.setStyle(TableStyle(stripe_style))

                # Apply detail row styles
                detail_stripe = []
                for row_idx in row_styles:
                    detail_stripe.extend([
                        ('SPAN', (0, row_idx), (-1, row_idx)),
                        ('BACKGROUND', (0, row_idx), (-1, row_idx), HexColor('#F0F4F8')), # Light blue-gray for details
                        ('TOPPADDING', (0, row_idx), (-1, row_idx), 10),
                        ('BOTTOMPADDING', (0, row_idx), (-1, row_idx), 10),
                        ('FONTSIZE', (0, row_idx), (-1, row_idx), 8),
                    ])
                
                vuln_table.setStyle(TableStyle(detail_stripe))
                top_findings_elements.append(vuln_table)
            
            # 5.3 General Findings (Below Threshold)
            bt_elements.append(Spacer(1, 25))
            below_threshold_vulns = self.report_data['vulnerability_analysis'].get('below_threshold_vulnerabilities', [])
            if below_threshold_vulns:
                if has_top_vulns:
                    bt_elements.append(Paragraph("4.3 General Findings (Below Prioritization Threshold)", styles['Heading3']))
                else:
                    bt_elements.append(Paragraph("4. General Findings (Below Prioritization Threshold)", heading_style))
                bt_elements.append(Paragraph(f"The following {len(below_threshold_vulns)} findings were analyzed but scored below the critical prioritization threshold ({self._get_threshold_score()}):", normal_style))
                bt_elements.append(Spacer(1, 10))
                
                risk_header = "ZAP/SONAR Severity"
                if report_focus == 'sast_focused': risk_header = "SonarQube Severity"
                elif report_focus == 'dast_focused': risk_header = "ZAP Severity"
                elif report_focus == 'sca_focused': risk_header = "Trivy Severity"
                
                bt_data = [[
                    Paragraph('Vulnerability', header_cell_style),
                    Paragraph('Type', header_cell_style),
                    Paragraph(risk_header, header_cell_style),
                    Paragraph('AppSecAI Severity', header_cell_style)
                    # Paragraph('AppSecAI Score', header_cell_style)
                ]]
                bt_row_styles = []
                current_bt_row = 1
                for vuln in below_threshold_vulns:
                    v_name = vuln['name']
                    v_cat = vuln.get('category', '')
                    v_full = f"{html.escape(v_name, quote=True)} : {html.escape(v_cat, quote=True)}" if v_cat and v_cat != 'Other' else html.escape(v_name, quote=True)
                    v_type = vuln.get('type', 'Unknown')
                    
                    if v_type == 'SAST':
                        raw_orig = vuln.get('original_risk_level', vuln.get('vulnerabilityProbability', 'LOW'))
                        orig_risk_display = self._map_sonar_severity(raw_orig)
                    else:
                        orig_risk_display = str(vuln.get('original_risk_level', vuln.get('risk', 'Low'))).title()
                    
                    # Add justifications - prioritize AI justification
                    ai_just = vuln.get('ai_justification')
                    enhanced_justs = vuln.get('enhanced_justifications', [])
                    
                    if ai_just:
                        safe_ai_just = html.escape(str(ai_just), quote=True)
                        details.append(f"<b>Justification:</b> {safe_ai_just}")
                    elif enhanced_justs:
                        relevant_justs = [self._clean_justification_text(j) for j in enhanced_justs if 'Risk Increasing Factors:' in j or 'Risk Decreasing Factors:' in j or 'Applied Modifiers:' in j or '•' in j]
                        if relevant_justs:
                            justification = '\n'.join(relevant_justs)
                            if len(justification) > 400:
                                justification = justification[:397] + "..."
                            safe_justification = html.escape(justification, quote=True).replace('\n', '<br/>')
                            details.append(f"<b>Justification:</b> {safe_justification}")
                    
                    bt_data.append([
                        Paragraph(v_full, ParagraphStyle('BTStyle', parent=styles['Normal'], fontSize=9)),
                        v_type,
                        orig_risk_display,
                        vuln.get('risk', 'Low')
                        # f"{vuln['score']:.2f}"
                    ])
                    current_bt_row += 1
                    
                    details = []
                    if v_type == 'SAST':
                        if vuln.get('component'): details.append(f"<b>component:</b> {html.escape(str(vuln['component']), quote=True)}")
                        if vuln.get('start_line'): details.append(f"<b>start_line:</b> {html.escape(str(vuln['start_line']), quote=True)}")
                        if vuln.get('end_line') and str(vuln.get('end_line')) != str(vuln.get('start_line')): details.append(f"<b>end_line:</b> {html.escape(str(vuln['end_line']), quote=True)}")
                        if vuln.get('line'): details.append(f"<b>line:</b> {html.escape(str(vuln['line']), quote=True)}")
                        
                        message = vuln.get('original_message', '')
                        if message: details.append(f"<b>message:</b> {html.escape(str(message), quote=True)}")
                        pr_url = vuln.get('pr_url', '')
                        if pr_url:
                            if isinstance(pr_url, list): pr_url = pr_url[0] if pr_url else ''
                            if pr_url and isinstance(pr_url, str): details.append(f"<b>PR:</b> <link href='{pr_url}' color='blue'>{pr_url}</link>")
                    elif v_type == 'DAST':
                        source_url = vuln.get('source_url')
                        if source_url: details.append(f"<b>Scanned URL:</b> {html.escape(source_url, quote=True)}")
                        
                        message = vuln.get('original_message', '')
                        if message:
                            if len(message) > 400: message = message[:397] + "..."
                            safe_message = html.escape(message, quote=True).replace('\n', '<br/>')
                            details.append(f"<b>Issue Description:</b> {safe_message}")
                            
                        # Add justification
                        enhanced_justs = vuln.get('enhanced_justifications', [])
                        if enhanced_justs:
                            relevant_justs = [self._clean_justification_text(j) for j in enhanced_justs if 'Risk Increasing Factors:' in j or 'Risk Decreasing Factors:' in j or 'Applied Modifiers:' in j or '•' in j]
                            if relevant_justs:
                                justification = '\n'.join(relevant_justs)
                                if len(justification) > 400:
                                    justification = justification[:397] + "..."
                                safe_justification = html.escape(justification, quote=True).replace('\n', '<br/>')
                                details.append(f"<b>Justification:</b> {safe_justification}")
                        else:
                            justification = vuln.get('framework_justification', '') or vuln.get('justification', '')
                            if justification and 'separation model' in justification:
                                justification = ""
                            if justification:
                                if len(justification) > 200:
                                    justification = justification[:197] + "..."
                                details.append(f"<b>Justification:</b> {html.escape(justification, quote=True)}")

                        # Add security recommendation
                        recommendation = vuln.get('solution', '')
                        if not recommendation:
                            rec_obj = vuln.get('recommendation', {})
                            if isinstance(rec_obj, dict):
                                recommendation = rec_obj.get('fix', '') or rec_obj.get('solution', '')
                            elif isinstance(rec_obj, str):
                                recommendation = rec_obj
                        
                        if recommendation and isinstance(recommendation, str):
                            if len(recommendation) > 300:
                                recommendation = recommendation[:297] + "..."
                            safe_recommendation = html.escape(recommendation, quote=True).replace('\n', '<br/>')
                            details.append(f"<b>Security Recommendation:</b> {safe_recommendation}")
                        
                        instances = vuln.get('instances', [])
                        if instances:
                            urls = list(set([inst.get('URL', '') for inst in instances if inst.get('URL')]))
                            if urls:
                                inst_text = f"<b>Instances ({len(urls)}):</b>"
                                for url in urls[:10]:
                                    display_url = url if len(url) <= 80 else url[:77] + "..."
                                    inst_text += f"<br/>• {html.escape(display_url, quote=True)}"
                                if len(urls) > 10:
                                    inst_text += f"<br/>• ...and {len(urls) - 10} more instances"
                                details.append(inst_text)
                        
                    elif v_type == 'SCA':
                        artifact_name = vuln.get('artifact', 'Unknown')
                        package_name = vuln.get('package_name', 'Unknown')
                        installed = vuln.get('installed_version', 'N/A')
                        fixed = vuln.get('fixed_version', 'N/A')
                        
                        details.append(f"<b>Artifact:</b> {html.escape(artifact_name, quote=True)}")
                        details.append(f"<b>Package:</b> {html.escape(package_name, quote=True)} (Installed: {html.escape(installed, quote=True)})")
                        if fixed and fixed != 'N/A':
                            details.append(f"<b>Fixed Version:</b> {html.escape(fixed, quote=True)}")
                        
                        primary_url = vuln.get('primary_url')
                        if primary_url:
                            safe_url = html.escape(str(primary_url), quote=True)
                            details.append(f"<b>Reference:</b> <link href='{safe_url}' color='blue'>{safe_url}</link>")
                    
                    if details:
                        detail_style = ParagraphStyle('DetailStyle', parent=styles['Normal'], fontSize=8, leading=10, leftIndent=10, textColor=HexColor('#555555'))
                        bt_data.append([Paragraph("<br/>".join(details), detail_style), '', '', ''])
                        bt_row_styles.append(current_bt_row)
                        current_bt_row += 1
                
                # Match the exact column sizing of the top vulnerabilities table
                bt_table = Table(bt_data, colWidths=[3.0*inch, 0.6*inch, 1.1*inch, 1.3*inch])
                
                table_style = [
                    ('BACKGROUND', (0, 0), (-1, 0), primary_color),
                    ('TEXTCOLOR', (0, 0), (-1, 0), white),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('GRID', (0, 0), (-1, -1), 0.5, neutral_gray),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('FONTSIZE', (0, 1), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('TOPPADDING', (0, 1), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
                ]
                
                for i in range(1, len(bt_data)):
                    if i % 2 == 0: table_style.append(('BACKGROUND', (0, i), (-1, i), light_gray))
                    else: table_style.append(('BACKGROUND', (0, i), (-1, i), white))
                    
                for row_idx in bt_row_styles:
                    table_style.extend([
                        ('SPAN', (0, row_idx), (-1, row_idx)),
                        ('BACKGROUND', (0, row_idx), (-1, row_idx), HexColor('#F0F4F8')),
                        ('TOPPADDING', (0, row_idx), (-1, row_idx), 8),
                        ('BOTTOMPADDING', (0, row_idx), (-1, row_idx), 8),
                    ])
                    
                bt_table.setStyle(TableStyle(table_style))
                bt_elements.append(bt_table)
            
            bt_elements.append(Spacer(1, 20))
            
            # Add Pull Requests section for unified reports if PR links exist
            pr_links = self._get_pr_links()
            if pr_links and has_top_vulns:
                pr_elements.append(Paragraph("Pull Requests", styles['Heading3']))
                pr_elements.append(Paragraph(f"The following pull requests were created to address SAST vulnerabilities:", styles['Normal']))
                pr_elements.append(Spacer(1, 10))
                
                # Create simple PR list
                for idx, (pr_num, pr_url) in enumerate(pr_links, start=1):
                    # Create clickable link
                    link_style = ParagraphStyle('LinkStyle', parent=styles['Normal'], fontSize=10, textColor=HexColor('#0066CC'))
                    pr_text = f"{idx}. PR #{pr_num}: <link href='{pr_url}' color='blue'>{pr_url}</link>"
                    pr_elements.append(Paragraph(pr_text, link_style))
                    pr_elements.append(Spacer(1, 5))
                
                pr_elements.append(Spacer(1, 15))
            
            # Removed AI Generated Fixes and Vulnerability Justifications sections
            # This information is now included directly in the vulnerability tables
            pr_elements.append(Spacer(1, 20))
        else:
            # NON-UNIFIED REPORT: Standard format with separate vulnerability table
            # Sections 3 (Scoring) and 4 (Vulnerability Analysis) are handled above
            
            # Detailed Findings Table
            if has_top_vulns:
                top_findings_elements.append(Paragraph("4.1 Top Vulnerabilities (prioritized)", subheading_style))
            
            # Show all vulnerabilities that meet the threshold (sorted by score)
            all_vulns = vuln_analysis.get('top_vulnerabilities', [])
            logger.info(f"Non-unified report: Found {len(all_vulns)} vulnerabilities in top_vulnerabilities")
            
            if all_vulns:
                # Count by risk level for summary
                critical_count = len([v for v in all_vulns if v.get('enhanced_risk_level') == 'Critical' or v.get('risk') == 'Critical'])
                high_count = len([v for v in all_vulns if v.get('enhanced_risk_level') == 'High' or v.get('risk') == 'High'])
                medium_count = len([v for v in all_vulns if v.get('enhanced_risk_level') == 'Medium' or v.get('risk') == 'Medium'])
                
                # Show summary based on what we have
                if has_top_vulns:
                    if critical_count > 0 or high_count > 0:
                        summary_parts = []
                        if critical_count > 0:
                            summary_parts.append(f"{critical_count} Critical")
                        if high_count > 0:
                            summary_parts.append(f"{high_count} High")
                        if medium_count > 0:
                            summary_parts.append(f"{medium_count} Medium")
                        
                        top_findings_elements.append(Paragraph(f"Showing all {len(all_vulns)} vulnerabilities above threshold", styles['Normal']))
                    else:
                        top_findings_elements.append(Paragraph(f"Showing all {len(all_vulns)} vulnerabilities above threshold:", styles['Normal']))
                
                top_vulns = all_vulns
            else:
                
                top_vulns = []
            
            if has_top_vulns:
                top_findings_elements.append(Spacer(1, 10))
            
            if top_vulns:
                # Get PR links mapped to specific SAST vulnerabilities
                # PR links will be displayed in a separate section after the vulnerability table
                # No need to map individual vulnerabilities to PRs
                
                risk_header = "ZAP/SonarQube Severity"
                if report_focus == 'sast_focused':
                    risk_header = "SonarQube Severity"
                elif report_focus == 'dast_focused':
                    risk_header = "ZAP Severity"
                elif report_focus == 'sca_focused':
                    risk_header = "Trivy Severity"
                    
                vuln_data = [[
                    Paragraph('Vulnerability', header_cell_style),
                    Paragraph(risk_header, header_cell_style),
                    Paragraph('AppSecAI Severity', header_cell_style)
                    # Paragraph('AppSecAI Score', header_cell_style)
                ]]
                row_styles = []
                current_row = 1
                
                # Dynamic Table Alignment for Non-Unified Reports
                # Vulnerability is 2.8, Tool Severity is 1.2, AI Severity is 1.2, Score is 1.0 (Total 6.2)
                vuln_table = Table(vuln_data, colWidths=[3.8*inch, 1.1*inch, 1.1*inch], repeatRows=1)
                for vuln in top_vulns:
                    # Calculate adjusted risk differently for SAST vs DAST vs SCA
                    if vuln.get('type') == 'SAST':
                        adjusted_risk = self._get_sast_adjusted_severity(vuln)
                        original_risk = vuln.get('original_risk', vuln.get('vulnerabilityProbability', 'Unknown'))
                        if original_risk:
                            original_risk = original_risk.title()
                    elif vuln.get('type') == 'SCA':
                        adjusted_risk = str(vuln.get('enhanced_risk_level', vuln.get('risk', 'Low'))).title()
                        original_risk = str(vuln.get('original_risk', vuln.get('original_risk_level', vuln.get('risk', 'Unknown')))).title()
                    else:
                        adjusted_risk = self._get_dast_adjusted_severity(vuln)
                        original_risk = vuln.get('original_risk', vuln.get('risk', 'Unknown'))
                    
                    # Create vulnerability name with category
                    vuln_name = vuln['name']
                    category = vuln.get('category', '')
                    if category and category != 'Other':
                        full_name = f"{html.escape(vuln_name, quote=True)} : {html.escape(category, quote=True)}"
                    else:
                        full_name = html.escape(vuln_name, quote=True)
                    
                    vuln_style = ParagraphStyle('VulnStyle', parent=styles['Normal'], fontSize=10, leading=12, leftIndent=0, rightIndent=0)
                    
                    # Add main vulnerability row
                    vuln_data.append([
                        Paragraph(full_name, vuln_style),
                        original_risk,
                        adjusted_risk
                        # str(vuln['score'])
                    ])
                    current_row += 1
                    
                    # Add SAST-specific details
                    if vuln.get('type') == 'SAST':
                        sast_details = []
                        
                        # Remove any 'links' field that might exist - we only use single 'pr_url'
                        if 'links' in vuln:
                            del vuln['links']
                        if 'pr_links' in vuln:
                            del vuln['pr_links']
                        
                        component = vuln.get('component', '')
                        if component:
                            sast_details.append(f"<b>component:</b> {component}")
                        
                        start_line = vuln.get('start_line', '')
                        end_line = vuln.get('end_line', '')
                        line = vuln.get('line', '')
                        
                        if start_line:
                            sast_details.append(f"<b>start_line:</b> {start_line}")
                        
                        if end_line and str(end_line) != str(start_line):
                            sast_details.append(f"<b>end_line:</b> {end_line}")
                        
                        if line:
                            sast_details.append(f"<b>line:</b> {line}")
                        
                        message = vuln.get('original_message', '')
                        if message:
                            sast_details.append(f"<b>message:</b> {message}")
                        
                        # Add PR link if available (accurately mapped)
                        pr_url = vuln.get('pr_url', '')
                        
                        if pr_url:
                            # Ensure pr_url is a string, not a list
                            if isinstance(pr_url, list):
                                pr_url = pr_url[0] if pr_url else ''
                            
                            if pr_url and isinstance(pr_url, str):
                                # Add ONLY the single mapped PR link
                                sast_details.append(f"<b>PR:</b> <link href='{pr_url}' color='blue'>{pr_url}</link>")
                        
                        # Add justification - prioritize AI justification if available
                        ai_just = vuln.get('ai_justification')
                        enhanced_justs = vuln.get('enhanced_justifications', [])
                        
                        if ai_just:
                            safe_ai_just = html.escape(str(ai_just), quote=True)
                            sast_details.append(f"<b>Justification:</b> {safe_ai_just}")
                        elif enhanced_justs:
                            # Filter to show only the relevant modifiers (risk increasing/decreasing factors or general modifiers)
                            relevant_justs = [self._clean_justification_text(j) for j in enhanced_justs if 'Risk Increasing Factors:' in j or 'Risk Decreasing Factors:' in j or 'Applied Modifiers:' in j or '•' in j]
                            if relevant_justs:
                                justification = '\n'.join(relevant_justs)
                                import re
                                justification = re.sub(r'links?:\s*\n\s*\d+\..*', '', justification, flags=re.IGNORECASE | re.DOTALL)
                                # Smarter URL removal: only remove the URL link, not the whole sentence
                                justification = re.sub(r'https?://[^\s]+', '', justification)
                                justification = justification.strip()
                                
                                if len(justification) > 400:
                                    justification = justification[:397] + "..."
                                
                                # Escape HTML to prevent any embedded HTML from breaking PDF generation
                                safe_justification = html.escape(justification, quote=True).replace('\n', '<br/>')
                                
                                if safe_justification:
                                    sast_details.append(f"<b>Justification:</b> {safe_justification}")
                        else:
                            # Fallback to framework_justification if enhanced not available
                            justification = vuln.get('framework_justification', '') or vuln.get('justification', '')
                            if justification:
                                import re
                                justification = re.sub(r'links?:\s*\n\s*\d+\..*', '', justification, flags=re.IGNORECASE | re.DOTALL)
                                justification = re.sub(r'https?://[^\s]+', '', justification)
                                justification = justification.strip()
                                
                                if len(justification) > 200:
                                    justification = justification[:197] + "..."
                                
                                if justification:
                                    safe_justification = html.escape(justification, quote=True)
                                    sast_details.append(f"<b>Justification:</b> {safe_justification}")
                        
                        if sast_details:
                            sast_text = "<br/>".join(sast_details)
                            sast_style = ParagraphStyle('SASTStyle', parent=styles['Normal'], fontSize=9, leading=11, leftIndent=10, textColor=HexColor('#2E86AB'))
                            vuln_data.append([Paragraph(sast_text, sast_style), '', ''])
                            row_styles.append(current_row)
                            current_row += 1
                    
                    # Add source URL for DAST vulnerabilities (multi-URL support)
                    source_url = vuln.get('source_url')
                    if source_url and vuln.get('type') == 'DAST':
                        # Escape HTML to prevent any embedded HTML from breaking PDF generation
                        safe_source_url = html.escape(source_url, quote=True)
                        source_text = f"<b>Scanned URL:</b> {safe_source_url}"
                        source_style = ParagraphStyle('SourceStyle', parent=styles['Normal'], fontSize=9, leading=11, leftIndent=10, textColor=HexColor('#666666'))
                        vuln_data.append([Paragraph(source_text, source_style), '', ''])
                        row_styles.append(current_row)
                        current_row += 1
                    
                    # Add instances row if vulnerability has instances (DAST vulnerabilities)
                    instances = vuln.get('instances', [])
                    if instances or vuln.get('type') == 'DAST':
                        dast_details = []
                        
                        # Add Issue Description
                        message = vuln.get('original_message', '')
                        if message:
                            if len(message) > 400:
                                message = message[:397] + "..."
                            safe_message = html.escape(message, quote=True).replace('\n', '<br/>')
                            dast_details.append(f"<b>Issue Description:</b> {safe_message}")
                        
                        # Add instances
                        if instances:
                            urls = []
                            for instance in instances:
                                url = instance.get('URL', '')
                                if url and url not in urls:
                                    urls.append(url)
                            
                            if urls:
                                # Limit instances to prevent PDF layout errors
                                MAX_INSTANCES = 10
                                MAX_CONTENT_LENGTH = 1500  # Additional safety limit
                                instances_text = f"<b>Instances ({len(urls)}):</b>"
                                
                                # Display limited number of instances
                                displayed_urls = urls[:MAX_INSTANCES]
                                for url in displayed_urls:
                                    # Truncate long URLs to prevent horizontal overflow
                                    display_url = url if len(url) <= 80 else url[:77] + "..."
                                    # Escape HTML to prevent XSS payloads from breaking PDF generation
                                    safe_url = html.escape(display_url, quote=True)
                                    instances_text += f"<br/>• {safe_url}"
                                
                                # Add overflow indicator if there are more instances
                                if len(urls) > MAX_INSTANCES:
                                    instances_text += f"<br/>• ...and {len(urls) - MAX_INSTANCES} more instances"
                                
                                # Additional safety: truncate if content is still too long
                                if len(instances_text) > MAX_CONTENT_LENGTH:
                                    instances_text = instances_text[:MAX_CONTENT_LENGTH-3] + "..."
                                
                                dast_details.append(instances_text)
                        
                        # Add justification for DAST - prioritize AI justification
                        if vuln.get('type') == 'DAST':
                            ai_just = vuln.get('ai_justification')
                            enhanced_justs = vuln.get('enhanced_justifications', [])
                            
                            if ai_just:
                                safe_ai_just = html.escape(str(ai_just), quote=True)
                                dast_details.append(f"<b>Justification:</b> {safe_ai_just}")
                            elif enhanced_justs:
                                # Filter to show only the relevant modifiers (risk increasing/decreasing factors or general modifiers)
                                relevant_justs = [self._clean_justification_text(j) for j in enhanced_justs if 'Risk Increasing Factors:' in j or 'Risk Decreasing Factors:' in j or 'Applied Modifiers:' in j or '•' in j]
                                if relevant_justs:
                                    justification = '\n'.join(relevant_justs)
                                    if len(justification) > 400:
                                        justification = justification[:397] + "..."
                                    # Escape HTML but keep our line breaks
                                    safe_justification = html.escape(justification, quote=True).replace('\n', '<br/>')
                                    dast_details.append(f"<b>Justification:</b> {safe_justification}")
                            else:
                                # Fallback to framework_justification if enhanced not available
                                justification = vuln.get('framework_justification', '') or vuln.get('justification', '')
                                # Filter out generic/boilerplate justifications
                                if justification and 'separation model' in justification:
                                    justification = ""
                                    
                                if justification:
                                    if len(justification) > 200:
                                        justification = justification[:197] + "..."
                                    safe_justification = html.escape(justification, quote=True)
                                    dast_details.append(f"<b>Justification:</b> {safe_justification}")
                            
                            # Add security recommendations for DAST
                            solution = vuln.get('solution', '')
                            if solution:
                                # Truncate long solutions
                                if len(solution) > 300:
                                    solution = solution[:297] + "..."
                                # Escape HTML to prevent any embedded HTML from breaking PDF generation
                                safe_solution = html.escape(solution, quote=True)
                                dast_details.append(f"<b>Recommendations:</b> {safe_solution}")
                        
                        if dast_details:
                            dast_text = "<br/>".join(dast_details)
                            # Use dast_text directly without risky truncation
                            instance_style = ParagraphStyle('InstanceStyle', parent=styles['Normal'], fontSize=9, leading=11, leftIndent=10, textColor=HexColor('#2E86AB'))
                            vuln_data.append([Paragraph(dast_text, instance_style), '', ''])
                            row_styles.append(current_row)
                            current_row += 1

                    # Add SCA details row if vulnerability is SCA
                    if vuln.get('type') == 'SCA':
                        sca_details = []
                        artifact_name = vuln.get('artifact', 'Unknown Analysis Target')
                        package_name = vuln.get('package_name', 'Unknown Package')
                        installed = vuln.get('installed_version', 'N/A')
                        fixed = vuln.get('fixed_version', 'N/A')
                        
                        sca_details.append(f"<b>Artifact:</b> {html.escape(artifact_name, quote=True)}")
                        sca_details.append(f"<b>Package:</b> {html.escape(package_name, quote=True)} (Installed: {html.escape(installed, quote=True)})")
                        
                        # Add description from Trivy raw JSON if available
                        description = vuln.get('description', '')
                        if description:
                            description = str(description)
                            if len(description) > 300:
                                description = description[:297] + "..."
                            safe_desc = html.escape(description, quote=True)
                            sca_details.append(f"<b>Description:</b> {safe_desc}")
                        if fixed and fixed != 'N/A' and str(fixed).strip():
                            sca_details.append(f"<b>Recommendation:</b> Update to <font color='green'>{html.escape(fixed, quote=True)}</font>")
                        else:
                            sca_details.append(f"<b>Recommendation:</b> <font color='green'>Upgrade to latest version</font>")
                        
                        # Add justification - prioritize AI justification
                        ai_just = vuln.get('ai_justification')
                        enhanced_justs = vuln.get('enhanced_justifications', [])
                        
                        if ai_just:
                            safe_ai_just = html.escape(str(ai_just), quote=True)
                            sca_details.append(f"<b>Justification:</b> {safe_ai_just}")
                        elif enhanced_justs:
                            relevant_justs = [self._clean_justification_text(j) for j in enhanced_justs if 'Risk Increasing Factors:' in j or 'Risk Decreasing Factors:' in j or 'Applied Modifiers:' in j or '•' in j]
                            if relevant_justs:
                                justification = '\n'.join(relevant_justs)
                                if len(justification) > 400:
                                    justification = justification[:397] + "..."
                                safe_justification = html.escape(justification, quote=True).replace('\n', '<br/>')
                                sca_details.append(f"<b>Justification:</b> {safe_justification}")

                        # Add reference
                        primary_url = vuln.get('primary_url')
                        if primary_url:
                            safe_url = html.escape(str(primary_url), quote=True)
                            sca_details.append(f"<b>Reference:</b> <link href='{safe_url}' color='blue'>{safe_url}</link>")
                        
                        if sca_details:
                            sca_style = ParagraphStyle('SCASTyleFocused', parent=styles['Normal'], fontSize=9, leading=11, leftIndent=10, textColor=HexColor('#2E86AB'))
                            vuln_data.append([Paragraph("<br/>".join(sca_details), sca_style), '', ''])
                            row_styles.append(current_row)
                            current_row += 1
                
                vuln_table = Table(vuln_data, colWidths=[3.8*inch, 1.1*inch, 1.1*inch], repeatRows=1)
                
                table_style = [
                    ('BACKGROUND', (0, 0), (-1, 0), primary_color),
                    ('TEXTCOLOR', (0, 0), (-1, 0), white),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('FONTSIZE', (0, 1), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('TOPPADDING', (0, 1), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 0.5, neutral_gray),
                ]
                
                # Stripe rows for better readability
                for i in range(1, len(vuln_data)):
                    if i % 2 == 0:
                        table_style.append(('BACKGROUND', (0, i), (-1, i), light_gray))
                    else:
                        table_style.append(('BACKGROUND', (0, i), (-1, i), white))

                for row_idx in row_styles:
                    table_style.extend([
                        ('SPAN', (0, row_idx), (-1, row_idx)),
                        ('BACKGROUND', (0, row_idx), (-1, row_idx), HexColor('#F0F4F8')),
                        ('TOPPADDING', (0, row_idx), (-1, row_idx), 10),
                        ('BOTTOMPADDING', (0, row_idx), (-1, row_idx), 10),
                        ('FONTSIZE', (0, row_idx), (-1, row_idx), 8),
                    ])
                
                vuln_table.setStyle(TableStyle(table_style))
                top_findings_elements.append(vuln_table)
            
            # 4.2 General Findings (Below Threshold)
            bt_elements.append(Spacer(1, 25))
            below_threshold_vulns = self.report_data['vulnerability_analysis'].get('below_threshold_vulnerabilities', [])
            if below_threshold_vulns:
                if has_top_vulns:
                    bt_elements.append(Paragraph("4.3 General Findings (Below Prioritization Threshold)", styles['Heading3']))
                else:
                    bt_elements.append(Paragraph("4. General Findings (Below Prioritization Threshold)", heading_style))
                bt_elements.append(Paragraph(f"The following {len(below_threshold_vulns)} findings were analyzed but scored below the critical prioritization threshold ({self._get_threshold_score()}):", normal_style))
                bt_elements.append(Spacer(1, 10))
                
                risk_header = "ZAP/SONAR Severity"
                if report_focus == 'sast_focused': risk_header = "SonarQube Severity"
                elif report_focus == 'dast_focused': risk_header = "ZAP Severity"
                elif report_focus == 'sca_focused': risk_header = "Trivy Severity"
                
                bt_data = [[
                    Paragraph('Vulnerability', header_cell_style),
                    Paragraph(risk_header, header_cell_style),
                    Paragraph('AppSecAI Severity', header_cell_style)
                    # Paragraph('AppSecAI Score', header_cell_style)
                ]]
                bt_row_styles = []
                current_bt_row = 1
                for vuln in below_threshold_vulns:
                    v_name = vuln['name']
                    v_cat = vuln.get('category', '')
                    v_full = f"{html.escape(v_name, quote=True)} : {html.escape(v_cat, quote=True)}" if v_cat and v_cat != 'Other' else html.escape(v_name, quote=True)
                    v_type = vuln.get('type', 'Unknown')
                    
                    bt_data.append([
                        Paragraph(v_full, ParagraphStyle('BTStyle', parent=styles['Normal'], fontSize=9)),
                        vuln.get('original_risk_level', vuln.get('risk', 'Low')),
                        vuln.get('risk', 'Low')
                        # f"{vuln['score']:.2f}"
                    ])
                    current_bt_row += 1
                    
                    details = []
                    if v_type == 'SAST':
                        if vuln.get('component'): details.append(f"<b>component:</b> {html.escape(str(vuln['component']), quote=True)}")
                        if vuln.get('start_line'): details.append(f"<b>start_line:</b> {html.escape(str(vuln['start_line']), quote=True)}")
                        if vuln.get('end_line') and str(vuln.get('end_line')) != str(vuln.get('start_line')): details.append(f"<b>end_line:</b> {html.escape(str(vuln['end_line']), quote=True)}")
                        if vuln.get('line'): details.append(f"<b>line:</b> {html.escape(str(vuln['line']), quote=True)}")
                        
                        message = vuln.get('original_message', '')
                        if message: details.append(f"<b>message:</b> {html.escape(str(message), quote=True)}")
                        
                        pr_url = vuln.get('pr_url', '')
                        if pr_url:
                            if isinstance(pr_url, list): pr_url = pr_url[0] if pr_url else ''
                            if pr_url and isinstance(pr_url, str): details.append(f"<b>PR:</b> <link href='{pr_url}' color='blue'>{pr_url}</link>")
                        
                        # [NEW] Add justification for SAST
                        ai_just = vuln.get('ai_justification')
                        if ai_just:
                            safe_ai_just = html.escape(str(ai_just), quote=True)
                            details.append(f"<b>Justification:</b> {safe_ai_just}")
                        else:
                            # Fallback to enhanced bullet points
                            enhanced_justs = vuln.get('enhanced_justifications', [])
                            if enhanced_justs:
                                relevant_justs = [self._clean_justification_text(j) for j in enhanced_justs if 'Risk ' in j or '•' in j]
                                if relevant_justs:
                                    justification = '\n'.join(relevant_justs)
                                    safe_just = html.escape(justification, quote=True).replace('\n', '<br/>')
                                    details.append(f"<b>Justification:</b> {safe_just}")

                    elif v_type == 'DAST':
                        source_url = vuln.get('source_url')
                        if source_url: details.append(f"<b>Scanned URL:</b> {html.escape(source_url, quote=True)}")
                        
                        message = vuln.get('original_message', '')
                        if message: details.append(f"<b>Description:</b> {html.escape(message, quote=True)}")
                        
                        instances = vuln.get('instances', [])
                        if instances:
                            urls = list(set([inst.get('URL', '') for inst in instances if inst.get('URL')]))
                            if urls:
                                inst_text = f"<b>Instances ({len(urls)}):</b>"
                                for url in urls[:10]:
                                    display_url = url if len(url) <= 80 else url[:77] + "..."
                                    inst_text += f"<br/>• {html.escape(display_url, quote=True)}"
                                if len(urls) > 10:
                                    inst_text += f"<br/>• ...and {len(urls) - 10} more instances"
                                details.append(inst_text)
                        
                        # Add justification - prioritize AI justification narrative
                        ai_just = vuln.get('ai_justification')
                        enhanced_justs = vuln.get('enhanced_justifications', [])
                        
                        if ai_just:
                            safe_ai_just = html.escape(str(ai_just), quote=True)
                            details.append(f"<b>Justification:</b> {safe_ai_just}")
                        elif enhanced_justs:
                            # Filter to show only the relevant modifiers
                            relevant_justs = [self._clean_justification_text(j) for j in enhanced_justs if 'Risk Increasing Factors:' in j or 'Risk Decreasing Factors:' in j or 'Applied Modifiers:' in j or '•' in j]
                            if relevant_justs:
                                justification = '\n'.join(relevant_justs)
                                if len(justification) > 400:
                                    justification = justification[:397] + "..."
                                # Escape HTML but keep our line breaks
                                safe_justification = html.escape(justification, quote=True).replace('\n', '<br/>')
                                details.append(f"<b>Justification:</b> {safe_justification}")

                        
                        # Add recommendations
                        solution = vuln.get('solution', '')
                        if solution:
                            if len(solution) > 300:
                                solution = solution[:297] + "..."
                            safe_solution = html.escape(solution, quote=True)
                            details.append(f"<b>Recommendations:</b> {safe_solution}")
                    
                    elif v_type == 'SCA':
                        artifact_name = vuln.get('artifact', 'Unknown')
                        package_name = vuln.get('package_name', 'Unknown')
                        installed = vuln.get('installed_version', 'N/A')
                        fixed = vuln.get('fixed_version', 'N/A')
                        
                        details.append(f"<b>Artifact:</b> {html.escape(artifact_name, quote=True)}")
                        details.append(f"<b>Package:</b> {html.escape(package_name, quote=True)} (Installed: {html.escape(installed, quote=True)})")
                        
                        # Add description from Trivy raw JSON if available
                        description = vuln.get('description', '')
                        if description:
                            description = str(description)
                            if len(description) > 300:
                                description = description[:297] + "..."
                            safe_desc = html.escape(description, quote=True)
                            details.append(f"<b>Description:</b> {safe_desc}")
                        
                        # Recommendation - use fixed version if available, otherwise generic fallback
                        if fixed and fixed != 'N/A' and str(fixed).strip():
                            details.append(f"<b>Recommendation:</b> Update to <font color='green'>{html.escape(fixed, quote=True)}</font>")
                        else:
                            details.append(f"<b>Recommendation:</b> <font color='green'>Upgrade to latest version</font>")
                        
                        primary_url = vuln.get('primary_url')
                        if primary_url:
                            safe_url = html.escape(str(primary_url), quote=True)
                            details.append(f"<b>Reference:</b> <link href='{safe_url}' color='blue'>{safe_url}</link>")
                        
                        # [NEW] Add justification for SCA - prioritize AI justification narrative
                        ai_just = vuln.get('ai_justification')
                        if ai_just:
                            safe_ai_just = html.escape(str(ai_just), quote=True)
                            details.append(f"<b>Justification:</b> {safe_ai_just}")
                        else:
                            enhanced_justs = vuln.get('enhanced_justifications', [])
                            if enhanced_justs:
                                relevant_justs = [self._clean_justification_text(j) for j in enhanced_justs if 'Risk ' in j or '•' in j]
                                if relevant_justs:
                                    justification = '\n'.join(relevant_justs)
                                    safe_just = html.escape(justification, quote=True).replace('\n', '<br/>')
                                    details.append(f"<b>Justification:</b> {safe_just}")

                    
                    if details:
                        detail_style = ParagraphStyle('DetailStyle', parent=styles['Normal'], fontSize=8, leading=10, leftIndent=10, textColor=HexColor('#555555'))
                        bt_data.append([Paragraph("<br/>".join(details), detail_style), '', ''])
                        bt_row_styles.append(current_bt_row)
                        current_bt_row += 1
                
                bt_table = Table(bt_data, colWidths=[3.8*inch, 1.1*inch, 1.1*inch])
                
                table_style = [
                    ('BACKGROUND', (0, 0), (-1, 0), primary_color),
                    ('TEXTCOLOR', (0, 0), (-1, 0), white),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('GRID', (0, 0), (-1, -1), 0.5, neutral_gray),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('FONTSIZE', (0, 1), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('TOPPADDING', (0, 1), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
                ]
                
                for i in range(1, len(bt_data)):
                    if i % 2 == 0: table_style.append(('BACKGROUND', (0, i), (-1, i), light_gray))
                    else: table_style.append(('BACKGROUND', (0, i), (-1, i), white))
                    
                for row_idx in bt_row_styles:
                    table_style.extend([
                        ('SPAN', (0, row_idx), (-1, row_idx)),
                        ('BACKGROUND', (0, row_idx), (-1, row_idx), HexColor('#F0F4F8')),
                        ('TOPPADDING', (0, row_idx), (-1, row_idx), 8),
                        ('BOTTOMPADDING', (0, row_idx), (-1, row_idx), 8),
                    ])
                    
                bt_table.setStyle(TableStyle(table_style))
                bt_elements.append(bt_table)
            
            bt_elements.append(Spacer(1, 20))
            
            # Add Pull Requests section for SAST-only reports
            if report_focus == 'sast_focused':
                pr_links = self._get_pr_links()
                if pr_links and has_top_vulns:
                    pr_elements.append(Paragraph("Pull Requests", styles['Heading3']))
                    pr_elements.append(Paragraph(f"The following pull requests were created to address SAST vulnerabilities:", styles['Normal']))
                    pr_elements.append(Spacer(1, 10))
                    
                    # Create simple PR list
                    for idx, (pr_num, pr_url) in enumerate(pr_links, start=1):
                        # Create clickable link
                        link_style = ParagraphStyle('LinkStyle', parent=styles['Normal'], fontSize=10, textColor=HexColor('#0066CC'))
                        pr_text = f"{idx}. PR #{pr_num}: <link href='{pr_url}' color='blue'>{pr_url}</link>"
                        pr_elements.append(Paragraph(pr_text, link_style))
                        pr_elements.append(Spacer(1, 5))
                    
                    pr_elements.append(Spacer(1, 15))


        # ====================================================
        # ASSEMBLE THE FINAL VULNERABILITY ANALYSIS SECTION
        # ====================================================
        if has_top_vulns:
            # Case A Layout (Top Vulns Exist)
            story.extend(opt_elements)            # 4. AppSecAI Analysis + Workload Table
            story.extend(top_findings_elements)   # 4.1 Top Vulnerabilities Table
            if severity_elements_list:            
                story.append(Paragraph("4.2 Severity Distribution", styles['Heading3']))
                story.extend(severity_elements_list)  # Severity Tables & Pie Charts
            story.extend(bt_elements)             # 4.3 General Findings Table
            story.extend(pr_elements)             # Pull Requests
        else:
            # Case B Layout (No Top Vulns)
            story.extend(bt_elements)             # 4. General Findings Table
            if severity_elements_list:
                story.append(Paragraph("4.1 Severity Distribution", styles['Heading3']))
                story.extend(severity_elements_list)  # Severity Tables & Pie Charts
        
        # 5. Expanded Environment & Security Controls / SCA Context Settings
        if report_focus != 'sca_focused':
            story.append(Paragraph("5. Deployment Settings & Controls", heading_style))
            
            lead_statement = "The following tables provide a comprehensive overview of the application's deployment environment and the security controls currently in place. These settings serve as critical context for the AppSecAI prioritization engine, influencing the final severity and risk scores of all identified vulnerabilities."
            story.append(Paragraph(lead_statement, normal_style))
            story.append(Spacer(1, 15))
            
            # 5.1 Environment Controls
            env_conf = controls_data.get('environment', {})
            env_rows = [
                [Paragraph("<b>Environment Controls:</b>", metadata_label_style), ""],
                [Paragraph("deployment_type (public/Internal_only):", normal_style), Paragraph(str(env_conf.get('deployment_type', 'unknown')).title(), normal_style)],
                [Paragraph("internet_exposure (true/false):", normal_style), Paragraph(str(env_conf.get('internet_exposure', 'unknown')).lower(), normal_style)],
                [Paragraph("api_type (rest/graphql/soap/none):", normal_style), Paragraph(str(env_conf.get('api_type', 'unknown')), normal_style)],
                [Paragraph("https_enabled (true/false):", normal_style), Paragraph(str(env_conf.get('https_enabled', 'unknown')).lower(), normal_style)],
                [Paragraph("data_classification (public/internal/confidential/restricted):", normal_style), Paragraph(str(env_conf.get('data_classification', 'unknown')), normal_style)],
                [Paragraph("pii_present (true/false):", normal_style), Paragraph(str(env_conf.get('pii_present', 'unknown')).lower(), normal_style)],
                [Paragraph("logging_audit_required (true/false):", normal_style), Paragraph(str(env_conf.get('logging_audit_required', 'unknown')).lower(), normal_style)],
                [Paragraph("encryption_in_transit_required (true/false):", normal_style), Paragraph(str(env_conf.get('encryption_in_transit_required', 'unknown')).lower(), normal_style)],
                [Paragraph("encryption_at_rest_required (true/false):", normal_style), Paragraph(str(env_conf.get('encryption_at_rest_required', 'unknown')).lower(), normal_style)],
                [Paragraph("system_criticality (low/medium/high/business_critical):", normal_style), Paragraph(str(env_conf.get('system_criticality', 'unknown')), normal_style)],
            ]
            
            env_table = Table(env_rows, colWidths=[3.5*inch, 2.5*inch])
            table_style = TableStyle([
                ('SPAN', (0, 0), (1, 0)),
                ('BACKGROUND', (0, 0), (1, 0), primary_color),
                ('BOX', (0, 0), (-1, -1), 0.5, primary_color),
                ('GRID', (0, 1), (-1, -1), 0.5, neutral_gray),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('TOPPADDING', (0,0), (-1,-1), 8),
                ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ])
            env_table.setStyle(table_style)
            story.append(env_table)
            story.append(Spacer(1, 15))
            
            # 5.2 Runtime Controls
            runtime_conf = controls_data.get('runtime', {})
            runtime_rows = [[Paragraph("<b>Runtime Controls:</b>", metadata_label_style), ""]]
            runtime_fields = [
                ('containerized (true/false)', 'containerized'),
                ('root_container (true/false)', 'root_container'),
                ('container_sig_enforced (true/false)', 'container_sig_enforced'),
                ('runtime_monitoring_enabled (true/false)', 'runtime_monitoring_enabled'),
                ('service_authn (true/false)', 'service_authn'),
                ('rate_limiting_enabled (true/false)', 'rate_limiting_enabled'),
                ('memory_limits_enforced (true/false)', 'memory_limits_enforced'),
                ('cpu_limits_enforced (true/false)', 'cpu_limits_enforced')
            ]
            for label, key in runtime_fields:
                val = str(runtime_conf.get(key, 'unknown')).lower()
                runtime_rows.append([Paragraph(label + ":", normal_style), Paragraph(val, normal_style)])
                
            runtime_table = Table(runtime_rows, colWidths=[3.5*inch, 2.5*inch])
            runtime_table.setStyle(table_style)
            story.append(runtime_table)
            story.append(Spacer(1, 15))
            
            # 5.3 Service Controls
            service_conf = controls_data.get('service', {})
            service_rows = [[Paragraph("<b>Service Controls:</b>", metadata_label_style), ""]]
            service_fields = [
                ('service_authn (true/false)', 'service_authn'),
                ('rate_limiting_enabled (true/false)', 'rate_limiting_enabled'),
                ('memory_limits_enforced (true/false)', 'memory_limits_enforced'),
                ('cpu_limits_enforced (true/false)', 'cpu_limits_enforced')
            ]
            for label, key in service_fields:
                val = str(service_conf.get(key, 'unknown')).lower()
                service_rows.append([Paragraph(label + ":", normal_style), Paragraph(val, normal_style)])
                
            service_table = Table(service_rows, colWidths=[3.5*inch, 2.5*inch])
            service_table.setStyle(table_style)
            story.append(service_table)
            story.append(Spacer(1, 15))
            
            # 5.4 Security Controls
            sec_conf = controls_data.get('security_controls', {})
            sec_rows = [[Paragraph("<b>Security Controls:</b>", metadata_label_style), ""]]
            sec_fields = [
                ('rbac_enabled (true/false)', 'rbac_enabled'),
                ('waf_enabled (true/false)', 'waf_enabled'),
                ('ids_enabled (true/false)', 'ids_enabled'),
                ('nfw_enabled (true/false)', 'nfw_enabled'),
                ('sso_enabled (true/false)', 'sso_enabled'),
                ('mfa_required_for_admin (true/false)', 'mfa_required_for_admin'),
                ('infrastructure_as_code_scan_enabled (true/false)', 'infrastructure_as_code_scan_enabled'),
                ('dependency_vulnerability_scan_enabled (true/false)', 'dependency_vulnerability_scan_enabled'),
                ('container_image_scan_enabled (true/false)', 'container_image_scan_enabled'),
                ('api_input_validation (true/false)', 'api_input_validation'),
                ('api_authentication_required (true/false)', 'api_authentication_required'),
                ('secrets_vault_enabled (true/false)', 'secrets_vault_enabled'),
                ('rate_limiting_enabled (true/false)', 'rate_limiting_enabled'),
                ('cloud_security_posture_management (true/false)', 'cloud_security_posture_management'),
                ('business_logic_testing (true/false)', 'business_logic_testing'),
                ('data_loss_prevention (true/false)', 'data_loss_prevention'),
                ('network_segmentation (true/false)', 'network_segmentation'),
                ('privileged_access_management (true/false)', 'privileged_access_management'),
                ('api_security_gateway (true/false)', 'api_security_gateway'),
                ('third_party_risk_assessment (true/false)', 'third_party_risk_assessment'),
                ('input_validation (true/false)', 'input_validation'),
                ('key_management_system (true/false)', 'key_management_system')
            ]
            for label, key in sec_fields:
                val = str(sec_conf.get(key, 'unknown')).lower()
                sec_rows.append([Paragraph(label + ":", normal_style), Paragraph(val, normal_style)])
                
            sec_table = Table(sec_rows, colWidths=[3.5*inch, 2.5*inch])
            sec_table.setStyle(table_style)
            story.append(sec_table)
            story.append(Spacer(1, 20))
            
            # 5.5 Deployment Controls Summary (V7)
            story.append(Spacer(1, 15))
            story.append(Paragraph("<b>Deployment Controls Summary</b>", styles['Normal']))
            story.append(Spacer(1, 5))
            summary_table = self._get_deployment_controls_summary(controls_data, header_cell_style, normal_style, primary_color, white, neutral_gray)
            story.append(summary_table)
            story.append(Spacer(1, 20))
        
        else:
            # SCA-focused report gets SCA Context Settings instead
            story.append(Paragraph("5. SCA Context Settings & Controls", heading_style))
            
            lead_statement = "The following tables provide a comprehensive overview of the software supply chain and dependency management controls currently in place. These settings serve as critical context for the AppSecAI prioritization engine, influencing the final severity and risk scores of all identified SCA vulnerabilities."
            story.append(Paragraph(lead_statement, normal_style))
            story.append(Spacer(1, 15))
            
            sca_conf = controls_data.get('sca_context', {})
            
            # Helper to create styled tables
            def _create_sca_table(title, section_key, fields):
                section_data = sca_conf.get(section_key, {})
                rows = [[Paragraph(f"<b>{title}:</b>", metadata_label_style), ""]]
                
                configured_count = 0
                for label, key in fields:
                    raw_val = section_data.get(key, 'unknown')
                    if raw_val != 'unknown' and raw_val != '':
                        configured_count += 1
                    
                    val = str(raw_val).lower() if isinstance(raw_val, bool) else str(raw_val)
                    rows.append([Paragraph(label + ":", normal_style), Paragraph(val, normal_style)])
                
                table = Table(rows, colWidths=[4.0*inch, 2.0*inch])
                table_style = TableStyle([
                    ('SPAN', (0, 0), (1, 0)),
                    ('BACKGROUND', (0, 0), (1, 0), primary_color),
                    ('BOX', (0, 0), (-1, -1), 0.5, primary_color),
                    ('GRID', (0, 1), (-1, -1), 0.5, neutral_gray),
                    ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                    ('TOPPADDING', (0,0), (-1,-1), 8),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 8),
                ])
                table.setStyle(table_style)
                return table, configured_count, len(fields)

            total_configured = 0
            total_fields = 0
            
            # 5.1 Dependency Management
            dep_fields = [
                ('dependency_update_frequency', 'dependency_update_frequency'),
                ('lock_files_enforced (true/false)', 'lock_files_enforced'),
                ('automated_dependency_updates (true/false)', 'automated_dependency_updates'),
                ('dependency_review_process', 'dependency_review_process'),
                ('sbom_generation_enabled (true/false)', 'sbom_generation_enabled'),
                ('dependency_pinning_strategy', 'dependency_pinning_strategy'),
                ('license_compliance_checking (true/false)', 'license_compliance_checking'),
                ('dependency_approval_required (true/false)', 'dependency_approval_required')
            ]
            dep_table, conf, tot = _create_sca_table("Dependency Management", "dependency_management", dep_fields)
            story.append(dep_table)
            story.append(Spacer(1, 15))
            total_configured += conf
            total_fields += tot
            
            # 5.2 Package Sources
            pkg_fields = [
                ('private_registry_used (true/false)', 'private_registry_used'),
                ('package_signature_verification (true/false)', 'package_signature_verification'),
                ('trusted_sources_only (true/false)', 'trusted_sources_only'),
                ('registry_mirrors_used (true/false)', 'registry_mirrors_used'),
                ('registry_scanning_enabled (true/false)', 'registry_scanning_enabled'),
                ('package_provenance_tracking (true/false)', 'package_provenance_tracking')
            ]
            pkg_table, conf, tot = _create_sca_table("Package Sources", "package_sources", pkg_fields)
            story.append(pkg_table)
            story.append(Spacer(1, 15))
            total_configured += conf
            total_fields += tot
            
            # 5.3 Dependency Usage
            use_fields = [
                ('unused_dependencies_present (true/false)', 'unused_dependencies_present'),
                ('dev_dependencies_in_production (true/false)', 'dev_dependencies_in_production'),
                ('optional_dependencies_used (true/false)', 'optional_dependencies_used'),
                ('peer_dependencies_managed (true/false)', 'peer_dependencies_managed')
            ]
            use_table, conf, tot = _create_sca_table("Dependency Usage", "dependency_usage", use_fields)
            story.append(use_table)
            story.append(Spacer(1, 15))
            total_configured += conf
            total_fields += tot
            
            # 5.4 Vulnerability Response
            vul_fields = [
                ('mean_time_to_patch', 'mean_time_to_patch'),
                ('vulnerability_monitoring', 'vulnerability_monitoring'),
                ('emergency_patch_process (true/false)', 'emergency_patch_process'),
                ('vulnerability_disclosure_policy (true/false)', 'vulnerability_disclosure_policy'),
                ('security_champion_assigned (true/false)', 'security_champion_assigned'),
                ('vulnerability_sla_defined (true/false)', 'vulnerability_sla_defined')
            ]
            vul_table, conf, tot = _create_sca_table("Vulnerability Response", "vulnerability_response", vul_fields)
            story.append(vul_table)
            story.append(Spacer(1, 15))
            total_configured += conf
            total_fields += tot
            
            # 5.5 Build Pipeline
            pipe_fields = [
                ('build_reproducibility (true/false)', 'build_reproducibility'),
                ('dependency_hash_verification (true/false)', 'dependency_hash_verification'),
                ('isolated_build_environment (true/false)', 'isolated_build_environment'),
                ('build_artifact_signing (true/false)', 'build_artifact_signing'),
                ('supply_chain_levels_for_software_artifacts', 'supply_chain_levels_for_software_artifacts')
            ]
            pipe_table, conf, tot = _create_sca_table("Build Pipeline", "build_pipeline", pipe_fields)
            story.append(pipe_table)
            story.append(Spacer(1, 15))
            total_configured += conf
            total_fields += tot
            
            # 5.6 Runtime Behavior
            run_fields = [
                ('dependency_isolation (true/false)', 'dependency_isolation'),
                ('sandboxing_enabled (true/false)', 'sandboxing_enabled'),
                ('runtime_dependency_monitoring (true/false)', 'runtime_dependency_monitoring'),
                ('dynamic_loading_restricted (true/false)', 'dynamic_loading_restricted'),
                ('native_code_dependencies (true/false)', 'native_code_dependencies'),
                ('network_access_by_dependencies', 'network_access_by_dependencies')
            ]
            run_table, conf, tot = _create_sca_table("Runtime Behavior", "runtime_behavior", run_fields)
            story.append(run_table)
            story.append(Spacer(1, 15))
            total_configured += conf
            total_fields += tot
            
            # 5.7 Ecosystem
            eco_fields = [
                ('primary_language', 'primary_language'),
                ('package_manager', 'package_manager'),
                ('language_version_eol (true/false)', 'language_version_eol'),
                ('package_manager_version', 'package_manager_version'),
                ('monorepo (true/false)', 'monorepo')
            ]
            eco_table, conf, tot = _create_sca_table("Ecosystem", "ecosystem", eco_fields)
            story.append(eco_table)
            story.append(Spacer(1, 20))
            total_configured += conf
            total_fields += tot
            
            # 5.8 SCA Controls Summary
            story.append(Paragraph("<b>SCA Controls Summary</b>", styles['Normal']))
            story.append(Spacer(1, 5))
            
            summary_data = [
                [Paragraph('<b>SCA Context Categories</b>', header_cell_style), Paragraph('<b>Status</b>', header_cell_style)],
                [Paragraph("Configured SCA Settings", normal_style), Paragraph(f"{total_configured} / {total_fields}", normal_style)],
                [Paragraph("Not Set or Missing", normal_style), Paragraph(f"{total_fields - total_configured} / {total_fields}", normal_style)]
            ]
            summary_table = Table(summary_data, colWidths=[4.0*inch, 2.0*inch])
            summary_style = TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), primary_color),
                ('TEXTCOLOR', (0, 0), (-1, 0), white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                ('BACKGROUND', (0, 1), (-1, -1), HexColor('#F8F9FA')),
                ('GRID', (0, 0), (-1, -1), 1, neutral_gray)
            ])
            summary_table.setStyle(summary_style)
            story.append(summary_table)
            story.append(Spacer(1, 20))

        # 6. Conclusion
        story.append(PageBreak())
        story.append(Paragraph("6. Conclusion", heading_style))
        
        # Calculate stats for Conclusion
        total_sast_count = len(self.sonar_raw_data) if hasattr(self, 'sonar_raw_data') and self.sonar_raw_data else len(self.sonar_data)
        total_dast_count = len(self.zap_data)
        # Use original SCA count if available
        total_sca_count = self.sca_original_count if self.sca_original_count > 0 else len(self.sca_data)
        
        # Calculate prioritized/actionable counts (filtered by threshold in Top Vulnerabilities extraction)
        top_vulns = self.report_data.get('vulnerability_analysis', {}).get('top_vulnerabilities', [])
        actionable_sast_count = sum(1 for v in top_vulns if v.get('type') == 'SAST')
        actionable_dast_count = sum(1 for v in top_vulns if v.get('type') == 'DAST')

        # Get threshold score for risk calculation
        threshold_score = self._get_threshold_score()
        
        # SCA Counts
        high_sca_count = 0
        for v in self.sca_data:
            original_risk = v.get('enhanced_risk_level', v.get('risk', 'Low'))
            score = v.get('enhanced_score', v.get('score', 0))
            
            prioritized_risk = self._upgrade_risk_for_report(original_risk, float(score or 0), threshold_score)
            if prioritized_risk in ['Critical', 'High']:
                high_sca_count += 1

        # Select Template based on Report Focus
        if report_focus == 'sast_focused':
            conclusion_template = f"""
            The SAST assessment identified <b>{total_sast_count}</b> vulnerabilities within the analyzed source code. After applying contextual risk prioritization, <b>{actionable_sast_count}</b> findings surpassed the configured prioritization threshold and are actionable/recommended for immediate remediation.
            <br/><br/>
            It is recommended that:
            <br/><br/>
            • All actionable findings be reviewed and remediated promptly.<br/>
            • Pull Requests generated by the system be validated and merged where appropriate.<br/>
            • SAST scans be integrated into CI/CD pipelines for continuous monitoring.<br/>
            <br/>
            This report reflects the security posture of the source code at the time of assessment and does not include runtime or dynamic analysis results.
            <br/>
            """
        elif report_focus == 'dast_focused':
            conclusion_template = f"""
            The DAST assessment identified <b>{total_dast_count}</b> vulnerabilities in the running application. After applying contextual risk prioritization, <b>{actionable_dast_count}</b> findings surpassed the configured prioritization threshold and are actionable/recommended for immediate remediation.
            <br/><br/>
            It is recommended that:
            <br/><br/>
            • All actionable findings be reviewed and remediated promptly.<br/>
            • Security headers and SSL/TLS configurations be strengthened.<br/>
            • DAST scans be scheduled regularly to catch runtime issues.<br/>
            <br/>
            This report reflects the security posture of the running application at the time of assessment and does not include source code analysis results.
            <br/>
            """
        elif report_focus == 'sca_focused':
            conclusion_template = f"""
            The SCA assessment identified <b>{total_sca_count}</b> dependency vulnerabilities within the analyzed artifacts. After applying contextual risk prioritization, <b>{high_sca_count}</b> findings were classified as high risk and recommended for immediate remediation.
            <br/><br/>
            It is recommended that:
            <br/><br/>
            • All high-risk dependency vulnerabilities be reviewed and remediated promptly.<br/>
            • Vulnerable packages be updated to fixed versions where available.<br/>
            • SCA scans be integrated into CI/CD pipelines for continuous dependency monitoring.<br/>
            • A software bill of materials (SBOM) be maintained for tracking dependencies.<br/>
            <br/>
            This report reflects the security posture of the application dependencies at the time of assessment and does not include source code or runtime analysis results.
            <br/>
            """
        else:
            # Unified/Comprehensive Conclusion
            conclusion_html = f"""
            The comprehensive security assessment identified a total of <b>{total_sast_count + total_dast_count}</b> vulnerabilities across both source code and runtime environments.
            <br/><br/>
            <b>SAST Results:</b> {total_sast_count} findings, with {actionable_sast_count} classified as actionable.<br/>
            <b>DAST Results:</b> {total_dast_count} findings, with {actionable_dast_count} classified as actionable.<br/>
            <br/>
            It is recommended that:
            <br/><br/>
            • All actionable findings from both SAST and DAST be prioritized for remediation.<br/>
            • Pull Requests be reviewed and merged to address code-level issues.<br/>
            • Runtime configurations be updated to address DAST findings.<br/>
            • Continuous monitoring be maintained for both code and application state.<br/>
            """
            conclusion_template = conclusion_html

        story.append(Paragraph(conclusion_template, normal_style))
        story.append(Spacer(1, 20))

        # Build PDF
        try:
            doc.multiBuild(story, onFirstPage=draw_header_footer, onLaterPages=draw_header_footer)
            logger.info(f"📄 PDF report generated: {output_file}")
            try:
                print(f"✅ Security posture PDF created: {output_file}")
            except Exception:
                print(f"[OK] Security posture PDF created: {output_file}")
            return str(output_file)
        except Exception as e:
            logger.error(f"Failed to build PDF report: {e}")
            import traceback
            traceback.print_exc()
            return ""

def main():
    """Main function to generate security posture reports."""
    parser = argparse.ArgumentParser(description='Generate security posture reports')
    parser.add_argument('--format', choices=['json', 'pdf', 'both'], default='both',
                       help='Output format (default: both)')
    parser.add_argument('--output-dir', default='generated_reports',
                       help='Output directory (default: generated_reports)')
    parser.add_argument('--input-dir', default='AppSecAI_output',
                       help='Input directory (default: AppSecAI_output)')
    parser.add_argument('--report-type', choices=['dast_only', 'sast_only', 'comprehensive', 'unified', 'auto'], 
                       default='auto', help='Force specific report type (default: auto-detect)')
    
    args = parser.parse_args()
    
    try:
        # Convert auto to None for auto-detection
        # Use args.report_type (matching --report-type)
        force_type = None if args.report_type == 'auto' else args.report_type
        
        # Set default threshold if not set
        if not os.environ.get('VULNERABILITY_THRESHOLD'):
            os.environ['VULNERABILITY_THRESHOLD'] = '0'
        
        # Initialize generator
        print(f"[*] Initializing report generator...")
        generator = SecurityPostureReportGenerator(args.input_dir, args.output_dir, force_report_type=force_type)
        
        # Load and analyze data
        generator.discover_and_load_data()
        generator.analyze_security_posture()
        
        # Generate reports
        generated_files = []
        
        if args.format in ['json', 'both']:
            json_file = generator.generate_json_report()
            generated_files.append(json_file)
        
        if args.format in ['pdf', 'both']:
            if PDF_AVAILABLE:
                print("[*] Calling generate_pdf_report...")
                pdf_file = generator.generate_pdf_report()
                generated_files.append(pdf_file)
            else:
                print("[-] PDF generation not available.")
        
        # Summary
        print("\n[*] Security posture report generation completed!")
        print(f"[*] Generated files:")
        for file_path in generated_files:
            if file_path:
                print(f"   • {file_path}")
                
    except Exception as e:
        print(f"ERROR: [!] Report generation failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
