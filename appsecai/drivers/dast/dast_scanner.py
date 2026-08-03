"""
DAST Scanner CLI Wrapper

Provides CLI interface for Dynamic Application Security Testing using OWASP ZAP.
This module wraps the existing zap_scanner.py functionality.
"""

import os
import sys
import logging
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from datetime import datetime

# Import backend functionality
from appsecai.common.utils import get_zap_scanner, get_resource_path

logger = logging.getLogger(__name__)

@dataclass
class DASTResult:
    """Result of DAST scan operation."""
    scan_id: str
    target_url: str
    start_time: datetime
    end_time: datetime
    vulnerabilities: List[Dict[str, Any]]
    summary: Dict[str, Any]
    report_path: str
    success: bool
    error_message: Optional[str] = None

class DASTScanner:
    """CLI wrapper for OWASP ZAP DAST scanning."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize DAST scanner with configuration.
        
        Args:
            config: Scanner configuration dictionary
        """
        self.config = config
        self.zap_scanner = get_zap_scanner()
        
        if not self.zap_scanner:
            raise RuntimeError("ZAP scanner not available. Cannot perform DAST scanning.")
    
    def scan(self, target_url: str, options: Dict[str, Any]) -> DASTResult:
        """
        Execute DAST scan against target URL.
        
        Args:
            target_url: URL to scan
            options: Additional scan options
            
        Returns:
            DASTResult with scan results and metadata
        """
        scan_id = f"dast_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        start_time = datetime.now()
        
        logger.info(f"Starting DAST scan {scan_id} for target: {target_url}")
        
        try:
            # Validate ZAP installation
            zap_path = self._find_zap_installation()
            # Note: Even if zap_path is None, we proceed. 
            # zap_driver.run_zap_scan() will handle auto-installation if needed.
            
            # Configure scan parameters
            scan_config = self._create_scan_config(target_url, options, zap_path)
            
            # Execute scan using existing backend functionality
            logger.info("Executing OWASP ZAP scan...")
            
            # Configure ZAP settings
            zap_config = {
                'installation_path': zap_path,
                'output_dir': scan_config['output_dir'],
                'scan_policy': scan_config.get('scan_policy', 'Default Policy'),
                'max_scan_time': scan_config.get('max_scan_time', 3600),
                'spider_max_depth': scan_config.get('spider_max_depth', 5)
            }
            
            scan_result = self.zap_scanner.run_zap_scan(
                target_url=target_url,
                active=True,
                passive=True,
                spider=True,
                quick=scan_config.get('scan_mode') == 'quick',
                auth=scan_config.get('auth_config'),
                api_config=scan_config.get('api_config'),
                zap_config=zap_config
            )
            
            # Process results
            if scan_result and scan_result.get('success', False):
                # Get configuration from environment
                threshold_str = os.environ.get('VULNERABILITY_THRESHOLD')
                if not threshold_str:
                    raise ValueError("VULNERABILITY_THRESHOLD must be set in environment or .env file")
                threshold_score = float(threshold_str)
                llm_url = os.environ.get('LLM_URL', 'http://4.247.140.236:11434/api/generate')
                llm_model = os.environ.get('LLM_MODEL', 'qwen2.5-coder:7b-instruct')
                
                # Parse vulnerabilities from the HTML report and generate AI recommendations
                report_path = scan_result.get('report_path')
                if report_path and os.path.exists(report_path):
                    try:
                        # Use ZAPReportAnalyzer for proper analysis and AI recommendations
                        from appsecai.drivers.dast.dast_processor import ZAPReportAnalyzer
                        
                        logger.info("🤖 Analyzing ZAP report with AI assistance...")
                        
                        # Create analyzer with proper config - CRITICAL: Pass output_dir
                        analyzer = ZAPReportAnalyzer(
                            html_file_path=report_path,
                            ollama_url=llm_url,
                            model=llm_model,
                            threshold_score=threshold_score,
                            config_path=get_resource_path('appsecai/risk_profiles/context_modifiers/vulnerability_framework.json'),
                            target_url=target_url,  # Pass explicit target URL
                            output_dir=scan_config['output_dir']  # CRITICAL: Pass output directory
                        )
                        
                        # Analyze and get AI recommendations
                        analysis_result = analyzer.analyze_and_recommend()
                        
                        if analysis_result.get('success', False):
                            # Extract vulnerabilities with AI recommendations
                            recommendations = analysis_result.get('recommendations', [])
                            raw_vulnerabilities = []
                            
                            for rec in recommendations:
                                vuln_data = rec.get('vulnerability', {})
                                # Add AI recommendation to vulnerability data
                                vuln_data['ai_recommendation'] = rec.get('recommendation', '')
                                vuln_data['ai_status'] = rec.get('status', 'pending')
                                # Use the AI-calculated score instead of recalculating
                                vuln_data['ai_calculated_score'] = vuln_data.get('score', 0)
                                raw_vulnerabilities.append(vuln_data)
                            
                            scan_result['vulnerabilities'] = raw_vulnerabilities
                            scan_result['ai_recommendations'] = recommendations
                            scan_result['analysis_summary'] = analysis_result.get('summary', {})
                            scan_result['use_ai_scores'] = True  # Flag to use AI scores
                            
                            logger.info(f"✅ Generated AI recommendations for {len(raw_vulnerabilities)} vulnerabilities")
                            
                            # Display CLI summary of recommendations
                            self._display_recommendations_summary_from_csv()
                        else:
                            # Fallback to basic parsing if AI analysis fails
                            logger.warning("AI analysis failed, falling back to basic parsing")
                            from appsecai.drivers.dast.zap_driver import parse_zap_html_to_df
                            zap_df = parse_zap_html_to_df(report_path)
                            
                            if not zap_df.empty:
                                raw_vulnerabilities = zap_df.to_dict('records')
                                scan_result['vulnerabilities'] = raw_vulnerabilities
                                logger.info(f"Parsed {len(raw_vulnerabilities)} vulnerabilities from ZAP HTML report")
                            else:
                                scan_result['vulnerabilities'] = []
                    
                    except Exception as e:
                        logger.error(f"Failed to analyze ZAP report with AI: {e}")
                        # Fallback to basic parsing
                        from appsecai.drivers.dast.zap_driver import parse_zap_html_to_df
                        zap_df = parse_zap_html_to_df(report_path)
                        
                        if not zap_df.empty:
                            raw_vulnerabilities = zap_df.to_dict('records')
                            scan_result['vulnerabilities'] = raw_vulnerabilities
                            logger.info(f"Parsed {len(raw_vulnerabilities)} vulnerabilities from ZAP HTML report (fallback)")
                        else:
                            scan_result['vulnerabilities'] = []
                else:
                    logger.error(f"ZAP report not found at: {report_path}")
                    scan_result['vulnerabilities'] = []
                
                vulnerabilities = self._process_scan_results(scan_result)
                summary = self._create_summary(vulnerabilities, scan_result)
                
                # Include AI recommendations in summary if available
                if 'ai_recommendations' in scan_result:
                    summary['ai_recommendations'] = scan_result['ai_recommendations']
                    summary['has_ai_recommendations'] = True
                else:
                    summary['has_ai_recommendations'] = False
                
                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()
                
                logger.info(f"DAST scan completed in {duration:.2f} seconds")
                logger.info(f"Found {len(vulnerabilities)} vulnerabilities")
                
                return DASTResult(
                    scan_id=scan_id,
                    target_url=target_url,
                    start_time=start_time,
                    end_time=end_time,
                    vulnerabilities=vulnerabilities,
                    summary=summary,
                    report_path=scan_result.get('report_path', ''),
                    success=True
                )
            else:
                error_msg = scan_result.get('error', 'Unknown scan error') if scan_result else 'Scan failed'
                logger.error(f"DAST scan failed: {error_msg}")
                
                return DASTResult(
                    scan_id=scan_id,
                    target_url=target_url,
                    start_time=start_time,
                    end_time=datetime.now(),
                    vulnerabilities=[],
                    summary={},
                    report_path="",
                    success=False,
                    error_message=error_msg
                )
            
        except Exception as e:
            error_msg = f"DAST scan failed: {str(e)}"
            logger.error(error_msg, exc_info=True)
            
            return DASTResult(
                scan_id=scan_id,
                target_url=target_url,
                start_time=start_time,
                end_time=datetime.now(),
                vulnerabilities=[],
                summary={},
                report_path="",
                success=False,
                error_message=error_msg
            )
    
    def _find_zap_installation(self) -> Optional[str]:
        """Find OWASP ZAP installation path."""
        # Check configured path first
        configured_path = self.config.get('zap', {}).get('installation_path')
        if configured_path and os.path.exists(configured_path):
            return configured_path
        
        # Use existing ZAP detection logic
        try:
            zap_path, _ = self.zap_scanner.resolve_zap_installation_path(configured_path)
            return zap_path
        except Exception as e:
            logger.error(f"Failed to detect ZAP installation: {e}")
            return None
    
    def _create_scan_config(self, target_url: str, options: Dict[str, Any], zap_path: str) -> Dict[str, Any]:
        """Create scan configuration."""
        zap_config = self.config.get('zap', {})
        
        # Build auth config from options or fallback to environment variables
        auth_config = options.get('auth_config')
        if not auth_config:
            auth_config = {
                'enabled': os.environ.get('DAST_USE_AUTH', 'false').lower() in ['true', '1', 'yes'],
                'method': os.environ.get('DAST_AUTH_METHOD', 'browser'),
                'username': os.environ.get('DAST_AUTH_USERNAME', ''),
                'password': os.environ.get('DAST_AUTH_PASSWORD', ''),
                'login_page_url': os.environ.get('DAST_AUTH_LOGIN_URL', ''),
                'login_request_url': os.environ.get('DAST_AUTH_REQUEST_URL', ''),
                'login_request_body': os.environ.get('DAST_AUTH_REQUEST_BODY', ''),
                'browser_id': os.environ.get('DAST_AUTH_BROWSER_ID', 'firefox'),
                'logged_in_regex': os.environ.get('DAST_AUTH_LOGGED_IN_REGEX', ''),
                'logged_out_regex': os.environ.get('DAST_AUTH_LOGGED_OUT_REGEX', '')
            }
            
        # Build API config from options or fallback to environment variables
        api_config = options.get('api_config')
        if not api_config:
            api_config = {
                'enabled': os.environ.get('DAST_USE_API', 'false').lower() in ['true', '1', 'yes'],
                'spec_url': os.environ.get('DAST_API_SPEC_URL', ''),
                'spec_type': os.environ.get('DAST_API_SPEC_TYPE', 'openapi')
            }
        
        return {
            'target_url': target_url,
            'zap_path': zap_path,
            'output_dir': options.get('output_dir', 'zap_output'),
            'scan_policy': options.get('scan_policy') or zap_config.get('scan_policy', 'Default Policy'),
            'max_scan_time': options.get('max_scan_time') or zap_config.get('max_scan_time', 3600),
            'spider_max_depth': options.get('spider_max_depth') or zap_config.get('spider_max_depth', 5),
            'auth_config': auth_config,
            'api_config': api_config,
            'scan_mode': options.get('scan_mode', 'standard')  # quick, standard, full
        }
    
    def _process_scan_results(self, scan_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process ZAP scan results into standardized vulnerability format."""
        vulnerabilities = []
        
        # Extract vulnerabilities from scan result
        raw_vulnerabilities = scan_result.get('vulnerabilities', [])
        
        for i, vuln in enumerate(raw_vulnerabilities):
            # Handle DataFrame format from parse_zap_html_to_df
            risk_level = vuln.get('Risk', vuln.get('risk', 'Low'))
            alert_name = vuln.get('Alert', vuln.get('name', 'Unknown Vulnerability'))
            description = vuln.get('Description', vuln.get('description', 'No description available'))
            url = vuln.get('URL', vuln.get('url', ''))
            parameter = vuln.get('Parameter', vuln.get('parameter', ''))
            confidence = vuln.get('Confidence', vuln.get('confidence', 'Unknown'))
            
            # Use AI-calculated score if available, otherwise calculate using enhanced framework
            if 'ai_calculated_score' in vuln:
                risk_score = float(vuln['ai_calculated_score'])
                logger.debug(f"Using AI-calculated score {risk_score} for {alert_name}")
            else:
                risk_score = self._calculate_risk_score(vuln)
            
            vulnerability = {
                'id': f"dast_{i+1}",
                'type': 'dast',
                'severity': self._map_zap_risk_level(risk_level),
                'title': alert_name,
                'description': description,
                'url': url,
                'parameter': parameter,
                'risk_level': risk_level,
                'original_risk': risk_level,
                'confidence': confidence,
                'solution': vuln.get('solution', ''),
                'reference': vuln.get('reference', ''),
                'cwe_id': vuln.get('cweid', ''),
                'wasc_id': vuln.get('wascid', ''),
                'risk_score': risk_score,
                'is_priority': self._is_priority_vulnerability(risk_score),
                'instances': vuln.get('instances', []),
                'ai_recommendation': vuln.get('ai_recommendation', ''),
                'ai_status': vuln.get('ai_status', 'pending'),
                'raw_data': vuln
            }
            vulnerabilities.append(vulnerability)
        
        # Filter vulnerabilities based on threshold
        threshold_str = os.environ.get('VULNERABILITY_THRESHOLD')
        if not threshold_str:
            raise ValueError("VULNERABILITY_THRESHOLD must be set in environment or .env file")
        threshold = float(threshold_str)
        
        # Display total vulnerabilities found before prioritization
        print(f"\n📊 VULNERABILITY ANALYSIS:")
        print(f"   Total vulnerabilities found: {len(vulnerabilities)}")
        print(f"   Prioritization threshold: {threshold}")
        
        # If AI analysis was used, the vulnerabilities are already filtered by the AI system
        if scan_result.get('use_ai_scores', False):
            print(f"   ✅ Using AI-enhanced scoring and prioritization")
            logger.info(f"Processed {len(vulnerabilities)} vulnerabilities from ZAP scan")
            logger.info(f"Using AI-filtered vulnerabilities (AI system already applied threshold)")
            print(f"   📋 Prioritized vulnerabilities: {len(vulnerabilities)}")
            return vulnerabilities
        else:
            # Apply manual filtering for non-AI processed vulnerabilities
            filtered_vulnerabilities = [v for v in vulnerabilities if v['risk_score'] >= threshold]
            print(f"   📋 Prioritized vulnerabilities (score >= {threshold}): {len(filtered_vulnerabilities)}")
            logger.info(f"Processed {len(vulnerabilities)} vulnerabilities from ZAP scan")
            logger.info(f"Filtered to {len(filtered_vulnerabilities)} vulnerabilities above threshold {threshold}")
            return filtered_vulnerabilities
    
    def _map_zap_risk_level(self, zap_risk: str) -> str:
        """Map ZAP risk level to standard severity levels."""
        risk_mapping = {
            'High': 'High',
            'Medium': 'Medium', 
            'Low': 'Low',
            'Informational': 'Low',
            'Info': 'Low'
        }
        
        return risk_mapping.get(str(zap_risk).strip(), 'Low')
    
    def _calculate_risk_score(self, vulnerability_data: Dict[str, Any]) -> float:
        """Calculate a numeric risk score using the enhanced scoring framework."""
        try:
            # Import the enhanced vulnerability scorer
            from appsecai.core.scorer import EnhancedVulnerabilityScorer
            
            # Get configuration from environment
            threshold_str = os.environ.get('VULNERABILITY_THRESHOLD')
            if not threshold_str:
                raise ValueError("VULNERABILITY_THRESHOLD must be set in environment or .env file")
            threshold_score = float(threshold_str)
            
            # Create enhanced scorer instance
            scorer = EnhancedVulnerabilityScorer()
            
            # Convert vulnerability data to format expected by scorer
            zap_alert = {
                'name': vulnerability_data.get('Alert', vulnerability_data.get('title', '')),
                'risk': vulnerability_data.get('Risk', vulnerability_data.get('risk_level', 'Low')),
                'description': vulnerability_data.get('Description', vulnerability_data.get('description', '')),
                'url': vulnerability_data.get('URL', vulnerability_data.get('url', ''))
            }
            
            # Calculate score using the proper scoring system
            enhanced_result = scorer.score_zap_vulnerability(zap_alert)
            return float(enhanced_result.final_score)
            
        except Exception as e:
            logger.warning(f"Failed to calculate vulnerability score using enhanced framework: {e}")
            # Fallback to simple scoring
            risk_level = vulnerability_data.get('Risk', vulnerability_data.get('risk_level', 'Low'))
            risk_scores = {
                'High': 15.0,
                'Medium': 10.0,
                'Low': 5.0,
                'Informational': 2.0,
                'Info': 2.0
            }
            return risk_scores.get(str(risk_level).strip(), 2.0)
    
    def _is_priority_vulnerability(self, risk_score: float) -> bool:
        """Determine if a vulnerability is high priority based on score."""
        # Get threshold from environment
        threshold_str = os.environ.get('VULNERABILITY_THRESHOLD', '2.5')
        threshold = float(threshold_str)
        return risk_score >= threshold
    
    def _display_recommendations_summary(self, recommendations: List[Dict[str, Any]]):
        """Display a formatted CLI summary of AI security recommendations matching CSV structure."""
        if not recommendations:
            return
        
        print("\n" + "="*120)
        print("🤖 AI SECURITY RECOMMENDATIONS SUMMARY")
        print("="*120)
        
        # Display each recommendation in detail
        for i, rec in enumerate(recommendations, 1):
            vuln = rec.get('vulnerability', {})
            recommendation = rec.get('recommendation', '')
            
            # Extract fields matching CSV structure
            title = vuln.get('name', 'Unknown')
            risk = vuln.get('risk', 'Unknown')
            score = vuln.get('score', 0)
            mapped_type = vuln.get('mapped_type', 'Unknown')
            status = rec.get('status', 'pending')
            
            # Parse AI recommendation to extract Impact and Fix
            impact = "Impact analysis pending"
            fix = "Remediation steps pending"
            
            if recommendation:
                # Try to extract impact and fix from the recommendation text
                lines = recommendation.split('\n')
                for line in lines:
                    if 'impact' in line.lower() or 'affect' in line.lower():
                        impact = line.strip()[:80] + "..." if len(line) > 80 else line.strip()
                        break
                
                # Look for fix/remediation information
                for line in lines:
                    if any(word in line.lower() for word in ['fix', 'remediat', 'implement', 'configure', 'set']):
                        fix = line.strip()[:80] + "..." if len(line) > 80 else line.strip()
                        break
            
            # Determine priority from risk and score
            if risk == 'High' or score >= 15:
                priority = "Critical"
            elif risk == 'Medium' or score >= 10:
                priority = "High"
            elif risk == 'Low' or score >= 5:
                priority = "Medium"
            else:
                priority = "Low"
            
            # Color coding for risk levels
            risk_color = {
                'High': '🔴',
                'Medium': '🟡', 
                'Low': '🟢',
                'Informational': '🔵'
            }.get(risk, '⚪')
            
            priority_color = {
                'Critical': '🚨',
                'High': '🔴',
                'Medium': '🟡',
                'Low': '🟢'
            }.get(priority, '⚪')
            
            print(f"\n┌─ VULNERABILITY #{i} " + "─" * (100 - len(f"VULNERABILITY #{i}")) + "┐")
            print(f"│ Title: {title:<90} │")
            print(f"│ Risk: {risk_color} {risk:<15} Score: {score:<10} Level: {priority_color} {priority:<15} │")
            print(f"│ Type: {mapped_type:<90} │")
            print(f"│ Status: {status:<87} │")
            print("├" + "─" * 100 + "┤")
            print(f"│ 💥 Impact: {impact:<85} │")
            print("├" + "─" * 100 + "┤")
            print(f"│ 🔧 Fix: {fix:<88} │")
            print("├" + "─" * 100 + "┤")
            print(f"│ 📋 Justification: {recommendation[:80] + '...' if len(recommendation) > 80 else recommendation:<85} │")
            print("└" + "─" * 100 + "┘")
        
        # Print summary statistics
        total_vulns = len(recommendations)
        high_risk = sum(1 for r in recommendations if r.get('vulnerability', {}).get('risk') == 'High')
        medium_risk = sum(1 for r in recommendations if r.get('vulnerability', {}).get('risk') == 'Medium')
        critical_priority = sum(1 for r in recommendations if r.get('vulnerability', {}).get('score', 0) >= 15)
        
        print(f"\n📊 SUMMARY STATISTICS:")
        print(f"   Total Vulnerabilities: {total_vulns}")
        print(f"   🔴 High Risk: {high_risk}")
        print(f"   🟡 Medium Risk: {medium_risk}")
        print(f"   🚨 Critical Priority: {critical_priority}")
        
        print(f"\n📁 Detailed CSV report: AppSecAI_output/security_recommendations_summary_*.csv")
        print(f"📄 Full JSON report: AppSecAI_output/security_recommendations.json")
        print("="*120)
    
    def _display_recommendations_summary_from_csv(self):
        """Display recommendations summary by reading the latest CSV file."""
        try:
            import glob
            import csv
            from datetime import datetime
            
            # Find the most recent CSV summary file
            csv_pattern = "AppSecAI_output/security_recommendations_summary_*.csv"
            csv_files = glob.glob(csv_pattern)
            
            if not csv_files:
                print("\n⚠️  No CSV summary file found")
                return
            
            # Get the most recent file
            latest_csv = max(csv_files, key=os.path.getmtime)
            
            print("\n" + "="*120)
            print("🤖 AI SECURITY RECOMMENDATIONS SUMMARY")
            print("="*120)
            
            with open(latest_csv, 'r', encoding='utf-8') as file:
                reader = csv.DictReader(file)
                recommendations = list(reader)
            
            if not recommendations:
                print("No recommendations found in CSV file")
                return
            
            # Display each recommendation
            for i, rec in enumerate(recommendations, 1):
                title = rec.get('Title', 'Unknown')
                risk = rec.get('Risk', 'Unknown')
                score = rec.get('Score', '0')
                mapped_type = rec.get('MappedType', 'Unknown')
                status = rec.get('Status', 'pending')
                impact = rec.get('Impact', 'Impact analysis pending')
                fix = rec.get('Fix', 'Remediation steps pending')
                justification = rec.get('Justification', 'Cybersecurity justification pending')
                priority = rec.get('Priority', 'Medium')  # Keep for backward compatibility
                
                # Truncate long text for display
                if len(impact) > 80:
                    impact = impact[:77] + "..."
                if len(fix) > 80:
                    fix = fix[:77] + "..."
                if len(justification) > 80:
                    justification = justification[:77] + "..."
                if len(title) > 85:
                    title = title[:82] + "..."
                
                # Color coding
                risk_color = {
                    'High': '🔴',
                    'Medium': '🟡', 
                    'Low': '🟢',
                    'Informational': '🔵'
                }.get(risk, '⚪')
                
                priority_color = {
                    'Critical': '🚨',
                    'High': '🔴',
                    'Medium': '🟡',
                    'Low': '🟢'
                }.get(priority, '⚪')
                
                print(f"\n┌─ VULNERABILITY #{i} " + "─" * (100 - len(f"VULNERABILITY #{i}")) + "┐")
                print(f"│ Title: {title:<90} │")
                print(f"│ Risk: {risk_color} {risk:<15} Score: {score:<10} Level: {priority_color} {priority:<15} │")
                print(f"│ Type: {mapped_type:<90} │")
                print(f"│ Status: {status:<87} │")
                print("├" + "─" * 100 + "┤")
                print(f"│ 💥 Impact: {impact:<85} │")
                print("├" + "─" * 100 + "┤")
                print(f"│ 🔧 Fix: {fix:<88} │")
                print("├" + "─" * 100 + "┤")
                print(f"│ 📋 Justification: {justification:<75} │")
                print("└" + "─" * 100 + "┘")
            
            # Summary statistics
            total_vulns = len(recommendations)
            high_risk = sum(1 for r in recommendations if r.get('Risk') == 'High')
            medium_risk = sum(1 for r in recommendations if r.get('Risk') == 'Medium')
            critical_priority = sum(1 for r in recommendations if r.get('Priority') == 'Critical')
            
            print(f"\n📊 SUMMARY STATISTICS:")
            print(f"   Total Vulnerabilities: {total_vulns}")
            print(f"   🔴 High Risk: {high_risk}")
            print(f"   🟡 Medium Risk: {medium_risk}")
            print(f"   🚨 Critical Priority: {critical_priority}")
            
            print(f"\n📁 Source: {os.path.basename(latest_csv)}")
            print(f"📄 Full details: AppSecAI_output/security_recommendations.json")
            print("="*120)
            
        except Exception as e:
            logger.error(f"Failed to display CSV summary: {e}")
            # Fallback to the original method
            print("\n⚠️  Could not read CSV file, showing basic summary")
    
    def _create_summary(self, vulnerabilities: List[Dict[str, Any]], scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """Create summary statistics from vulnerabilities."""
        summary = {
            'total_vulnerabilities': len(vulnerabilities),
            'risk_counts': {
                'High': 0,
                'Medium': 0,
                'Low': 0,
                'Informational': 0
            },
            'url_counts': {},
            'vulnerability_types': {},
            'scan_metadata': {
                'target_url': scan_result.get('target_url', ''),
                'scan_duration': scan_result.get('scan_duration', 0),
                'urls_found': scan_result.get('urls_found', 0),
                'scan_policy': scan_result.get('scan_policy', 'Unknown')
            }
        }
        
        # Use prioritized summary if available (from existing backend logic)
        if 'prioritized_summary' in scan_result:
            prioritized = scan_result['prioritized_summary']
            summary['risk_counts'].update({
                'High': prioritized.get('High', 0),
                'Medium': prioritized.get('Medium', 0),
                'Low': prioritized.get('Low', 0),
                'Informational': prioritized.get('Informational', 0)
            })
        else:
            # Count vulnerabilities by risk level
            for vuln in vulnerabilities:
                risk_level = vuln.get('risk_level', 'Low')
                if risk_level in summary['risk_counts']:
                    summary['risk_counts'][risk_level] += 1
                elif risk_level == 'Info':
                    summary['risk_counts']['Informational'] += 1
        
        # Count by URL
        for vuln in vulnerabilities:
            url = vuln.get('url', 'Unknown')
            summary['url_counts'][url] = summary['url_counts'].get(url, 0) + 1
        
        # Count by vulnerability type
        for vuln in vulnerabilities:
            vuln_type = vuln.get('title', 'Unknown')
            summary['vulnerability_types'][vuln_type] = summary['vulnerability_types'].get(vuln_type, 0) + 1
        
        return summary
    
    def test_zap_installation(self) -> Tuple[bool, str]:
        """
        Test OWASP ZAP installation.
        
        Returns:
            Tuple of (success, message)
        """
        try:
            zap_path = self._find_zap_installation()
            
            if not zap_path:
                return False, "OWASP ZAP installation not found"
            
            # Test ZAP executable
            zap_executable = os.path.join(zap_path, 'zap.bat' if os.name == 'nt' else 'zap.sh')
            
            if not os.path.exists(zap_executable):
                return False, f"ZAP executable not found at {zap_executable}"
            
            return True, f"OWASP ZAP found at {zap_path}"
            
        except Exception as e:
            return False, f"ZAP installation test failed: {str(e)}"
    
    def get_scan_policies(self) -> List[str]:
        """
        Get available ZAP scan policies.
        
        Returns:
            List of available scan policy names
        """
        # Default ZAP policies
        default_policies = [
            'Default Policy',
            'Light Policy',
            'API-minimal-example',
            'API-full-example'
        ]
        
        try:
            # Could be extended to read actual policies from ZAP installation
            zap_path = self._find_zap_installation()
            if zap_path:
                policies_dir = os.path.join(zap_path, 'policies')
                if os.path.exists(policies_dir):
                    policy_files = [f[:-7] for f in os.listdir(policies_dir) if f.endswith('.policy')]
                    return policy_files if policy_files else default_policies
            
            return default_policies
            
        except Exception as e:
            logger.error(f"Failed to get scan policies: {e}")
            return default_policies
    
    def validate_target_url(self, url: str) -> Tuple[bool, str]:
        """
        Validate target URL for DAST scanning.
        
        Args:
            url: URL to validate
            
        Returns:
            Tuple of (is_valid, message)
        """
        try:
            from urllib.parse import urlparse
            import requests
            
            # Parse URL
            parsed = urlparse(url)
            
            if not parsed.scheme:
                return False, "URL must include protocol (http:// or https://)"
            
            if parsed.scheme not in ['http', 'https']:
                return False, "URL must use HTTP or HTTPS protocol"
            
            if not parsed.netloc:
                return False, "URL must include hostname"
            
            # Test connectivity
            try:
                response = requests.head(url, timeout=10, allow_redirects=True)
                if response.status_code < 400:
                    return True, f"Target URL is accessible (HTTP {response.status_code})"
                else:
                    return False, f"Target URL returned HTTP {response.status_code}"
            except requests.exceptions.RequestException as e:
                return False, f"Cannot connect to target URL: {str(e)}"
            
        except Exception as e:
            return False, f"URL validation failed: {str(e)}"
