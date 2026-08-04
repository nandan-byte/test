"""
SAST Scanner CLI Wrapper

Provides CLI interface for Static Application Security Testing using SonarQube.
This module wraps the existing sast_processor.py functionality and adds orchestration.
"""

import os
import logging
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from datetime import datetime

# Import backend functionality
from appsecai.drivers.sast.sast_processor import run_sonarqube_processing, SonarQubeConfig
from appsecai.core.orchestration.manager import OrchestrationManager
from appsecai.common.utils import get_resource_path

logger = logging.getLogger(__name__)

@dataclass
class SASTResult:
    """Result of SAST scan operation."""
    scan_id: str
    target_repo: str
    start_time: datetime
    end_time: datetime
    vulnerabilities: List[Dict[str, Any]]
    summary: Dict[str, Any]
    report_path: str
    success: bool
    filtered_csv_path: Optional[str] = None
    raw_csv_path: Optional[str] = None
    clone_dir: Optional[str] = None
    target: Optional[str] = None
    error_message: Optional[str] = None

class SASTScanner:
    """CLI wrapper for SonarQube SAST scanning with Zero-Touch support."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize SAST scanner with configuration.
        
        Args:
            config: Scanner configuration dictionary
        """
        self.config = config
        
    def scan(self, target_repo: str, options: Dict[str, Any]) -> SASTResult:
        """
        Execute SAST scan against target repository.
        
        Args:
            target_repo: Git repository URL
            options: Additional scan options
            
        Returns:
            SASTResult with scan results and metadata
        """
        scan_id = f"sast_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        start_time = datetime.now()
        orchestrator = None
        sq_config = None
        
        logger.info(f"Starting SAST scan {scan_id} for target: {target_repo}")
        
        try:
            # 1. Orchestration Check (Zero-Touch)
            if OrchestrationManager.is_auto_setup_needed(self.config):
                logger.info("🛠️ Auto-setup triggered. Initializing managed infrastructure...")
                orchestrator = OrchestrationManager(target_repo)
                managed_creds = orchestrator.setup_sast_environment()
                
                # Update config with managed credentials
                self.config['url'] = managed_creds['sonar_url']
                self.config['password'] = "" # Use token mode
                self.config['username'] = managed_creds['sonar_token']
                self.config['project_key'] = managed_creds['sonar_project_key']
            
            # 2. Prepare SonarQubeConfig
            sq_config = self._prepare_sonar_config(target_repo, options)
            
            # 2.5 Run Analysis (Push to SonarQube)
            if orchestrator:
                # Ensure repo is cloned before analysis
                from appsecai.drivers.sast.sast_processor import clone_repository
                if not os.path.exists(sq_config.CLONE_DIR):
                    clone_repository(sq_config)
                scan_success = orchestrator.run_analysis(sq_config.CLONE_DIR, sq_config.USERNAME)
                if not scan_success:
                    raise Exception("SonarQube Docker scanner run failed. Check scanner logs.")
            else:
                self._run_sonar_scanner(sq_config)
            
            # 3. Execute Processing (Fetch from SonarQube)
            raw_csv, filtered_csv, statuses = run_sonarqube_processing(sq_config)
            
            # 4. Process Results
            success = filtered_csv is not None
            vulnerabilities = self._load_vulnerabilities(filtered_csv) if success else []
            
            # Create summary
            summary = self._create_summary(vulnerabilities, statuses)
            
            end_time = datetime.now()
            
            return SASTResult(
                scan_id=scan_id,
                target_repo=target_repo,
                start_time=start_time,
                end_time=end_time,
                vulnerabilities=vulnerabilities,
                summary=summary,
                report_path=filtered_csv or "",
                success=success,
                filtered_csv_path=filtered_csv,
                raw_csv_path=raw_csv,
                clone_dir=sq_config.CLONE_DIR,
                target=target_repo,
                error_message=None if success else "SonarQube processing failed. Check logs."
            )
            
        except Exception as e:
            logger.error(f"SAST scan failed: {e}", exc_info=True)
            return SASTResult(
                scan_id=scan_id,
                target_repo=target_repo,
                start_time=start_time,
                end_time=datetime.now(),
                vulnerabilities=[],
                summary={},
                report_path="",
                success=False,
                error_message=str(e)
            )
        finally:
            # Clean up local cloned repository to save disk space
            if sq_config and os.path.exists(sq_config.CLONE_DIR):
                logger.info(f"🧹 Cleaning up cloned repository: {sq_config.CLONE_DIR}")
                try:
                    def handle_remove_readonly(func, path, exc):
                        import stat
                        try:
                            os.chmod(path, stat.S_IWRITE)
                            func(path)
                        except Exception:
                            pass
                    import shutil
                    shutil.rmtree(sq_config.CLONE_DIR, onerror=handle_remove_readonly)
                except Exception as cleanup_err:
                    logger.warning(f"⚠️ Failed to clean up clone directory: {cleanup_err}")

            # Automatic container cleanup (stops & removes container/network, preserves volume by default for performance)
            if orchestrator:
                remove_vol = os.environ.get('CLEANUP_VOLUMES') == 'true'
                orchestrator.shutdown_environment(cleanup=True, remove_volumes=remove_vol)

    def _run_sonar_scanner(self, sq_config: SonarQubeConfig):
        """Executes the sonar-scanner CLI tool."""
        import subprocess
        import os
        from appsecai.common.scanner_downloader import ensure_sonar_scanner_installed
        
        # Increase Java heap space for the local scanner JVM
        os.environ["SONAR_SCANNER_OPTS"] = "-Xmx6144m"
        
        logger.info(f"📡 Pushing code to SonarQube for analysis: {sq_config.PROJECT_KEY}")
        
        # 1. Clone repository (needed for scanner)
        from appsecai.drivers.sast.sast_processor import clone_repository
        if not os.path.exists(sq_config.CLONE_DIR):
            clone_repository(sq_config)
            
        # 1.5 Ensure sonar-scanner is installed or downloaded locally
        scanner_executable = ensure_sonar_scanner_installed()
            
        # 2. Build scanner command
        # Use token if username is present and password is empty (managed mode)
        auth_token = sq_config.USERNAME
        
        cmd = [
            scanner_executable,
            f"-Dsonar.projectKey={sq_config.PROJECT_KEY}",
            f"-Dsonar.sources={sq_config.CLONE_DIR}",
            f"-Dsonar.host.url={sq_config.SONARQUBE_URL}",
            f"-Dsonar.login={auth_token}",
            "-Dsonar.scm.disabled=true",
            "-Dsonar.qualitygate.wait=true",
            f"-Dsonar.exclusions=**/vendor/**,**/third_party/**,**/staging/**,**/_output/**,**/test/**,**/testdata/**,**/*_test.go,**/*.pb.go,**/zz_generated*",
            "-Dsonar.java.binaries=."
        ]
        
        try:
            logger.info(f"Running command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            logger.info("✅ Sonar analysis pushed successfully.")
        except subprocess.CalledProcessError as e:
            logger.error(f"❌ Sonar analysis failed: {e.stderr}")
            # We don't raise here yet to allow the processor to try fetching what it can
        except FileNotFoundError:
            logger.error("❌ 'sonar-scanner' executable not found in PATH.")
            raise Exception("sonar-scanner not found. Please install the SonarScanner CLI.")

    def _prepare_sonar_config(self, target_repo: str, options: Dict[str, Any]) -> SonarQubeConfig:
        """Creates a SonarQubeConfig instance for the processor."""
        # Sanitize target_repo URL (remove double dots or trailing dots)
        target_repo = target_repo.replace("..git", ".git")
        if target_repo.endswith("."):
            target_repo = target_repo[:-1]
            
        # Use provided options or fall back to self.config
        sonar_url = self.config.get('url', 'http://localhost:9000')
        username = self.config.get('username', 'admin')
        password = self.config.get('password', 'admin')
        project_key = options.get('project_key') or self.config.get('project_key') or "appsecai_project"
        
        # Use resource paths for framework config
        vul_config_path = get_resource_path('appsecai/risk_profiles/context_modifiers/vulnerability_framework.json')
        
        return SonarQubeConfig(
            sonarqube_url=sonar_url,
            username=username,
            password=password,
            project_key=project_key,
            github_repo_clone_url=target_repo,
            clone_dir_base=os.path.abspath(options.get('clone_dir', 'cloned_repos')),
            output_dir_base=os.path.abspath(options.get('output_dir', 'AppSecAI_output')),
            vul_config_json_path=vul_config_path,
            threshold_score=options.get('threshold', 2.5),
            branch=options.get('branch')
        )

    def _load_vulnerabilities(self, csv_path: str) -> List[Dict[str, Any]]:
        """Loads and standardizes vulnerabilities from the results CSV."""
        import csv
        vulnerabilities = []
        
        if not csv_path or not os.path.exists(csv_path):
            return []
            
        try:
            with open(csv_path, mode='r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Map SonarQube fields to standardized AppSecAI format
                    vuln = {
                        'id': row.get('key', 'unknown'),
                        'type': 'sast',
                        'title': row.get('message', 'No message'),
                        'severity': row.get('severity', 'Info'),
                        'risk_level': row.get('enhanced_risk_level', 'Low'),
                        'risk_score': float(row.get('enhanced_score', 0)),
                        'category': row.get('enhanced_category', 'Software Security'),
                        'file_path': row.get('component', '').split(':')[-1],
                        'line_number': row.get('line', '0'),
                        'justification': row.get('ai_justification', ''),
                        'raw_data': row
                    }
                    vulnerabilities.append(vuln)
        except Exception as e:
            logger.error(f"Error loading vulnerabilities from CSV: {e}")
            
        return vulnerabilities

    def _create_summary(self, vulnerabilities: List[Dict[str, Any]], statuses: List[str]) -> Dict[str, Any]:
        """Creates a summary of the scan results."""
        summary = {
            'total_found': len(vulnerabilities),
            'risk_counts': {},
            'status_log': statuses
        }
        
        for v in vulnerabilities:
            risk = v.get('risk_level', 'Unknown')
            summary['risk_counts'][risk] = summary['risk_counts'].get(risk, 0) + 1
            
        return summary
