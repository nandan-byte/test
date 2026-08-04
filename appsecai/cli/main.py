#!/usr/bin/env python3
"""
Caze AppSecAI CLI - Main Entry Point

A comprehensive command-line interface for security scanning, vulnerability remediation,
and automated security reporting.

Usage:
    python -m cli scan --type sast --target <repo_url>
    python -m cli scan --type dast --target <url>  
    python -m cli fix --input <scan_results.csv>
    python -m cli report --input <results> --format html,pdf
    python -m cli config --validate
"""

import argparse
import sys
import os

# Detect Nuitka compilation and set sys.frozen for compatibility
if "__compiled__" in globals() or "__compiled__" in sys.modules or hasattr(sys, "frozen"):
    sys.frozen = True

# Force UTF-8 encoding on Windows to avoid UnicodeEncodeError in CP1252 consoles
if sys.platform == 'win32':
    if sys.stdout is not None:
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except Exception:
            pass
    if sys.stderr is not None:
        try:
            sys.stderr.reconfigure(encoding='utf-8')
        except Exception:
            pass
from typing import List, Optional
from pathlib import Path
from datetime import datetime

# Add project root to path for backend imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Load environment variables from .env file
def load_env_file():
    """Load environment variables from .env file if it exists."""
    if getattr(sys, 'frozen', False):
        exe_dir = Path(sys.executable).parent
        env_file = exe_dir / '.env'
    else:
        env_file = project_root / '.env'
        
    if env_file.exists():
        with open(env_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ.setdefault(key.strip(), value.strip())

# Load .env file at module import
load_env_file()

from appsecai.common.utils import validate_project_structure

class CLIMain:
    """Main CLI application class."""
    
    def __init__(self):
        self.parser = self._create_parser()
        
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create the main argument parser with all subcommands."""
        parser = argparse.ArgumentParser(
            prog='cazeAppSecAI',
            description='🛡️ AppSecAI - AI-Powered Security Scanning Platform',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # SAST scan of a repository
  %(prog)s scan --type sast --target https://github.com/user/repo.git
  
  # DAST scan of a web application
  %(prog)s scan --type dast --target https://example.com
  
  # Combined SAST + DAST scan
  %(prog)s scan --type both --target https://github.com/user/repo.git --dast-url https://app.com
  
  # Generate AI fixes for vulnerabilities
  %(prog)s fix --input scan_results.csv --create-prs
  
  # Generate comprehensive reports
  %(prog)s report --input results.json --format html,pdf,csv
  
  # Validate configuration
  %(prog)s config --validate
  
  # Initialize configuration template
  %(prog)s config --init

For more help on specific commands, use:
  %(prog)s <command> --help
            """
        )
        
        # Global options
        parser.add_argument(
            '--config', '-c',
            type=str,
            default='appsecai/risk_profiles/app_config.yaml',
            help='Configuration file path (default: appsecai/risk_profiles/app_config.yaml)'
        )
        parser.add_argument(
            '--verbose', '-v',
            action='store_true',
            help='Enable verbose output'
        )
        parser.add_argument(
            '--quiet', '-q', 
            action='store_true',
            help='Suppress non-essential output'
        )
        parser.add_argument(
            '--output-dir', '-o',
            type=str,
            default='AppSecAI_output',
            help='Output directory for results (default: AppSecAI_output)'
        )
        parser.add_argument(
            '--format', '-f',
            type=str,
            choices=['json', 'csv', 'html', 'pdf'],
            default='json',
            help='Output format (default: json)'
        )
        
        # Create subparsers
        subparsers = parser.add_subparsers(
            dest='command',
            help='Available commands',
            metavar='<command>'
        )
        
        # Interactive app command
        app_parser = subparsers.add_parser(
            'app',
            help='Start interactive CLI application',
            description='Launch the interactive menu-driven interface'
        )

        # SCA / Trivy analysis command
        sca_parser = subparsers.add_parser(
            'sca',
            help='Analyze Trivy SCA reports',
            description='Ingest Trivy reports and reprioritize vulnerabilities using AppSecAI context'
        )
        sca_parser.add_argument(
            '--trivy-report',
            required=True,
            help='Path to Trivy JSON report file'
        )
        sca_parser.add_argument(
            '--threshold',
            type=float,
            default=None,
            help=argparse.SUPPRESS
        )
        sca_parser.add_argument(
            '--output-dir',
            help='Output directory for SCA results (overrides config/output_dir)'
        )
        sca_parser.add_argument(
            '--export-json',
            action='store_true',
            help='Export prioritized SCA findings to JSON (for reuse with report command)'
        )
        sca_parser.add_argument(
            '--export-pdf',
            action='store_true',
            help='Generate SCA security posture PDF report'
        )

        # Scan command
        self._add_scan_parser(subparsers)
        
        # Fix command  
        self._add_fix_parser(subparsers)
        
        # Report command
        self._add_report_parser(subparsers)
        
        # Config command
        self._add_config_parser(subparsers)
        
        return parser
    
    def _add_scan_parser(self, subparsers):
        """Add scan subcommand parser."""
        scan_parser = subparsers.add_parser(
            'scan',
            help='Run security scans (SAST/DAST)',
            description='Perform static and/or dynamic security testing'
        )
        
        scan_parser.add_argument(
            '--type', '-t',
            choices=['sast', 'dast', 'sca', 'both', 'all'],
            required=True,
            help='Type of scan to perform'
        )
        scan_parser.add_argument(
            '--target-type',
            choices=['fs', 'image', 'repo', 'k8s', 'vm', 'rootfs'],
            default='fs',
            help='Target type for SCA (Trivy) scanning (default: fs)'
        )
        scan_parser.add_argument(
            '--target',
            required=True,
            help='Target repository URL (for SAST) or application URL (for DAST)'
        )
        scan_parser.add_argument(
            '--dast-url',
            help='Application URL for DAST scanning (when using --type both)'
        )
        scan_parser.add_argument(
            '--threshold',
            type=float,
            default=None,
            help=argparse.SUPPRESS
        )
        scan_parser.add_argument(
            '--severity',
            choices=['Critical', 'High', 'Medium', 'Low'],
            help='Minimum severity level to report'
        )
        scan_parser.add_argument(
            '--export',
            action='store_true',
            help='Export results to files'
        )
        scan_parser.add_argument(
            '--output-dir',
            help='Output directory for scan results (overrides config)'
        )
        scan_parser.add_argument(
            '--clone-dir',
            default='cloned_repos',
            help='Directory for cloning repositories during SAST scans (default: cloned_repos)'
        )
        scan_parser.add_argument(
            '--github-token',
            help='GitHub token (overrides config)'
        )
        scan_parser.add_argument(
            '--timeout',
            type=int,
            help='Scan timeout in seconds (for DAST scans)'
        )
        
        # DAST scan authentication parameters
        scan_parser.add_argument(
            '--auth-enabled',
            action='store_true',
            help='Enable authentication for DAST scans'
        )
        scan_parser.add_argument(
            '--auth-method',
            choices=['browser', 'form', 'json', 'http'],
            help='Authentication method'
        )
        scan_parser.add_argument(
            '--auth-username',
            help='Username for DAST scan authentication'
        )
        scan_parser.add_argument(
            '--auth-password',
            help='Password for DAST scan authentication'
        )
        scan_parser.add_argument(
            '--auth-login-url',
            help='Login page URL'
        )
        scan_parser.add_argument(
            '--auth-request-url',
            help='Login request POST URL (for form/json)'
        )
        scan_parser.add_argument(
            '--auth-request-body',
            help='Login POST request body (for form/json)'
        )
        scan_parser.add_argument(
            '--auth-browser',
            help='Browser ID to use for browser-based auth (e.g., firefox, chrome, firefox-headless, chrome-headless, edge, edge-headless, safari)'
        )
        scan_parser.add_argument(
            '--auth-logged-in',
            help='Logged in regex indicator pattern'
        )
        scan_parser.add_argument(
            '--auth-logged-out',
            help='Logged out regex indicator pattern'
        )
        
        # DAST API scan parameters
        scan_parser.add_argument(
            '--api-spec-url',
            help='API specification URL or file path (openapi/swagger JSON)'
        )
        scan_parser.add_argument(
            '--api-spec-type',
            choices=['openapi', 'graphql', 'soap'],
            help='Type of API specification'
        )
        scan_parser.add_argument(
            '--github-repo',
            help='GitHub repository (overrides config)'
        )
        scan_parser.add_argument(
            '--sonar-url',
            help='SonarQube URL (overrides config)'
        )
        scan_parser.add_argument(
            '--sonar-username',
            help='SonarQube username (overrides config)'
        )
        scan_parser.add_argument(
            '--sonar-password',
            help='SonarQube password (overrides config)'
        )
        scan_parser.add_argument(
            '--auto-fix',
            action='store_true',
            help='Automatically run AI remediation after scan'
        )
        scan_parser.add_argument(
            '--interactive-pr',
            action='store_true',
            help='Ask for confirmation before creating PRs (use with --auto-fix)'
        )
        scan_parser.add_argument(
            '--project-key',
            help='SonarQube project key (overrides automatic derivation)'
        )
        scan_parser.add_argument(
            '--branch',
            help='Repository branch to scan (e.g., main, develop, alen-sec)'
        )
    
    def _add_fix_parser(self, subparsers):
        """Add fix subcommand parser."""
        fix_parser = subparsers.add_parser(
            'fix',
            help='Generate and apply AI-powered vulnerability fixes',
            description='Use AI to generate and apply security fixes'
        )
        
        fix_parser.add_argument(
            '--input', '-i',
            required=True,
            help='Input file with scan results (CSV or JSON)'
        )
        fix_parser.add_argument(
            '--batch-size',
            type=int,
            default=10,
            help='Number of vulnerabilities to process per batch (default: 10)'
        )
        fix_parser.add_argument(
            '--create-prs',
            action='store_true',
            help='Create GitHub pull requests with fixes'
        )
        fix_parser.add_argument(
            '--interactive',
            action='store_true',
            help='Ask for confirmation before creating PRs'
        )
        fix_parser.add_argument(
            '--create-issues',
            action='store_true', 
            help='Create GitHub issues for failed fixes'
        )
        fix_parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Generate fixes without applying them'
        )
        fix_parser.add_argument(
            '--github-token',
            help='GitHub token (overrides config)'
        )
        fix_parser.add_argument(
            '--github-repo',
            help='GitHub repository (overrides config)'
        )
    
    def _add_report_parser(self, subparsers):
        """Add report subcommand parser."""
        report_parser = subparsers.add_parser(
            'report',
            help='Generate security reports',
            description='Generate comprehensive security reports in various formats'
        )
        
        report_parser.add_argument(
            '--input', '-i',
            required=True,
            help='Input file with scan/fix results'
        )
        report_parser.add_argument(
            '--format', '-f',
            default='html',
            help='Report formats (comma-separated): html,pdf,csv,json'
        )
        report_parser.add_argument(
            '--template',
            help='Custom report template directory'
        )
        report_parser.add_argument(
            '--executive-summary',
            action='store_true',
            help='Include executive summary'
        )
    
    def _add_config_parser(self, subparsers):
        """Add config subcommand parser."""
        config_parser = subparsers.add_parser(
            'config',
            help='Configuration management',
            description='Manage CLI configuration settings'
        )
        
        config_group = config_parser.add_mutually_exclusive_group(required=True)
        config_group.add_argument(
            '--validate',
            action='store_true',
            help='Validate current configuration'
        )
        config_group.add_argument(
            '--init',
            action='store_true',
            help='Create configuration template'
        )
        config_group.add_argument(
            '--show',
            action='store_true',
            help='Show current configuration'
        )
        config_group.add_argument(
            '--setup',
            action='store_true',
            help='Interactive setup wizard'
        )
    
    def main(self, args: Optional[List[str]] = None) -> int:
        """
        Main entry point for the CLI application.
        
        Args:
            args: Command line arguments (defaults to sys.argv)
            
        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        try:
            # Validate project structure first
            if not validate_project_structure():
                print("❌ Project structure validation failed")
                print("💡 Please run the CLI from the Caze AppSecAI project root directory")
                return 2
                
            # Automatically generate appsec_config.json template if it doesn't exist
            try:
                from appsecai.common.config import ConfigManager
                cm = ConfigManager(getattr(self.parser.parse_known_args(args)[0], 'config', 'appsecai/risk_profiles/app_config.yaml'))
                cm.generate_default_appsec_json()
            except Exception as e:
                print(f"⚠️ Warning: Could not initialize or read appsec_config.json: {e}")
            
            # Parse arguments
            parsed_args = self.parser.parse_args(args)
            
            # Handle no command provided
            if not parsed_args.command:
                self.parser.print_help()
                return 1
            
            # Set up logging based on verbosity
            self._setup_logging(parsed_args.verbose, parsed_args.quiet)
            
            # Route to appropriate command handler
            if parsed_args.command == 'app':
                return self._handle_app_command(parsed_args)
            elif parsed_args.command == 'sca':
                return self._handle_sca_command(parsed_args)
            elif parsed_args.command == 'scan':
                return self._handle_scan_command(parsed_args)
            elif parsed_args.command == 'fix':
                return self._handle_fix_command(parsed_args)
            elif parsed_args.command == 'report':
                return self._handle_report_command(parsed_args)
            elif parsed_args.command == 'config':
                return self._handle_config_command(parsed_args)
            else:
                print(f"❌ Unknown command: {parsed_args.command}")
                return 1
                
        except KeyboardInterrupt:
            print("\n⚠️ Operation cancelled by user")
            return 130
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            if hasattr(parsed_args, 'verbose') and parsed_args.verbose:
                import traceback
                traceback.print_exc()
            return 1
    
    def _setup_logging(self, verbose: bool, quiet: bool):
        """Set up logging based on verbosity flags."""
        import logging
        
        if quiet:
            level = logging.ERROR
        elif verbose:
            level = logging.DEBUG
        else:
            level = logging.INFO
            
        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def _handle_sca_command(self, args) -> int:
        """Handle SCA (Trivy) analysis command."""
        try:
            from appsecai.common.config import ConfigManager
            from appsecai.drivers.sca.sca_scanner import TrivySCAScanner
            from pathlib import Path
            from datetime import datetime

            # Load configuration
            config_manager = ConfigManager(args.config)

            # Determine output directory before validation
            output_dir = args.output_dir or config_manager.config.get('output_dir')
            if not output_dir:
                from appsecai.cli.menu import get_base_directory
                base_dir = get_base_directory()
                output_dir = str(base_dir / 'AppSecAI_output')
                print(f"🔧 Using default output directory for SCA: {output_dir}")

            # Ensure the config knows about the output_dir
            config_manager.config['output_dir'] = output_dir

            # Validate configuration for SCA-only flow (no SonarQube/ZAP/LLM required)
            is_valid, errors = config_manager.validate_config(scan_type='sca')
            if not is_valid:
                print("❌ Configuration validation failed:")
                for error in errors:
                    print(f"   • {error}")
                return 2

            print(f"🔍 Starting SCA (Trivy) analysis from report: {args.trivy_report}")

            threshold = args.threshold
            if threshold is None:
                # Use a safe parsing pattern for env/config values
                raw_val = os.environ.get('VULNERABILITY_THRESHOLD', '').strip()
                config_val = config_manager.config.get('vulnerability_scoring', {}).get('threshold_score')
                
                try:
                    if raw_val:
                        threshold = float(raw_val)
                    elif config_val is not None and str(config_val).strip():
                        threshold = float(config_val)
                    else:
                        threshold = 5.0
                except (ValueError, TypeError):
                    threshold = 5.0
                    
                pass
            else:
                pass

            scanner = TrivySCAScanner(config_manager.config)
            sca_result = scanner.analyze_report(
                args.trivy_report,
                options={'threshold': threshold, 'output_dir': output_dir},
            )

            if not sca_result.success:
                print(f"❌ SCA analysis failed: {sca_result.error_message}")
                return 3

            print(
                f"✅ SCA analysis completed: "
                f"{len(sca_result.vulnerabilities)} prioritized vulnerabilities"
            )

            generated_files = []
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)

            # Export prioritized JSON report compatible with the report command
            if args.export_json or True:
                sca_json_path = output_path / f"sca_trivy_prioritized_{timestamp}.json"
                sca_payload = {
                    "scan_metadata": {
                        "scan_id": sca_result.scan_id,
                        "scan_type": "sca",
                        "scanner": "trivy",
                        "artifact": sca_result.target,
                        "scan_source": sca_result.scan_source,
                        "input_report": sca_result.input_report_path,
                        "generated_at": datetime.now().isoformat(),
                        "summary": sca_result.summary,
                        "total_vulnerabilities": sca_result.summary.get("total_vulnerabilities", len(sca_result.vulnerabilities)),
                    },
                    "vulnerabilities": sca_result.vulnerabilities,
                }
                import json

                with open(sca_json_path, 'w', encoding='utf-8') as f:
                    json.dump(sca_payload, f, indent=2, default=str)

                generated_files.append(str(sca_json_path))
                print(f"📄 Prioritized SCA JSON written to {sca_json_path}")

            # Optionally generate SCA PDF security posture report
            if args.export_pdf:
                print(f"\n[*] Generating SCA posture report...")
                
                # Use the professional posture report generator (same style as SAST/DAST)
                from appsecai.reporting.posture_report import SecurityPostureReportGenerator
                from pathlib import Path as PathLib
                
                # Use generated_reports directory like DAST
                from appsecai.cli.menu import get_base_directory
                base_dir = get_base_directory()
                reports_output_dir = base_dir / "generated_reports"
                
                # Ensure it's created
                reports_output_dir.mkdir(parents=True, exist_ok=True)
                
                print(f"    Input directory: {output_dir}")
                print(f"    Output directory: {reports_output_dir}")

                generator = SecurityPostureReportGenerator(
                    input_dir=str(output_dir),
                    output_dir=str(reports_output_dir),
                    force_report_type="sca_only",
                )
                generator.discover_and_load_data()
                generator.analyze_security_posture()
                pdf_path = generator.generate_pdf_report()
                if pdf_path:
                    generated_files.append(pdf_path)
                    print(f"✅ SCA Security Posture PDF report generated: {reports_output_dir}")


            if generated_files:
                print(f"✅ Generated {len(generated_files)} SCA output file(s):")
                for path in generated_files:
                    print(f"   📄 {path}")
                
                # Only ask to open reports directory if PDF was generated
                if args.export_pdf:
                    try:
                        user_input = input("\n🔍 Open reports directory? (y/N): ").strip().lower()
                        if user_input.startswith('y'):
                            import platform
                            import subprocess
                            from appsecai.cli.menu import get_base_directory
                            
                            base_dir = get_base_directory()
                            reports_path = str(base_dir / "generated_reports")
                            
                            if platform.system() == "Windows":
                                import os
                                os.startfile(reports_path)
                            elif platform.system() == "Darwin":  # macOS
                                subprocess.run(["open", reports_path])
                            else:  # Linux
                                subprocess.run(["xdg-open", reports_path])
                            print(f"📂 Opened: {reports_path}")
                    except Exception as e:
                        # If input fails (non-interactive), just skip
                        pass

            return 0

        except Exception as e:
            print(f"❌ SCA command failed: {e}")
            if getattr(args, 'verbose', False):
                import traceback
                traceback.print_exc()
            return 1
    
    def _handle_app_command(self, args) -> int:
        """Handle interactive app command."""
        try:
            from appsecai.cli.menu import InteractiveCLI
            app = InteractiveCLI()
            app.start()
            return 0
        except Exception as e:
            print(f"❌ Failed to start interactive app: {e}")
            return 1
    
    def _handle_scan_command(self, args) -> int:
        """Handle scan subcommand."""
        try:
            from appsecai.common.config import ConfigManager
            from appsecai.drivers.sast.sast_scanner import SASTScanner
            from appsecai.drivers.dast.dast_scanner import DASTScanner
            
            # Load configuration
            config_manager = ConfigManager(args.config)
            
            # Determine output directory BEFORE validation - set default if not provided
            output_dir = args.output_dir
            if not output_dir:
                # Import get_base_directory from interactive_app
                from appsecai.cli.menu import get_base_directory
                base_dir = get_base_directory()
                output_dir = str(base_dir / 'AppSecAI_output')
                print(f"🔧 Using default output directory: {output_dir}")
            
            # Set output_dir in config before validation
            config_manager.config['output_dir'] = output_dir

            # CLI OVERRIDES: Merge specific CLI arguments into config before validation
            # This ensures validation passes if these are provided as arguments but missing in config file
            if getattr(args, 'sonar_url', None):
                config_manager.config.setdefault('security_tools', {}).setdefault('sonarqube', {})['url'] = args.sonar_url
            if getattr(args, 'sonar_username', None):
                config_manager.config.setdefault('security_tools', {}).setdefault('sonarqube', {})['username'] = args.sonar_username
            if getattr(args, 'sonar_password', None):
                config_manager.config.setdefault('security_tools', {}).setdefault('sonarqube', {})['password'] = args.sonar_password
            if getattr(args, 'project_key', None):
                config_manager.config.setdefault('security_tools', {}).setdefault('sonarqube', {})['project_key'] = args.project_key
            if getattr(args, 'github_token', None):
                config_manager.config.setdefault('github', {})['token'] = args.github_token
            if getattr(args, 'github_repo', None):
                config_manager.config.setdefault('github', {})['repo'] = args.github_repo
                
            # Auto-derive GITHUB_REPO from target if target is a GitHub URL and repo is not set
            if not config_manager.config.get('github', {}).get('repo'):
                target = getattr(args, 'target', '')
                if target and ("github.com" in target or target.startswith("git@github.com")):
                    derived_repo = None
                    if target.startswith("http"):
                        derived_repo = target.split("github.com/")[-1]
                    elif target.startswith("git@"):
                        derived_repo = target.split("github.com:")[-1]
                    
                    if derived_repo:
                        if derived_repo.endswith(".git"):
                            derived_repo = derived_repo[:-4]
                        config_manager.config.setdefault('github', {})['repo'] = derived_repo
                        print(f"🌿 Auto-derived GitHub Repository from target: {derived_repo}")
            
            # Validate only relevant configuration based on scan type
            is_valid, errors = config_manager.validate_config(scan_type=args.type)
            
            if not is_valid:
                print("❌ Configuration validation failed:")
                for error in errors:
                    print(f"   • {error}")
                return 2
            
            print(f"🔍 Starting {args.type.upper()} scan of {args.target}")
            
            # Prepare scan options
            # Use config file threshold if not provided via CLI
            threshold = args.threshold
            if threshold is None:
                raw_val = os.environ.get('VULNERABILITY_THRESHOLD', '').strip()
                config_val = config_manager.config.get('vulnerability_scoring', {}).get('threshold_score')
                
                try:
                    if raw_val:
                        threshold = float(raw_val)
                    elif config_val is not None and str(config_val).strip():
                        threshold = float(config_val)
                    else:
                        threshold = 5.0
                except (ValueError, TypeError):
                    threshold = 5.0
                
                pass
            else:
                pass
            
            # Build DAST auth configuration from CLI arguments if provided
            auth_config = {}
            if getattr(args, 'auth_enabled', False):
                auth_config['enabled'] = True
                if getattr(args, 'auth_method', None):
                    auth_config['method'] = args.auth_method
                if getattr(args, 'auth_username', None):
                    auth_config['username'] = args.auth_username
                if getattr(args, 'auth_password', None):
                    auth_config['password'] = args.auth_password
                if getattr(args, 'auth_login_url', None):
                    auth_config['login_page_url'] = args.auth_login_url
                if getattr(args, 'auth_request_url', None):
                    auth_config['login_request_url'] = args.auth_request_url
                if getattr(args, 'auth_request_body', None):
                    auth_config['login_request_body'] = args.auth_request_body
                if getattr(args, 'auth_browser', None):
                    auth_config['browser_id'] = args.auth_browser
                if getattr(args, 'auth_logged_in', None):
                    auth_config['logged_in_regex'] = args.auth_logged_in
                if getattr(args, 'auth_logged_out', None):
                    auth_config['logged_out_regex'] = args.auth_logged_out
            
            # Build DAST API configuration from CLI arguments if provided
            api_config = {}
            if getattr(args, 'api_spec_url', None):
                api_config['enabled'] = True
                api_config['spec_url'] = args.api_spec_url
                if getattr(args, 'api_spec_type', None):
                    api_config['spec_type'] = args.api_spec_type

            scan_options = {
                'output_dir': output_dir,
                'clone_dir': args.clone_dir if hasattr(args, 'clone_dir') else 'cloned_repos',
                'threshold': threshold,
                'severity': args.severity,
                'export': args.export,
                'project_key': args.project_key,
                'branch': getattr(args, 'branch', None)
            }
            
            if auth_config:
                scan_options['auth_config'] = auth_config
            if api_config:
                scan_options['api_config'] = api_config
            
            # Add timeout for DAST scans
            if args.timeout and args.type in ['dast', 'both']:
                scan_options['max_scan_time'] = args.timeout
                print(f"🔧 Using CLI timeout: {args.timeout} seconds")
            elif args.type in ['dast', 'both']:
                # Use environment variable if no CLI timeout specified
                env_timeout = os.environ.get('ZAP_MAX_SCAN_TIME', '').strip()
                if env_timeout:
                    try:
                        scan_options['max_scan_time'] = int(env_timeout)
                        print(f"🔧 Using environment timeout: {env_timeout} seconds")
                    except (ValueError, TypeError):
                        print(f"⚠️ Invalid ZAP_MAX_SCAN_TIME '{env_timeout}', ignoring...")
            
            results = []
            
            # Execute SCA scan natively (Trivy)
            if args.type in ['sca', 'all']:
                print(f"📦 Executing SCA scan strictly over {args.target_type} target...")
                from appsecai.drivers.sca.sca_runner import TrivyRunner
                
                scan_options['target_type'] = args.target_type if hasattr(args, 'target_type') else 'fs'
                trivy_runner = TrivyRunner(config_manager.config)
                trivy_result = trivy_runner.scan(args.target, scan_options)
                results.append(trivy_result)
                
                if trivy_result and getattr(trivy_result, 'success', False):
                    vulnerabilities = getattr(trivy_result, 'vulnerabilities', [])
                    print(f"✅ SCA scan completed: {len(vulnerabilities)} vulnerabilities prioritized")
                    
                    # PERSISTENCE FIX: Save prioritized SCA results so the PDF report generator can find them
                    try:
                        from datetime import datetime
                        import json
                        from pathlib import Path
                        
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        sca_json_path = Path(output_dir) / f"sca_trivy_prioritized_{timestamp}.json"
                        
                        sca_summary = getattr(trivy_result, 'summary', {})
                        sca_payload = {
                            "scan_metadata": {
                                "scan_id": getattr(trivy_result, 'scan_id', f"sca_{timestamp}"),
                                "scan_type": "sca",
                                "scanner": "trivy",
                                "artifact": getattr(trivy_result, 'target', args.target),
                                "scan_source": getattr(trivy_result, 'scan_source', 'trivy'),
                                "input_report": getattr(trivy_result, 'input_report_path', ''),
                                "generated_at": datetime.now().isoformat(),
                                "summary": sca_summary,
                                "total_vulnerabilities": sca_summary.get("total_vulnerabilities", len(vulnerabilities)),
                                "prioritized_vulnerabilities": sca_summary.get("prioritized_vulnerabilities", len(vulnerabilities)),
                            },
                            "vulnerabilities": vulnerabilities,
                        }
                        
                        with open(sca_json_path, 'w', encoding='utf-8') as f:
                            json.dump(sca_payload, f, indent=2, default=str)
                        
                        print(f"📄 Prioritized SCA results saved to {sca_json_path}")
                    except Exception as export_err:
                        print(f"⚠️  Failed to save prioritized SCA results: {export_err}")
                else:
                    error_msg = getattr(trivy_result, 'error_message', 'Unknown Error')
                    print(f"❌ SCA scan failed: {error_msg}")
            
            # Execute SAST scan
            if args.type in ['sast', 'both']:
                print("📊 Executing SAST scan...")
                sast_scanner = SASTScanner(config_manager.get_scanner_config('sonarqube'))
                sast_result = sast_scanner.scan(args.target, scan_options)
                results.append(sast_result)
                
                if sast_result.success:
                    print(f"✅ SAST scan completed: {len(sast_result.vulnerabilities)} vulnerabilities found")
                else:
                    print(f"❌ SAST scan failed: {sast_result.error_message}")
            
            # Execute DAST scan
            if args.type in ['dast', 'both']:
                dast_url = args.dast_url if args.type == 'both' else args.target
                print(f"🌐 Executing DAST scan on {dast_url}...")
                dast_scanner = DASTScanner(config_manager.get_scanner_config('zap'))
                dast_result = dast_scanner.scan(dast_url, scan_options)
                results.append(dast_result)
                
                if dast_result.success:
                    print(f"✅ DAST scan completed: {len(dast_result.vulnerabilities)} vulnerabilities found")
                    
                    # Display AI recommendations if available
                    if hasattr(dast_result, 'summary') and 'ai_recommendations' in dast_result.summary:
                        ai_recs = dast_result.summary['ai_recommendations']
                        if ai_recs:
                            print(f"🤖 Generated {len(ai_recs)} AI-powered remediation recommendations")
                    
                else:
                    print(f"❌ DAST scan failed: {dast_result.error_message}")
            
            # Export results if requested
            if args.export:
                self._export_scan_results(results, args.format, output_dir)
            
            # Check if any scans failed
            failed_scans = [r for r in results if not r.success]
            if failed_scans:
                return 3  # Scan execution error
            
            # Check vulnerability threshold using proper scoring system
            total_vulns = sum(len(r.vulnerabilities) for r in results)
            
            # The backend already filters vulnerabilities based on vul.json scoring
            # So if we have vulnerabilities in results, they already passed the threshold
            print(f"📊 Found {total_vulns} vulnerabilities that meet the threshold criteria")
            
            if total_vulns > 0:
                print("⚠️  Security vulnerabilities detected that require attention")
                
                # Always generate the PDF report regardless of vulnerability count
                if results:
                    self._auto_download_reports_from_results(results, has_ai_fixes=False)
                
                # Auto-fix workflow
                if args.auto_fix:
                    try:
                        return self._run_auto_fix_workflow(results, args, output_dir, config_manager)
                    except Exception as auto_fix_error:
                        print(f"⚠️  Auto-fix workflow failed: {auto_fix_error}")
                        print("💡 Continuing without AI remediation...")
                        # Don't return error code, just continue
                
                return 1  # Vulnerabilities found that need attention
            
            print("✅ All scans completed successfully")
            
            # Auto-download reports without AI fixes
            if results:
                self._auto_download_reports_from_results(results, has_ai_fixes=False)
            
            # Auto-fix workflow even if under threshold
            if args.auto_fix and total_vulns > 0:
                return self._run_auto_fix_workflow(results, args, output_dir, config_manager)
            
            return 0
            
        except Exception as e:
            print(f"❌ Scan command failed: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            return 1
    
    def _run_auto_fix_workflow(self, scan_results, args, output_dir, config_manager=None) -> int:
        """Run automatic AI remediation workflow after scan."""
        try:
            print(f"\n🤖 Starting automatic AI remediation workflow...")
            
            # Find the latest scan result file
            latest_result = None
            latest_file = None
            
            target_repo = None
            clone_dir = None
            
            for result in scan_results:
                if result.success:
                    # Get target repo and clone dir from the result
                    if hasattr(result, 'target'):
                        target_repo = result.target
                    if hasattr(result, 'clone_dir'):
                        clone_dir = result.clone_dir
                        
                    # Check for different file attributes based on scan type
                    if hasattr(result, 'filtered_csv_path') and result.filtered_csv_path:
                        latest_result = result
                        latest_file = result.filtered_csv_path
                        break
                    elif hasattr(result, 'output_file') and result.output_file:
                        latest_result = result
                        latest_file = result.output_file
                        break
                    elif hasattr(result, 'raw_csv_path') and result.raw_csv_path:
                        latest_result = result
                        latest_file = result.raw_csv_path
                        break
            
            if not latest_file:
                print("❌ No scan result file found for AI remediation")
                print("💡 Scan results are available but AI remediation requires CSV output")
                print("💡 You can manually review the vulnerabilities in the output directory")
                return 0  # Don't fail, just skip AI remediation
            
            # Interactive PR creation confirmation
            create_prs = True  # Default to creating PRs
            target_branch = "main"  # Default branch
            
            if args.interactive_pr:
                total_vulns = sum(len(r.vulnerabilities) for r in scan_results)
                print(f"\n📊 Found {total_vulns} vulnerabilities from scan")
                response = input("🔀 Do you want to create GitHub PRs with AI fixes? (Y/n): ").strip().lower()
                create_prs = response not in ['n', 'no']
                
                if create_prs:
                    # Ask for target branch
                    current_branch = 'main'  # Default branch
                    print(f"\n🌿 Target branch for PRs (current: {current_branch})")
                    branch_input = input("Enter target branch (or press Enter for current): ").strip()
                    if branch_input:
                        target_branch = branch_input
                    else:
                        target_branch = current_branch
                    print(f"✅ PRs will target branch: {target_branch}")
                else:
                    print("ℹ️  Will generate fixes without creating PRs")
            
            # Prepare remediation options using the output_dir from scan command
            remediation_options = {
                'output_dir': output_dir,
                'batch_size': 5,  # Smaller batches for auto-fix
                'create_prs': create_prs,
                'create_issues': False,
                'dry_run': False,
                'clone_dir': clone_dir  # Reuse the scanner's clone directory
            }
            
            # Load configuration for AI engine
            if config_manager is None:
                from appsecai.common.config import ConfigManager
                config_manager = ConfigManager(args.config)
            github_config = config_manager.get_github_config().copy()
            
            # Update target branch and repo if specified
            if target_repo:
                github_config['repo'] = target_repo
            if 'target_branch' in locals():
                github_config['base_branch'] = target_branch
            
            ai_config = {
                'llm': config_manager.get_llm_config(),
                'github': github_config
            }
            
            # Try to import and use AI remediation engine
            try:
                from appsecai.core.remediation.ai_remediation import AIRemediationEngine
                ai_engine = AIRemediationEngine(ai_config)
                
                if not ai_engine.is_available():
                    print("⚠️  AI remediation not available: Process1GitHub module cannot be imported")
                    print("💡 Scan completed successfully, but AI fixes cannot be generated")
                    print("💡 You can manually review vulnerabilities in:")
                    print(f"   📁 {latest_file}")
                    return 0  # Success but without AI remediation
                
                result = ai_engine.process_vulnerabilities(latest_file, remediation_options)
            except ImportError as import_error:
                print(f"⚠️  AI remediation module not available: {import_error}")
                print("💡 Scan completed successfully, but AI fixes cannot be generated")
                print("💡 You can manually review vulnerabilities in:")
                print(f"   📁 {latest_file}")
                return 0  # Success but without AI remediation
            except Exception as ai_init_error:
                print(f"⚠️  AI remediation initialization failed: {ai_init_error}")
                print("💡 Scan completed successfully, but AI fixes cannot be generated")
                print("💡 You can manually review vulnerabilities in:")
                print(f"   📁 {latest_file}")
                return 0  # Success but without AI remediation
            
            if result.success:
                print(f"✅ Auto-fix workflow completed successfully")
                print(f"   • Processed: {len(result.fixes)} vulnerabilities")
                print(f"   • Success rate: {result.summary.get('success_rate', 0):.1%}")
                
                if result.pull_requests:
                    print(f"   • Created {len(result.pull_requests)} pull requests:")
                    for pr_url in result.pull_requests:
                        print(f"     - {pr_url}")
                    
                    # Save PR URLs to a file for report generation
                    try:
                        import os
                        import re
                        from datetime import datetime
                        os.makedirs('vulnerability-fixes', exist_ok=True)
                        
                        # Extract timestamp from the scan data file to match report with scan
                        timestamp = None
                        if latest_file:
                            # Extract timestamp from filename: sonarqube_filtered_20251111_063523.csv
                            timestamp_match = re.search(r'(\d{8}_\d{6})', latest_file)
                            if timestamp_match:
                                timestamp = timestamp_match.group(1)
                        
                        # Fallback to current time if we can't extract from filename
                        if not timestamp:
                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        
                        pr_file = os.path.join('vulnerability-fixes', f'fix_report_{timestamp}.md')
                        with open(pr_file, 'w') as f:
                            f.write(f"# Security Vulnerability Fix Report\n\n")
                            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                            f.write(f"## Pull Requests\n\n")
                            for i, pr_url in enumerate(result.pull_requests, 1):
                                # Extract PR number from URL
                                pr_num = pr_url.split('/')[-1]
                                # Note: We don't show issue count here because the actual per-PR count
                                # is not available in result.pull_requests (it's just a list of URLs)
                                f.write(f"- PR #{pr_num}: {pr_url}\n")
                    except Exception as e:
                        # Don't fail if we can't save the file
                        pass
                
                # Auto-download reports with AI fixes
                self._auto_download_reports(latest_file, has_ai_fixes=True)
                
                return 0
            else:
                print(f"❌ Auto-fix workflow failed: {result.error_message}")
                return 3
                
        except Exception as e:
            print(f"❌ Auto-fix workflow error: {e}")
            return 1
    
    def _auto_download_reports(self, scan_result_file, has_ai_fixes=False):
        """Auto-download reports after scan completion."""
        try:
            import os
            import shutil
            import glob
            from pathlib import Path
            
            # Get the scan directory from the result file path
            scan_dir = os.path.dirname(scan_result_file)
            scan_name = os.path.basename(scan_dir)
            
            # Create downloads directory in user's Downloads folder
            import os
            user_downloads = os.path.join(os.path.expanduser("~"), "Downloads")
            downloads_dir = os.path.join(user_downloads, "Caze AppSecAI_Reports")
            os.makedirs(downloads_dir, exist_ok=True)
            
            print(f"\n📥 Auto-downloading scan reports...")
            
            reports_downloaded = []
            
            # Standard SAST reports
            standard_reports = [
                ('hotspots_with_code_*.csv', 'Vulnerability_Summary.csv'),
                ('filtered_vulnerabilities_*.csv', 'High_Priority_Issues.csv')
            ]
            
            for pattern, output_name in standard_reports:
                files = glob.glob(os.path.join(scan_dir, pattern))
                if files:
                    source_file = files[0]
                    dest_file = os.path.join(downloads_dir, f"{scan_name}_{output_name}")
                    shutil.copy2(source_file, dest_file)
                    reports_downloaded.append(os.path.basename(dest_file))
            
            # AI fix reports (if AI remediation was used)
            if has_ai_fixes:
                # Look for AI fix files in the vulnerability-fixes directory
                ai_fix_dir = "vulnerability-fixes"
                if os.path.exists(ai_fix_dir):
                    ai_patterns = [
                        ('fixes_*.csv', 'AI_Fixes_Results.csv'),
                        ('fix_report_*.md', 'AI_Fix_Report.md')
                    ]
                    
                    for pattern, output_name in ai_patterns:
                        files = glob.glob(os.path.join(ai_fix_dir, pattern))
                        if files:
                            # Get the most recent file
                            source_file = max(files, key=os.path.getmtime)
                            dest_file = os.path.join(downloads_dir, f"{scan_name}_{output_name}")
                            shutil.copy2(source_file, dest_file)
                            reports_downloaded.append(os.path.basename(dest_file))
            
            if reports_downloaded:
                print(f"✅ Downloaded {len(reports_downloaded)} reports to '{downloads_dir}':")
                for report in reports_downloaded:
                    print(f"   📄 {report}")
            
        except Exception as e:
            print(f"⚠️  Could not auto-download reports: {e}")
    
    def _auto_download_reports_from_results(self, scan_results, has_ai_fixes=False):
        """Auto-download reports from scan results."""
        try:
            for result in scan_results:
                if result.success and hasattr(result, 'filtered_csv_path') and result.filtered_csv_path:
                    self._auto_download_reports(result.filtered_csv_path, has_ai_fixes)
                    break  # Only download from the first successful result
        except Exception as e:
            print(f"⚠️  Could not auto-download reports: {e}")
    
    def _handle_fix_command(self, args) -> int:
        """Handle fix subcommand."""
        try:
            from appsecai.common.config import ConfigManager
            from appsecai.core.remediation.ai_remediation import AIRemediationEngine
            
            # Load configuration
            config_manager = ConfigManager(args.config)
            # Fix command needs full validation (GitHub, LLM, etc.)
            is_valid, errors = config_manager.validate_config(scan_type=None)
            
            if not is_valid:
                print("❌ Configuration validation failed:")
                for error in errors:
                    print(f"   • {error}")
                return 2
            
            print(f"🤖 Starting AI remediation for {args.input}")
            
            # Validate input file
            if not os.path.exists(args.input):
                print(f"❌ Input file not found: {args.input}")
                return 2
            
            # Interactive PR creation confirmation
            create_prs = args.create_prs
            target_branch = "main"  # Default branch
            
            if args.interactive and not args.dry_run:
                print(f"\n📊 Found vulnerabilities in: {args.input}")
                response = input("🔀 Do you want to create GitHub PRs with AI fixes? (y/N): ").strip().lower()
                create_prs = response in ['y', 'yes']
                
                if create_prs:
                    # Ask for target branch
                    current_branch = 'main'  # Default branch
                    print(f"\n🌿 Target branch for PRs (current: {current_branch})")
                    branch_input = input("Enter target branch (or press Enter for current): ").strip()
                    if branch_input:
                        target_branch = branch_input
                    else:
                        target_branch = current_branch
                    print(f"✅ PRs will target branch: {target_branch}")
                else:
                    print("ℹ️  Will generate fixes without creating PRs")
            
            # Prepare remediation options
            remediation_options = {
                'output_dir': args.output_dir,
                'batch_size': args.batch_size,
                'create_prs': create_prs,
                'create_issues': args.create_issues,
                'dry_run': args.dry_run
            }
            
            # Create AI remediation engine
            github_config = config_manager.get_github_config().copy()
            
            # Update target branch if specified
            if 'target_branch' in locals():
                github_config['base_branch'] = target_branch
            
            ai_config = {
                'llm': config_manager.get_llm_config(),
                'github': github_config
            }
            
            try:
                ai_engine = AIRemediationEngine(ai_config)
                if not ai_engine.is_available():
                    print("❌ AI remediation not available: Core remediation modules cannot be loaded")
                    print("💡 This might be due to missing dependencies or import issues")
                    print("💡 You can still view the vulnerabilities in the input file:")
                    print(f"   📁 {args.input}")
                    return 2
            except Exception as ai_init_error:
                print(f"❌ Failed to initialize AI remediation engine: {ai_init_error}")
                print("💡 You can still view the vulnerabilities in the input file:")
                print(f"   📁 {args.input}")
                return 2
            
            # Test LLM connection
            llm_success, llm_message = ai_engine.test_llm_connection()
            if not llm_success:
                print(f"⚠️  LLM connection issue: {llm_message}")
                if not args.dry_run:
                    print("💡 Consider using --dry-run to test without LLM")
                    return 2
            
            # Execute remediation
            result = ai_engine.process_vulnerabilities(args.input, remediation_options)
            
            if result.success:
                print(f"✅ AI remediation completed successfully")
                print(f"   • Processed: {len(result.fixes)} vulnerabilities")
                print(f"   • Success rate: {result.summary.get('success_rate', 0):.1%}")
                
                # Show detailed status breakdown
                status_counts = result.summary.get('status_counts', {})
                if status_counts:
                    print(f"   • Status breakdown:")
                    for status, count in status_counts.items():
                        if count > 0:
                            print(f"     - {status}: {count}")
                
                if result.pull_requests:
                    print(f"   • Created {len(result.pull_requests)} pull requests:")
                    for pr_url in result.pull_requests:
                        print(f"     - {pr_url}")
                    
                    # Save PR URLs to a file for report generation
                    try:
                        import os
                        import re
                        from datetime import datetime
                        os.makedirs('vulnerability-fixes', exist_ok=True)
                        
                        # Extract timestamp from the scan data file to match report with scan
                        timestamp = None
                        if args.input:
                            # Extract timestamp from filename: sonarqube_filtered_20251111_063523.csv
                            timestamp_match = re.search(r'(\d{8}_\d{6})', args.input)
                            if timestamp_match:
                                timestamp = timestamp_match.group(1)
                        
                        # Fallback to current time if we can't extract from filename
                        if not timestamp:
                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        
                        pr_file = os.path.join('vulnerability-fixes', f'fix_report_{timestamp}.md')
                        with open(pr_file, 'w') as f:
                            f.write(f"# Security Vulnerability Fix Report\n\n")
                            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                            f.write(f"## Pull Requests\n\n")
                            for i, pr_url in enumerate(result.pull_requests, 1):
                                # Extract PR number from URL
                                pr_num = pr_url.split('/')[-1]
                                # Note: We don't show issue count here because the actual per-PR count
                                # is not available in result.pull_requests (it's just a list of URLs)
                                f.write(f"- PR #{pr_num}: {pr_url}\n")
                    except Exception as e:
                        # Don't fail if we can't save the file
                        pass
                else:
                    print(f"   • No pull requests created")
                    if create_prs:
                        print(f"     💡 This might indicate issues with fix application or GitHub permissions")
                
                # Export results if requested
                if args.format != 'json':  # Default format
                    self._export_remediation_results(result, args.format, args.output_dir)
                
                return 0
            else:
                print(f"❌ AI remediation failed: {result.error_message}")
                return 3
                
        except Exception as e:
            print(f"❌ Fix command failed: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            return 1
    
    def _handle_report_command(self, args) -> int:
        """Handle report subcommand."""
        try:
            from appsecai.common.config import ConfigManager
            from appsecai.reporting.engine import ReportGenerator, ReportData
            
            # Load configuration
            config_manager = ConfigManager(args.config)
            
            print(f"📊 Generating {args.format} report from {args.input}")
            
            # Validate input file
            if not os.path.exists(args.input):
                print(f"❌ Input file not found: {args.input}")
                return 2
            
            # Load input data
            report_data = self._load_report_data(args.input)
            if not report_data:
                print("❌ Failed to load report data")
                return 2
            
            # Parse formats
            formats = [f.strip().lower() for f in args.format.split(',')]
            
            # Create report generator
            reporting_config = config_manager.get_reporting_config()
            if args.template:
                reporting_config['template_dir'] = args.template
            if args.executive_summary:
                reporting_config['include_executive_summary'] = True
            
            report_generator = ReportGenerator(reporting_config)
            
            # Generate reports
            generated_files = report_generator.generate_report(
                report_data, 
                formats, 
                args.output_dir
            )
            
            if generated_files:
                print(f"✅ Successfully generated {len(generated_files)} report(s):")
                for file_path in generated_files:
                    print(f"   📄 {file_path}")
                return 0
            else:
                print("❌ No reports were generated")
                return 3
                
        except Exception as e:
            print(f"❌ Report command failed: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            return 1
    
    def _handle_config_command(self, args) -> int:
        """Handle config subcommand."""
        try:
            from appsecai.common.config import ConfigManager
            
            if args.validate:
                print("🔍 Validating configuration...")
                config_manager = ConfigManager(args.config)
                # Config validation should check everything
                is_valid, errors = config_manager.validate_config(scan_type=None)
                
                if is_valid:
                    print("✅ Configuration is valid")
                    
                    # Test connections if possible
                    from appsecai.drivers.sast.sast_scanner import SASTScanner
                    from appsecai.drivers.dast.dast_scanner import DASTScanner
                    
                    # Test SonarQube connection
                    try:
                        sast_scanner = SASTScanner(config_manager.get_scanner_config('sonarqube'))
                        success, message = sast_scanner.test_connection()
                        print(f"   SonarQube: {'✅' if success else '❌'} {message}")
                    except Exception as e:
                        print(f"   SonarQube: ❌ {e}")
                    
                    # Test ZAP installation
                    try:
                        dast_scanner = DASTScanner(config_manager.get_scanner_config('zap'))
                        success, message = dast_scanner.test_zap_installation()
                        print(f"   OWASP ZAP: {'✅' if success else '❌'} {message}")
                    except Exception as e:
                        print(f"   OWASP ZAP: ❌ {e}")
                    
                    return 0
                else:
                    print("❌ Configuration validation failed:")
                    for error in errors:
                        print(f"   • {error}")
                    return 1
                    
            elif args.init:
                print("📝 Creating configuration template...")
                config_manager = ConfigManager()
                if config_manager.create_template_config(args.config):
                    return 0
                else:
                    return 1
                    
            elif args.show:
                print("📋 Current configuration:")
                config_manager = ConfigManager(args.config)
                import json
                print(json.dumps(config_manager.config, indent=2))
                return 0
                
            elif args.setup:
                print("🚀 Starting interactive setup...")
                # pyrefly: ignore [missing-import]
                from appsecai.cli.interactive_setup import interactive_setup
                interactive_setup()
                return 0
                
        except Exception as e:
            print(f"❌ Config command failed: {e}")
            return 1

    def _export_scan_results(self, results, format_type: str, output_dir: str):
        """Export scan results to files."""
        try:
            import json
            import csv
            from pathlib import Path
            
            # Create output directory
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            
            # Combine all vulnerabilities
            all_vulnerabilities = []
            for result in results:
                all_vulnerabilities.extend(result.vulnerabilities)
            
            from datetime import datetime
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            if format_type == 'json':
                output_file = Path(output_dir) / f"scan_results_{timestamp}.json"
                with open(output_file, 'w') as f:
                    json.dump({
                        'scan_metadata': {
                            'timestamp': timestamp,
                            'total_vulnerabilities': len(all_vulnerabilities)
                        },
                        'vulnerabilities': all_vulnerabilities
                    }, f, indent=2, default=str)
                print(f"📄 Results exported to {output_file}")
                
            elif format_type == 'csv':
                output_file = Path(output_dir) / f"scan_results_{timestamp}.csv"
                if all_vulnerabilities:
                    fieldnames = all_vulnerabilities[0].keys()
                    with open(output_file, 'w', newline='') as f:
                        writer = csv.DictWriter(f, fieldnames=fieldnames)
                        writer.writeheader()
                        writer.writerows(all_vulnerabilities)
                    print(f"📄 Results exported to {output_file}")
                
        except Exception as e:
            print(f"⚠️  Failed to export results: {e}")
            # Verbose check removed to avoid scope issues or could use self.verbose if stored
    
    def _export_remediation_results(self, result, format_type: str, output_dir: str):
        """Export remediation results to files."""
        try:
            import json
            from pathlib import Path
            
            # Create output directory
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            if format_type == 'json':
                output_file = Path(output_dir) / f"remediation_results_{timestamp}.json"
                with open(output_file, 'w') as f:
                    json.dump({
                        'remediation_id': result.remediation_id,
                        'summary': result.summary,
                        'fixes': [fix.__dict__ for fix in result.fixes],
                        'pull_requests': result.pull_requests,
                        'issues': result.issues
                    }, f, indent=2, default=str)
                print(f"📄 Remediation results exported to {output_file}")
                
        except Exception as e:
            print(f"⚠️  Failed to export remediation results: {e}")
    
    def _load_report_data(self, input_file: str):
        """Load data for report generation."""
        try:
            import json
            
            with open(input_file, 'r') as f:
                if input_file.endswith('.json'):
                    data = json.load(f)
                    
                    # Handle different input formats
                    if 'scan_results' in data:
                        # Direct scan results format
                        from appsecai.reporting.engine import ReportData
                        return ReportData(
                            scan_results=data['scan_results'],
                            remediation_results=data.get('remediation_results'),
                            metadata=data.get('metadata'),
                            summary=data.get('summary')
                        )
                    elif 'vulnerabilities' in data:
                        # Simple vulnerability list format
                        from appsecai.reporting.engine import ReportData
                        return ReportData(
                            scan_results=[{
                                'scan_type': 'combined',
                                'vulnerabilities': data['vulnerabilities']
                            }],
                            metadata=data.get('scan_metadata')
                        )
                else:
                    print(f"⚠️  Unsupported input format: {input_file}")
                    return None
                    
        except Exception as e:
            print(f"❌ Failed to load report data: {e}")
            return None

def main():
    """Entry point for the CLI application."""
    cli = CLIMain()

    import sys

    # ------------------------------------------------------
    # 🟢 Auto-start interactive menu when double-clicked
    # ------------------------------------------------------
    if len(sys.argv) == 1:
        sys.argv.append("app")  # default to interactive CLI

    return cli.main()


if __name__ == '__main__':
    import sys

    try:
        exit_code = main()
    except KeyboardInterrupt:
        print("\n⚠️ Operation cancelled by user")
        exit_code = 130
    except Exception as e:
        print(f"\n❌ Fatal Error: {e}")
        import traceback
        traceback.print_exc()
        exit_code = 1

    # ------------------------------------------------------
    # 🟡 Prevent EXE window from closing instantly
    # ------------------------------------------------------
    if getattr(sys, 'frozen', False):  # running as packaged EXE
        print("\n⚠️ Press ENTER to exit...")
        try:
            input()
        except Exception:
            pass

    sys.exit(exit_code)

