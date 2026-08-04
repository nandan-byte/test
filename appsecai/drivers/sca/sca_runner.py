import os
import subprocess
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

from appsecai.drivers.sca.sca_downloader import get_trivy_executable
from appsecai.drivers.sca.sca_scanner import TrivySCAScanner

class TrivyRunner:
    """
    Executes raw Trivy scans against a variety of targets natively, 
    stores the output to AppSecAI_output in JSON format, 
    and then invokes the custom prioritization framework.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.executable = get_trivy_executable()
        
    def scan(self, target: str, scan_options: Dict[str, Any]) -> Any:
        """
        Run Trivy CLI against the target and pipeline to prioritization.
        
        Args:
            target: The target to scan (e.g. '.', 'python:3.9', 'https://github.com/org/repo')
            scan_options: Must contain 'target_type' (fs, image, repo, k8s, etc.) and 'output_dir'
        """
        target_type = scan_options.get('target_type', 'fs')
        output_dir = Path(scan_options.get('output_dir', 'AppSecAI_output'))
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        raw_json_path = output_dir / f"trivy_raw_{timestamp}.json"
        
        print(f"🛡️  Initializing native Trivy scan...")
        print(f"   Target Type: {target_type}")
        print(f"   Target: {target}")
        
        # Build command — each target type has different Trivy argument conventions:
        #
        #   image (registry):   trivy image python:3.9
        #   image (local tar):  trivy image --input /path/image.tar
        #   fs:                 trivy fs ./my_project
        #   repo:               trivy repo https://github.com/org/repo
        #   sbom:               trivy sbom /path/sbom.json
        #   config:             trivy config ./infrastructure/
        #   k8s:                trivy k8s --report all cluster
        #   vm:                 trivy vm /dev/sda  (or --input for archives)
        #   rootfs:             trivy rootfs /path/rootfs
        #   aws:                trivy aws --region us-east-1
        #
        # Common base flags applied to all types that produce JSON findings:
        base_flags = [
            "--format", "json",
            "--output", str(raw_json_path),
        ]

        # Scanner flags are only meaningful for types that scan for vulns/secrets/misconfig.
        # k8s, aws, config etc. use their own scanner defaults, so we keep it universal.
        scanner_flags = ["--scanners", "vuln,secret,misconfig"]

        target_lower = target.lower()

        if target_type == "image":
            # Local tar archives (exported via `docker save`) need --input
            if target_lower.endswith(".tar") or target_lower.endswith(".tar.gz"):
                command = [
                    self.executable, "image",
                    "--input", target,
                ] + scanner_flags + base_flags

            else:
                # Registry image reference (e.g. python:3.9, nginx:latest, myrepo/img@sha256:…)
                command = [
                    self.executable, "image",
                ] + scanner_flags + base_flags + [target]

        elif target_type == "sbom":
            # SBOM scanning does not need --scanners; Trivy derives type from the file
            command = [
                self.executable, "sbom",
                "--format", "json",
                "--output", str(raw_json_path),
                target
            ]

        elif target_type == "k8s":
            # k8s uses a subcommand model: trivy k8s --report all cluster
            # target here is expected to be the subcommand or target (e.g. "cluster", "namespace", or context name)
            # If target doesn't start with a known subcommand, we default to 'cluster'
            if target not in ["cluster", "all", "namespace", "resource"]:
                command = [
                    self.executable, "k8s",
                    "--report", "summary",
                ] + scanner_flags + base_flags + ["cluster", "--context", target]
            else:
                command = [
                    self.executable, "k8s",
                    "--report", "summary",
                ] + scanner_flags + base_flags + [target]

        elif target_type == "container":
            # Scanning a running container: trivy container <container_id>
            command = [
                self.executable, "container",
            ] + scanner_flags + base_flags + [target]

        elif target_type == "aws":
            # AWS: trivy aws --region <region> --format json --output out.json
            # target is expected to be the AWS region (e.g. "us-east-1")
            command = [
                self.executable, "aws",
                "--region", target,
                "--format", "json",
                "--output", str(raw_json_path),
            ]

        else:
            # General fallback: fs, repo, config, vm, rootfs
            # All accept a positional target argument
            command = [
                self.executable, target_type,
            ] + scanner_flags + base_flags + [target]
        
        # Environment setup for Trivy (e.g. for private repo access)
        env = os.environ.copy()
        github_config = self.config.get('github', {})
        token = github_config.get('token') or os.environ.get('GITHUB_TOKEN')
        if token:
            env['TRIVY_GITHUB_TOKEN'] = token

        try:
            print(f"⏳ Running Trivy scan (this may take a few minutes for large targets)...")
            result = subprocess.run(command, capture_output=True, text=True, env=env)
            
            if result.returncode != 0 and raw_json_path.exists() == False:
                # Trivy returns non-zero for found vulnerabilities sometimes depending on exit-code flag, 
                # but if the JSON wasn't created, it's a hard crash.
                print(f"❌ Trivy binary execution failed:\n{result.stderr}")
                # We return a mock failure-like object expected by cli_main
                from appsecai.drivers.sast.sast_scanner import SASTResult # Using duck-typing equivalent
                return SASTResult(
                    scan_id="mock", target=target, start_time=datetime.now(), end_time=datetime.now(),
                    vulnerabilities=[], summary={}, raw_csv_path="", filtered_csv_path="",
                    clone_dir="", success=False, error_message=f"Trivy CLI Error: {result.stderr}"
                )
                
            print(f"✅ Raw Trivy JSON generated successfully.")
            
            # Step 2: Instantly pipe to prioritizing scanner
            print(f"🧮 Piping to AppSecAI Prioritization Engine...")
            prioritization_scanner = TrivySCAScanner(self.config)
            
            # Use the existing analyzer logic
            sca_result = prioritization_scanner.analyze_report(
                str(raw_json_path),
                options=scan_options
            )
            
            return sca_result
            
        except Exception as e:
            from appsecai.drivers.sast.sast_scanner import SASTResult
            return SASTResult(
                    scan_id="mock", target=target, start_time=datetime.now(), end_time=datetime.now(),
                    vulnerabilities=[], summary={}, raw_csv_path="", filtered_csv_path="",
                    clone_dir="", success=False, error_message=str(e)
            )
