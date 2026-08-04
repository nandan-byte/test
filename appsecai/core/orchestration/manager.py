import logging
import os
from typing import Dict, Any
from appsecai.core.orchestration.docker_manager import DockerManager
from appsecai.core.orchestration.sonar_api_client import SonarAPIClient
from appsecai.common.exceptions import OrchestrationError

logger = logging.getLogger(__name__)

class OrchestrationManager:
    """
    High-level coordinator for Zero-Touch security infrastructure.
    """
    
    def __init__(self, target_repo_url: str):
        self.target_repo_url = target_repo_url
        self.project_key = self._generate_project_key(target_repo_url)
        self.docker = DockerManager()
        self.sonar_api = SonarAPIClient()
        
    def _generate_project_key(self, url: str) -> str:
        """Extracts a clean project key from a repo URL."""
        repo_name = url.split("/")[-1].replace(".git", "")
        return repo_name.replace("-", "_").replace(".", "_")

    def setup_sast_environment(self) -> Dict[str, Any]:
        """
        Performs E2E setup: Starts Docker, Waits for SonarQube, 
        Creates Project, Generates Token.
        """
        logger.info(f"🚀 Starting Zero-Touch Orchestration for: {self.target_repo_url}")
        
        try:
            # 1. Start Docker Container
            self.docker.start_container()
            
            # 2. Wait for SonarQube API to be ready
            self.sonar_api.wait_until_ready()
            
            # 3. Handle initial credentials
            self.sonar_api.ensure_credentials_updated()
            
            # 4. Provision Project
            self.sonar_api.create_project(self.project_key)
            
            # 5. Generate Analysis Token
            token = self.sonar_api.generate_analysis_token(f"AppSecAI_{self.project_key}")
            
            logger.info("✅ Orchestration complete. Infrastructure is ready for scan.")
            
            return {
                "sonar_url": self.sonar_api.base_url,
                "sonar_token": token,
                "sonar_project_key": self.project_key,
                "is_managed": True
            }
        except Exception as e:
            logger.error(f"❌ Orchestration failed: {e}")
            raise OrchestrationError(f"Failed to setup security infrastructure: {e}")

    def run_analysis(self, source_dir: str, token: str) -> bool:
        """Triggers the Docker-based SonarScanner analysis."""
        try:
            self.docker.run_scanner(
                project_key=self.project_key,
                source_dir=source_dir,
                sonar_url=self.sonar_api.base_url,
                token=token
            )
            return True
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return False

    def shutdown_environment(self, cleanup: bool = False, remove_volumes: bool = False):
        """Stops and optionally removes the managed infrastructure."""
        logger.info("🛑 Shutting down managed infrastructure...")
        if cleanup:
            self.docker.cleanup(remove_volumes=remove_volumes)
        else:
            self.docker.stop_container()
            
    @staticmethod
    def is_auto_setup_needed(config: Dict[str, Any]) -> bool:
        """Determines if orchestration should be triggered based on config."""
        # 1. MOCKED: Always force Zero-Touch Mode
        return True
        
        # 2. Leave original checks below (bypassed but not deleted)
        # Trigger if explicitly requested or if Sonar URL is missing
        if config.get("auto_setup") is True or config.get("sonar_auto_setup") is True:
            return True
        
        # Trigger if SONAR_AUTO_SETUP env var is set
        if os.environ.get('SONAR_AUTO_SETUP') == 'true':
            return True
            
        # Check if Sonar credentials are missing
        # For compatibility with various config structures
        sonar_cfg = config.get("security_tools", {}).get("sonarqube", {})
        if not sonar_cfg:
            sonar_cfg = config # Fallback to flat config
            
        if not sonar_cfg.get("url") or not sonar_cfg.get("username"):
            return True
            
        return False
