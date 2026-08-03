import requests
import time
import logging
from typing import Optional, Dict, Any
from requests.auth import HTTPBasicAuth
from appsecai.common.exceptions import SonarQubeAPIError, SonarQubeBootTimeout

logger = logging.getLogger(__name__)

class SonarAPIClient:
    """
    Automates interactions with the SonarQube Web API for provisioning.
    """
    
    def __init__(self, base_url: str = "http://localhost:9000", admin_user: str = "admin", admin_pass: str = "admin"):
        self.base_url = base_url.rstrip("/")
        self.admin_user = admin_user
        self.admin_pass = admin_pass
        self.current_pass = admin_pass
        
    def wait_until_ready(self, timeout_seconds: int = 1200, interval: int = 5) -> bool:
        """Polls the system status until it is 'UP'."""
        logger.info(f"Waiting for SonarQube at {self.base_url} to be ready (this can take up to 10 mins on first boot)...")
        start_time = time.time()
        
        while time.time() - start_time < timeout_seconds:
            try:
                response = requests.get(f"{self.base_url}/api/system/status", timeout=5)
                if response.status_code == 200:
                    status = response.json().get("status")
                    if status == "UP":
                        logger.info("✅ SonarQube is UP and ready.")
                        return True
                    elif status:
                        logger.info(f"SonarQube status: {status}. Still initializing...")
            except requests.exceptions.RequestException:
                pass
            
            time.sleep(interval)
            
        raise SonarQubeBootTimeout(f"SonarQube failed to reach 'UP' status within {timeout_seconds}s. Please check Docker logs.")

    def ensure_credentials_updated(self, new_password: str = "AppSecAI_Secure_2026"):
        """
        SonarQube forces a password change on first login with 'admin/admin'.
        This method handles that transition.
        """
        try:
            # Test if current credentials work (if they are still admin/admin)
            response = requests.post(
                f"{self.base_url}/api/users/change_password",
                auth=HTTPBasicAuth(self.admin_user, self.admin_pass),
                params={
                    "login": self.admin_user,
                    "previousPassword": self.admin_pass,
                    "password": new_password
                },
                timeout=10
            )
            
            if response.status_code == 204:
                logger.info("✅ Initial admin password reset successfully.")
                self.current_pass = new_password
            elif response.status_code == 401:
                # Password might have already been changed in a previous run
                logger.info("Admin password change skipped (already updated or handled).")
                self.current_pass = new_password # Assume it matches our target for now
            else:
                logger.warning(f"Unexpected response during password change: {response.status_code} - {response.text}")
                
        except Exception as e:
            logger.error(f"Error during password reset: {e}")

    def create_project(self, project_key: str, project_name: Optional[str] = None) -> bool:
        """Creates a new project if it doesn't exist."""
        project_name = project_name or project_key
        logger.info(f"Ensuring project exists: {project_key}")
        
        try:
            response = requests.post(
                f"{self.base_url}/api/projects/create",
                auth=HTTPBasicAuth(self.admin_user, self.current_pass),
                params={
                    "name": project_name,
                    "project": project_key
                },
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f"✅ Project '{project_key}' created.")
                return True
            elif response.status_code == 400 and "already exists" in response.text:
                logger.info(f"Project '{project_key}' already exists.")
                return True
            else:
                raise SonarQubeAPIError(f"Failed to create project: {response.status_code} - {response.text}")
                
        except requests.exceptions.RequestException as e:
            raise SonarQubeAPIError(f"Network error creating project: {e}")

    def generate_analysis_token(self, token_name: str = "AppSecAI_Analysis_Token") -> str:
        """Generates a fresh analysis token."""
        logger.info(f"Generating analysis token: {token_name}")
        
        try:
            # First, revoke existing token with same name to avoid duplicates
            requests.post(
                f"{self.base_url}/api/user_tokens/revoke",
                auth=HTTPBasicAuth(self.admin_user, self.current_pass),
                params={"name": token_name},
                timeout=10
            )
            
            # Generate new token
            response = requests.post(
                f"{self.base_url}/api/user_tokens/generate",
                auth=HTTPBasicAuth(self.admin_user, self.current_pass),
                params={
                    "name": token_name,
                    "type": "USER_TOKEN" # Use USER_TOKEN for analysis
                },
                timeout=10
            )
            
            if response.status_code == 200:
                token = response.json().get("token")
                logger.info("✅ Successfully generated analysis token.")
                return token
            else:
                raise SonarQubeAPIError(f"Failed to generate token: {response.status_code} - {response.text}")
                
        except requests.exceptions.RequestException as e:
            raise SonarQubeAPIError(f"Network error generating token: {e}")
