import subprocess
import logging
import time
import os
from typing import Optional, Dict, Any
from appsecai.common.exceptions import DockerNotFoundError, DockerExecutionError
from appsecai.common.utils import get_clean_env

logger = logging.getLogger(__name__)

class DockerManager:
    """
    Manages the lifecycle of Docker containers for security tools.
    """
    
    def __init__(self, container_name: str = "appsecai-sonarqube", image: str = "sonarqube:community"):
        self.container_name = container_name
        self.image = image
        self.port = 9000
        self.network_name = "appsecai-net"
        self.scanner_image = "sonarsource/sonar-scanner-cli:latest"
        
    def is_docker_available(self) -> bool:
        """Check if Docker is installed and running."""
        try:
            result = subprocess.run(["docker", "info"], capture_output=True, text=True, check=False, env=get_clean_env())
            return result.returncode == 0
        except FileNotFoundError:
            return False
            
    def ensure_image_present(self):
        """Ensure the required Docker image is pulled."""
        logger.info(f"Checking for Docker image: {self.image}")
        try:
            # Check if image exists
            result = subprocess.run(["docker", "images", "-q", self.image], capture_output=True, text=True, check=True, env=get_clean_env())
            if not result.stdout.strip():
                logger.info(f"Image {self.image} not found locally. Pulling (this may take a few minutes)...")
                subprocess.run(["docker", "pull", self.image], check=True, env=get_clean_env())
                logger.info(f"Successfully pulled {self.image}")
            else:
                logger.info(f"Image {self.image} is already present.")
        except subprocess.CalledProcessError as e:
            raise DockerExecutionError(f"Failed to check or pull Docker image: {e}")

    def ensure_network_exists(self):
        """Ensure the shared Docker network exists."""
        try:
            result = subprocess.run(["docker", "network", "ls", "--filter", f"name={self.network_name}", "-q"], capture_output=True, text=True, check=True, env=get_clean_env())
            if not result.stdout.strip():
                logger.info(f"Creating Docker network: {self.network_name}")
                subprocess.run(["docker", "network", "create", self.network_name], check=True, env=get_clean_env())
        except subprocess.CalledProcessError as e:
            logger.warning(f"Failed to manage Docker network: {e}. Falling back to default bridge.")

    def get_container_info(self) -> Dict[str, str]:
        """Get the current status and image of the container."""
        try:
            result = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Status}}|{{.Config.Image}}", self.container_name],
                capture_output=True, text=True, check=False, env=get_clean_env()
            )
            if result.returncode != 0:
                return {"status": None, "image": None}
            parts = result.stdout.strip().split("|")
            return {"status": parts[0], "image": parts[1] if len(parts) > 1 else None}
        except Exception:
            return {"status": None, "image": None}

    def start_container(self) -> bool:
        """Starts the SonarQube container. Creates it if it doesn't exist."""
        if not self.is_docker_available():
            raise DockerNotFoundError("Docker is not available or not running.")
            
        info = self.get_container_info()
        status = info["status"]
        current_image = info["image"]
        
        # If container exists but has wrong image, remove it along with volumes
        if status and current_image and current_image != self.image:
            logger.info(f"Container {self.container_name} is using image {current_image}, but we need {self.image}. Wiping old data for clean boot...")
            self.cleanup(remove_volumes=True)
            status = None
            
        if status == "running":
            logger.info(f"Container {self.container_name} is already running.")
            self.ensure_network_exists()
            # Try to connect to network if not already connected (ignores error if already connected)
            subprocess.run(["docker", "network", "connect", self.network_name, self.container_name], capture_output=True, env=get_clean_env())
            return True
            
        if status == "exited":
            logger.info(f"Container {self.container_name} is in a failed state. Performing a Hard Reset for E2E recovery...")
            self.cleanup(remove_volumes=True)
            status = None # Force fresh creation from scratch
            
        # Create and start new container
        logger.info(f"Provisioning new container: {self.container_name}")
        self.ensure_image_present()
        
        # Use a persistent volume for faster reboots and persistence
        volume_name = f"{self.container_name}-data"
        self.ensure_network_exists()
        
        cmd = [
            "docker", "run", "-d",
            "--name", self.container_name,
            "--network", self.network_name,
            "-p", f"{self.color_port()}:9000",
            "-v", f"{volume_name}:/opt/sonarqube/data",
            self.image
        ]
        
        try:
            subprocess.run(cmd, check=True, env=get_clean_env())
            logger.info(f"Container {self.container_name} started successfully.")
            return True
        except subprocess.CalledProcessError as e:
            raise DockerExecutionError(f"Failed to start container: {e}")

    def color_port(self) -> int:
        """Returns the port to map to. Default 9000."""
        return self.port

    def run_scanner(self, project_key: str, source_dir: str, sonar_url: str, token: str):
        """Runs the SonarScanner CLI inside a Docker container."""
        logger.info(f"🚀 Running Docker-based SonarScanner for project: {project_key}")
        
        # Pull scanner image if needed
        original_image = self.image
        self.image = self.scanner_image 
        self.ensure_image_present()
        self.image = original_image 
        
        # Resolve absolute path for volume mounting
        abs_source_dir = os.path.abspath(source_dir)
        sync_container = f"appsecai-scan-sync-{int(time.time())}"
        
        try:
            # 1. Create a temporary data holder container
            logger.info(f"📦 Creating temporary sync container: {sync_container}")
            subprocess.run(["docker", "create", "--name", sync_container, "-v", "/usr/src", "busybox"], check=True, capture_output=True, env=get_clean_env())
            
            # 2. Copy files from host to container (GURANTEED to work on Windows even without drive sharing)
            logger.info(f"🚚 Syncing files from {abs_source_dir} to Docker (bypassing drive sharing restrictions)...")
            # Normalize path for docker cp (use forward slashes for better compatibility)
            normalized_source = abs_source_dir.replace('\\', '/')
            # Using /. at the end of source path copies contents, not the folder itself
            subprocess.run(["docker", "cp", f"{normalized_source}/.", f"{sync_container}:/usr/src"], check=True, capture_output=True, env=get_clean_env())
            
            # Use the container name as the host if we are on the same network
            internal_url = f"http://{self.container_name}:9000"
            
            cmd = [
                "docker", "run", "--rm",
                "--network", self.network_name,
                "-e", "SONAR_SCANNER_OPTS=-Xmx6144m",
                "--volumes-from", sync_container,
                "-w", "/usr/src",
                self.scanner_image,
                "-Dsonar.projectKey=" + project_key,
                "-Dsonar.sources=.",
                "-Dsonar.host.url=" + internal_url,
                "-Dsonar.login=" + token,
                "-Dsonar.scm.disabled=true",
                "-Dsonar.qualitygate.wait=true",
                "-Dsonar.javascript.node.max_old_space_size=4096",
                "-Dsonar.verbose=true",
                "-Dsonar.inclusions=**/*",
                "-Dsonar.exclusions=**/vendor/**,**/third_party/**,**/staging/**,**/_output/**,**/test/**,**/testdata/**,**/*_test.go,**/*.pb.go,**/zz_generated*",
                "-Dsonar.java.binaries=."
            ]
            
            logger.info(f"Executing scanner with internally synced volumes...")
            # SonarScanner may return non-zero codes (like 1, 2, or 3) if the Quality Gate fails. 
            # We treat these as a success for the orchestration phase so we can fetch the issues.
            process = subprocess.run(cmd, check=False, env=get_clean_env())
            if process.returncode not in [0, 1, 2, 3]:
                raise DockerExecutionError(f"Scanner container failed with exit code {process.returncode}")
                
            logger.info("✅ Docker-based scan completed successfully.")
            
        except Exception as e:
            logger.error(f"❌ Docker Sync/Scan failed: {str(e)}")
            raise DockerExecutionError(f"Robust sync failed: {str(e)}")
        finally:
            # 3. Always cleanup the sync container
            logger.info(f"🧹 Cleaning up sync container: {sync_container}")
            subprocess.run(["docker", "rm", "-v", sync_container], capture_output=True, env=get_clean_env())

    def stop_container(self):
        """Stops the container if it is running."""
        try:
            logger.info(f"Stopping container {self.container_name}...")
            subprocess.run(["docker", "stop", self.container_name], capture_output=True, env=get_clean_env())
        except Exception as e:
            logger.warning(f"Failed to stop container: {e}")

    def cleanup(self, remove_volumes: bool = False):
        """Removes the container and network."""
        self.stop_container()
        try:
            logger.info(f"Removing container {self.container_name}...")
            subprocess.run(["docker", "rm", self.container_name], capture_output=True, env=get_clean_env())
            logger.info(f"Removing network {self.network_name}...")
            subprocess.run(["docker", "network", "rm", self.network_name], capture_output=True, env=get_clean_env())
            if remove_volumes:
                volume_name = f"{self.container_name}-data"
                subprocess.run(["docker", "volume", "rm", volume_name], capture_output=True, env=get_clean_env())
        except Exception as e:
            logger.warning(f"Failed to cleanup Docker resources: {e}")
