import os
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

class WorkspaceManager:
    """
    Manages temporary workspaces and path normalization for security scans.
    """
    
    def __init__(self, base_dir: Optional[str] = None):
        if base_dir:
            self.base_path = Path(base_dir)
        else:
            # Default to project root / AppSecAI_Workspaces
            self.base_path = Path(os.getcwd()) / "AppSecAI_Workspaces"
            
        self.base_path.mkdir(parents=True, exist_ok=True)
        
    def get_repo_dir(self, repo_name: str) -> Path:
        """Returns the directory for a specific repository."""
        repo_dir = self.base_path / "clones" / repo_name
        repo_dir.mkdir(parents=True, exist_ok=True)
        return repo_dir
        
    def get_output_dir(self, repo_name: str) -> Path:
        """Returns the output directory for a specific repository."""
        output_dir = self.base_path / "outputs" / repo_name
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir
        
    def normalize_finding_path(self, repo_path: str, component_path: str) -> str:
        """
        Translates a SonarQube component path to a local absolute path.
        Example: 'my_project:src/main.py' -> '/abs/path/to/clones/my_project/src/main.py'
        """
        # Remove project prefix (e.g., 'my_project:')
        if ":" in component_path:
            relative_path = component_path.split(":", 1)[1]
        else:
            relative_path = component_path
            
        return os.path.join(repo_path, relative_path)
        
    def cleanup_workspace(self, repo_name: str):
        """Removes temporary files for a repository."""
        import shutil
        repo_dir = self.get_repo_dir(repo_name)
        if repo_dir.exists():
            shutil.rmtree(repo_dir)
            logger.info(f"Cleaned up workspace for {repo_name}")
