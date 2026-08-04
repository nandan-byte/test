import os
import sys
import platform
import urllib.request
import zipfile
import tarfile
import shutil
from pathlib import Path

def _get_project_root() -> Path:
    """Return the absolute path to the project root directory (or temp extraction dir for EXE)."""
    if getattr(sys, 'frozen', False):
        if hasattr(sys, '_MEIPASS'):
            # In PyInstaller onefile mode, everything is in sys._MEIPASS
            return Path(sys._MEIPASS)
        # Nuitka Standalone
        return Path(sys.executable).parent
        
    # Standard development mode
    current_file = Path(__file__).resolve()
    # Go up two levels: cli/tools -> cli -> project_root
    return current_file.parent.parent.parent

def _get_trivy_bin_dir() -> Path:
    """Return the path to the hidden Trivy binary directory."""
    root = _get_project_root()
    
    if getattr(sys, 'frozen', False):
        # In EXE mode, trivy.exe was bundled to the root of the package
        return root
        
    bin_dir = root / '.bin' / 'trivy'
    bin_dir.mkdir(parents=True, exist_ok=True)
    return bin_dir

def get_trivy_executable() -> str:
    """Returns the path to the Trivy executable, downloading it if necessary."""
    bin_dir = _get_trivy_bin_dir()
    os_name = platform.system().lower()
    
    exe_name = 'trivy.exe' if os_name == 'windows' else 'trivy'
    exe_path = bin_dir / exe_name
    
    if exe_path.exists() and os.access(exe_path, os.X_OK):
        return str(exe_path)
        
    # Standard fallback path if already exist globally
    if shutil.which("trivy"):
        return "trivy"
        
    print(f"📥 Trivy executable not found locally.")
    print(f"📥 Downloading and provisioning Trivy for {os_name}...")
    _download_trivy(bin_dir, os_name)
    
    if os_name != 'windows':
        os.chmod(exe_path, 0o755)
        
    print(f"✅ Trivy provisioned successfully at {exe_path}")
    return str(exe_path)

def _download_trivy(bin_dir: Path, os_name: str):
    """Downloads and extracts the correct Trivy binary from GitHub."""
    import json
    
    machine = platform.machine().lower()
    arch = "64bit"
    if machine in ["aarch64", "arm64"]:
        arch = "ARM64"
    elif machine in ["x86_64", "amd64"]:
        arch = "64bit"
        
    # Map OS string for Trivy releases searching
    if os_name == 'windows':
        os_search = "windows"
        ext = "zip"
    elif os_name == 'darwin':
        os_search = "macos"
        ext = "tar.gz"
    else:
        os_search = "linux"
        ext = "tar.gz"
        
    print(f"   Fetching latest release info from AquaSecurity...")
    api_url = "https://api.github.com/repos/aquasecurity/trivy/releases/latest"
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'application/vnd.github.v3+json'
    }
    token = os.environ.get('GITHUB_TOKEN')
    if token:
        headers['Authorization'] = f'Bearer {token}'
        
    try:
        req = urllib.request.Request(api_url, headers=headers)
        with urllib.request.urlopen(req) as response:
            release_data = json.loads(response.read().decode())
    except Exception as e:
        # If GitHub API fails, we could potentially fallback to a hardcoded version, 
        # but for now we raise the error with details
        raise RuntimeError(f"Failed to fetch release info from {api_url}: {e}")

    # Find the matching asset
    download_url = None
    filename = None
    
    for asset in release_data.get('assets', []):
        asset_name = asset['name'].lower()
        if os_search in asset_name and arch.lower() in asset_name and asset_name.endswith(ext) and 'sbom' not in asset_name:
            download_url = asset['browser_download_url']
            filename = asset['name']
            break
            
    if not download_url:
        raise RuntimeError(f"Could not find a valid Trivy binary release for {os_name} {arch}.")
    
    download_path = bin_dir / filename
    
    # Download
    print(f"   Downloading from {download_url}...")
    try:
        urllib.request.urlretrieve(download_url, download_path)
    except Exception as e:
        raise RuntimeError(f"Failed to download Trivy from {download_url}. Error: {e}")
        
    # Extract
    print(f"   Extracting {filename}...")
    try:
        if ext == "zip":
            with zipfile.ZipFile(download_path, 'r') as zip_ref:
                # Extract only the executable to avoid clutter
                for member in zip_ref.namelist():
                    if member.endswith('trivy.exe'):
                        # Flatten extraction to bin_dir directly
                        source = zip_ref.open(member)
                        target = open(os.path.join(bin_dir, "trivy.exe"), "wb")
                        with source, target:
                            shutil.copyfileobj(source, target)
                        break
        else:
            with tarfile.open(download_path, 'r:gz') as tar_ref:
                for member in tar_ref.getmembers():
                    if member.name.endswith('trivy'):
                        member.name = os.path.basename(member.name)
                        tar_ref.extract(member, bin_dir)
                        break
    finally:
        # Cleanup archive
        if download_path.exists():
            os.remove(download_path)
    
if __name__ == "__main__":
    # Test execution
    print(get_trivy_executable())
