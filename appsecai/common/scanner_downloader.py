import os
import sys
import urllib.request
import zipfile
import logging
import shutil

from appsecai.common.utils import get_resource_path

logger = logging.getLogger(__name__)

# Constants for SonarScanner
SONAR_SCANNER_VERSION = "6.2.1.4610"
BASE_URL = f"https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-{SONAR_SCANNER_VERSION}"

def get_platform_info():
    if sys.platform.startswith("win"):
        return "windows-x64", "sonar-scanner.bat"
    elif sys.platform.startswith("linux"):
        return "linux-x64", "sonar-scanner"
    elif sys.platform == "darwin":
        return "macosx-x64", "sonar-scanner"
    else:
        return "windows-x64", "sonar-scanner.bat" # Fallback to Windows

def ensure_sonar_scanner_installed() -> str:
    """
    Checks if SonarScanner is installed in the local .bin directory or system PATH.
    If not, downloads and extracts it automatically.
    Returns the absolute path to the executable.
    """
    # First, check if it's already in system PATH
    system_path_scanner = shutil.which("sonar-scanner")
    # Some environments have it as sonar-scanner.bat explicitly in PATH
    if not system_path_scanner and sys.platform.startswith("win"):
        system_path_scanner = shutil.which("sonar-scanner.bat")
        
    if system_path_scanner:
        return system_path_scanner
        
    os_suffix, executable_name = get_platform_info()
    bin_dir = get_resource_path("appsecai/.bin")
    scanner_dir_name = f"sonar-scanner-{SONAR_SCANNER_VERSION}-{os_suffix}"
    scanner_base_dir = os.path.join(bin_dir, "sonar-scanner")
    
    # Target executable path within local bin directory
    executable_path = os.path.join(scanner_base_dir, scanner_dir_name, "bin", executable_name)
    
    # If the executable exists, return it
    if os.path.exists(executable_path):
        return executable_path
        
    # Start download process
    os.makedirs(scanner_base_dir, exist_ok=True)
    zip_url = f"{BASE_URL}-{os_suffix}.zip"
    zip_path = os.path.join(scanner_base_dir, "sonar-scanner.zip")
    
    logger.info(f"📥 SonarScanner CLI not found. Downloading from {zip_url}...")
    try:
        # Create a progress hook for download
        def report_hook(count, block_size, total_size):
            if count == 0:
                logger.info(f"Initiating download ({total_size / 1024 / 1024:.1f} MB)...")
            elif count % 500 == 0:
                logger.info(f"Downloading... {count * block_size / 1024 / 1024:.1f} MB downloaded")
                
        urllib.request.urlretrieve(zip_url, zip_path, reporthook=report_hook)
        logger.info(f"✅ Download complete. Extracting archive...")
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(scanner_base_dir)
            
        # Clean up zip
        os.remove(zip_path)
        
        # Make executable on Unix
        if not sys.platform.startswith("win"):
            import stat
            st = os.stat(executable_path)
            os.chmod(executable_path, st.st_mode | stat.S_IEXEC)
            
        logger.info(f"✅ SonarScanner CLI successfully installed and ready for use.")
        return executable_path
    except Exception as e:
        logger.error(f"❌ Failed to download/install SonarScanner CLI: {e}")
        # Always fallback to default command if download completely fails
        return "sonar-scanner.bat" if sys.platform.startswith("win") else "sonar-scanner"
