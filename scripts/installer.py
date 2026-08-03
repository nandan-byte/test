import os
import sys

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

import zipfile
import shutil
import tempfile
import stat
import time

def install():
    print("Installing AppSecAI...")
    # Determine the install directory (user's home directory to avoid Admin privileges)
    install_dir = os.path.join(os.path.expanduser("~"), "CazeAppSecAI")
    
    if os.path.exists(install_dir):
        print(f"Cleaning up previous installation at {install_dir}")
        shutil.rmtree(install_dir, ignore_errors=True)
    
    os.makedirs(install_dir, exist_ok=True)
    
    # The zip file is bundled with Nuitka via --include-data-file
    # In Nuitka, we can find the data file relative to os.path.dirname(__file__) or sys.argv[0]
    base_dir = os.path.dirname(os.path.abspath(__file__)) if '__file__' in globals() else os.path.dirname(sys.executable)
    zip_path = os.path.join(base_dir, "appsecai.zip")
    
    if not os.path.exists(zip_path):
        print(f"Error: Installation data not found at {zip_path}")
        input("Press Enter to exit...")
        return
        
    print("Extracting files...")
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(install_dir)
        
    main_exe = os.path.join(install_dir, "main.exe")
    if not os.path.exists(main_exe):
        print("Error: Extracted successfully but main.exe is missing.")
        input("Press Enter to exit...")
        return
        
    print("\n✅ Installation Successful!")
    print(f"AppSecAI is now installed at: {install_dir}")
    print("\nLaunching AppSecAI interactive console...")
    
    try:
        os.startfile(main_exe)
    except Exception as e:
        print(f"Could not automatically launch AppSecAI: {e}")
        print("Please run it manually from the directory.")

    print("\nPress Enter to finish...")
    input()

if __name__ == "__main__":
    try:
        install()
    except Exception as e:
        print(f"Fatal error during installation: {e}")
        input("Press Enter to exit...")
