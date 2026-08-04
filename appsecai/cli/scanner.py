#!/usr/bin/env python3
"""
CLI Runner Script

Ensures the CLI runs in the correct Python environment with all dependencies.
"""

import sys
import os
import subprocess
from pathlib import Path

def ensure_venv():
    """Ensure we're running in the virtual environment."""
    venv_path = Path('.venv')
    if venv_path.exists():
        if sys.platform == 'win32':
            python_exe = venv_path / 'Scripts' / 'python.exe'
        else:
            python_exe = venv_path / 'bin' / 'python'
        
        if python_exe.exists() and str(python_exe) not in sys.executable:
            print(f"🔄 Switching to virtual environment: {python_exe}")
            # Re-run with the virtual environment Python
            cmd = [str(python_exe)] + sys.argv
            return subprocess.run(cmd).returncode
    
    return None

def main():
    """Main CLI runner."""
    # Check if we need to switch to venv
    venv_result = ensure_venv()
    if venv_result is not None:
        return venv_result
    
    # Import and run the CLI
    try:
        from appsecai.cli.main import CLIMain
        cli = CLIMain()
        return cli.main()
    except ImportError as e:
        print(f"❌ Failed to import CLI: {e}")
        print("💡 Try running: python setup_cli.py")
        return 1
    except Exception as e:
        print(f"❌ CLI error: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())