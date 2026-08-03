# pyinstaller_hooks\set_cwd.py
import os, sys
if getattr(sys, "frozen", False):
    # When running the onefile exe, PyInstaller extracts files to _MEIPASS
    try:
        os.chdir(sys._MEIPASS)
    except Exception:
        pass
