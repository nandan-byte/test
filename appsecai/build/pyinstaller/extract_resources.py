# pyinstaller_hooks/extract_resources.py
# Runtime hook to prepare bundled resources for AppSecAI onefile EXE.

import os
import sys

def _ensure_dir(path):
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        # If creation fails, continue — the code using directories should handle errors.
        pass

def _init_appsecai_runtime():
    """
    When running from a PyInstaller onefile EXE, sys._MEIPASS points
    to the extracted runtime folder. Ensure required runtime folders
    exist and add base path to sys.path for imports.
    """
    if not getattr(sys, "frozen", False):
        # Not running as an EXE — nothing to do here.
        return

    # sys._MEIPASS is where PyInstaller unpacks the app at runtime.
    base = getattr(sys, "_MEIPASS", None)
    if not base:
        return

    # Ensure important runtime folders exist inside the extracted bundle.
    # We create cloned_repos (empty) so code that expects the folder won't fail.
    expected_dirs = [
        "external",
        "appsecai/vcs_integrations/git_workflow",
        "Splitted_workflow",
        "cloned_repos",
    ]

    for d in expected_dirs:
        full = os.path.join(base, d)
        _ensure_dir(full)

    # Add the runtime base to sys.path (highest priority)
    if base not in sys.path:
        sys.path.insert(0, base)

    # Export runtime base path so other modules can read it
    os.environ.setdefault("APPSECAI_RUNTIME", base)

# Execute on import (PyInstaller runtime hooks are executed automatically)
_init_appsecai_runtime()
