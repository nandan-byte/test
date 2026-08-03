"""
Adapter to integrate the advanced appsecai/vcs_integrations/git_workflow with the CLI.
Fully compatible with both source execution and PyInstaller OneFile EXE.
"""

import os
import sys

# Detect Nuitka compilation and set sys.frozen for compatibility
if "__compiled__" in globals() or "__compiled__" in sys.modules or hasattr(sys, "frozen"):
    sys.frozen = True

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

import tempfile
import yaml
from typing import Dict, Any, List, Tuple
from pathlib import Path


# ------------------------------------------------------------
# BASE PATH HANDLER (Important for PyInstaller EXE)
# ------------------------------------------------------------
def get_base_path():
    """Return the correct base path whether running from source, PyInstaller, or Nuitka."""
    if getattr(sys, "frozen", False):  # Running inside packaged EXE
        if hasattr(sys, "_MEIPASS"):  # PyInstaller
            return sys._MEIPASS
        # Nuitka Standalone (data files are in the same folder as the executable)
        return os.path.dirname(sys.executable)
    
    # Safely find the project root regardless of whether we are running from .py or .pyc in __pycache__
    current_dir = os.path.abspath(os.path.dirname(__file__))
    while current_dir and current_dir != os.path.dirname(current_dir):
        if os.path.exists(os.path.join(current_dir, 'requirements.txt')) and os.path.exists(os.path.join(current_dir, 'appsecai')):
            return current_dir
        current_dir = os.path.dirname(current_dir)
        
    # Fallback if not found
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def get_executable_path() -> str:
    """Return the actual executable binary path for launching sub-commands."""
    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
        binary_name = "main.exe" if sys.platform == "win32" else "main"
        main_bin = os.path.join(exe_dir, binary_name)
        if os.path.exists(main_bin):
            return main_bin
        if sys.executable and os.path.exists(sys.executable):
            return sys.executable
        if sys.argv and sys.argv[0] and os.path.exists(sys.argv[0]):
            return os.path.abspath(sys.argv[0])
        return main_bin
    return sys.executable


def fix_tls_certificate_paths():
    """
    Fix TLS/SSL certificate paths for misconfigured environments.
    
    Some Python installations (e.g., bundled/embedded Python, conda, or systems
    with legacy PostgreSQL) may not have SSL_CERT_FILE or REQUESTS_CA_BUNDLE set,
    causing TLS verification failures. This function sets them to the certifi
    CA bundle if available.
    """
    # Skip if already configured
    if os.environ.get("SSL_CERT_FILE") and os.environ.get("REQUESTS_CA_BUNDLE"):
        return

    try:
        import certifi
        ca_bundle = certifi.where()
        if ca_bundle and os.path.exists(ca_bundle):
            os.environ.setdefault("SSL_CERT_FILE", ca_bundle)
            os.environ.setdefault("REQUESTS_CA_BUNDLE", ca_bundle)
    except ImportError:
        # certifi not installed – nothing to fix
        pass


BASE_PATH = get_base_path()


def get_resource_path(relative_path: str) -> str:
    """
    Resolve a resource file path that works both when running as a
    normal Python script and when packaged as a PyInstaller .exe.

    PyInstaller extracts bundled files to a temp folder stored in
    sys._MEIPASS at runtime. For regular Python execution the path
    is resolved relative to the project base path.
    """
    return os.path.join(BASE_PATH, relative_path)


# ------------------------------------------------------------
# ADVANCED WORKFLOW CONFIG CREATOR
# ------------------------------------------------------------
def create_advanced_config(
    input_csv: str,
    github_config: Dict[str, Any],
    llm_config: Dict[str, Any],
    batch_size: int = 2,
) -> str:
    """Create a temporary YAML config file for the advanced workflow."""

    config = {
        "input_csv": input_csv,
        "output_dir": "vulnerability-fixes",
        "batch_size": batch_size,
        "commit_batch_size": batch_size,
        "pr_batch_size": batch_size,
        "max_readme_vulnerabilities": 10,
        "github": {
            "token": github_config.get("token", ""),
            "repo": github_config.get("repo", ""),
            "pr_title_prefix": github_config.get("pr_title_prefix", "AI Security Fixes"),
            "base_branch": github_config.get("base_branch", "main"),
            "clone_dir": f"cloned_repos/repo_clone_{github_config.get('repo', 'unknown').replace('/', '_')}",
        },
        "llm": {
            "model": llm_config.get("model", " WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B"),
            "url": llm_config.get("url", "http://4.247.140.236:11434").rstrip("/") + "/api/generate",
            "timeout": llm_config.get("timeout", 30),
            "max_retries": llm_config.get("max_retries", 2),
            "retry_delay": llm_config.get("retry_delay", 1),
            "prompt_template": """
You are a security expert fixing code vulnerabilities. You MUST provide COMPLETE, WORKING code that can directly replace the original code.

CRITICAL REQUIREMENTS:
1. Provide ONLY the complete fixed code - no explanations, comments, or placeholders
2. NEVER use phrases like "rest of the code remains the same", "...", or similar placeholders
3. Include ALL original code with ONLY the security fixes applied
4. Maintain exact formatting, indentation, and structure
5. Ensure the code compiles and runs correctly after replacement

Security Issue: {message}
Rule: {ruleKey}
Risk Level: {vulnerabilityProbability}

ORIGINAL CODE TO FIX:
{extracted_code}

RESPOND WITH ONLY THE COMPLETE FIXED CODE:""",
        },
    }

    # Create the temporary YAML config file
    temp_fd, temp_path = tempfile.mkstemp(suffix=".yaml", prefix="advanced_config_")
    try:
        with os.fdopen(temp_fd, "w") as f:
            yaml.dump(config, f, default_flow_style=False)
    except:
        os.close(temp_fd)
        raise

    return temp_path


# ------------------------------------------------------------
# ADVANCED WORKFLOW EXECUTION (EXE Safe)
# ------------------------------------------------------------
def run_advanced_workflow(
    input_csv: str,
    github_config: Dict[str, Any],
    llm_config: Dict[str, Any],
    create_prs: bool = False,
    batch_size: int = 2,
) -> Tuple[List[Dict], List[str]]:

    # Import advanced workflow modules
    try:
        from appsecai.core.remediation.pr_generator import (
            FixerConfig,
            process_vulnerabilities_in_batches,
            clone_repository,
            load_csv_vulnerabilities,
        )
    except Exception as e:
        raise Exception(f"Failed to import advanced workflow modules: {e}")

    # Create the advanced workflow configuration
    config_path = create_advanced_config(input_csv, github_config, llm_config, batch_size)

    try:
        advanced_config = FixerConfig(config_path)

        # CLONE REPO (if PR creation enabled)
        if create_prs:
            print("🔄 Cloning repository for PR creation...")
            if not clone_repository(advanced_config):
                raise Exception("Failed to clone repository")

        # LOAD VULNERABILITIES
        print("📊 Loading vulnerabilities...")
        vulnerabilities = load_csv_vulnerabilities(advanced_config)

        if not vulnerabilities:
            print("⚠️ No vulnerabilities found to process")
            return [], []

        print(f"✅ Loaded {len(vulnerabilities)} vulnerabilities")

        # PR CREATION MODE
        if create_prs:
            print("🤖 Processing vulnerabilities with AI and creating PRs...")
            processed_vulns, pr_urls = process_vulnerabilities_in_batches(
                advanced_config, vulnerabilities
            )

        # DRY RUN MODE
        else:
            print("🤖 Simulating vulnerability processing (dry-run)...")
            processed_vulns = []
            for vuln in vulnerabilities:
                temp = vuln.copy()
                temp["status"] = "simulated"
                temp["fixed_code"] = (
                    f"Would generate AI fix for: {vuln.get('message', 'Unknown issue')}"
                )
                processed_vulns.append(temp)
            pr_urls = []

        return (
            processed_vulns,
            [url for _, url, _ in pr_urls] if pr_urls else [],
        )

    except Exception as e:
        raise Exception(f"Advanced workflow execution failed: {e}")

    finally:
        # Cleanup temp config file
        if os.path.exists(config_path):
            os.unlink(config_path)


# --------------------------------------------------------
# SAFE IMPORT FUNCTION
# --------------------------------------------------------
def safe_import(module_name: str, error_message: str = None) -> Any:
    """
    Safely import a module. Works inside EXE as well.
    """
    try:
        return __import__(module_name)

    except ImportError:
        # Try to add EXE/base path
        if BASE_PATH not in sys.path:
            sys.path.insert(0, BASE_PATH)
        try:
            return __import__(module_name)
        except Exception as e:
            if error_message:
                print(f"❌ {error_message}")
            else:
                print(f"❌ Failed to import {module_name}: {e}")

            print(f"💡 Running from EXE: {getattr(sys, 'frozen', False)}")
            print(f"💡 Base path: {BASE_PATH}")
            return None


# --------------------------------------------------------
# BACKEND IMPORT WRAPPERS
# --------------------------------------------------------
def get_sonarqube_processor():
    import importlib
    try:
        return importlib.import_module('appsecai.drivers.sast.sast_processor')
    except Exception as e:
        print(f"❌ Cannot import sast_processor (appsecai.drivers.sast.sast_processor): {e}")
        print(f"💡 Running from EXE: {getattr(sys, 'frozen', False)}")
        print(f"💡 Base path: {BASE_PATH}")
        return None


def get_zap_scanner():
    import importlib
    try:
        return importlib.import_module('appsecai.drivers.dast.zap_driver')
    except Exception as e:
        print(f"❌ Cannot import zap_driver (appsecai.drivers.dast.zap_driver): {e}")
        print(f"💡 Running from EXE: {getattr(sys, 'frozen', False)}")
        print(f"💡 Base path: {BASE_PATH}")
        return None


def get_process1github():
    import importlib
    try:
        return importlib.import_module('appsecai.core.remediation.pr_generator')
    except Exception as e:
        print(f"❌ Cannot import pr_generator (appsecai.core.remediation.pr_generator): {e}")
        return None


# --------------------------------------------------------
# PROJECT STRUCTURE VALIDATION (FIXED FOR EXE MODE)
# --------------------------------------------------------
def validate_project_structure() -> bool:
    """
    Validates required backend files. Works even inside EXE.
    """
    # When running inside EXE, DO NOT REQUIRE real .py files on disk
    if getattr(sys, "frozen", False):
        # Skip strict checks – modules are inside the EXE archive
        # Try to import the modules to verify they're bundled
        try:
            from appsecai.drivers.sast import sast_processor
            from appsecai.drivers.dast import zap_driver as zap_scanner
            from appsecai.core.remediation import pr_generator as process1github
            return True
        except ImportError as e:
            print(f"⚠️ Some backend modules not bundled in EXE: {e}")
            # Don't fail completely, allow graceful degradation
            return True

    # Only check files when running from source
    required_files = [
        'requirements.txt',
        os.path.join('appsecai', 'drivers', 'sast', 'sast_processor.py'),
        os.path.join('appsecai', 'drivers', 'dast', 'dast_scanner.py'),
        os.path.join('appsecai', 'core', 'remediation', 'pr_generator.py'),
    ]

    missing = []
    for f in required_files:
        full_path = os.path.join(BASE_PATH, f)
        if not os.path.exists(full_path):
            missing.append(f)

    if missing:
        print(f"❌ Missing required files: {', '.join(missing)}")
        print("💡 Please run the CLI from the project root directory")
        return False

    return True


# --------------------------------------------------------
# VALIDATE ON IMPORT
# --------------------------------------------------------
# Only validate when NOT running as EXE and not during PyInstaller build
if not getattr(sys, "frozen", False) and not getattr(sys, "_MEIPASS", None):
    if not validate_project_structure():
        print("⚠️ Project structure validation failed. Some CLI features may not work properly.")


# --------------------------------------------------------
# ROBUST JSON PARSER (Handles comments and raw Windows paths)
# --------------------------------------------------------
def load_appsec_json_data(file_path: str) -> Dict[str, Any]:
    """
    Safely load a JSON configuration file.
    1. Strips single-line and multi-line comments.
    2. Automatically escapes unescaped raw backslashes inside string values.
    """
    import re
    import json
    
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
        
    # Strip comments while preserving strings
    comment_pattern = re.compile(r'("(?:\\[\s\S]|[^"])*")|(/\*.*?\*/|//[^\r\n]*)', re.MULTILINE | re.DOTALL)
    content = comment_pattern.sub(lambda m: m.group(1) if m.group(1) else "", content)
    
    # Escape invalid backslashes inside string literals (e.g. Windows paths like D:\path)
    string_pattern = re.compile(r'"((?:\\[\s\S]|[^"])*)"')
    
    def sanitize_string_literal(match):
        inner_str = match.group(1)
        res = []
        i = 0
        n = len(inner_str)
        while i < n:
            if inner_str[i] == '\\':
                if i + 1 < n:
                    next_char = inner_str[i+1]
                    if next_char in '"\\/bfnrt':
                        res.append('\\' + next_char)
                        i += 2
                    elif next_char == 'u' and i + 5 < n and all(c in '0123456789abcdefABCDEF' for c in inner_str[i+2:i+6]):
                        res.append('\\' + inner_str[i+1:i+6])
                        i += 6
                    else:
                        res.append('\\\\')
                        i += 1
                else:
                    res.append('\\\\')
                    i += 1
            else:
                res.append(inner_str[i])
                i += 1
        return '"' + "".join(res) + '"'

    sanitized_content = string_pattern.sub(sanitize_string_literal, content)
    return json.loads(sanitized_content)

