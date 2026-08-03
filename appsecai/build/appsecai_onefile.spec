# appsecai_onefile.spec - FINAL ONEFILE VERSION FOR PYINSTALLER 6+
# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
import platform
import os

# PyInstaller provides SPECPATH which is the directory containing the spec file
try:
    spec_dir = Path(SPECPATH).resolve()
except NameError:
    spec_dir = Path(os.getcwd()).resolve()

# project_root should be the repository root
# If spec is in appsecai/build/, root is 2 levels up
if "appsecai" in str(spec_dir).lower() and "build" in str(spec_dir).lower():
    project_root = spec_dir.parent.parent.resolve()
else:
    # Fallback search for root
    project_root = spec_dir
    while project_root.parent != project_root:
        if (project_root / "appsecai").exists():
            break
        project_root = project_root.parent

print(f"--- Spec Directory: {spec_dir} ---")
print(f"--- Project Root Found: {project_root} ---")

block_cipher = None

os_name = platform.system().lower()
trivy_bin = "trivy.exe" if os_name == "windows" else "trivy"

# Data files to bundle - Essential resources
datas = [
    (str(project_root / "appsecai" / "risk_profiles" / "context_modifiers" / "vulnerability_framework.json"), "appsecai/risk_profiles/context_modifiers"),
    (str(project_root / "appsecai" / "risk_profiles" / "context_modifiers" / "risk_context_template.json"), "appsecai/risk_profiles/context_modifiers"),
    (str(project_root / "appsecai" / "risk_profiles" / "app_config.yaml"), "appsecai/risk_profiles"),
    (str(project_root / "README.md"), "."),
    (str(project_root / "external"), "external"),
]

# Optional: include appsec_config.json if it exists
if os.path.exists(str(project_root / "appsec_config.json")):
    datas.append((str(project_root / "appsec_config.json"), "."))

# Optional: include .env if it exists
if os.path.exists(str(project_root / ".env")):
    datas.append((str(project_root / ".env"), "."))

# Optional: include trivy binary if it exists
trivy_path = str(project_root / "appsecai" / ".bin" / "trivy" / trivy_bin)
if os.path.exists(trivy_path):
    datas.append((trivy_path, "."))

a = Analysis(
    [str(project_root / 'appsecai' / 'cli' / 'main.py')],  # ENTRY POINT
    pathex=[str(project_root)],
    binaries=[],
    datas=datas,
    hiddenimports=[
        # Core backend modules
        "appsecai.drivers.sast.processor",
        "appsecai.drivers.dast.scanner",
        "appsecai.drivers.dast.processor",
        "appsecai.drivers.dast.zap_driver",
        "appsecai.core.scorer",
        "appsecai.reporting.posture_report",
        "appsecai.reporting.engine",
        "appsecai.drivers.sast.mapper",
        "appsecai.drivers.sca.runner",
        "appsecai.drivers.sca.scanner",
        "appsecai.drivers.sca.category_mapper",
        "appsecai.drivers.sca.downloader",
        "appsecai.cli.menu",
        "appsecai.cli.interactive_setup",
        "appsecai.cli.scanner",
        
        # Orchestration and Common
        "appsecai.common.config",
        "appsecai.common.utils",
        "appsecai.common.scanner_downloader",
        "appsecai.core.orchestration.manager",
        "appsecai.core.orchestration.docker_manager",
        
        # Core remediation
        "appsecai.core.remediation.rule_based_remediation",
        "appsecai.core.remediation.ai_remediation",
        "appsecai.core.remediation.pr_generator",
        "appsecai.core.remediation.github_pr_batch",
        "appsecai.core.remediation.remediation_strategies",
        
        # Report generation - reportlab (advanced PDF)
        "reportlab",
        "reportlab.pdfgen",
        "reportlab.pdfgen.canvas",
        "reportlab.lib",
        "reportlab.lib.pagesizes",
        "reportlab.lib.styles",
        "reportlab.lib.colors",
        "reportlab.lib.units",
        "reportlab.lib.enums",
        "reportlab.platypus",
        "reportlab.graphics",
        "reportlab.graphics.shapes",
        "reportlab.graphics.charts.piecharts",
        "reportlab.graphics.charts.barcharts",
        
        # Report generation - fpdf (simple PDF)
        "fpdf",
        
        # Data processing
        "pandas",
        "pandas.core",
        "pandas.io.parsers",
        
        # HTML parsing
        "bs4",
        "html5lib",
        
        # Plotting
        "plotly",
        "plotly.graph_objs",
        
        # GitHub API
        "github",
        "github.MainClass",
        "github.GithubException",
        "github.Repository",
        "github.PullRequest",
        
        # HTTP & networking
        "requests",
        "requests.auth",
        "urllib3",
        
        # YAML parsing
        "yaml",
        
        # Progress bars
        "tqdm",
        
        # Concurrency
        "concurrent.futures",
        "threading",
        
        # Standard library (PyInstaller sometimes misses these)
        "encodings.idna",
        "importlib._bootstrap",
        "importlib._bootstrap_external",
        "subprocess",
        "csv",
        "json",
        "datetime",
        "pathlib",
    ],
    hookspath=[],
    runtime_hooks=[
        str(project_root / 'appsecai' / 'build' / 'pyinstaller' / 'extract_resources.py'),
        str(project_root / 'appsecai' / 'build' / 'pyinstaller' / 'set_cwd.py')
    ],
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# -----------------------------
# ✔ NEW ONEFILE EXE FORMAT
# -----------------------------
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    name='AppSecAI',
    debug=False,
    strip=False,
    upx=True,
    console=True,
)
