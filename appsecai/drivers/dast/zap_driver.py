from appsecai.common.config import logger
import os
import time
import threading
import socket
from datetime import datetime
import pandas as pd
from bs4 import BeautifulSoup
from glob import glob


# ======================
# Utility Functions
# ======================

def run_zap_command(cmd, cwd):
    """Runs a system command for ZAP, prints progress to stdout in real-time, and returns stdout/stderr."""
    import subprocess
    import sys
    
    process = subprocess.Popen(
        cmd,
        cwd=cwd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    
    stdout_lines = []
    while True:
        line = process.stdout.readline()
        if not line and process.poll() is not None:
            break
        if line:
            stdout_lines.append(line)
            line_clean = line.strip()
            # Filter and print ZAP progress logs in real-time
            if "%" in line_clean or "Job" in line_clean or "progress" in line_clean.lower() or "activeScan" in line_clean or "spider" in line_clean:
                print(f"[ZAP PROGRESS] {line_clean}")
                sys.stdout.flush()
                
    process.wait()
    return subprocess.CompletedProcess(
        args=cmd,
        returncode=process.returncode,
        stdout="".join(stdout_lines),
        stderr=""
    )

def find_project_root():
    """Find the project root directory by looking for key files."""
    current_dir = os.path.abspath(os.path.dirname(__file__))
    
    # Look for project indicators
    indicators = ['app_config.yaml', 'requirements.txt', '.git', 'main.py']
    
    # Start from current file's directory and go up
    while current_dir != os.path.dirname(current_dir):  # Not at filesystem root
        if any(os.path.exists(os.path.join(current_dir, indicator)) for indicator in indicators):
            return current_dir
        current_dir = os.path.dirname(current_dir)
    
    # Fallback to current working directory
    return os.getcwd()

def resolve_zap_installation_path(path_hint: str | None) -> tuple[str | None, str | None]:
    """Resolve the ZAP installation directory that contains zap executable.

    Returns (install_dir, zap_executable_path) or (None, None) if not found.
    """
    try:
        project_root = find_project_root()
        
        # Determine the correct ZAP executable based on OS
        import platform
        if platform.system() == "Windows":
            zap_executable = "zap.bat"
        else:
            zap_executable = "zap.sh"
        
        # 1) If hint provided and valid, use it
        if path_hint:
            # Handle both absolute and relative paths
            if os.path.isabs(path_hint):
                abs_path_hint = path_hint
            else:
                # Make relative paths relative to project root
                abs_path_hint = os.path.join(project_root, path_hint)
            
            abs_path_hint = os.path.abspath(abs_path_hint)
            zap_exec_hint = os.path.join(abs_path_hint, zap_executable)
            if os.path.exists(zap_exec_hint):
                # Ensure executable permissions on Unix-like systems
                if platform.system() != "Windows":
                    try:
                        import stat
                        os.chmod(zap_exec_hint, os.stat(zap_exec_hint).st_mode | stat.S_IEXEC)
                    except Exception as e:
                        print(f"Warning: Could not set execute permissions on {zap_exec_hint}: {e}")
                return abs_path_hint, zap_exec_hint
            
        # 2) Search common locations relative to project root
        search_roots = [
            os.path.join(project_root, "external"),
            project_root,
        ]
        for root in search_roots:
            try:
                matches = glob(os.path.join(root, "**", zap_executable), recursive=True)
            except Exception:
                matches = []
            if matches:
                # Prefer the most recently modified executable
                matches.sort(key=lambda p: os.path.getmtime(p), reverse=True)
                zap_exec = matches[0]
                
                # Ensure executable permissions on Unix-like systems
                if platform.system() != "Windows":
                    try:
                        import stat
                        os.chmod(zap_exec, os.stat(zap_exec).st_mode | stat.S_IEXEC)
                    except Exception as e:
                        print(f"Warning: Could not set execute permissions on {zap_exec}: {e}")
                
                return os.path.dirname(zap_exec), zap_exec
        return None, None
    except Exception:
        return None, None

def find_available_port(start_port=8000, max_attempts=50):
    """Find an available port starting from start_port."""
    for port in range(start_port, start_port + max_attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('localhost', port))
                return port
        except OSError:
            continue
    return None

def kill_existing_zap_processes():
    """Kill any existing ZAP processes to avoid port conflicts."""
    import platform
    if platform.system() == "Windows":
        os.system("taskkill /F /IM java.exe >nul 2>&1")
    else:
        # On Linux, be more specific to avoid killing other Java processes
        os.system("pkill -f 'org.zaproxy.zap.ZAP' 2>/dev/null || true")
        os.system("pkill -f 'zap.sh' 2>/dev/null || true")

def monitor_report_and_kill(timeout, report_path):
    """Monitor ZAP scan and kill if it exceeds timeout.
    
    Checks if the report file is created and has content (> 100 bytes).
    """
    start = time.time()
    while time.time() - start < timeout:
        if os.path.exists(report_path) and os.path.getsize(report_path) > 100:
            print("[Monitor] Report ready, stopping monitor.")
            return
        time.sleep(5)

    print("[Monitor] Timeout reached. Killing ZAP process...")
    kill_existing_zap_processes()

def find_latest_zap_report():
    """Find the most recent zap_report.html in zap_reports/."""
    report_files = glob(os.path.join("zap_reports", "**", "zap_report.html"), recursive=True)
    if not report_files:
        return None
    return max(report_files, key=os.path.getmtime)

def parse_zap_html_to_df(report_path=None):
    """
    Parses ZAP HTML report into a DataFrame.
    Supports:
    - New 'alertsTable' format (ZAP 2.16+)
    - Old 'alertitem' format
    - dast_processor fallback
    """
    try:
        if not report_path or not os.path.exists(report_path):
            report_path = find_latest_zap_report()
            if not report_path:
                print("[Parser] No ZAP report found.")
                return pd.DataFrame()
            print(f"[Parser] Using latest report: {report_path}")

        with open(report_path, "r", encoding="utf-8") as f:
            soup = BeautifulSoup(f, "html.parser")

        findings = []

        # ---- 1. Traditional ZAP HTML format (results table) ----
        results_tables = soup.find_all("table", class_="results")
        for table in results_tables:
            rows = table.find_all("tr")
            current_alert = None
            current_risk = None
            current_description = None
            
            for row in rows:
                # Check if this is an alert header row
                header_cells = row.find_all("th")
                if len(header_cells) >= 2 and "risk-" in str(header_cells[0].get("class", [])):
                    # This is an alert header row
                    current_risk = header_cells[0].get_text(strip=True)
                    current_alert = header_cells[1].get_text(strip=True)
                    current_description = ""
                    
                    # Get description from next row
                    next_row = row.find_next_sibling("tr")
                    if next_row and next_row.find("td", text="Description"):
                        desc_cell = next_row.find("td", attrs={"width": "80%"})
                        if desc_cell:
                            current_description = desc_cell.get_text(strip=True)
                
                # Check if this is a URL detail row
                elif row.find("td", text="URL"):
                    url_cell = row.find("td", attrs={"width": "80%"})
                    if url_cell:
                        url_link = url_cell.find("a")
                        url = url_link.get("href") if url_link else url_cell.get_text(strip=True)
                        
                        # Get parameter from next row if available
                        parameter = ""
                        param_row = row.find_next_sibling("tr")
                        if param_row and param_row.find("td", text="Parameter"):
                            param_cell = param_row.find("td", attrs={"width": "80%"})
                            if param_cell:
                                parameter = param_cell.get_text(strip=True)
                        
                        if current_alert and url:
                            findings.append({
                                "Alert": current_alert,
                                "Risk": current_risk,
                                "Description": current_description,
                                "URL": url,
                                "Parameter": parameter
                            })

        # ---- 2. New alertsTable format ----
        if not findings:
            alert_sections = soup.find_all("section", class_="alert")
            for section in alert_sections:
                # Alert name
                heading = section.find(["h2", "h3"])
                alert_name = heading.get_text(strip=True) if heading else "Unknown Alert"

                table = section.find("table", class_="alertsTable")
                if table:
                    rows = table.find_all("tr")[1:]  # skip header
                    for row in rows:
                        cols = [c.get_text(strip=True) for c in row.find_all("td")]
                        if len(cols) >= 4:
                            findings.append({
                                "Alert": alert_name,
                                "URL": cols[0],
                                "Risk": cols[1],
                                "Confidence": cols[2],
                                "Parameter": cols[3]
                            })

        # ---- 3. Old 'alertitem' format ----
        if not findings:
            alert_items = soup.find_all(lambda tag: tag.name == "div" and "alertitem" in tag.get("class", []))
            for item in alert_items:
                alert = item.find("span", class_="alerttitle")
                risk = item.find("span", class_="risklevel")
                desc = item.find("div", class_="alertdesc")
                instances = item.find_all("td", class_="url")
                alert_name = alert.text.strip() if alert else "N/A"
                risk_level = risk.text.strip() if risk else "N/A"
                description = desc.text.strip() if desc else "N/A"
                urls = [i.text.strip() for i in instances if i.text.strip()]
                for url in urls:
                    findings.append({
                        "Alert": alert_name,
                        "Risk": risk_level,
                        "Description": description,
                        "URL": url
                    })

        # ---- 4. risk-confidence-html parser block ----
        if not findings:
            try:
                instances = soup.find_all("span", class_="request-method-n-url")
                for inst in instances:
                    # Method and URL
                    method_url_text = inst.get_text(strip=True)
                    parts = method_url_text.split(" ", 1)
                    url = parts[1] if len(parts) > 1 else method_url_text
                    
                    # Alert Name (from h5)
                    h5 = inst.find_previous("h5")
                    alert_name = "Unknown Alert"
                    if h5:
                        a_tag = h5.find("a")
                        if a_tag:
                            alert_name = a_tag.get_text(strip=True)
                        else:
                            alert_name = h5.get_text(strip=True)
                    
                    # Risk Level (from h3)
                    h3 = inst.find_previous("h3")
                    risk_level = "N/A"
                    if h3:
                        risk_span = h3.find("span", class_="risk-level")
                        if risk_span:
                            risk_level = risk_span.get_text(strip=True)
                    
                    # Parameter (from alerts-table inside details)
                    parameter = ""
                    parent_li = inst.find_parent("li")
                    if parent_li:
                        table = parent_li.find("table", class_="alerts-table")
                        if table:
                            for row in table.find_all("tr"):
                                th = row.find("th")
                                if th and "parameter" in th.get_text(strip=True).lower():
                                    td = row.find("td")
                                    if td:
                                        parameter = td.get_text(strip=True)
                    
                    findings.append({
                        "Alert": alert_name,
                        "Risk": risk_level,
                        "URL": url,
                        "Parameter": parameter,
                        "Description": alert_name
                    })
            except Exception as e:
                print(f"[Parser risk-confidence-html Error] {e}")

        # ---- 5. dast_processor fallback ----
        if not findings:
            try:
                from appsecai.drivers.dast.dast_processor import extract_alerts, parse_html_report
                soup2 = parse_html_report(report_path)
                if soup2:
                    alerts = extract_alerts(soup2)
                    for a in alerts:
                        findings.append({
                            "Alert": a.get("name", ""),
                            "Risk": a.get("risk", ""),
                            "Description": a.get("description", ""),
                            "URL": a.get("url", "")
                        })
            except Exception as fe:
                print(f"[Parser Fallback Error] {fe}")

        df = pd.DataFrame(findings)

        # ---- Risk sorting ----
        if not df.empty and "Risk" in df.columns:
            df["Risk"] = df["Risk"].astype(str).str.capitalize()
            df = df.sort_values(by=["Risk", "Alert"], ascending=[False, True])

        print(f"[Parser] Parsed {len(df)} findings into DataFrame.")
        return df

    except Exception as e:
        print(f"[Parser Error] Failed to parse ZAP HTML report: {e}")
        return pd.DataFrame()


# ======================
# Main Scan Function
# ======================

def run_zap_scan(
    target_url: str,
    active: bool = True,
    passive: bool = True,
    spider: bool = True,
    quick: bool = False,
    api_spec_url: str = None,
    auth: dict = None,
    api_config: dict = None,
    zap_config: dict = None
):
    """Run OWASP ZAP scan and return results dict."""
    
    # Defensive URL type checking
    if not isinstance(target_url, str):
        error_msg = f"Invalid target_url type: expected string, got {type(target_url).__name__}. Please provide target_url as a string."
        return {
            "success": False,
            "message": error_msg,
            "error": error_msg,
        }
    
    if target_url is None or target_url.strip() == "":
        error_msg = "target_url cannot be None or empty. Please provide a valid URL string."
        return {
            "success": False,
            "message": error_msg,
            "error": error_msg,
        }
    
    # Merge api_spec_url into api_config for backward compatibility
    if not api_config:
        api_config = {}
    if api_spec_url:
        api_config["enabled"] = True
        api_config["spec_url"] = api_spec_url
        if "spec_type" not in api_config:
            api_config["spec_type"] = "openapi"

    # Validate api_spec_url if provided
    if api_spec_url is not None and not isinstance(api_spec_url, str):
        error_msg = f"Invalid api_spec_url type: expected string or None, got {type(api_spec_url).__name__}. Please provide api_spec_url as a string or None."
        return {
            "success": False,
            "message": error_msg,
            "error": error_msg,
        }
    
    # Kill any existing ZAP processes to avoid port conflicts
    kill_existing_zap_processes()
    
    # Set higher memory limit for ZAP to prevent 'insufficient memory' errors
    # Defaulting to 4GB, but can be overridden by environment variable if more is available
    os.environ["JAVA_TOOL_OPTIONS"] = os.environ.get("JAVA_TOOL_OPTIONS", "-Xmx4g")
    logger.info(f"Setting ZAP memory limit to {os.environ['JAVA_TOOL_OPTIONS']} via JAVA_TOOL_OPTIONS")
    
    # Find available ports for ZAP
    zap_port = find_available_port(8000)
    if not zap_port:
        return {
            "success": False,
            "message": "No available ports found for ZAP proxy",
            "error": "Port allocation failed"
        }

    print(f"[ZAP] Starting scan: {target_url}, active={active}, passive={passive}, spider={spider}")
    print(f"[ZAP] Using port: {zap_port}")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Get base directory (works for both Python and EXE)
    import sys
    
    # Check if output_dir was provided in zap_config
    if zap_config and 'output_dir' in zap_config:
        # Use the provided output directory (from CLI --output-dir parameter)
        base_dir = zap_config['output_dir']
    else:
        # Fallback to current working directory
        base_dir = os.getcwd()
    
    output_dir = os.path.abspath(os.path.join(base_dir, f"zap_reports/zap_{timestamp}"))
    os.makedirs(output_dir, exist_ok=True)

    # Get ZAP paths from config or auto-detect
    if zap_config is None:
        zap_config = {}
    configured_path = zap_config.get("installation_path")
    zap_installation_path, zap_bat = resolve_zap_installation_path(configured_path)
    
    if not zap_installation_path or not zap_bat:
        print("\n🚀 ZAP engine not found. Initiating automatic setup...")
        
        # Run the platform-specific installer using project_root for absolute pathing
        project_root = find_project_root()
        if os.name == 'nt':
            installer = os.path.join(project_root, "external", "zap", "install_zap.bat")
            if os.path.exists(installer):
                # Run from project root to ensure script's relative paths work
                os.system(f'cmd /c "cd /d {project_root} && {installer}"')
            else:
                return {"success": False, "message": "Installer script missing: " + installer, "error": "Installer script missing."}
        else:
            installer = os.path.join(project_root, "external", "zap", "install_zap.sh")
            if os.path.exists(installer):
                # Run from project root to ensure script's relative paths work
                os.system(f'cd {project_root} && bash {installer}')
            else:
                return {"success": False, "message": "Installer script missing: " + installer, "error": "Installer script missing."}
        
        # Re-verify path after installation
        zap_installation_path, zap_bat = resolve_zap_installation_path(configured_path)
        
        if not zap_installation_path or not zap_bat:
            error_msg = "Automatic ZAP installation failed. Please check your internet connection or install manually."
            return {
                "success": False,
                "message": error_msg,
                "error": error_msg,
            }
    zap_cwd = zap_installation_path
    report_path = os.path.join(output_dir, "zap_report.html")
    full_log = ""

    try:
        # Install add-ons with port specification
        addons = ["selenium", "spiderAjax"]
        import platform
        if platform.system() == "Windows":
            addons.append("webdriverwindows")
        elif platform.system() == "Linux":
            addons.append("webdriverlinux")
        elif platform.system() == "Darwin":
            addons.append("webdrivermacos")

        is_auth_enabled = False
        if auth:
            auth_enabled_val = auth.get("enabled", False)
            if isinstance(auth_enabled_val, bool):
                is_auth_enabled = auth_enabled_val
            else:
                is_auth_enabled = str(auth_enabled_val).lower() in ["true", "1", "yes"]

        if is_auth_enabled:
            addons.append("authhelper")

        # Update the local ZAP add-on catalog before attempting to install
        try:
            cmd = f'"{zap_bat}" -cmd -port {zap_port} -addonupdate'
            result = run_zap_command(cmd, zap_cwd)
            full_log += f"\n=== Updated Add-on Catalog ===\n{result.stdout}\n{result.stderr}"
        except Exception as e:
            full_log += f"\n[WARN] Failed to update add-on catalog: {str(e)}"

        for addon in addons:
            try:
                cmd = f'"{zap_bat}" -cmd -port {zap_port} -addoninstall {addon}'
                result = run_zap_command(cmd, zap_cwd)
                full_log += f"\n=== Installed Add-on: {addon} ===\n{result.stdout}\n{result.stderr}"
            except Exception as e:
                full_log += f"\n[WARN] Failed to install {addon}: {str(e)}"

        if active:
            yaml_path = os.path.normpath(os.path.join(output_dir, "full_scan.yaml"))
            # Ensure report_dir uses forward slashes to avoid YAML string escape issues on Windows
            report_dir = os.path.normpath(output_dir).replace('\\', '/')
            import re
            from urllib.parse import urlparse
            parsed_url = urlparse(target_url)
            base_origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
            escaped_url_pattern = re.escape(base_origin) + "/.*"

            # 1. Parse auth settings and build Context YAML blocks
            context_auth_yaml = ""
            user_param = ""
            if is_auth_enabled:
                method = auth.get("method", "browser")
                username = auth.get("username", "")
                password = auth.get("password", "")
                login_url = auth.get("login_page_url", "")
                
                # Map short names to official ZAP AF method names
                zap_method = method
                if method == "form":
                    zap_method = "formBased"
                elif method == "json":
                    zap_method = "jsonBased"

                context_auth_yaml += f"\n      authentication:\n        method: '{zap_method}'\n        parameters:\n"
                if method == "browser":
                    context_auth_yaml += f"          loginPageUrl: '{login_url}'\n"
                    context_auth_yaml += f"          browserId: '{auth.get('browser_id', 'firefox')}'\n"
                elif method in ["form", "json", "formBased", "jsonBased"]:
                    context_auth_yaml += f"          loginPageUrl: '{login_url}'\n"
                    req_url = auth.get("login_request_url") or login_url
                    context_auth_yaml += f"          loginRequestUrl: '{req_url}'\n"
                    if auth.get("login_request_body"):
                        context_auth_yaml += f"          loginRequestBody: '{auth.get('login_request_body')}'\n"
                elif method == "http":
                    from urllib.parse import urlparse
                    parsed = urlparse(login_url or target_url)
                    hostname = parsed.hostname or "localhost"
                    context_auth_yaml += f"          hostname: '{hostname}'\n"
                    if parsed.port:
                        context_auth_yaml += f"          port: {parsed.port}\n"
                    context_auth_yaml += f"          realm: '{auth.get('realm', '')}'\n"
                
                # Verification
                logged_in = auth.get("logged_in_regex", "")
                logged_out = auth.get("logged_out_regex", "")
                if logged_in or logged_out:
                    context_auth_yaml += "        verification:\n          method: 'response'\n"
                    if logged_in:
                        context_auth_yaml += f"          loggedInRegex: '{logged_in}'\n"
                    if logged_out:
                        context_auth_yaml += f"          loggedOutRegex: '{logged_out}'\n"
                else:
                    context_auth_yaml += "        verification:\n          method: 'autodetect'\n"
                
                # Session Management
                context_auth_yaml += "      sessionManagement:\n        method: 'cookie'\n"
                
                # Users
                context_auth_yaml += f"""      users:
        - name: 'scan_user'
          credentials:
            username: '{username}'
            password: '{password}'"""
                
                user_param = "\n    user: 'scan_user'"

            # 2. Parse API config and build import job
            is_api_enabled = False
            if api_config:
                api_enabled_val = api_config.get("enabled", False)
                if isinstance(api_enabled_val, bool):
                    is_api_enabled = api_enabled_val
                else:
                    is_api_enabled = str(api_enabled_val).lower() in ["true", "1", "yes"]

            api_job = None
            if is_api_enabled and api_config.get("spec_url"):
                spec_url = api_config.get("spec_url", "")
                spec_type = api_config.get("spec_type", "openapi").lower()
                is_web_url = spec_url.startswith("http://") or spec_url.startswith("https://")
                api_user_line = f"\n    user: 'scan_user'" if is_auth_enabled else ""
                
                if spec_type == "openapi":
                    if is_web_url:
                        api_job = f"""- type: openapi
  parameters:
    apiUrl: '{spec_url}'
    context: 'Default Context'{api_user_line}"""
                    else:
                        abs_spec_path = os.path.abspath(spec_url)
                        api_job = f"""- type: openapi
  parameters:
    apiFile: '{abs_spec_path}'
    context: 'Default Context'{api_user_line}"""
                elif spec_type == "graphql":
                    if is_web_url:
                        api_job = f"""- type: graphql
  parameters:
    schemaUrl: '{spec_url}'
    context: 'Default Context'{api_user_line}"""
                    else:
                        abs_spec_path = os.path.abspath(spec_url)
                        api_job = f"""- type: graphql
  parameters:
    schemaFile: '{abs_spec_path}'
    context: 'Default Context'{api_user_line}"""
                elif spec_type == "soap":
                    if is_web_url:
                        api_job = f"""- type: soap
  parameters:
    wsdlUrl: '{spec_url}'
    context: 'Default Context'{api_user_line}"""
                    else:
                        abs_spec_path = os.path.abspath(spec_url)
                        api_job = f"""- type: soap
  parameters:
    wsdlFile: '{abs_spec_path}'
    context: 'Default Context'{api_user_line}"""

            # 3. Assemble jobs list
            jobs = []
            if api_job:
                jobs.append(api_job)
                
            if spider:
                jobs.append(
                    f"""- type: spider
  parameters:
    context: 'Default Context'{user_param}
    maxDuration: 10"""
                )
            jobs.append(
                f"""- type: spiderAjax
  parameters:
    context: 'Default Context'{user_param}
    url: '{target_url}'
    maxCrawlDepth: 5
    maxDuration: 10"""
            )
            if passive:
                jobs.append("- type: passiveScan-wait")
            jobs.append(
                f"""- type: activeScan
  parameters:
    context: 'Default Context'{user_param}
    policy: 'Default Policy'"""
            )
            jobs.append(
                f"""- type: report
  parameters:
    template: risk-confidence-html
    reportDir: '{report_dir}'
    reportFile: zap_report.html"""
            )

            # 4. Construct YAML file content
            yaml_content = f"""env:
  parameters:
    progressToStdout: true
  contexts:
    - name: 'Default Context'
      urls:
        - '{target_url}'
        - '{base_origin}'
      includePaths:
        - '{escaped_url_pattern}'{context_auth_yaml}
jobs:
{chr(10).join(jobs)}"""

            with open(yaml_path, "w", newline="\n") as f:
                f.write(yaml_content)

            print("[ZAP] YAML config written:", yaml_path)
            print(yaml_content)

            # Get timeout from config or use default
            scan_timeout = 14400  # Default 4 hours to accommodate deep authenticated scans
            if zap_config and 'max_scan_time' in zap_config:
                scan_timeout = zap_config['max_scan_time']
            
            print("\n[Phase 1/3] Crawling application (Spider & Ajax Spider)...")
            # Wait for spidering to complete
            
            threading.Thread(
                target=monitor_report_and_kill,
                args=(scan_timeout, report_path),
                daemon=True
            ).start()

            zap_cmd = f'"{zap_bat}" -cmd -port {zap_port} -autorun "{yaml_path}"'
            
            # Print phase markers - since autorun is one command, we show what's happening
            print("[Phase 2/3] Passive scanning & wait...")
            print("[Phase 3/3] Active testing...")
            
            result = run_zap_command(zap_cmd, zap_cwd)
            full_log += f"\n=== Automation Scan Output ===\n{result.stdout}\n{result.stderr}"

        elif quick:
            zap_cmd = f'"{zap_bat}" -cmd -port {zap_port} -quickurl "{target_url}" -quickout "{report_path}" -quickprogress'
            result = run_zap_command(zap_cmd, zap_cwd)
            full_log += f"\n=== Quick Scan Output ===\n{result.stdout}\n{result.stderr}"

        log_file_path = os.path.join(output_dir, "zap_log.txt")
        with open(log_file_path, "w", encoding="utf-8") as log_file:
            log_file.write(full_log)

        # Wait for report readiness (since run_zap_command is blocking, it should be immediate)
        timeout = 60
        while timeout > 0 and (not os.path.exists(report_path) or os.path.getsize(report_path) <= 100):
            time.sleep(2)
            timeout -= 1

        if os.path.exists(report_path):
            print("[ZAP] Report generated successfully:", report_path)
            return {
                "success": True,
                "message": "ZAP scan completed successfully.",
                "report_path": report_path,
                "log": full_log
            }
        else:
            return {
                "success": False,
                "message": f"Report not generated at: {report_path}",
                "error": full_log
            }

    except Exception as e:
        return {
            "success": False,
            "message": f"ZAP scan failed: {str(e)}",
            "error": full_log
        }
