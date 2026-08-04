import os
import json
import csv
import shutil
import logging
import subprocess
import time
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple, Set

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Define data classes/structures for configuration
class SonarQubeConfig:
    def __init__(self, sonarqube_url, username, password, project_key, 
                 github_repo_clone_url, clone_dir_base, output_dir_base, 
                 vul_config_json_path, threshold_score, status_callback=None,
                 branch=None):
        self.SONARQUBE_URL = sonarqube_url
        self.USERNAME = username
        self.PASSWORD = password
        self.PROJECT_KEY = project_key
        # Sanitize GitHub URL
        github_repo_clone_url = github_repo_clone_url.rstrip(".")
        if github_repo_clone_url.endswith(".git.git"):
            github_repo_clone_url = github_repo_clone_url[:-4]
        github_repo_clone_url = github_repo_clone_url.replace("..git", ".git")
        
        self.GITHUB_URL = github_repo_clone_url
        self.CONFIG_JSON_PATH = vul_config_json_path
        self.THRESHOLD_SCORE = threshold_score
        self.status_callback = status_callback
        self.BRANCH = branch
        
        # Directories
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.CLONE_DIR = os.path.join(clone_dir_base, f"{project_key}_{timestamp}")
        self.OUTPUT_DIR = os.path.join(output_dir_base, f"{project_key}_{timestamp}")
        
        # Output Files
        self.EXTRACTED_CODE_JSON = os.path.join(self.OUTPUT_DIR, f"hotspots_with_code_{project_key}.json")
        self.EXTRACTED_CODE_CSV = os.path.join(self.OUTPUT_DIR, f"hotspots_with_code_{project_key}.csv")
        self.FILTERED_VULNERABILITIES_JSON = os.path.join(self.OUTPUT_DIR, f"filtered_vulnerabilities_{project_key}.json")
        self.FILTERED_VULNERABILITIES_CSV = os.path.join(self.OUTPUT_DIR, f"filtered_vulnerabilities_{project_key}.csv")
        
        # State
        self.status_updates = []

    def _add_status(self, message):
        timestamped_message = f"{datetime.now().strftime('%H:%M:%S')} - {message}"
        self.status_updates.append(timestamped_message)
        logger.info(message)
        if self.status_callback:
            self.status_callback(message)

# --- Helper Functions ---

def clone_repository(sq_config):
    """Clones the GitHub repository."""
    if os.path.exists(sq_config.CLONE_DIR):
        logger.info(f"🧹 Cleaning up existing directory: {sq_config.CLONE_DIR}")
        def handle_remove_readonly(func, path, exc):
            import stat
            os.chmod(path, stat.S_IWRITE)
            func(path)
        shutil.rmtree(sq_config.CLONE_DIR, onerror=handle_remove_readonly)
    
    os.makedirs(sq_config.CLONE_DIR, exist_ok=True)
    sq_config._add_status(f"⬇️ Cloning repository from {sq_config.GITHUB_URL}...")
    
    try:
        clone_cmd = ["git", "clone", sq_config.GITHUB_URL, sq_config.CLONE_DIR]
        if sq_config.BRANCH:
            sq_config._add_status(f"🌿 Cloning specific branch: {sq_config.BRANCH}")
            clone_cmd = ["git", "clone", "-b", sq_config.BRANCH, sq_config.GITHUB_URL, sq_config.CLONE_DIR]
            
        subprocess.run(clone_cmd, check=True, capture_output=True)
        sq_config._add_status("✅ Repository cloned successfully.")
        return True
    except subprocess.CalledProcessError as e:
        sq_config._add_status(f"❌ Failed to clone repository: {e}")
        return False
    except FileNotFoundError:
        sq_config._add_status("❌ Git command not found. Please install Git.")
        return False
        
def fetch_hotspots(sq_config):
    """Fetches security hotspots and issues from SonarQube."""
    import requests
    from requests.auth import HTTPBasicAuth
    
    sq_config._add_status(f"🔍 Fetching security hotspots for project '{sq_config.PROJECT_KEY}' from SonarQube...")
    
    auth = HTTPBasicAuth(sq_config.USERNAME, sq_config.PASSWORD)
    
    all_hotspots = []
    
    # 1. Fetch Security Hotspots
    try:
        url = f"{sq_config.SONARQUBE_URL}/api/hotspots/search"
        params = {'projectKey': sq_config.PROJECT_KEY, 'p': 1, 'ps': 500}
        
        while True:
            response = requests.get(url, auth=auth, params=params)
            response.raise_for_status()
            data = response.json()
            hotspots = data.get('hotspots', [])
            all_hotspots.extend(hotspots)
            
            sq_config._add_status(f"   Fetched {len(hotspots)} hotspots (Page {params['p']})")
            
            paging = data.get('paging', {})
            total = paging.get('total', 0)
            if len(all_hotspots) >= total or not hotspots:
                break
            params['p'] += 1
            
    except Exception as e:
        sq_config._add_status(f"❌ Error fetching hotspots: {e}")
        return None # Critical failure

    # 2. Fetch Issues (Vulnerabilities)
    try:
        sq_config._add_status("🔍 Fetching issues (type=VULNERABILITY)...")
        url_issues = f"{sq_config.SONARQUBE_URL}/api/issues/search"
        params_issues = {
            'componentKeys': sq_config.PROJECT_KEY,
            'types': 'VULNERABILITY',
            'p': 1, 'ps': 500
        }
        
        while True:
            response = requests.get(url_issues, auth=auth, params=params_issues)
            response.raise_for_status()
            data = response.json()
            issues = data.get('issues', [])
            
            # Normalize issues to match hotspot structure where possible
            for issue in issues:
                issue['key'] = issue.get('key')
                issue['component'] = issue.get('component')
                issue['line'] = issue.get('line')
                issue['message'] = issue.get('message')
                issue['ruleKey'] = issue.get('rule')
                issue['vulnerabilityProbability'] = issue.get('severity') # Map severity to probability field for consistency
                # Security category needs to be fetched from rule, but we'll infer or skip for now
                
            all_hotspots.extend(issues)
            sq_config._add_status(f"   Fetched {len(issues)} issues (Page {params_issues['p']})")
            
            paging = data.get('paging', {})
            total = paging.get('total', 0)
            if (params_issues['p'] * params_issues['ps']) >= total:
                break
            params_issues['p'] += 1

    except Exception as e:
         sq_config._add_status(f"⚠️ Error fetching issues: {e} (Continuing with hotspots only)")

    sq_config._add_status(f"✅ Total findings fetched: {len(all_hotspots)}")
    return all_hotspots

def extract_code_for_hotspots(hotspots, sq_config):
    """Extracts code snippets for each hotspot from the cloned repo."""
    sq_config._add_status("✂️ Extracting code context for findings...")
    
    count = 0
    for hotspot in hotspots:
        component = hotspot.get('component', '')
        # Remove project key prefix if present
        file_path_rel = component.replace(f"{sq_config.PROJECT_KEY}:", "")
        file_path_abs = os.path.join(sq_config.CLONE_DIR, file_path_rel)
        
        # Get line number from multiple possible sources
        line_num = hotspot.get('line')
        start_line = line_num
        end_line = line_num
        
        # Try to get more precise range from textRange
        text_range = hotspot.get('textRange')
        if text_range:
            start_line = text_range.get('startLine', line_num)
            end_line = text_range.get('endLine', line_num)
            if not line_num:
                line_num = start_line
        
        # Ensure we have a line number to work with
        if not line_num:
            hotspot['code_snippet'] = "N/A (No line number)"
            # Set default values to prevent reporting issues
            hotspot['start_line'] = ""
            hotspot['end_line'] = ""
            continue
            
        # Store standardized line numbers for reporting
        hotspot['start_line'] = start_line
        hotspot['end_line'] = end_line
        hotspot['line'] = line_num  # Ensure 'line' is set even if invalid
            
        if os.path.exists(file_path_abs):
            try:
                with open(file_path_abs, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    # Context window around the vulnerability
                    ctx_start = max(0, start_line - 5)
                    ctx_end = min(len(lines), end_line + 5)
                    
                    snippet_lines = []
                    for i in range(ctx_start, ctx_end):
                        is_vuln_line = (i + 1) >= start_line and (i + 1) <= end_line
                        prefix = ">> " if is_vuln_line else "   "
                        snippet_lines.append(f"{prefix}{i + 1}: {lines[i].rstrip()}")
                    
                    hotspot['code_snippet'] = "\n".join(snippet_lines)
                    count += 1
            except Exception as e:
                hotspot['code_snippet'] = f"Error reading file: {e}"
        else:
            hotspot['code_snippet'] = f"File not found locally: {file_path_rel}"
            
    sq_config._add_status(f"✅ Extracted code for {count} findings.")

def save_hotspots_to_file(sq_config, hotspots, file_path_json, file_path_csv, label):
    """Saves findings to JSON and CSV."""
    os.makedirs(os.path.dirname(file_path_json), exist_ok=True)
    
    # JSON
    try:
        with open(file_path_json, 'w', encoding='utf-8') as f:
            json.dump(hotspots, f, indent=4)
        sq_config._add_status(f"💾 Saved {label} to {file_path_json}")
    except Exception as e:
        sq_config._add_status(f"❌ Error saving {label} JSON: {e}")

    # CSV
    if hotspots:
        try:
            # Flatten for CSV
            csv_rows = []
            keys_to_exclude = ['code_snippet', 'flows', 'textRange'] # Exclude bulky fields
            
            # Determine headers dynamically but keep important ones first
            all_keys = set()
            for h in hotspots:
                all_keys.update(h.keys())
            
            headers = ['key', 'component', 'line', 'message', 'ruleKey', 'severity', 'vulnerabilityProbability', 
                       'enhanced_score', 'enhanced_risk_level', 'enhanced_category']
            
            # Add remaining keys
            for k in all_keys:
                if k not in headers and k not in keys_to_exclude:
                    headers.append(k)
            
            rows_to_write = []
            for h in hotspots:
                row = {k: h.get(k, '') for k in headers}
                # Clean up list/dict fields for CSV
                for k, v in row.items():
                    if isinstance(v, (list, dict)):
                        row[k] = str(v)
                rows_to_write.append(row)

            with open(file_path_csv, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
                writer.writerows(rows_to_write)
            sq_config._add_status(f"📝 Saved {label} to {file_path_csv}")
        except Exception as e:
            sq_config._add_status(f"❌ Error writing {label} CSV {file_path_csv}: {e}")
    else:
        sq_config._add_status(f"⚠️ No {label} rows to write to CSV.")


def run_sonarqube_processing(sq_config_instance: SonarQubeConfig):
    """Main function to run the security analysis process, callable from Streamlit."""
    sq_config_instance._add_status("🚀 Starting SonarQube security analysis process...")

    if not all([sq_config_instance.SONARQUBE_URL, sq_config_instance.USERNAME, 
                sq_config_instance.PROJECT_KEY, sq_config_instance.GITHUB_URL,
                sq_config_instance.CONFIG_JSON_PATH]):
        sq_config_instance._add_status("❌ Missing critical SonarQube configuration. Exiting.")
        return None, None, None # raw_csv_path, filtered_csv_path, status_updates

    if not clone_repository(sq_config_instance):
        sq_config_instance._add_status("❌ Failed to clone repository. Exiting.")
        return None, None, sq_config_instance.status_updates

    hotspots = fetch_hotspots(sq_config_instance)
    if hotspots is None: # fetch_hotspots returns None on critical error
        sq_config_instance._add_status("❌ Failed to fetch hotspots. Exiting.")
        return None, None, sq_config_instance.status_updates
    if not hotspots:
        sq_config_instance._add_status(f"⚠️ No hotspots found for project {sq_config_instance.PROJECT_KEY}.")
        # Still save empty files if expected
        save_hotspots_to_file(sq_config_instance, [], sq_config_instance.EXTRACTED_CODE_JSON, sq_config_instance.EXTRACTED_CODE_CSV, "raw hotspots")
        save_hotspots_to_file(sq_config_instance, [], sq_config_instance.FILTERED_VULNERABILITIES_JSON, sq_config_instance.FILTERED_VULNERABILITIES_CSV, "filtered vulnerabilities")
        return sq_config_instance.EXTRACTED_CODE_CSV, sq_config_instance.FILTERED_VULNERABILITIES_CSV, sq_config_instance.status_updates


    extract_code_for_hotspots(hotspots, sq_config_instance)
    save_hotspots_to_file(sq_config_instance, hotspots, sq_config_instance.EXTRACTED_CODE_JSON, sq_config_instance.EXTRACTED_CODE_CSV, "raw hotspots")

    sq_config_instance._add_status("⚖️ Scoring and filtering vulnerabilities...")
    
    # Try to use enhanced vulnerability scorer first, fallback to simple scorer
    try:
        from appsecai.core.scorer import EnhancedVulnerabilityScorer
        
        sq_config_instance._add_status("🧠 Using enhanced vulnerability scoring system...")
        
        # Initialize enhanced scorer
        enhanced_scorer = EnhancedVulnerabilityScorer()
        
        # Process each hotspot with enhanced scoring
        enhanced_vulnerabilities = []
        
        sq_config_instance._add_status(f"🎯 [PRIORITIZATION] Processing {len(hotspots)} vulnerabilities...")
        
        for i, hotspot in enumerate(hotspots):
            try:
                rule_key = hotspot.get('ruleKey', 'Unknown')
                raw_severity = hotspot.get('severity') or hotspot.get('vulnerabilityProbability') or 'Unknown'
                
                # Modernize SonarQube severity labels for user clarity in the console
                modern_severity_map = {
                    "BLOCKER": "Critical",
                    "CRITICAL": "Critical",
                    "MAJOR": "High",
                    "HIGH": "High",
                    "MEDIUM": "Medium",
                    "MINOR": "Low",
                    "LOW": "Low",
                    "INFO": "Informational"
                }
                display_severity = modern_severity_map.get(str(raw_severity).upper(), raw_severity)
                
                # Log detailed scoring info (similar to ZAP)
                # Only log details for first 20 to avoid spamming 500+ items, unless it's critical/high
                should_log = i < 20
                if should_log:
                    sq_config_instance._add_status(f"--- Vulnerability {i+1}/{len(hotspots)} ---")
                    sq_config_instance._add_status(f"🔄 [SAST SCORER] Starting calculation for: '{rule_key}'")

                # Score the vulnerability using enhanced system
                enhanced_score = enhanced_scorer.score_sonarqube_vulnerability(hotspot)
                
                if should_log:
                    sq_config_instance._add_status(f"✅ [ENHANCED] Using enhanced vulnerability scorer")
                    sq_config_instance._add_status(f"📊 [BASE SEVERITY] '{display_severity}' ({raw_severity}) → Score: {enhanced_score.base_severity}")
                    sq_config_instance._add_status(f"🏷️  [CATEGORY] '{enhanced_score.category}'")
                    
                    applied_mods_str = ", ".join([f"{k}: x{v}" for k,v in enhanced_score.applied_modifiers.items()]) or "None"
                    sq_config_instance._add_status(f"⚙️  [ADJUSTMENTS] Context: {{{applied_mods_str}}}")
                    sq_config_instance._add_status(f"🧮 [CALCULATION] {enhanced_score.base_severity} * {enhanced_score.context_multiplier} = {enhanced_score.final_score}")
                    sq_config_instance._add_status(f"🎯 [FINAL RESULT] Score: {enhanced_score.final_score} → Risk: {enhanced_score.risk_level.value}")

                # Add enhanced scoring results to hotspot
                hotspot['enhanced_score'] = enhanced_score.final_score
                hotspot['enhanced_category'] = enhanced_score.category
                hotspot['enhanced_risk_level'] = enhanced_score.risk_level.value
                hotspot['enhanced_justifications'] = enhanced_score.justifications
                hotspot['ai_justification'] = enhanced_score.ai_justification
                hotspot['context_adjustments'] = str(enhanced_score.applied_modifiers)
                
                if should_log and enhanced_score.ai_justification:
                    sq_config_instance._add_status(f"🤖 [AI JUSTIFICATION] {enhanced_score.ai_justification}")
                
                # Add framework-based cybersecurity justification
                framework_justification = enhanced_scorer.get_framework_justification(
                    enhanced_score.category, hotspot
                )
                hotspot['framework_justification'] = framework_justification
                
                # Only include if above threshold
                threshold = float(sq_config_instance.THRESHOLD_SCORE)
                if enhanced_score.final_score >= threshold:
                    enhanced_vulnerabilities.append(hotspot)
            
            except Exception as item_e:
                sq_config_instance._add_status(f"❌ Error scoring '{hotspot.get('ruleKey', 'Unknown')}': {item_e}")
                hotspot['enhanced_score'] = 0
                hotspot['enhanced_risk_level'] = 'ScoringFailed'
        
        filtered_vulnerabilities = enhanced_vulnerabilities
        
        # Save complete vulnerability list with enhanced scores
        complete_list_path = sq_config_instance.EXTRACTED_CODE_CSV.replace('hotspots_with_code_', 'complete_enhanced_vulnerabilities_')
        save_hotspots_to_file(sq_config_instance, hotspots, 
                            complete_list_path.replace('.csv', '.json'), 
                            complete_list_path, 
                            "complete enhanced vulnerabilities")
        
        sq_config_instance._add_status(f"✅ Enhanced scoring applied:")
        sq_config_instance._add_status(f"   📋 Complete list: {len(hotspots)} vulnerabilities")
        sq_config_instance._add_status(f"   🎯 High priority: {len(filtered_vulnerabilities)} vulnerabilities above threshold")
        
    except Exception as e:
        sq_config_instance._add_status(f"⚠️ Enhanced scoring failed ({str(e)}), using basic fallback...")
        # Basic fallback without vul.json dependency
        basic_vulnerabilities = []
        threshold = float(sq_config_instance.THRESHOLD_SCORE)
        for hotspot in hotspots:
            # Simple severity-based scoring on 0-10 scale
            severity_map = {"BLOCKER": 8.5, "CRITICAL": 7.5, "HIGH": 7.5, "MAJOR": 5.0, "MEDIUM": 5.0, "MINOR": 2.5, "LOW": 2.5, "INFO": 1.0}
            basic_score = severity_map.get(hotspot.get("vulnerabilityProbability", hotspot.get("severity", "LOW")).upper(), 2.5)
            
            if basic_score >= threshold:
                hotspot['basic_score'] = basic_score
                basic_vulnerabilities.append(hotspot)
        
        filtered_vulnerabilities = basic_vulnerabilities
        sq_config_instance._add_status(f"✅ Basic scoring applied: {len(filtered_vulnerabilities)} vulnerabilities above threshold")
    
    save_hotspots_to_file(sq_config_instance, filtered_vulnerabilities, sq_config_instance.FILTERED_VULNERABILITIES_JSON, sq_config_instance.FILTERED_VULNERABILITIES_CSV, "filtered vulnerabilities")

    # Copy reports to AppSecAI_output for consistency with ZAP reports
    files_to_copy = [
        sq_config_instance.EXTRACTED_CODE_JSON,
        sq_config_instance.EXTRACTED_CODE_CSV,
        sq_config_instance.FILTERED_VULNERABILITIES_JSON,
        sq_config_instance.FILTERED_VULNERABILITIES_CSV
    ]
    
    # Also copy the complete enhanced vulnerabilities if they exist
    complete_list_path = sq_config_instance.EXTRACTED_CODE_CSV.replace('hotspots_with_code_', 'complete_enhanced_vulnerabilities_')
    if os.path.exists(complete_list_path):
        files_to_copy.append(complete_list_path)
        files_to_copy.append(complete_list_path.replace('.csv', '.json'))
    
    copied_files = copy_to_appsecai_output(files_to_copy, sq_config_instance)
    
    sq_config_instance._add_status(f"✨ SonarQube analysis complete! Results saved in {sq_config_instance.OUTPUT_DIR}")
    if copied_files:
        sq_config_instance._add_status(f"📋 Reports also copied to AppSecAI_output directory ({len(copied_files)} files)")
    
    return sq_config_instance.EXTRACTED_CODE_CSV, sq_config_instance.FILTERED_VULNERABILITIES_CSV, sq_config_instance.status_updates

def copy_to_appsecai_output(files, sq_config):
    """Copies report files to a central AppSecAI_output directory."""
    try:
        # Determine central output dir (assume parallel to repo or fixed path)
        # Using a relative path 'AppSecAI_output' in the project root
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        central_dir = os.path.join(project_root, "AppSecAI_output")
        os.makedirs(central_dir, exist_ok=True)
        
        copied = []
        timestamp = os.path.basename(sq_config.OUTPUT_DIR).split('_')[-2:] # Get YYYYMMDD and HHMMSS
        timestamp_str = "_".join(timestamp)
        
        for file_path in files:
            if os.path.exists(file_path):
                file_name = os.path.basename(file_path)
                # Ensure filename is unique by adding timestamp if not already there
                if timestamp_str not in file_name:
                    name_parts = os.path.splitext(file_name)
                    file_name = f"{name_parts[0]}_{timestamp_str}{name_parts[1]}"
                
                dest_path = os.path.join(central_dir, file_name)
                shutil.copy2(file_path, dest_path)
                copied.append(dest_path)
        return copied
    except Exception as e:
        sq_config._add_status(f"⚠️ Failed to copy reports to central output: {e}")
        return []

if __name__ == "__main__":
    # Example usage (for testing sonarqube_processor.py directly)
    # Replace with your actual test values
    test_config = SonarQubeConfig(
        sonarqube_url="YOUR_SONARQUBE_URL", # e.g. http://localhost:9000
        username="YOUR_SONAR_USERNAME_OR_TOKEN",
        password="YOUR_SONAR_PASSWORD_IF_USING_USER_PASS", #  Empty if token used in username
        project_key="YOUR_PROJECT_KEY",
        github_repo_clone_url="https://github.com/your_org/your_repo.git",
        clone_dir_base="test_cloned_repos",
        output_dir_base="test_sonarqube_output",
        vul_config_json_path="vul.json", # Ensure this file exists with content for testing
        threshold_score=10
    )
    # Create a dummy vul.json for testing if it doesn't exist
    if not os.path.exists("vul.json"):
        dummy_vul_config = {
            "questionnaire": [
                {
                    "vulnerabilityType": "Default",
                    "vulCategoryScores": [
                        {"vulCategory": "Potential Impact", "score": 1},
                        {"vulCategory": "EaseOfExploitation", "score": 1},
                        {"vulCategory": "AssetExposure", "score": 1},
                        {"vulCategory": "RealWorldAttackLikelihood", "score": 1},
                        {"vulCategory": "SecurityControlDeployment", "score": 1}
                    ]
                }
            ]
        }
        with open("vul.json", "w") as f:
            json.dump(dummy_vul_config, f, indent=4)
        print("Created a dummy vul.json for testing.")

    raw_csv, filtered_csv, statuses = run_sonarqube_processing(test_config)
    print("\n--- Status Updates ---")
    for status in statuses:
        print(status)
    if filtered_csv:
        print(f"\nFiltered vulnerabilities CSV: {filtered_csv}")
    if raw_csv:
        print(f"Raw hotspots CSV: {raw_csv}")
