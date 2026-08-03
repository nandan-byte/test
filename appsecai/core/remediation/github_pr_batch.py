import os
import csv
import json
import yaml
import argparse
import requests
import subprocess
import time
import logging
from datetime import datetime
from github import Github, GithubException
from tqdm import tqdm
import ast
import concurrent.futures
from threading import Lock

# Configure detailed logging for PR creation debugging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('pr_creation_debug.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class FixerConfig:
    def __init__(self, config_file):
        # Load configuration from YAML file
        with open(config_file, 'r') as file:
            config = yaml.safe_load(file)
        
        # Input/Output configuration
        self.INPUT_CSV = config.get('input_csv', "filtered_vulnerabilities.csv")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Get output directory - handle both absolute and relative paths
        output_dir_name = config.get('output_dir', 'vulnerability-fixes')
        
        if os.path.isabs(output_dir_name):
            # output_dir is already an absolute path (passed from CLI)
            self.OUTPUT_DIR = output_dir_name
        else:
            # output_dir is relative - resolve it properly
            import sys
            if getattr(sys, 'frozen', False):
                # Running as EXE - get base directory from interactive_app
                try:
                    from appsecai.cli.menu import get_base_directory
                    base_dir = get_base_directory()
                except ImportError:
                    # Fallback if import fails
                    base_dir = os.getcwd()
            else:
                # Running as Python - use current working directory
                base_dir = os.getcwd()
            
            self.OUTPUT_DIR = os.path.join(base_dir, output_dir_name)
        
        os.makedirs(self.OUTPUT_DIR, exist_ok=True)
        self.FIXES_CSV = os.path.join(self.OUTPUT_DIR, f"fixes_{timestamp}.csv")
        self.REPORT_PATH = os.path.join(self.OUTPUT_DIR, f"fix_report_{timestamp}.md")
        
        # Batch processing configuration
        self.BATCH_SIZE = config.get('batch_size', 20)  # Reduced from 30
        self.MAX_README_VULNERABILITIES = config.get('max_readme_vulnerabilities', 15)
        self.MAX_CONCURRENT_FIXES = config.get('max_concurrent_fixes', 3)  # New: parallel processing
        
        # GitHub configuration
        github_config = config.get('github', {})
        self.GITHUB_TOKEN = github_config.get('token')
        self.GITHUB_REPO = github_config.get('repo')
        self.PR_TITLE_PREFIX = github_config.get('pr_title_prefix', "Security Hotspot Fixes")
        self.PR_BASE_BRANCH = github_config.get('base_branch', 'main')
        self.CLONE_DIR = github_config.get('clone_dir', 'cloned_repos/repo_clone')
        
        # Ollama configuration - OPTIMIZED
        llm_config = config.get('llm', {})
        self.OLLAMA_MODEL = llm_config.get('model', ' WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B')
        base_url = llm_config.get('url', 'http://4.247.140.236:11434')
        # Ensure we use the correct API endpoint for the Ollama version
        if base_url.endswith('/api/generate'):
            self.OLLAMA_URL = base_url
        else:
            self.OLLAMA_URL = f"{base_url.rstrip('/')}/api/generate"
        self.REQUEST_TIMEOUT = llm_config.get('timeout', 30)  # Reduced from 90
        self.MAX_RETRIES = llm_config.get('max_retries', 2)  # Reduced from 3
        self.RETRY_DELAY = llm_config.get('retry_delay', 1)  # Reduced from 2
        
        # OPTIMIZED PROMPT TEMPLATE
        self.PROMPT_TEMPLATE = llm_config.get('prompt_template', """
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
```
{extracted_code}
```

RESPOND WITH ONLY THE COMPLETE FIXED CODE:""")
        
        # Issue creation settings
        self.CREATE_ISSUES = github_config.get('create_issues', False)
        self.ISSUES_LABELS = github_config.get('issue_labels', ["security", "automated-fix"])

def clone_repository(config):
    """Clone the GitHub repository locally."""
    print(f"🔄 Cloning repository {config.GITHUB_REPO}...")
    
    # Remove existing clone directory if it exists
    if os.path.exists(config.CLONE_DIR):
        print(f"Repository already exists at {config.CLONE_DIR}")
        return True
    
    try:
        repo_url = f"https://{config.GITHUB_TOKEN}@github.com/{config.GITHUB_REPO}.git"
        subprocess.run(["git", "clone", repo_url, config.CLONE_DIR], 
                      check=True, capture_output=True)
        print(f"✅ Repository cloned successfully to {config.CLONE_DIR}")
        
        # Configure Git with token for pushes
        original_dir = os.getcwd()
        os.chdir(config.CLONE_DIR)
        token_url = f"https://{config.GITHUB_TOKEN}@github.com/{config.GITHUB_REPO}.git"
        subprocess.run(["git", "remote", "set-url", "origin", token_url], 
                     check=True, capture_output=True)
        os.chdir(original_dir)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to clone repository: {e}")
        return False

def create_new_branch(config, batch_number):
    """Create a new branch for a batch of fixes."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    branch_name = f"security-fixes-batch-{batch_number}-{timestamp}"
    
    try:
        original_dir = os.getcwd()
        os.chdir(config.CLONE_DIR)
        
        # Fetch latest changes
        subprocess.run(["git", "fetch", "origin"], check=True, capture_output=True)
        
        # Checkout base branch and pull latest
        subprocess.run(["git", "checkout", config.PR_BASE_BRANCH], check=True, capture_output=True)
        subprocess.run(["git", "pull", "origin", config.PR_BASE_BRANCH], check=True, capture_output=True)
        
        # Create and checkout new branch
        subprocess.run(["git", "checkout", "-b", branch_name], check=True, capture_output=True)
        print(f"✅ Created branch: {branch_name}")
        
        os.chdir(original_dir)
        return branch_name
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to create branch: {e}")
        os.chdir(original_dir)
        return None

def load_csv_vulnerabilities(config):
    """Load vulnerabilities from the input CSV file."""
    print(f"📊 Loading vulnerabilities from {config.INPUT_CSV}...")
    vulnerabilities = []
    
    try:
        with open(config.INPUT_CSV, 'r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                vulnerabilities.append(row)
        
        print(f"✅ Loaded {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    except Exception as e:
        print(f"❌ Failed to load CSV: {str(e)}")
        return []

def validate_fixed_code(fixed_code, original_code):
    """Validate that the fixed code is complete and doesn't contain placeholders."""
    if not fixed_code or not fixed_code.strip():
        return False, "Empty response"
    
    # Check for placeholder phrases
    placeholder_phrases = [
        "rest of the code remains the same",
        "...",
        "// rest of",
        "# rest of",
        "/* rest of",
        "rest of the function",
        "remaining code",
        "other code unchanged",
        "keep the rest",
        "// ... existing code"
    ]
    
    fixed_lower = fixed_code.lower()
    for phrase in placeholder_phrases:
        if phrase in fixed_lower:
            return False, f"Contains placeholder: {phrase}"
    
    # Check if code is significantly shorter than original (likely incomplete)
    if len(fixed_code.strip()) < len(original_code.strip()) * 0.5:
        return False, "Code appears incomplete (too short)"
    
    # Check for basic code structure
    if original_code.strip():
        # For code with functions/classes, ensure they're still present
        if 'def ' in original_code and 'def ' not in fixed_code:
            return False, "Missing function definitions"
        if 'class ' in original_code and 'class ' not in fixed_code:
            return False, "Missing class definitions"
    
    return True, "Valid"

def clean_code_from_response(code_text, original_code):
    """Clean up code from LLM response and validate it."""
    if not code_text:
        return None, "Empty response"
    
    # Handle markdown code blocks
    cleaned_code = code_text
    if "```" in code_text:
        parts = code_text.split("```")
        if len(parts) >= 3:
            code_block = parts[1]
            # Remove language specifier if present
            lines = code_block.split("\n")
            if len(lines) > 0 and lines[0].strip().lower() in ["python", "java", "javascript", "js", "typescript", "ts", "c", "cpp", "go", "jsx", "tsx"]:
                code_block = "\n".join(lines[1:])
            cleaned_code = code_block.strip()
    
    # Check for error messages
    error_phrases = ["i cannot provide", "i'm unable to", "sorry, i can't", "i can't help"]
    if any(phrase in cleaned_code.lower() for phrase in error_phrases):
        return None, "LLM refused to provide fix"
    
    # Validate the cleaned code
    is_valid, reason = validate_fixed_code(cleaned_code, original_code)
    if not is_valid:
        return None, reason
        
    return cleaned_code.strip(), "Success"

def generate_fix_with_ollama(config, vulnerability):
    """Generate a fix for the vulnerability using Ollama LLM with optimized settings."""
    original_code = vulnerability.get('extracted_code', 'No code available')
    
    # Enhanced prompt with more context
    prompt = config.PROMPT_TEMPLATE.format(
        message=vulnerability.get('message', 'Unknown issue'),
        ruleKey=vulnerability.get('ruleKey', 'Unknown rule'),
        vulnerabilityProbability=vulnerability.get('vulnerabilityProbability', 'Unknown'),
        extracted_code=original_code
    )

    for attempt in range(config.MAX_RETRIES + 1):
        try:
            # Debug: Print the actual URL being used
            print(f"    🔗 Making request to: {config.OLLAMA_URL}")
            
            # Optimized request parameters
            response = requests.post(
                config.OLLAMA_URL,
                json={
                    "model": config.OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.1,  # Low temperature for consistent output
                        "top_k": 10,
                        "top_p": 0.9,
                        "repeat_penalty": 1.1,
                        "num_predict": min(4096, len(original_code) * 2),  # Limit but ensure enough tokens
                    }
                },
                timeout=config.REQUEST_TIMEOUT
            )
            
            if response.status_code == 200:
                result = response.json()
                fixed_code_raw = result.get('response', '').strip()
                
                # Clean and validate the response
                cleaned_code, status = clean_code_from_response(fixed_code_raw, original_code)
                if cleaned_code:
                    return cleaned_code, "Success"
                else:
                    print(f"    ⚠️ Attempt {attempt+1} failed: {status}")
                    
            else:
                print(f"    ⚠️ Attempt {attempt+1} failed: HTTP {response.status_code}")
                
            if attempt < config.MAX_RETRIES:
                time.sleep(config.RETRY_DELAY)
                
        except requests.exceptions.Timeout:
            print(f"    ⚠️ Attempt {attempt+1} timed out ({config.REQUEST_TIMEOUT}s)")
            if attempt < config.MAX_RETRIES:
                time.sleep(config.RETRY_DELAY)
        except Exception as e:
            print(f"    ⚠️ Attempt {attempt+1} failed: {str(e)}")
            if attempt < config.MAX_RETRIES:
                time.sleep(config.RETRY_DELAY)
    
    return None, "All attempts failed"

def process_single_vulnerability(config, vulnerability, pbar_lock):
    """Process a single vulnerability - designed for parallel execution."""
    vuln_id = vulnerability.get('key', 'unknown')
    
    try:
        if not vulnerability.get('extracted_code'):
            vulnerability['status'] = "Skipped - No original code"
            vulnerability['error_reason'] = "No code to fix"
            return vulnerability, False
        
        # Generate fix
        fixed_code, status = generate_fix_with_ollama(config, vulnerability)
        
        if fixed_code:
            vulnerability['fixed_code'] = fixed_code
            vulnerability['status'] = "Fixed"
            vulnerability['error_reason'] = ""
            
            # Update progress bar safely
            with pbar_lock:
                print(f"    ✅ Fixed: {vuln_id}")
            return vulnerability, True
        else:
            vulnerability['status'] = f"Failed - {status}"
            vulnerability['error_reason'] = status
            vulnerability['fixed_code'] = ""
            
            with pbar_lock:
                print(f"    ❌ Failed: {vuln_id} - {status}")
            return vulnerability, False
            
    except Exception as e:
        vulnerability['status'] = f"Failed - {str(e)}"
        vulnerability['error_reason'] = str(e)
        vulnerability['fixed_code'] = ""
        
        with pbar_lock:
            print(f"    ❌ Error: {vuln_id} - {str(e)}")
        return vulnerability, False

def normalize_file_path(component_path, clone_dir):
    """
    Normalize file path from SonarQube component to match cloned repository structure.
    
    Handles cases where SonarQube scans include extra directory prefixes that don't
    exist in the actual GitHub repository.
    
    Args:
        component_path: Full component path from SonarQube (e.g., "Dating-app:WeeChaMaster-main/src/file.js")
        clone_dir: Path to cloned repository
        
    Returns:
        Normalized file path that exists in the cloned repository
    """
    logger.debug(f"normalize_file_path called:")
    logger.debug(f"  component_path: {component_path}")
    logger.debug(f"  clone_dir: {clone_dir}")
    
    # Extract file path after project key
    file_path = component_path.split(':')[-1]
    logger.debug(f"  Extracted file_path: {file_path}")
    
    # Try the path as-is first
    full_path = os.path.join(clone_dir, file_path)
    logger.debug(f"  Trying original path: {full_path}")
    
    if os.path.exists(full_path):
        logger.debug(f"  ✅ Original path exists")
        return file_path
    
    logger.debug(f"  ❌ Original path not found, trying normalization...")
    
    # If not found, try removing the first directory component
    # This handles cases like "WeeChaMaster-main/dating_app/src/file.js" -> "dating_app/src/file.js"
    path_parts = file_path.split('/')
    logger.debug(f"  Path parts: {path_parts}")
    
    if len(path_parts) > 1:
        # Try removing first directory
        alternative_path = '/'.join(path_parts[1:])
        full_alternative = os.path.join(clone_dir, alternative_path)
        logger.debug(f"  Trying alternative path: {full_alternative}")
        
        if os.path.exists(full_alternative):
            logger.debug(f"  ✅ Alternative path exists")
            return alternative_path
        else:
            logger.debug(f"  ❌ Alternative path not found")
    
    logger.warning(f"  ⚠️ No valid path found, returning original: {file_path}")
    return file_path

def apply_fixes_to_batch(config, batch):
    """Apply the generated fixes to the local repository files for a batch using parallel processing."""
    fixes_applied = []
    failed_fixes = []
    
    print(f"🔄 Processing batch of {len(batch)} vulnerabilities...")
    
    # Use ThreadPoolExecutor for parallel processing
    pbar_lock = Lock()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=config.MAX_CONCURRENT_FIXES) as executor:
        # Submit all tasks
        future_to_vuln = {
            executor.submit(process_single_vulnerability, config, vuln, pbar_lock): vuln 
            for vuln in batch
        }
        
        # Process completed tasks
        with tqdm(total=len(batch), desc="Generating fixes") as pbar:
            for future in concurrent.futures.as_completed(future_to_vuln):
                vuln, success = future.result()
                pbar.update(1)
                
                if success:
                    # Apply the fix to the file
                    try:
                        # Extract and normalize file path from component
                        file_path = normalize_file_path(vuln.get('component', ''), config.CLONE_DIR)
                        # Normalize file path for Windows
                        file_path = file_path.replace('/', os.sep)
                        local_file_path = os.path.join(config.CLONE_DIR, file_path)
                        
                        # Check if file exists before attempting to apply fix
                        if not os.path.exists(local_file_path):
                            raise FileNotFoundError(f"Source file not found: {local_file_path}")
                        
                        # Read file content
                        with open(local_file_path, 'r', encoding='utf-8') as file:
                            file_content = file.read()
                            
                        # Get the lines
                        lines = file_content.splitlines()
                        
                        # Extract start and end line from vulnerability
                        start_line = int(vuln.get('start_line', 0))
                        end_line = int(vuln.get('end_line', 0))
                        
                        if start_line <= 0 or end_line <= 0 or start_line > len(lines):
                            raise ValueError(f"Invalid line numbers: start={start_line}, end={end_line}")
                            
                        # Replace the code section with fixed code
                        fixed_lines = vuln['fixed_code'].splitlines()
                        new_lines = lines[:start_line-1] + fixed_lines + lines[end_line:]
                        new_content = '\n'.join(new_lines)
                        
                        # Write updated content back to file
                        with open(local_file_path, 'w', encoding='utf-8') as file:
                            file.write(new_content)
                            
                        vuln['status'] = "Applied"
                        fixes_applied.append(vuln)
                        
                    except Exception as e:
                        vuln['status'] = f"Failed to apply - {str(e)}"
                        vuln['error_reason'] = f"File operation failed: {str(e)}"
                        failed_fixes.append(vuln)
                else:
                    failed_fixes.append(vuln)
    
    print(f"✅ Completed: {len(fixes_applied)} applied, {len(failed_fixes)} failed")
    return fixes_applied, failed_fixes

def commit_and_push_changes(config, fixes_applied, branch_name):
    """Commit and push changes for a batch of fixes."""
    if not fixes_applied:
        return False
        
    try:
        original_dir = os.getcwd()
        os.chdir(config.CLONE_DIR)
        
        # Add all changed files
        subprocess.run(["git", "add", "."], check=True, capture_output=True)
        
        # Check if there are changes to commit
        result = subprocess.run(["git", "status", "--porcelain"], 
                              check=True, capture_output=True, text=True)
        if not result.stdout.strip():
            print("No changes to commit")
            os.chdir(original_dir)
            return False
        
        # Create commit message
        commit_msg = f"Fix security hotspots (batch of {len(fixes_applied)} issues)\n\n"
        for fix in fixes_applied[:10]:
            component = fix.get('component', '').split(':')[-1]
            rule = fix.get('ruleKey', '').split(':')[-1]
            commit_msg += f"- {component}: {rule}\n"
            
        if len(fixes_applied) > 10:
            commit_msg += f"- ... and {len(fixes_applied) - 10} more fixes\n"
            
        # Commit changes
        subprocess.run(["git", "commit", "-m", commit_msg], check=True, capture_output=True)
        
        # Push changes
        subprocess.run(["git", "push", "-u", "origin", branch_name], check=True, capture_output=True)
        
        print(f"✅ Pushed {len(fixes_applied)} fixes to branch {branch_name}")
        os.chdir(original_dir)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to commit and push: {e}")
        os.chdir(original_dir)
        return False

def create_pull_request(config, fixes_applied, branch_name, batch_number):
    """Create a pull request for the fixes."""
    if not fixes_applied:
        return None
        
    try:
        g = Github(config.GITHUB_TOKEN)
        repo = g.get_repo(config.GITHUB_REPO)
        
        # Create PR title
        pr_title = f"{config.PR_TITLE_PREFIX} - Batch {batch_number} ({len(fixes_applied)} issues)"
        
        # Create PR description with more detail
        pr_body = f"""# 🔒 Security Hotspot Fixes - Batch {batch_number}

## Summary
- **Total Issues Fixed**: {len(fixes_applied)}
- **Automated Fix**: Yes ✅
- **Review Required**: Please verify the fixes before merging ⚠️

## Security Issues Addressed

"""
        
        # Group fixes by rule type
        rule_counts = {}
        for fix in fixes_applied:
            rule = fix.get('ruleKey', '').split(':')[-1]
            rule_counts[rule] = rule_counts.get(rule, 0) + 1
        
        for rule, count in sorted(rule_counts.items()):
            pr_body += f"- **{rule}**: {count} issue(s)\n"
        
        pr_body += f"""

## Detailed Fix List

"""
        
        # List the first 15 fixes in detail
        for i, fix in enumerate(fixes_applied[:15]):
            component = fix.get('component', '').split(':')[-1]
            rule = fix.get('ruleKey', '').split(':')[-1]
            probability = fix.get('vulnerabilityProbability', 'Unknown')
            line = fix.get('line', 'Unknown')
            pr_body += f"{i+1}. **{component}:{line}** - {rule} ({probability} risk)\n"
        
        if len(fixes_applied) > 15:
            pr_body += f"\n... and {len(fixes_applied) - 15} more fixes\n"
        
        pr_body += f"""

## Files Modified ({len(set(fix.get('component', '').split(':')[-1] for fix in fixes_applied))})
"""
        
        # List modified files
        files_modified = set()
        for fix in fixes_applied:
            file_path = fix.get('component', '').split(':')[-1]
            files_modified.add(file_path)
        
        for file_path in sorted(files_modified):
            pr_body += f"- `{file_path}`\n"
        
        pr_body += f"""

## ⚠️ Review Guidelines
- Verify that the fixes don't break existing functionality
- Check that the security issues are properly addressed
- Run tests to ensure no regressions
- Review the changes for any unexpected modifications

---
*This PR was generated automatically by the Security Vulnerability Fixer*  
*Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*  
*Batch processed with parallel execution for faster results*
"""
        
        # Create the PR
        pr = repo.create_pull(
            title=pr_title,
            body=pr_body,
            head=branch_name,
            base=config.PR_BASE_BRANCH
        )
        
        # Add labels
        try:
            pr.add_to_labels("security", "automated-fix")
        except Exception as e:
            print(f"⚠️ Could not add labels: {str(e)}")
        
        print(f"✅ Created PR #{pr.number}: {pr.html_url}")
        return pr.html_url
        
    except Exception as e:
        print(f"❌ Failed to create PR: {str(e)}")
        return None

def create_issue_for_vulnerability(config, vulnerability, repo):
    """Create a GitHub issue for a specific vulnerability."""
    component = vulnerability.get('component', '').split(':')[-1]
    rule = vulnerability.get('ruleKey', '').split(':')[-1]
    message = vulnerability.get('message', 'No description')
    probability = vulnerability.get('vulnerabilityProbability', 'Unknown')
    error_reason = vulnerability.get('error_reason', 'Unknown error')
    
    issue_title = f"Security Hotspot: {rule} in {component}"
    
    issue_body = f"""## Security Hotspot Details

* **File**: `{component}`
* **Rule**: {rule}
* **Probability**: {probability}
* **Line**: {vulnerability.get('line', 'Unknown')}
* **Fix Status**: Failed
* **Failure Reason**: {error_reason}

### Description
{message}

### Original Code
```
{vulnerability.get('extracted_code', 'No code available')}
```

### Why the fix failed
{error_reason}

*This issue was created automatically because the automated fix could not be applied.*
*Manual review and fixing is required.*
"""
    
    try:
        issue = repo.create_issue(
            title=issue_title,
            body=issue_body,
            labels=config.ISSUES_LABELS
        )
        return issue
    except Exception as e:
        print(f"⚠️ Failed to create issue: {str(e)}")
        return None

def process_vulnerabilities_in_batches(config, vulnerabilities):
    """Process vulnerabilities in batches and create PRs."""
    total_vulnerabilities = len(vulnerabilities)
    batch_number = 1
    pr_urls = []
    all_processed = []
    all_failed = []
    
    # Calculate number of batches needed
    batch_count = (total_vulnerabilities + config.BATCH_SIZE - 1) // config.BATCH_SIZE
    print(f"🚀 Processing {total_vulnerabilities} vulnerabilities in {batch_count} batches")
    print(f"⚙️ Using {config.MAX_CONCURRENT_FIXES} concurrent threads per batch")
    print(f"⏱️ Request timeout: {config.REQUEST_TIMEOUT}s")
    
    # Initialize GitHub client for issue creation
    repo = None
    if config.CREATE_ISSUES:
        try:
            g = Github(config.GITHUB_TOKEN)
            repo = g.get_repo(config.GITHUB_REPO)
        except Exception as e:
            print(f"❌ Failed to initialize GitHub client: {str(e)}")
    
    # Process each batch
    for batch_idx in range(batch_count):
        start_idx = batch_idx * config.BATCH_SIZE
        end_idx = min(start_idx + config.BATCH_SIZE, total_vulnerabilities)
        batch = vulnerabilities[start_idx:end_idx]
        
        # Pre-filter: Remove vulnerabilities with missing source files
        valid_batch = []
        skipped_count = 0
        for vuln in batch:
            # Extract and normalize file path from component
            file_path = normalize_file_path(vuln.get('component', ''), config.CLONE_DIR)
            file_path = file_path.replace('/', os.sep)  # Normalize for Windows
            local_file_path = os.path.join(config.CLONE_DIR, file_path)
            
            if os.path.exists(local_file_path):
                valid_batch.append(vuln)
            else:
                skipped_count += 1
                vuln['status'] = "Skipped - Source file not found"
                vuln['error_reason'] = f"File not found: {local_file_path}"
                all_failed.append(vuln)
        
        if skipped_count > 0:
            print(f"⚠️ Skipped {skipped_count} vulnerabilities with missing source files")
        
        if not valid_batch:
            print(f"⚠️ No valid vulnerabilities in batch {batch_number}. Skipping.")
            batch_number += 1
            continue
        
        batch = valid_batch  # Use only valid vulnerabilities
        
        print(f"\n📦 Processing batch {batch_number}/{batch_count} ({len(batch)} vulnerabilities)")
        
        # Create a new branch for this batch
        branch_name = create_new_branch(config, batch_number)
        if not branch_name:
            print(f"❌ Failed to create branch for batch {batch_number}. Skipping.")
            # Mark all as failed
            for vuln in batch:
                vuln['status'] = "Failed - Branch creation error"
                vuln['error_reason'] = "Could not create Git branch"
                all_failed.append(vuln)
            batch_number += 1
            continue
        
        # Apply fixes to this batch (with parallel processing)
        batch_start_time = time.time()
        fixes_applied, failed_batch = apply_fixes_to_batch(config, batch)
        batch_duration = time.time() - batch_start_time
        
        print(f"⏱️ Batch {batch_number} completed in {batch_duration:.1f}s")
        
        # Create issues for failed fixes if enabled
        if repo and config.CREATE_ISSUES:
            for failed_fix in failed_batch:
                issue = create_issue_for_vulnerability(config, failed_fix, repo)
                if issue:
                    failed_fix['issue_number'] = issue.number
                    failed_fix['issue_url'] = issue.html_url
        
        all_failed.extend(failed_batch)
        
        # Commit and push fixes
        if fixes_applied:
            success = commit_and_push_changes(config, fixes_applied, branch_name)
            if success:
                all_processed.extend(fixes_applied)
                
                # Create PR for this batch
                pr_url = create_pull_request(config, fixes_applied, branch_name, batch_number)
                if pr_url:
                    pr_urls.append((batch_number, pr_url, len(fixes_applied)))
            else:
                # If commit failed, mark these as failed
                for fix in fixes_applied:
                    fix['status'] = "Failed to commit"
                    fix['error_reason'] = "Git commit/push failed"
                    all_failed.append(fix)
        else:
            print(f"⚠️ No successful fixes in batch {batch_number}. Not creating PR.")
            # Clean up unused branch
            try:
                original_dir = os.getcwd()
                os.chdir(config.CLONE_DIR)
                subprocess.run(["git", "checkout", config.PR_BASE_BRANCH], check=True, capture_output=True)
                subprocess.run(["git", "branch", "-D", branch_name], check=True, capture_output=True)
                os.chdir(original_dir)
            except Exception:
                pass
                
        batch_number += 1
    
    # Combine all results
    all_results = all_processed + all_failed
    return all_results, pr_urls

def save_results(config, vulnerabilities, pr_urls):
    """Save results to CSV and generate report."""
    # Save to CSV with additional fields
    fieldnames = [
        'key', 'component', 'line', 'message', 'ruleKey', 
        'vulnerabilityProbability', 'extracted_code', 'fixed_code',
        'status', 'error_reason', 'context_type', 'start_line', 'end_line',
        'issue_number', 'issue_url'
    ]
    
    with open(config.FIXES_CSV, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for vuln in vulnerabilities:
            row = {k: vuln.get(k, '') for k in fieldnames}
            writer.writerow(row)
    print(f"📝 Saved fixes to {config.FIXES_CSV}")
    
    # Generate enhanced report
    with open(config.REPORT_PATH, 'w', encoding='utf-8') as f:
        f.write(f"# Security Vulnerability Fix Report\n\n")
        f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Summary
        applied = sum(1 for v in vulnerabilities if v.get('status') == 'Applied')
        failed = len(vulnerabilities) - applied
        
        f.write(f"## Summary\n\n")
        f.write(f"- **Total vulnerabilities**: {len(vulnerabilities)}\n")
        f.write(f"- **Successfully fixed**: {applied} ({applied/len(vulnerabilities)*100:.1f}%)\n")
        f.write(f"- **Failed**: {failed} ({failed/len(vulnerabilities)*100:.1f}%)\n\n")
        
        # Configuration used
        f.write(f"## Configuration\n\n")
        f.write(f"- **Timeout**: {config.REQUEST_TIMEOUT}s\n")
        f.write(f"- **Max retries**: {config.MAX_RETRIES}\n")
        f.write(f"- **Concurrent fixes**: {config.MAX_CONCURRENT_FIXES}\n")
        f.write(f"- **Batch size**: {config.BATCH_SIZE}\n\n")
        
        # List all PRs
        if pr_urls:
            f.write(f"## Pull Requests Created\n\n")
            for batch_num, url, count in pr_urls:
                f.write(f"- **Batch {batch_num}**: [{count} issues fixed]({url})\n")
            f.write("\n")
        
# Failure analysis
        if failed > 0:
            f.write(f"## Failure Analysis\n\n")
            failure_reasons = {}
            for vuln in vulnerabilities:
                if vuln.get('status') != 'Applied':
                    reason = vuln.get('error_reason', 'Unknown error')
                    failure_reasons[reason] = failure_reasons.get(reason, 0) + 1
            
            f.write("| Failure Reason | Count |\n")
            f.write("|----------------|-------|\n")
            for reason, count in sorted(failure_reasons.items(), key=lambda x: x[1], reverse=True):
                f.write(f"| {reason} | {count} |\n")
            f.write("\n")
        
        # Rule type analysis
        f.write(f"## Rule Type Analysis\n\n")
        rule_stats = {}
        for vuln in vulnerabilities:
            rule = vuln.get('ruleKey', '').split(':')[-1]
            status = vuln.get('status', 'Unknown')
            if rule not in rule_stats:
                rule_stats[rule] = {'total': 0, 'fixed': 0, 'failed': 0}
            rule_stats[rule]['total'] += 1
            if status == 'Applied':
                rule_stats[rule]['fixed'] += 1
            else:
                rule_stats[rule]['failed'] += 1
        
        f.write("| Rule | Total | Fixed | Failed | Success Rate |\n")
        f.write("|------|-------|-------|--------|-------------|\n")
        for rule, stats in sorted(rule_stats.items()):
            success_rate = (stats['fixed'] / stats['total'] * 100) if stats['total'] > 0 else 0
            f.write(f"| {rule} | {stats['total']} | {stats['fixed']} | {stats['failed']} | {success_rate:.1f}% |\n")
        f.write("\n")
        
        # Performance metrics
        f.write(f"## Performance Metrics\n\n")
        f.write(f"- **Batch size**: {config.BATCH_SIZE}\n")
        f.write(f"- **Concurrent threads**: {config.MAX_CONCURRENT_FIXES}\n")
        f.write(f"- **Request timeout**: {config.REQUEST_TIMEOUT}s\n")
        f.write(f"- **Max retries**: {config.MAX_RETRIES}\n")
        f.write(f"- **Model used**: {config.OLLAMA_MODEL}\n\n")
        
        # Issues created (if enabled)
        issues_created = [v for v in vulnerabilities if v.get('issue_number')]
        if issues_created:
            f.write(f"## GitHub Issues Created\n\n")
            f.write(f"Created {len(issues_created)} issues for failed fixes:\n\n")
            for issue_vuln in issues_created:
                component = issue_vuln.get('component', '').split(':')[-1]
                f.write(f"- [{component}]({issue_vuln.get('issue_url')}) - Issue #{issue_vuln.get('issue_number')}\n")
            f.write("\n")
        
        # Detailed failure list
        failed_vulns = [v for v in vulnerabilities if v.get('status') != 'Applied']
        if failed_vulns:
            f.write(f"## Failed Fixes Details\n\n")
            for vuln in failed_vulns[:20]:  # Limit to first 20 for readability
                f.write(f"### {vuln.get('key', 'Unknown')}\n\n")
                f.write(f"- **File**: {vuln.get('component', '').split(':')[-1]}\n")
                f.write(f"- **Line**: {vuln.get('line')}\n")
                f.write(f"- **Rule**: {vuln.get('ruleKey')}\n")
                f.write(f"- **Status**: {vuln.get('status', 'Unknown')}\n")
                f.write(f"- **Error**: {vuln.get('error_reason', 'No error details')}\n")
                f.write(f"- **Message**: {vuln.get('message')}\n\n")
            
            if len(failed_vulns) > 20:
                f.write(f"... and {len(failed_vulns) - 20} more failed fixes\n\n")
    
    print(f"📊 Generated comprehensive report at {config.REPORT_PATH}")
    return True

def generate_config_template():
    """Generate a sample configuration file."""
    config_template = """# Security Vulnerability Fixer Configuration

# Input/Output Configuration
input_csv: "vulnerabilities.csv"
output_dir: "vulnerability-fixes"
batch_size: 20
max_readme_vulnerabilities: 15
max_concurrent_fixes: 3

# GitHub Configuration
github:
  token: "your_github_token_here"
  repo: "owner/repository"
  pr_title_prefix: "Security Hotspot Fixes"
  base_branch: "main"
  clone_dir: "repo_clone"
  create_issues: false
  issue_labels: ["security", "automated-fix"]

# LLM Configuration (Ollama)
llm:
  model: "llama3"
  url: "http://4.247.140.236:11434/api/generate"
  timeout: 30
  max_retries: 2
  retry_delay: 1
  prompt_template: |
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
    ```
    {extracted_code}
    ```

    RESPOND WITH ONLY THE COMPLETE FIXED CODE:
"""
    
    with open('config_template.yaml', 'w') as f:
        f.write(config_template)
    
    print("📋 Generated config_template.yaml - please customize it for your environment")

def validate_environment(config):
    """Validate that all required tools and configurations are available."""
    print("🔍 Validating environment...")
    
    issues = []
    
    # Check Git
    try:
        subprocess.run(["git", "--version"], check=True, capture_output=True)
        print("  ✅ Git is available")
    except (subprocess.CalledProcessError, FileNotFoundError):
        issues.append("Git is not installed or not in PATH")
    
    # Check Ollama
    try:
        response = requests.get(f"{config.OLLAMA_URL.replace('/api/generate', '')}/api/version", timeout=5)
        if response.status_code == 200:
            print("  ✅ Ollama is running and accessible")
        else:
            issues.append(f"Ollama responded with status {response.status_code}")
    except Exception as e:
        issues.append(f"Cannot connect to Ollama: {str(e)}")
    
    # Check GitHub token
    if not config.GITHUB_TOKEN:
        issues.append("GitHub token not configured")
    else:
        try:
            g = Github(config.GITHUB_TOKEN)
            user = g.get_user()
            print(f"  ✅ GitHub token valid (user: {user.login})")
        except Exception as e:
            issues.append(f"GitHub token invalid: {str(e)}")
    
    # Check input file
    if not os.path.exists(config.INPUT_CSV):
        issues.append(f"Input CSV file not found: {config.INPUT_CSV}")
    else:
        print(f"  ✅ Input CSV file exists: {config.INPUT_CSV}")
    
    if issues:
        print("\n❌ Environment validation failed:")
        for issue in issues:
            print(f"  - {issue}")
        return False
    
    print("✅ Environment validation passed")
    return True

def main():
    """Main function to run the security vulnerability fixer."""
    parser = argparse.ArgumentParser(description='Security Vulnerability Fixer')
    parser.add_argument('--config', type=str, default='config.yaml', 
                      help='Path to configuration YAML file')
    parser.add_argument('--input', type=str, 
                      help='Input CSV file with vulnerabilities (overrides config)')
    parser.add_argument('--generate-config', action='store_true',
                      help='Generate a sample configuration file')
    parser.add_argument('--validate-env', action='store_true',
                      help='Validate environment before processing')
    args = parser.parse_args()
    
    # Generate config template if requested
    if args.generate_config:
        generate_config_template()
        return True
    
    # Initialize configuration
    try:
        config = FixerConfig(args.config)
    except Exception as e:
        print(f"❌ Failed to load configuration: {str(e)}")
        print("💡 Use --generate-config to create a sample configuration file")
        return False
    
    # Override input file if provided
    if args.input:
        config.INPUT_CSV = args.input
    
    # Validate environment if requested
    if args.validate_env:
        if not validate_environment(config):
            return False
    
    # Check if input file exists
    if not os.path.exists(config.INPUT_CSV):
        print(f"❌ Input file {config.INPUT_CSV} does not exist!")
        return False
    
    print(f"🚀 Starting Security Vulnerability Fixer")
    print(f"📊 Configuration: {args.config}")
    print(f"📄 Input file: {config.INPUT_CSV}")
    print(f"🤖 Model: {config.OLLAMA_MODEL}")
    print(f"📦 Batch size: {config.BATCH_SIZE}")
    print(f"🧵 Concurrent fixes: {config.MAX_CONCURRENT_FIXES}")
    
    start_time = time.time()
    
    # Load vulnerabilities from CSV
    vulnerabilities = load_csv_vulnerabilities(config)
    if not vulnerabilities:
        print("❌ No vulnerabilities found in input file!")
        return False
    
    # Clone repository
    success = clone_repository(config)
    if not success:
        print("❌ Failed to clone repository!")
        return False
    
    # Process vulnerabilities in batches
    processed_vulns, pr_urls = process_vulnerabilities_in_batches(config, vulnerabilities)
    
    # Save results
    save_results(config, processed_vulns, pr_urls)
    
    # Final summary
    total_time = time.time() - start_time
    applied = sum(1 for v in processed_vulns if v.get('status') == 'Applied')
    total = len(processed_vulns)
    
    print(f"\n🎉 Processing completed in {total_time:.1f} seconds!")
    print(f"📊 Results: {applied}/{total} vulnerabilities successfully fixed ({applied/total*100:.1f}%)")
    
    if pr_urls:
        print(f"🔗 Created {len(pr_urls)} Pull Requests:")
        for batch_num, url, count in pr_urls:
            print(f"  - Batch {batch_num}: {url} ({count} issues)")
    
    if applied > 0:
        print(f"✅ Success! Check your repository for the created pull requests.")
    else:
        print(f"⚠️ No fixes were successfully applied. Check the report for details.")
    
    print(f"📋 Full report available at: {config.REPORT_PATH}")
    
    return True

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
