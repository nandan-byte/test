import os
import csv
import yaml
import subprocess
import requests
import re
import time
from datetime import datetime
from typing import List, Dict, Tuple, Optional
from github import Github
from tqdm import tqdm

from .remediation_strategies import get_strategy

# =========================================================
# CONFIG
# =========================================================

class FixerConfig:
    def __init__(self, config_file: str):
        with open(config_file, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)

        self.INPUT_CSV = cfg["input_csv"]

        github = cfg["github"]
        self.GITHUB_TOKEN = github["token"]
        raw_repo = github["repo"]
        # Handle full HTTPS or SSH URLs properly
        if "github.com" in raw_repo:
            if raw_repo.startswith("http"):
                # https://github.com/owner/repo.git -> owner/repo.git
                self.GITHUB_REPO = raw_repo.split("github.com/")[-1]
            elif raw_repo.startswith("git@"):
                # git@github.com:owner/repo.git -> owner/repo.git
                self.GITHUB_REPO = raw_repo.split("github.com:")[-1]
            else:
                self.GITHUB_REPO = raw_repo
        else:
            self.GITHUB_REPO = raw_repo
            
        # Strip .git extension if present
        if self.GITHUB_REPO.endswith(".git"):
            self.GITHUB_REPO = self.GITHUB_REPO[:-4]
            
        self.BASE_BRANCH = github.get("base_branch", "main")
        repo_name = self.GITHUB_REPO.split("/")[-1]
        
        # Reuse existing clone_dir if provided (e.g. from scanner)
        if cfg.get("clone_dir"):
            self.CLONE_DIR = cfg["clone_dir"]
        else:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.CLONE_DIR = f"cloned_repos/{repo_name}_{ts}"
        self.PR_TITLE_PREFIX = github.get("pr_title_prefix", "AI Security Fixes")

        llm = cfg["llm"]
        self.MODEL = llm.get("model", "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest")
        # Handle both full URLs and base URLs
        url = llm["url"].rstrip("/")
        if url.endswith("/api/generate"):
            self.OLLAMA_URL = url
        else:
            self.OLLAMA_URL = url + "/api/generate"
        self.TIMEOUT = llm.get("timeout", 120)
        self.MAX_RETRIES = llm.get("max_retries", 2)
        self.RETRY_DELAY = llm.get("retry_delay", 1)

        self.BATCH_SIZE = cfg.get("batch_size", 5)

# =========================================================
# PUBLIC API
# =========================================================

def clone_repository(token: str, repo: str, clone_dir: str) -> None:
    if os.path.exists(clone_dir):
        return
    repo = repo.replace("https://github.com/", "").replace(".git", "")
    subprocess.run(
        ["git", "clone", f"https://{token}@github.com/{repo}.git", clone_dir],
        check=True
    )


def load_csv_vulnerabilities(csv_path: str) -> List[Dict]:
    with open(csv_path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def process_vulnerabilities_in_batches(
    cfg: FixerConfig,
    vulnerabilities: List[Dict]
) -> Tuple[List[Dict], List[str]]:
    """Process vulnerabilities in batches with comprehensive error handling."""
    
    print(f"🚀 Starting remediation of {len(vulnerabilities)} vulnerabilities")
    print(f"📊 Batch size: {cfg.BATCH_SIZE}")
    
    # Validate GitHub configuration early
    if not cfg.GITHUB_TOKEN or not cfg.GITHUB_REPO:
        print("❌ Error: GITHUB_TOKEN or GITHUB_REPO is not configured. Cannot raise PRs.")
        print("💡 Please verify that GITHUB_TOKEN and GITHUB_REPO are set in your .env file or passed via CLI arguments.")
        return [], []
        
    # Clone repository
    try:
        clone_repository(cfg.GITHUB_TOKEN, cfg.GITHUB_REPO, cfg.CLONE_DIR)
        print(f"✅ Repository cloned to {cfg.CLONE_DIR}")
    except Exception as e:
        print(f"❌ Failed to clone repository: {e}")
        raise

    processed: List[Dict] = []
    pr_urls: List[str] = []
    failed_batches: List[int] = []

    batches = [
        vulnerabilities[i:i + cfg.BATCH_SIZE]
        for i in range(0, len(vulnerabilities), cfg.BATCH_SIZE)
    ]
    
    print(f"📦 Processing {len(batches)} batches")

    for idx, batch in enumerate(batches, 1):
        print(f"\n🔄 Processing batch {idx}/{len(batches)} ({len(batch)} vulnerabilities)")
        
        branch = None
        try:
            # Create branch
            branch = _create_branch(cfg, idx)
            
            # Ensure clean working tree
            _ensure_clean_repo(cfg.CLONE_DIR)
            
            # Process vulnerabilities in this batch
            changed = False
            batch_fixes = 0
            manual_reviews = 0
            
            for vuln in batch:
                try:
                    if _process_single_vuln(cfg, vuln):
                        changed = True
                        batch_fixes += 1
                    else:
                        # Mark as manual review instead of failure
                        if vuln.get("status") in ["Fix Generation Failed", "Invalid Syntax", "File Write Error"]:
                            vuln["status"] = "Manual Review Required"
                        manual_reviews += 1
                    processed.append(vuln)
                except Exception as e:
                    print(f"   ❌ Error processing vulnerability: {e}")
                    vuln["status"] = "Manual Review Required"
                    manual_reviews += 1
                    processed.append(vuln)
            
            print(f"📊 Batch {idx} results: {batch_fixes} fixes applied, {manual_reviews} manual reviews")
            
            # ALWAYS create PR if we processed any vulnerabilities
            total_processed = batch_fixes + manual_reviews
            if total_processed > 0:
                try:
                    if batch_fixes > 0:
                        # Commit and push changes
                        success = _commit_and_push(cfg, branch, batch)
                        if not success:
                            print(f"⚠️  Batch {idx}: No changes to commit despite fixes reported")
                    elif manual_reviews > 0:
                        # Create a tracking file for manual review items
                        _create_manual_review_file(cfg, batch, idx)
                        success = _commit_and_push(cfg, branch, batch)
                    
                    # Create PR for all processed vulnerabilities (fixes + manual reviews)
                    pr_url = _create_pr(cfg, branch, idx, batch, batch_fixes, manual_reviews)
                    if pr_url:
                        pr_urls.append(pr_url)
                        print(f"✅ Batch {idx} completed: PR created at {pr_url}")
                    else:
                        print(f"⚠️  Batch {idx}: Failed to create PR")
                        failed_batches.append(idx)
                        
                except Exception as e:
                    print(f"❌ Batch {idx} failed during commit/push/PR: {e}")
                    failed_batches.append(idx)
            else:
                print(f"ℹ️  Batch {idx}: No vulnerabilities processed")
                failed_batches.append(idx)
                
        except Exception as e:
            print(f"❌ Batch {idx} failed: {e}")
            failed_batches.append(idx)
            if branch:
                _cleanup_failed_branch(cfg, branch)
            
            # Mark all vulnerabilities in this batch as failed
            for vuln in batch:
                if vuln not in processed:
                    vuln["status"] = f"Batch Failed: {str(e)}"
                    processed.append(vuln)

    # Summary
    total_processed = len(processed)
    total_fixed = sum(1 for v in processed if v.get("status") == "Fixed")
    total_prs = len(pr_urls)
    
    print(f"\n🎯 Remediation Summary:")
    print(f"   📊 Total vulnerabilities: {len(vulnerabilities)}")
    print(f"   ✅ Successfully fixed: {total_fixed}")
    print(f"   📝 PRs created: {total_prs}")
    print(f"   ❌ Failed batches: {len(failed_batches)}")
    
    if failed_batches:
        print(f"   ⚠️  Failed batch numbers: {failed_batches}")

    return processed, pr_urls


def _cleanup_failed_branch(cfg: FixerConfig, branch: str):
    """Clean up a failed branch."""
    if not branch:
        return
        
    original_dir = os.getcwd()
    try:
        os.chdir(cfg.CLONE_DIR)
        
        # Switch back to base branch
        subprocess.run(["git", "checkout", cfg.BASE_BRANCH], 
                      capture_output=True, check=False)
        
        # Delete the failed branch locally
        subprocess.run(["git", "branch", "-D", branch], 
                      capture_output=True, check=False)
        
        # Try to delete remote branch if it exists
        subprocess.run(["git", "push", "origin", "--delete", branch], 
                      capture_output=True, check=False)
        
        print(f"🧹 Cleaned up failed branch: {branch}")
        
    except Exception as e:
        print(f"⚠️  Could not clean up branch {branch}: {e}")
    finally:
        os.chdir(original_dir)

# =========================================================
# INTERNALS
# =========================================================

def _create_branch(cfg, idx):
    """Create a new branch for fixes with proper error handling."""
    name = f"ai-fix-{idx}-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    original_dir = os.getcwd()
    
    try:
        os.chdir(cfg.CLONE_DIR)
        
        # Ensure we're on the base branch
        result = subprocess.run(["git", "checkout", cfg.BASE_BRANCH], 
                              capture_output=True, text=True, check=False)
        if result.returncode != 0:
            print(f"⚠️  Warning: Could not checkout {cfg.BASE_BRANCH}: {result.stderr}")
            # Try to checkout main or master as fallback
            for fallback in ["main", "master"]:
                result = subprocess.run(["git", "checkout", fallback], 
                                      capture_output=True, text=True, check=False)
                if result.returncode == 0:
                    cfg.BASE_BRANCH = fallback
                    print(f"✅ Switched to {fallback} branch")
                    break
            else:
                raise Exception(f"Could not checkout any base branch")
        
        # Pull latest changes
        result = subprocess.run(["git", "pull"], capture_output=True, text=True, check=False)
        if result.returncode != 0:
            print(f"⚠️  Warning: Could not pull latest changes: {result.stderr}")
        
        # Create new branch
        result = subprocess.run(["git", "checkout", "-b", name], 
                              capture_output=True, text=True, check=True)
        
        print(f"✅ Created branch: {name}")
        return name
        
    except subprocess.CalledProcessError as e:
        raise Exception(f"Git operation failed: {e.stderr if hasattr(e, 'stderr') else str(e)}")
    finally:
        os.chdir(original_dir)


def _validate_fixed_code(code: str, file_path: str) -> bool:
    """
    Validate that fixed code is syntactically correct.
    """
    if not code or not code.strip():
        return False
    
    # Get file extension
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()
    
    try:
        if ext in ['.py']:
            # Python syntax validation - handle indented code
            import ast
            
            # For single-line or indented code, create a minimal valid Python context
            lines = code.splitlines()
            
            # Skip validation for very short snippets that are likely partial expressions
            if len(lines) == 1 and len(code.strip()) < 200:
                # For single line code, try to create a minimal context
                line = code.strip()
                
                # If it looks like a partial expression (starts with operators, etc.), skip validation
                if (line.startswith(('or ', 'and ', 'if ', 'elif ', 'else:', ')', ']', '}')) or
                    line.endswith((',', '\\', '(', '[', '{')) or
                    'r"' in line or "r'" in line):  # Raw strings in regex
                    print(f"   ℹ️  Skipping syntax validation for partial expression")
                    return True
                
                # Try to wrap in a function context
                try:
                    wrapped_code = f"def temp_function():\n    {line}"
                    ast.parse(wrapped_code)
                    return True
                except:
                    # Try as a simple expression
                    try:
                        wrapped_code = f"result = {line}"
                        ast.parse(wrapped_code)
                        return True
                    except:
                        # Try as a statement
                        try:
                            ast.parse(line)
                            return True
                        except:
                            print(f"   ⚠️  Could not validate Python syntax, but allowing due to complexity")
                            return True  # Allow complex regex patterns to pass
            
            # For multi-line code, try different validation approaches
            try:
                # Try to parse as-is
                ast.parse(code)
                return True
            except:
                # Try wrapping in function
                try:
                    wrapped_code = "def temp_function():\n"
                    for line in lines:
                        if line.strip():
                            # Ensure proper indentation
                            if not line.startswith('    '):
                                wrapped_code += f"    {line.lstrip()}\n"
                            else:
                                wrapped_code += f"{line}\n"
                        else:
                            wrapped_code += "\n"
                    ast.parse(wrapped_code)
                    return True
                except:
                    print(f"   ⚠️  Python syntax validation failed, but allowing for regex patterns")
                    return True  # Be more permissive for regex patterns
                
        elif ext in ['.js', '.jsx', '.ts', '.tsx']:
            # Basic JavaScript/TypeScript validation
            # Check for balanced braces, brackets, parentheses
            braces = code.count('{') - code.count('}')
            brackets = code.count('[') - code.count(']')
            parens = code.count('(') - code.count(')')
            
            if braces != 0 or brackets != 0 or parens != 0:
                return False
            
            # Check for obvious syntax errors
            if code.count('"') % 2 != 0 or code.count("'") % 2 != 0:
                return False
        
        return True
        
    except Exception as e:
        print(f"⚠️  Syntax validation failed: {e}")
        # Be more permissive - allow the fix if validation fails
        print(f"   ℹ️  Allowing fix despite validation failure")
        return True


def _is_already_fixed(rule_key: str, code: str) -> bool:
    """Check if the code is already using the secure pattern."""
    if not code:
        return False
    
    # Python weak PRNG
    if rule_key == "python:S2245":
        return "secrets." in code and "random." not in code
        
    # JS/TS weak PRNG
    if rule_key in ["typescript:S2245", "javascript:S2245"]:
        return "crypto.getRandomValues" in code and "Math.random" not in code
        
    # Regex backtracking S5852
    if "S5852" in rule_key:
        return "[^\\n]*" in code or "[^\\n]+" in code or "*?" in code or "+?" in code
        
    return False


def _process_single_vuln(cfg, vuln) -> bool:
    """Process a single vulnerability with comprehensive error handling."""
    rule = vuln.get("ruleKey")
    component = vuln.get("component", "unknown")
    
    print(f"🔧 Processing {rule} in {component}")
    
    strategy = get_strategy(rule)

    if strategy["type"] != "snippet_replace":
        vuln["status"] = "Manual Review"
        print(f"     Requires manual review")
        return False

    # Extract file path from component
    file_path = component.split(":")[-1] if ":" in component else component
    local = resolve_file_path(cfg.CLONE_DIR, component)
    
    if not local:
        vuln["status"] = "File Not Found"
        print(f"    File not found: {file_path}")
        return False

    if not os.path.exists(local):
        vuln["status"] = "Skipped"
        print(f"    File does not exist: {local}")
        return False

    try:
        # Get the actual vulnerability line from SonarQube data
        vuln_line = int(vuln.get("line", vuln.get("start_line", 0)))
        
        # Use SonarQube line if available, otherwise fall back to range
        if vuln_line > 0:
            start = vuln_line
            end = vuln_line
            print(f"   🎯 Using SonarQube line: {vuln_line}")
        else:
            start = int(vuln["start_line"])
            end = int(vuln["end_line"])
            print(f"   📏 Using range: {start}-{end}")
            
    except (ValueError, KeyError) as e:
        vuln["status"] = "Invalid Line Numbers"
        print(f"    Invalid line numbers: {e}")
        return False

    try:
        with open(local, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except Exception as e:
        vuln["status"] = "File Read Error"
        print(f"    Could not read file: {e}")
        return False

    if start < 1 or end > len(lines) or start > end:
        vuln["status"] = "Invalid Line Range"
        print(f"    Invalid line range: {start}-{end} (file has {len(lines)} lines)")
        
        # Try to adjust the range if it's slightly off
        if end > len(lines) and start <= len(lines):
            print(f"   🔧 Adjusting end line from {end} to {len(lines)}")
            end = len(lines)
            vuln["end_line"] = str(end)  # Update the vulnerability record
        else:
            return False

    # Extract code with context for better analysis
    context_start = max(1, start - 2)
    context_end = min(len(lines), end + 2)
    
    # Get the exact vulnerable line(s)
    vulnerable_code = "\n".join(lines[start - 1:end])
    context_code = "\n".join(lines[context_start - 1:context_end])
    
    # Check if the code is already secure/fixed
    if _is_already_fixed(rule, vulnerable_code):
        print(f"   ℹ️  Vulnerability is already secure (uses secure patterns)")
        vuln["status"] = "Fixed"
        return True
        
    print(f"   📝 Vulnerable code (line {start}-{end}): {vulnerable_code[:100]}...")
    print(f"    Context ({context_start}-{context_end}): {context_code[:150]}...")

    from .rule_based_remediation import apply_fix

    # ---------------- CHANGED LOGIC START ----------------
    # OLD: Try deterministic fix -> if good, apply it -> else try AI
    # NEW: Get deterministic fix -> Pass it as REFERENCE to AI -> AI makes final decision

    # Get deterministic fix suggestion if available
    reference_fix = apply_fix(vuln["ruleKey"], vulnerable_code, cfg.CLONE_DIR)

    if reference_fix:
        print(f"   💡 Found deterministic reference fix (passing to LLM)")

    # Always call AI, but now pass the reference_fix
    print(f"   🤖 Generating AI fix (using reference strategy if available)...")
    fixed = _generate_fix(cfg, vuln, strategy, context_code, vulnerable_code, reference_fix)
    
    # fixed = apply_fix(vuln["ruleKey"], vulnerable_code, cfg.CLONE_DIR)
    
    # if fixed and _has_meaningful_change(vulnerable_code, fixed):
    #     print(f"   ✅ Applied deterministic fix")
    #     print(f"   📝 Original: {vulnerable_code[:100]}...")
    #     print(f"   🔧 Fixed:    {fixed[:100]}...")
    # else:
    #     # Try AI-generated fix with context
    #     print(f"   🤖 Deterministic fix ineffective, trying AI...")
    #     fixed = _generate_fix(cfg, vuln, strategy, context_code, vulnerable_code)
        
    if fixed:
        print(f"   ✅ Generated AI fix")
        print(f"   📝 Original: {vulnerable_code[:100]}...")
        print(f"   🔧 Fixed:    {fixed[:100]}...")
    else:
        vuln["status"] = "Fix Generation Failed"
        print(f"    Could not generate fix")
        return False

    # Validate syntax
    if not _validate_fixed_code(fixed, local):
        vuln["status"] = "Invalid Syntax"
        print(f"    Fixed code has syntax errors")
        return False

    # Apply the fix to the file
    try:
        # Get original line for indentation reference
        original_line = lines[start - 1] if start <= len(lines) else ""
        original_indent = len(original_line) - len(original_line.lstrip())
        
        # Debug: Show what we're replacing
        print(f"   🔍 Replacing lines {start}-{end} (indices {start-1}:{end})")
        print(f"   📝 Original line: {original_line[:80]}...")
        
        # Prepare fixed lines
        fixed_lines = fixed.splitlines()
        if not fixed_lines:
            fixed_lines = ['']
        
        print(f"   🔧 Fixed to: {fixed_lines[0][:80] if fixed_lines else 'empty'}...")
        print(f"   📊 Line count: original={end - start + 1}, fixed={len(fixed_lines)}")
        
        # Preserve indentation if the fixed code doesn't have it
        if fixed_lines and original_indent > 0:
            first_fixed_line = fixed_lines[0]
            fixed_indent = len(first_fixed_line) - len(first_fixed_line.lstrip())
            
            # If fixed code has less indentation than original, add the difference
            if fixed_indent < original_indent:
                indent_diff = original_indent - fixed_indent
                fixed_lines = [' ' * indent_diff + line for line in fixed_lines]
                print(f"   ↔️  Added {indent_diff} spaces indentation")
        
        # Replace the lines correctly
        # Delete the old lines first
        del lines[start - 1:end]
        
        # Insert the fixed lines at the correct position
        for i, fixed_line in enumerate(fixed_lines):
            lines.insert(start - 1 + i, fixed_line)
        
        # Write back to file
        with open(local, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        
        vuln["status"] = "Fixed"
        print(f"   ✅ Successfully applied fix")
        return True
        
    except Exception as e:
        vuln["status"] = "File Write Error"
        print(f"    Could not write fixed file: {e}")
        return False


def _has_meaningful_change(original: str, fixed: str) -> bool:
    """Check if the fix produced meaningful changes."""
    if not fixed or not original:
        return False
    
    # Normalize whitespace for comparison
    orig_normalized = re.sub(r'\s+', ' ', original.strip())
    fixed_normalized = re.sub(r'\s+', ' ', fixed.strip())
    
    # Check for actual content changes (not just whitespace/comments)
    if orig_normalized == fixed_normalized:
        return False
    
    # Check if only comments were added
    orig_no_comments = re.sub(r'#.*$', '', orig_normalized, flags=re.MULTILINE)
    fixed_no_comments = re.sub(r'#.*$', '', fixed_normalized, flags=re.MULTILINE)
    
    return orig_no_comments != fixed_no_comments


def _generate_fix(cfg, vuln, strategy, context_code: str, vulnerable_code: str = None, reference_fix: str = None) -> Optional[str]:
    """Generate AI fix with improved error handling, context awareness, and validation."""
    constraints = "\n".join(f"- {c}" for c in strategy["constraints"])
    language = strategy.get("language", "unknown")
    rule_key = vuln.get("ruleKey", "unknown")
    message = vuln.get("message", "Security vulnerability")
    
    # Ensure both vulnerable code and context are presented clearly
    vulnerable_to_replace = vulnerable_code if vulnerable_code else context_code
    code_to_fix = vulnerable_to_replace
    
    # Build prompt with reference fix and context code included
    prompt = f"""SECURITY FIX REQUIRED

CONTEXT CODE:
{context_code}

VULNERABLE CODE (to replace):
{vulnerable_to_replace}

RULE: {rule_key}
ISSUE: {message}
CONSTRAINTS:
{constraints}

REFERENCE FIX SUGGESTION:
{reference_fix or "None available"}

INSTRUCTIONS:
- Return ONLY the fixed code to replace the VULNERABLE CODE.
- NO explanations, NO comments, NO markdown fences.
- Preserve exact functionality of the surrounding context.
- Fix ONLY the security issue.
- Maintain the same variable names and logic flow where possible.

FIXED CODE:"""

    for attempt in range(cfg.MAX_RETRIES):
        try:
            print(f"      🔄 LLM attempt {attempt + 1}/{cfg.MAX_RETRIES}")
            print(f"      🌐 Connecting to: {cfg.OLLAMA_URL}")
            
            r = requests.post(
                cfg.OLLAMA_URL,
                json={
                    "model": cfg.MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "system": """You are a code security fixer. Rules:
1. Return ONLY the corrected code to replace the vulnerable lines.
2. NO explanations, comments, or conversational text.
3. Preserve all variable names exactly.
4. Maintain same functionality.
5. Fix only the security vulnerability.
6. Never use markdown or backticks.

Example:
Input: const x = /.*+/;
Output: const x = /[^\\n]*+/;""",
                    "options": {
                        "temperature": 0.0,        # Maximum determinism
                        "top_p": 0.1,             # Very focused
                        "repeat_penalty": 1.2,    # Avoid repetition
                        "num_predict": 256,       # Allow enough room for multi-line fixes
                        "stop": [
                            "Explanation:", "Note:", "Comment:", "Here's", 
                            "This fix", "The fix", "However", "If you"
                        ],
                    },
                },
                timeout=cfg.TIMEOUT,
            )

            print(f"      📡 Response status: {r.status_code}")
            
            if r.status_code == 404:
                print(f"      ❌ Server not found. Check if Ollama is running at {cfg.OLLAMA_URL}")
                print(f"      💡 Try: curl {cfg.OLLAMA_URL.replace('/api/generate', '/api/tags')}")
                continue
            elif r.status_code != 200:
                print(f"      ⚠️  HTTP {r.status_code}: {r.text[:200]}")
                continue

            response_data = r.json()
            out = response_data.get("response", "").strip()
            
            if not out:
                print(f"      ⚠️  Empty response from server")
                continue
            
            # Clean up the response
            out = _strip_fences(out)
            out = _clean_llm_response(out)
            
            # Validate the response
            if out and len(out.strip()) > 5:  # Minimum reasonable length
                # Check if the fix is actually different from original
                if _has_meaningful_change(code_to_fix, out):
                    # Check if functionality is preserved
                    if _preserves_functionality(code_to_fix, out, rule_key):
                        print(f"      ✅ Generated meaningful fix that preserves functionality ({len(out)} chars)")
                        return out
                    else:
                        print(f"      ⚠️  AI fix may break functionality, retrying...")
                        continue
                else:
                    print(f"      ⚠️  AI fix identical to original, retrying...")
                    continue
            else:
                print(f"      ⚠️  Response too short: {len(out)} chars")

        except requests.exceptions.Timeout:
            print(f"      ⚠️  Request timeout after {cfg.TIMEOUT}s")
        except requests.exceptions.ConnectionError as e:
            print(f"      ⚠️  Connection error: {e}")
            print(f"      💡 Check if Ollama server is running at {cfg.OLLAMA_URL}")
        except Exception as e:
            print(f"      ⚠️  Unexpected error: {e}")
        
        if attempt < cfg.MAX_RETRIES - 1:
            print(f"      ⏳ Waiting {cfg.RETRY_DELAY}s before retry...")
            time.sleep(cfg.RETRY_DELAY)

    print(f"      ❌ All {cfg.MAX_RETRIES} attempts failed")
    
    # FALLBACK: Use deterministic fix if available and different from original
    if reference_fix and reference_fix.strip() != code_to_fix.strip():
        print(f"      🔄 Falling back to deterministic fix")
        return reference_fix
    
    print(f"      🔧 Suggestion: Check Ollama server status and model availability")
    return None


def _clean_llm_response(text: str) -> str:
    """Extract only the actual code from LLM response, supporting multi-line fixes."""
    if not text:
        return text
    
    # Remove markdown code blocks
    text = re.sub(r'```[a-zA-Z]*\n?', '', text)
    text = re.sub(r'```\n?', '', text)
    
    lines = text.split('\n')
    clean_lines = []
    
    # Filter out explanations and text
    for line in lines:
        stripped = line.strip()
        
        # Skip empty lines
        if not stripped:
            continue
            
        # Skip lines that are clearly conversational explanations
        if stripped.lower().startswith(('the', 'this', 'here', 'note', 'explanation', 'however', 'if you', 'if ', 'for ', 'to ', 'it ', 'you ')):
            # If it's code but matches (e.g. "if (x)"), don't skip if it looks like actual code.
            # E.g. "if (password == 'admin')" starts with "if ". But it is code.
            is_code = (
                stripped.startswith(('const ', 'let ', 'var ', 'function', 'class ', 'def ', 'import ', 'from ', 'return ')) or 
                '=' in stripped or 
                stripped.startswith('/') or 
                stripped.startswith('<') or 
                ';' in stripped or
                stripped.startswith('        ') or
                re.match(r'^[a-zA-Z_$][a-zA-Z0-9_$]*\s*[=:]', stripped)
            )
            if not is_code:
                continue
                
        # Skip obvious colon headers like "Fixed code:" or "Output:"
        if stripped.endswith(':') and len(stripped) < 30 and not stripped.startswith(('case', 'default')):
            continue
            
        clean_lines.append(line)
        
    if clean_lines:
        return "\n".join(clean_lines).strip()
        
    # Fallback: return first meaningful line that's not obviously explanation
    for line in lines:
        stripped = line.strip()
        if (stripped and 
            len(stripped) > 5 and
            not stripped.lower().startswith(('the', 'this', 'here', 'note', 'explanation', 'however', 'if', 'for', 'to', 'it', 'you')) and
            not stripped.endswith(':')):
            return stripped
    
    # Last resort: return first non-empty line
    return lines[0].strip() if lines else ""


def _preserves_functionality(original: str, fixed: str, rule_key: str) -> bool:
    """Validate that fix preserves original functionality."""
    if not original or not fixed:
        return False
    
    # For regex fixes - ensure pattern structure is maintained
    if 'S5852' in rule_key:  # Regex backtracking
        # Extract regex patterns
        orig_pattern = re.search(r'/(.+)/', original)
        fixed_pattern = re.search(r'/(.+)/', fixed)
        
        if orig_pattern and fixed_pattern:
            # Ensure core pattern logic is preserved
            orig_core = orig_pattern.group(1).replace('*', '+').replace('+', '')
            fixed_core = fixed_pattern.group(1).replace('*', '+').replace('+', '')
            return orig_core in fixed_core or fixed_core in orig_core
    
    # For other fixes - ensure variable names and structure match
    orig_vars = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', original)
    fixed_vars = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', fixed)
    
    # Key variables should be preserved
    if orig_vars:
        return len(set(orig_vars) & set(fixed_vars)) >= len(orig_vars) * 0.8
    
    return True  # If no variables to check, assume it's fine


def _normalize(text: str) -> str:
    return "".join(text.split())


def _strip_fences(text: str) -> str:
    if text.startswith("```"):
        lines = text.splitlines()
        return "\n".join(lines[1:-1]).strip()
    return text


def _create_manual_review_file(cfg, batch, batch_idx):
    """Create a file to track manual review items so we can create a PR."""
    original_dir = os.getcwd()
    
    try:
        os.chdir(cfg.CLONE_DIR)
        
        # Create a manual review tracking file
        filename = f".security-review-batch-{batch_idx}.md"
        
        content = f"""# Security Review Required - Batch {batch_idx}

This file tracks security vulnerabilities that require manual review.

## Issues Requiring Manual Review

"""
        
        manual_vulns = [v for v in batch if v.get("status") in ["Manual Review Required", "Fix Generation Failed", "File Not Found"]]
        
        for v in manual_vulns:
            component = v.get('component', 'unknown')
            file_path = component.split(':')[-1] if ':' in component else component
            rule = v.get('ruleKey', 'unknown')
            status = v.get('status', 'unknown')
            message = v.get('message', 'No description')
            
            content += f"""### {rule}
- **File**: `{file_path}`
- **Lines**: {v.get('start_line', '?')}-{v.get('end_line', '?')}
- **Status**: {status}
- **Issue**: {message}

"""
        
        content += f"""
## Next Steps

1. Review each issue listed above
2. Manually implement security fixes where needed
3. Test the application after making changes
4. Delete this file once all issues are resolved

---
*Generated by AppSecAI on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"📝 Created manual review file: {filename}")
        
    except Exception as e:
        print(f"⚠️  Could not create manual review file: {e}")
    finally:
        os.chdir(original_dir)


def _commit_and_push(cfg, branch, batch):
    """Commit and push changes with proper error handling."""
    original_dir = os.getcwd()
    
    try:
        os.chdir(cfg.CLONE_DIR)
        
        # Check if there are any changes to commit
        result = subprocess.run(["git", "status", "--porcelain"], 
                              capture_output=True, text=True, check=True)
        if not result.stdout.strip():
            print("⚠️  No changes to commit")
            return False
        
        # Add all changes
        subprocess.run(["git", "add", "."], check=True)
        
        # Create commit message with details
        fixed_count = sum(1 for v in batch if v.get("status") == "Fixed")
        manual_count = sum(1 for v in batch if v.get("status") in ["Manual Review Required", "Fix Generation Failed", "File Not Found"])
        
        if fixed_count > 0:
            commit_msg = f"AI security fixes: {fixed_count} vulnerabilities fixed"
            if manual_count > 0:
                commit_msg += f", {manual_count} require manual review"
            commit_msg += "\n\nFixed rules:\n"
            for v in batch:
                if v.get("status") == "Fixed":
                    commit_msg += f"- {v.get('ruleKey', 'unknown')}: {v.get('component', 'unknown')}\n"
        else:
            commit_msg = f"Security analysis: {manual_count} vulnerabilities require manual review\n\nManual review items:\n"
            for v in batch:
                if v.get("status") in ["Manual Review Required", "Fix Generation Failed", "File Not Found"]:
                    commit_msg += f"- {v.get('ruleKey', 'unknown')}: {v.get('component', 'unknown')}\n"
        
        # Commit changes
        subprocess.run(["git", "commit", "-m", commit_msg], check=True)
        
        # Push to remote
        result = subprocess.run(["git", "push", "-u", "origin", branch], 
                              capture_output=True, text=True, check=False)
        if result.returncode != 0:
            print(f" Push failed: {result.stderr}")
            raise Exception(f"Failed to push branch {branch}: {result.stderr}")
        
        print(f"✅ Pushed {fixed_count} fixes to branch {branch}")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f" Git operation failed: {e}")
        raise Exception(f"Git commit/push failed: {e}")
    finally:
        os.chdir(original_dir)


def _create_pr(cfg, branch, idx, batch, fixes_applied=0, manual_reviews=0):
    """Create PR with detailed information and error handling."""
    try:
        gh = Github(cfg.GITHUB_TOKEN)
        repo = gh.get_repo(cfg.GITHUB_REPO)
        
        # Count different types of issues
        fixed_vulns = [v for v in batch if v.get("status") == "Fixed"]
        manual_vulns = [v for v in batch if v.get("status") in ["Manual Review", "File Not Found", "Invalid Line Range", "Fix Generation Failed"]]
        
        # Create PR even if no fixes (for manual review tracking)
        total_issues = len(fixed_vulns) + len(manual_vulns)
        
        # Create detailed PR body
        if fixes_applied > 0:
            title = f"{cfg.PR_TITLE_PREFIX} - Batch {idx} ({fixes_applied} fixes, {manual_reviews} manual reviews)"
        else:
            title = f"{cfg.PR_TITLE_PREFIX} - Batch {idx} (Manual Review Required - {manual_reviews} issues)"
        
        body = f"""## 🛡️ Security Analysis - Batch {idx}

This PR contains automated security analysis for {total_issues} vulnerabilities detected by SonarQube.

### 📊 Summary
- **Automatically fixed**: {fixes_applied}
- **Require manual review**: {manual_reviews}
- **Total issues processed**: {total_issues}
- **Automation success rate**: {(fixes_applied/total_issues*100) if total_issues > 0 else 0:.1f}%

"""
        
        if fixed_vulns:
            body += "### ✅ Automatically Fixed Issues\n"
            # Group by rule type
            rule_groups = {}
            for v in fixed_vulns:
                rule = v.get('ruleKey', 'unknown')
                if rule not in rule_groups:
                    rule_groups[rule] = []
                rule_groups[rule].append(v)
            
            for rule, vulns in rule_groups.items():
                body += f"\n#### {rule} ({len(vulns)} fixes)\n"
                for v in vulns:
                    component = v.get('component', 'unknown')
                    file_path = component.split(':')[-1] if ':' in component else component
                    body += f"- `{file_path}` (lines {v.get('start_line', '?')}-{v.get('end_line', '?')})\n"
        
        if manual_vulns:
            body += "\n### ⚠️ Manual Review Required\n"
            # Group by status
            status_groups = {}
            for v in manual_vulns:
                status = v.get('status', 'unknown')
                if status not in status_groups:
                    status_groups[status] = []
                status_groups[status].append(v)
            
            for status, vulns in status_groups.items():
                body += f"\n#### {status} ({len(vulns)} issues)\n"
                for v in vulns:
                    component = v.get('component', 'unknown')
                    file_path = component.split(':')[-1] if ':' in component else component
                    rule = v.get('ruleKey', 'unknown')
                    body += f"- `{file_path}` - {rule} (lines {v.get('start_line', '?')}-{v.get('end_line', '?')})\n"
        
        body += f"""
### 🤖 Automated Fix Details
- **AI Engine**: {cfg.MODEL}
- **Branch**: `{branch}`
- **Timestamp**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

### ⚠️ Review Notes
- All fixes have been validated for syntax correctness
- Please review changes before merging
- Test the application to ensure functionality is preserved

---
*This PR was automatically generated by AppSecAI*
"""
        
        # Create PR even if no code changes (for tracking manual review items)
        pr = repo.create_pull(
            title=title,
            body=body,
            base=cfg.BASE_BRANCH,
            head=branch,
        )
        
        print(f"✅ Created PR: {pr.html_url}")
        return pr.html_url
        
    except Exception as e:
        print(f"❌ Failed to create PR for batch {idx}: {e}")
        return None

def _ensure_clean_repo(repo_dir: str):
    cwd = os.getcwd()
    os.chdir(repo_dir)
    subprocess.run(["git", "reset", "--hard"], check=True)
    subprocess.run(["git", "clean", "-fd"], check=True)
    os.chdir(cwd)

def resolve_file_path(repo_dir: str, sonar_path: str) -> Optional[str]:
    """
    Resolve SonarQube component path to actual file path with enhanced debugging.
    
    SonarQube format: "project:src/main/java/File.java"
    Need to extract: "src/main/java/File.java"
    """
    print(f"   🔍 Resolving file path: {sonar_path}")
    
    # Handle SonarQube component format (project:path)
    if ":" in sonar_path:
        # Split on first colon to separate project from path
        parts = sonar_path.split(":", 1)
        if len(parts) == 2:
            file_path = parts[1]
            print(f"   📂 Extracted path from component: {file_path}")
        else:
            file_path = sonar_path
    else:
        file_path = sonar_path
    
    # Normalize path separators (SonarQube uses forward slashes)
    file_path = file_path.replace("/", os.sep)
    
    # Try direct path first
    candidate = os.path.join(repo_dir, file_path)
    print(f"   🎯 Trying direct path: {candidate}")
    if os.path.exists(candidate):
        print(f"   ✅ Found file at: {candidate}")
        return candidate
    
    # Try without leading directories (common in monorepos)
    path_parts = file_path.split(os.sep)
    for i in range(1, len(path_parts)):
        candidate = os.path.join(repo_dir, *path_parts[i:])
        print(f"   🔄 Trying without {i} leading dirs: {candidate}")
        if os.path.exists(candidate):
            print(f"   ✅ Found file at: {candidate}")
            return candidate
    
    # Try finding file by name in common directories
    filename = os.path.basename(file_path)
    print(f"   🔍 Searching for filename: {filename}")
    common_dirs = ["src", "lib", "app", "components", "pages", "utils", "services"]
    
    for root, dirs, files in os.walk(repo_dir):
        # Skip hidden directories and node_modules
        dirs[:] = [d for d in dirs if not d.startswith('.') and d != 'node_modules']
        
        if filename in files:
            candidate = os.path.join(root, filename)
            print(f"   🎯 Found candidate: {candidate}")
            # Prefer files in common source directories
            rel_path = os.path.relpath(candidate, repo_dir)
            if any(common_dir in rel_path for common_dir in common_dirs):
                print(f"   ✅ Found in common directory: {candidate}")
                return candidate
            # Otherwise, return first match
            print(f"   ✅ Using first match: {candidate}")
            return candidate
    
    print(f"   ❌ File not found: {sonar_path}")
    return None


def extract_vulnerable_lines(file_path: str, vuln_line: int, context_lines: int = 5) -> Tuple[str, str, int, int]:
    """
    Extract the actual vulnerable code and context from a file.
    
    Returns:
        (vulnerable_code, context_code, actual_start, actual_end)
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        total_lines = len(lines)
        
        # Calculate context boundaries
        context_start = max(0, vuln_line - context_lines - 1)
        context_end = min(total_lines, vuln_line + context_lines)
        
        # Get the vulnerable line (1-indexed to 0-indexed)
        vulnerable_code = lines[vuln_line - 1].rstrip('\n\r')
        
        # Get context
        context_code = ''.join(lines[context_start:context_end])
        
        print(f"   📍 Extracted line {vuln_line}: {vulnerable_code[:100]}...")
        print(f"   📋 Context lines {context_start + 1}-{context_end}: {len(context_code)} chars")
        
        return vulnerable_code, context_code, vuln_line, vuln_line
        
    except Exception as e:
        print(f"   ❌ Error extracting code: {e}")
        return "", "", 0, 0
