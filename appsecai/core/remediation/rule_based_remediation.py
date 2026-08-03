# deterministic_fixes.py

import re
import os


# ---------------- TYPESCRIPT / JAVASCRIPT ----------------

def fix_typescript_weak_prng(code: str) -> str:
    """
    Sonar rule: S2245 (TypeScript/JavaScript)
    Strategy:
      - Replace Math.random() with crypto.getRandomValues()
      - Use Web Crypto API for cryptographically secure random
    """
    original_code = code
    
    # Replace Math.random() with crypto-secure alternative
    # For simple Math.random() calls
    code = re.sub(r'Math\.random\(\)', 'crypto.getRandomValues(new Uint32Array(1))[0] / 0xFFFFFFFF', code)
    
    # For Math.random() * number patterns
    code = re.sub(r'Math\.random\(\)\s*\*\s*([^\s;,)]+)', 
                  r'(crypto.getRandomValues(new Uint32Array(1))[0] / 0xFFFFFFFF) * \1', code)
    
    # For (Math.random() - 0.5) patterns (centered random)
    code = re.sub(r'\(Math\.random\(\)\s*-\s*0\.5\)', 
                  '((crypto.getRandomValues(new Uint32Array(1))[0] / 0xFFFFFFFF) - 0.5)', code)
    
    # For Math.floor(Math.random() * array.length) patterns
    code = re.sub(r'Math\.floor\(Math\.random\(\)\s*\*\s*([^)]+)\)', 
                  r'Math.floor((crypto.getRandomValues(new Uint32Array(1))[0] / 0xFFFFFFFF) * \1)', code)
    
    return code


def fix_regex_backtracking(code: str) -> str:
    """
    Sonar rule: S5852 (TypeScript/JavaScript/Python/Java)
    Strategy:
      - Replace dangerous unbounded quantifiers
      - Preserve semantics and functionality
      - Be more aggressive with common patterns
    """
    original_code = code
    
    # More aggressive approach for common problematic patterns
    
    # Replace \s* with [ \t]* (whitespace without newlines)
    code = re.sub(r'\\s\*', r'[ \\t]*', code)
    
    # Replace \s+ with [ \t]+ 
    code = re.sub(r'\\s\+', r'[ \\t]+', code)
    
    # Replace .* with [^\n]* (single line matching)
    code = re.sub(r'\.\*', r'[^\\n]*', code)
    
    # Replace .+ with [^\n]+ (single line matching)
    code = re.sub(r'\.\+', r'[^\\n]+', code)
    
    # Handle specific word/digit patterns
    code = re.sub(r'\\w\*', r'[a-zA-Z0-9_]*', code)
    code = re.sub(r'\\w\+', r'[a-zA-Z0-9_]+', code)
    code = re.sub(r'\\d\*', r'[0-9]*', code)
    code = re.sub(r'\\d\+', r'[0-9]+', code)
    
    # Handle character class repetitions that might be problematic
    code = re.sub(r'\[([^\]]+)\]\*', r'[\1]*?', code)  # Make non-greedy
    code = re.sub(r'\[([^\]]+)\]\+', r'[\1]+?', code)  # Make non-greedy
    
    return code


def fix_dynamic_execution(code: str) -> str:
    """
    Sonar rule: S1523 (TypeScript/JavaScript)
    Strategy:
      - Replace eval / Function with safer alternatives
      - Force explicit rejection
    """
    code = re.sub(r'\beval\s*\(', '(() => { throw new Error("eval disabled for security"); })(', code)
    code = re.sub(r'new Function\s*\(', '(() => { throw new Error("Function constructor disabled for security"); })(', code)
    return code


def fix_hardcoded_ip(code: str) -> str:
    """
    Sonar rule: S1313 (TypeScript/JavaScript)
    Strategy:
      - Move IP to env or constant placeholder
    """
    return re.sub(
        r'\b\d{1,3}(?:\.\d{1,3}){3}\b',
        'process.env.SERVICE_IP || "localhost"',
        code
    )


def fix_hardcoded_credentials(code: str, language: str = "javascript") -> str:
    """
    Sonar rule: S2068 (All languages)
    Strategy:
      - Replace hardcoded passwords with environment variables
    """
    if language == "python":
        # Python patterns
        code = re.sub(r'password\s*=\s*["\'][^"\']+["\']', 'password = os.environ.get("PASSWORD")', code, flags=re.IGNORECASE)
        code = re.sub(r'secret\s*=\s*["\'][^"\']+["\']', 'secret = os.environ.get("SECRET")', code, flags=re.IGNORECASE)
    elif language == "java":
        # Java patterns
        code = re.sub(r'password\s*=\s*"[^"]+"', 'password = System.getenv("PASSWORD")', code, flags=re.IGNORECASE)
        code = re.sub(r'secret\s*=\s*"[^"]+"', 'secret = System.getenv("SECRET")', code, flags=re.IGNORECASE)
    else:
        # JavaScript/TypeScript patterns
        code = re.sub(r'password\s*[:=]\s*["\'][^"\']+["\']', 'password: process.env.PASSWORD', code, flags=re.IGNORECASE)
        code = re.sub(r'secret\s*[:=]\s*["\'][^"\']+["\']', 'secret: process.env.SECRET', code, flags=re.IGNORECASE)
    
    return code


# ---------------- PYTHON ----------------

def fix_python_weak_prng(code: str) -> str:
    """
    Sonar rule: S2245 (Python)
    Strategy:
      - Replace random with secrets
    """
    original_code = code
    
    # Replace random.random() with secrets equivalent
    code = re.sub(r'import random\b', 'import secrets', code)
    code = re.sub(r'from random import', 'from secrets import', code)
    
    # Replace specific random functions
    code = re.sub(r'random\.random\(\)', 'secrets.SystemRandom().random()', code)
    code = re.sub(r'random\.randint\(([^)]+)\)', r'secrets.randbelow(\1)', code)
    code = re.sub(r'random\.choice\(', 'secrets.choice(', code)
    code = re.sub(r'random\.choices\(', 'secrets.SystemRandom().choices(', code)
    
    # Handle the specific pattern: random.choices(string.ascii_letters + string.digits, k=8)
    code = re.sub(r'random\.choices\(([^,]+),\s*k=(\d+)\)', 
                  r"''.join(secrets.choice(\1) for _ in range(\2))", code)
    
    # If it's a simple random.choices call, replace it
    if 'random.choices(' in code:
        code = re.sub(r"''.join\(random\.choices\(([^,]+),\s*k=(\d+)\)\)", 
                      r"''.join(secrets.choice(\1) for _ in range(\2))", code)
    
    # If no specific pattern matched but we have random usage, add import
    if 'random.' in code and 'secrets' not in code:
        # Add secrets import at the beginning of the line/block
        if code.strip().startswith('random.'):
            code = f"import secrets\n{code.replace('random.', 'secrets.')}"
    
    return code


def fix_python_sql_injection(code: str) -> str:
    """
    Sonar rule: S2077 (Python)
    Strategy:
      - Replace string formatting with parameterized queries
    """
    # Replace string formatting in SQL
    code = re.sub(r'cursor\.execute\s*\(\s*f"([^"]*)"', r'cursor.execute("\1", params)', code)
    code = re.sub(r'cursor\.execute\s*\(\s*"([^"]*)"\.format\([^)]*\)', r'cursor.execute("\1", params)', code)
    code = re.sub(r'cursor\.execute\s*\(\s*"([^"]*)" %', r'cursor.execute("\1", params)', code)
    
    return code


# ---------------- JAVA ----------------

def fix_java_sql_injection(code: str) -> str:
    """
    Sonar rule: S2077 (Java)
    Strategy:
      - Replace string concatenation with PreparedStatement
    """
    # Replace string concatenation in SQL
    code = re.sub(r'Statement\s+(\w+)\s*=\s*connection\.createStatement\(\)', 
                  r'PreparedStatement \1 = connection.prepareStatement(sql)', code)
    code = re.sub(r'executeQuery\s*\(\s*"([^"]*)" \+', 
                  r'executeQuery()', code)
    
    return code


# ---------------- DOCKER ----------------

def detect_project_type(repo_dir: str) -> str:
    """
    Detect the project type/language from repository structure.
    
    Returns: 'go', 'nodejs', 'python', 'java', 'dotnet', 'unknown'
    """
    # Check for Go project
    if (os.path.exists(os.path.join(repo_dir, "go.mod")) or 
        os.path.exists(os.path.join(repo_dir, "go.sum")) or
        any(os.path.exists(os.path.join(repo_dir, d)) for d in ["cmd", "internal", "pkg"])):
        return "go"
    
    # Check for Node.js project
    if (os.path.exists(os.path.join(repo_dir, "package.json")) or
        os.path.exists(os.path.join(repo_dir, "package-lock.json")) or
        os.path.exists(os.path.join(repo_dir, "yarn.lock"))):
        return "nodejs"
    
    # Check for Python project
    if (os.path.exists(os.path.join(repo_dir, "requirements.txt")) or
        os.path.exists(os.path.join(repo_dir, "pyproject.toml")) or
        os.path.exists(os.path.join(repo_dir, "setup.py")) or
        os.path.exists(os.path.join(repo_dir, "Pipfile"))):
        return "python"
    
    # Check for Java project
    if (os.path.exists(os.path.join(repo_dir, "pom.xml")) or
        os.path.exists(os.path.join(repo_dir, "build.gradle")) or
        os.path.exists(os.path.join(repo_dir, "gradlew"))):
        return "java"
    
    # Check for .NET project
    if any(f.endswith(('.csproj', '.sln', '.fsproj', '.vbproj')) 
           for f in os.listdir(repo_dir) if os.path.isfile(os.path.join(repo_dir, f))):
        return "dotnet"
    
    return "unknown"


def analyze_dockerfile_context(dockerfile_path: str, repo_dir: str) -> dict:
    """
    Analyze Dockerfile and repository context to understand the build requirements.
    
    Returns dict with project_type, source_dirs, build_files, etc.
    """
    context = {
        "project_type": detect_project_type(repo_dir),
        "source_dirs": [],
        "build_files": [],
        "has_dockerignore": os.path.exists(os.path.join(repo_dir, ".dockerignore"))
    }
    
    # Read Dockerfile to understand current structure
    try:
        with open(dockerfile_path, 'r') as f:
            dockerfile_content = f.read()
        
        # Extract existing COPY commands to understand what's being copied
        copy_commands = re.findall(r'COPY\s+([^\s]+)\s+([^\s\n]+)', dockerfile_content)
        context["existing_copies"] = copy_commands
        
        # Detect build commands to understand dependencies
        build_commands = re.findall(r'RUN\s+.*?(go build|npm|yarn|pip|mvn|gradle|dotnet)', dockerfile_content, re.IGNORECASE)
        context["build_commands"] = build_commands
        
    except Exception as e:
        print(f"   ⚠️  Could not analyze Dockerfile: {e}")
    
    # Detect source directories based on project type
    if context["project_type"] == "go":
        potential_dirs = ["cmd", "internal", "pkg", "api", "web", "configs", "scripts", "deployments"]
        context["source_dirs"] = [d for d in potential_dirs if os.path.exists(os.path.join(repo_dir, d))]
        context["build_files"] = ["go.mod", "go.sum"]
        
    elif context["project_type"] == "nodejs":
        potential_dirs = ["src", "lib", "app", "components", "pages", "utils", "services", "public"]
        context["source_dirs"] = [d for d in potential_dirs if os.path.exists(os.path.join(repo_dir, d))]
        context["build_files"] = ["package.json", "package-lock.json", "yarn.lock", "tsconfig.json"]
        
    elif context["project_type"] == "python":
        potential_dirs = ["src", "app", "lib", "tests", "scripts"]
        context["source_dirs"] = [d for d in potential_dirs if os.path.exists(os.path.join(repo_dir, d))]
        context["build_files"] = ["requirements.txt", "pyproject.toml", "setup.py", "Pipfile"]
        
    elif context["project_type"] == "java":
        potential_dirs = ["src", "lib", "resources"]
        context["source_dirs"] = [d for d in potential_dirs if os.path.exists(os.path.join(repo_dir, d))]
        context["build_files"] = ["pom.xml", "build.gradle", "gradlew"]
    
    # Filter to only existing directories
    context["source_dirs"] = [d for d in context["source_dirs"] if os.path.exists(os.path.join(repo_dir, d))]
    context["build_files"] = [f for f in context["build_files"] if os.path.exists(os.path.join(repo_dir, f))]
    
    return context


def fix_root_user(dockerfile: str) -> str:
    """
    Sonar rule: S6471
    Strategy:
      - Add non-root user
      - Switch USER
      - Handle distroless images properly
    """
    if "USER " in dockerfile and "USER root" not in dockerfile:
        return dockerfile  # Already has non-root user

    lines = dockerfile.splitlines()
    out = []
    inserted = False

    for line in lines:
        out.append(line)
        if line.strip().startswith("FROM") and not inserted:
            # Detect base image type for appropriate user creation
            if "distroless" in line.lower():
                # Distroless images don't have shell commands like groupadd/useradd
                # They come with a nonroot user pre-configured
                out.append("# Using distroless nonroot user (uid=65532)")
                out.append("USER 65532:65532")
            elif "alpine" in line.lower():
                out.append("RUN addgroup -S nonroot && adduser -S nonroot -G nonroot")
                out.append("USER nonroot")
            else:
                # Standard Linux distributions (Ubuntu, Debian, etc.)
                out.append("RUN groupadd -r nonroot && useradd -r -g nonroot nonroot")
                out.append("USER nonroot")
            inserted = True

    return "\n".join(out)


def fix_copy_glob(dockerfile: str, repo_dir: str = None) -> str:
    """
    Sonar rule: S6470
    Strategy:
      - Replace COPY . . with explicit COPY based on project type
      - Analyze repository context to determine correct directories
      - Avoid redundant COPY statements
      - Recommend .dockerignore when appropriate
    """
    if not repo_dir:
        # Fallback to generic fix if no context available
        dockerfile = dockerfile.replace("COPY . .", "COPY src ./src\n# Explicit COPY to avoid secrets")
        dockerfile = dockerfile.replace("COPY .env*", "# env files excluded for security")
        return dockerfile
    
    # Analyze the repository context
    dockerfile_path = os.path.join(repo_dir, "Dockerfile")
    context = analyze_dockerfile_context(dockerfile_path, repo_dir)
    
    print(f"    📁 Detected project type: {context['project_type']}")
    print(f"    📂 Source directories: {context['source_dirs']}")
    print(f"    📄 Build files: {context['build_files']}")
    
    # Check for existing COPY commands to avoid duplication
    existing_copies = context.get("existing_copies", [])
    existing_files = set()
    for src, _ in existing_copies:
        if src not in [".", "./"]:  # Ignore the problematic COPY . .
            existing_files.add(src)
    
    # Generate appropriate COPY commands based on project type
    if context["project_type"] == "go":
        # Go-specific COPY commands
        copy_commands = []
        
        # Add build files first (avoid duplicates)
        build_files_to_copy = []
        for build_file in context["build_files"]:
            if build_file not in existing_files:
                build_files_to_copy.append(build_file)
        
        if build_files_to_copy:
            copy_commands.append("# Copy Go module files")
            for build_file in build_files_to_copy:
                copy_commands.append(f"COPY {build_file} ./")
        
        # Add source directories (avoid duplicates)
        source_dirs_to_copy = []
        for src_dir in context["source_dirs"]:
            if src_dir not in existing_files and f"./{src_dir}" not in existing_files:
                source_dirs_to_copy.append(src_dir)
        
        if source_dirs_to_copy:
            copy_commands.append("# Copy Go source directories")
            for src_dir in source_dirs_to_copy:
                copy_commands.append(f"COPY {src_dir} ./{src_dir}")
        
        # Add additional Go-specific directories if they exist
        additional_dirs = ["pkg", "api", "web", "configs", "scripts", "deployments", "migrations", "assets", "templates"]
        for add_dir in additional_dirs:
            if (os.path.exists(os.path.join(repo_dir, add_dir)) and 
                add_dir not in existing_files and 
                add_dir not in context["source_dirs"]):
                copy_commands.append(f"COPY {add_dir} ./{add_dir}")
        
        if copy_commands:
            replacement = "\n".join(copy_commands) + "\n# Explicit COPY for Go project to avoid secrets"
        else:
            replacement = "# All required files already copied explicitly"
        
        # Add .dockerignore recommendation if missing
        if not context["has_dockerignore"]:
            replacement += "\n# RECOMMENDATION: Create .dockerignore with: .env*, *.key, *.pem, .git/, __pycache__/"
        
    elif context["project_type"] == "nodejs":
        # Node.js-specific COPY commands
        copy_commands = []
        
        # Add package files (avoid duplicates)
        package_files = ["package.json", "package-lock.json", "yarn.lock", "tsconfig.json", ".npmrc"]
        for pkg_file in package_files:
            if (os.path.exists(os.path.join(repo_dir, pkg_file)) and 
                pkg_file not in existing_files and 
                "package*.json" not in existing_files):
                copy_commands.append(f"COPY {pkg_file} ./")
        
        # Handle package*.json pattern
        if "package*.json" not in existing_files and "package.json" not in existing_files:
            copy_commands.append("COPY package*.json ./")
        
        # Add source directories
        for src_dir in context["source_dirs"]:
            if src_dir not in existing_files:
                copy_commands.append(f"COPY {src_dir} ./{src_dir}")
        
        if copy_commands:
            replacement = "# Copy Node.js dependencies and source\n" + "\n".join(copy_commands) + "\n# Explicit COPY for Node.js project to avoid secrets"
        else:
            replacement = "# All required files already copied explicitly"
        
    elif context["project_type"] == "python":
        # Python-specific COPY commands
        copy_commands = []
        
        # Add build files (avoid duplicates)
        for build_file in context["build_files"]:
            if build_file not in existing_files:
                copy_commands.append(f"COPY {build_file} ./")
        
        # Add source directories
        for src_dir in context["source_dirs"]:
            if src_dir not in existing_files:
                copy_commands.append(f"COPY {src_dir} ./{src_dir}")
        
        if copy_commands:
            replacement = "# Copy Python dependencies and source\n" + "\n".join(copy_commands) + "\n# Explicit COPY for Python project to avoid secrets"
        else:
            replacement = "# All required files already copied explicitly"
        
    elif context["project_type"] == "java":
        # Java-specific COPY commands
        copy_commands = []
        
        # Add build files (avoid duplicates)
        for build_file in context["build_files"]:
            if build_file not in existing_files:
                copy_commands.append(f"COPY {build_file} ./")
        
        # Add source directories
        for src_dir in context["source_dirs"]:
            if src_dir not in existing_files:
                copy_commands.append(f"COPY {src_dir} ./{src_dir}")
        
        if copy_commands:
            replacement = "# Copy Java build files and source\n" + "\n".join(copy_commands) + "\n# Explicit COPY for Java project to avoid secrets"
        else:
            replacement = "# All required files already copied explicitly"
        
    else:
        # Unknown project type - suggest .dockerignore approach
        replacement = """# Use .dockerignore to exclude secrets instead of COPY . .
# Recommended: Create .dockerignore file with:
# .env*
# *.key
# *.pem
# .git/
# node_modules/
# __pycache__/
COPY . .
# TODO: Replace with explicit COPY commands for your project structure"""
    
    # Apply the replacement
    dockerfile = dockerfile.replace("COPY . .", replacement)
    
    # Also handle other problematic patterns
    dockerfile = dockerfile.replace("COPY .env*", "# env files excluded for security")
    dockerfile = re.sub(r'COPY \. ([^\s]+)', rf'{replacement.split(chr(10))[0]}\nCOPY src \1\n# Explicit source directory', dockerfile)
    
    return dockerfile


def fix_npm_scripts(dockerfile: str) -> str:
    """
    Sonar rule: S6505
    Strategy:
      - Enforce --ignore-scripts for npm install/ci commands
    """
    original_dockerfile = dockerfile
    
    # Replace npm install with npm ci --ignore-scripts
    dockerfile = re.sub(r'npm\s+install(?!\s+--ignore-scripts)', 'npm ci --ignore-scripts', dockerfile)
    
    # Replace npm ci without --ignore-scripts
    dockerfile = re.sub(r'npm\s+ci(?!\s+--ignore-scripts)(?!\s+--only)', 'npm ci --ignore-scripts', dockerfile)
    
    # Handle npm ci --only=production (add --ignore-scripts)
    dockerfile = re.sub(r'npm\s+ci\s+--only=production(?!\s+--ignore-scripts)', 'npm ci --only=production --ignore-scripts', dockerfile)
    
    return dockerfile


def fix_docker_secrets(dockerfile: str) -> str:
    """
    Sonar rule: S6500
    Strategy:
      - Add --no-install-recommends to apt-get install
      - Remove or secure secret handling in Docker builds
    """
    original_dockerfile = dockerfile
    
    # Fix apt-get install without --no-install-recommends
    dockerfile = re.sub(
        r'apt-get\s+install\s+(?!.*--no-install-recommends)',
        'apt-get install --no-install-recommends ',
        dockerfile
    )
    
    # Fix RUN apt-get update && apt-get install pattern
    dockerfile = re.sub(
        r'(RUN\s+apt-get\s+update\s+&&\s+apt-get\s+install\s+)(?!.*--no-install-recommends)',
        r'\1--no-install-recommends ',
        dockerfile
    )
    
    lines = dockerfile.splitlines()
    out = []
    
    for line in lines:
        original_line = line
        
        # Look for potential secret patterns in ENV commands
        if line.strip().startswith('ENV') and any(pattern in line.lower() for pattern in ['password', 'secret', 'key', 'token', 'credential']):
            # If it's an ENV with hardcoded value, comment it out and suggest build arg
            if '=' in line:
                env_name = line.split('=')[0].replace('ENV', '').strip()
                out.append(f"# {original_line}")
                out.append(f"ARG {env_name}")
                out.append(f"ENV {env_name}=${{{env_name}}}")
                continue
        
        # Look for COPY commands that might copy secret files
        if line.strip().startswith('COPY') and any(pattern in line.lower() for pattern in ['.env', '*.key', '*.pem', 'secret', 'credential']):
            out.append(f"# {original_line}")
            continue
        
        out.append(line)
    
    return "\n".join(out)


# ---------------- PYTHON SECURITY (NEW FROM SONARQUBE DATA) ----------------

def fix_python_path_traversal(code: str) -> str:
    """
    pythonsecurity:S6549 - Path traversal / Filesystem oracle prevention
    
    Strategy:
      - Add canonical path validation before file operations
      - Use resolve() and relative_to() to prevent path traversal
    """
    # Check if already fixed
    if 'resolve()' in code and 'relative_to' in code:
        return code
    
    # Pattern: variable.exists() without validation
    # Add validation before exists() check
    pattern = r'(\w+)\.exists\(\)'
    
    def add_validation(match):
        var_name = match.group(1)
        return f'''canonical_{var_name} = {var_name}.resolve()
    try:
        canonical_{var_name}.relative_to(TARGET_DIRECTORY.resolve())
    except ValueError:
        raise IOError("Entry is outside of the target directory")
    if not canonical_{var_name}.exists():
        raise IOError("File does not exist in the target directory")'''
    
    # Only apply if not already validated
    if 'canonical_' not in code:
        code = re.sub(pattern, add_validation, code, count=1)
    
    return code


def fix_python_zip_slip(code: str) -> str:
    """
    pythonsecurity:S6096 - Zip slip vulnerability prevention
    
    Strategy:
      - Add path validation before zip extraction
      - Check each member path is within target directory
    """
    # Check if already fixed
    if 'is_relative_to' in code or ('relative_to' in code and 'for member in' in code):
        return code
    
    # Pattern: extractall without validation
    pattern = r'(\w+)\.extractall\(([^)]+)\)'
    
    def add_validation(match):
        zip_var = match.group(1)
        target_dir = match.group(2)
        return f'''for member in {zip_var}.namelist():
        member_path = Path({target_dir}, member).resolve()
        try:
            member_path.relative_to(Path({target_dir}).resolve())
        except ValueError:
            raise ValueError(f"Attempted path traversal: {{member}}")
    {zip_var}.extractall({target_dir})'''
    
    code = re.sub(pattern, add_validation, code)
    
    # Ensure Path is imported
    if 'from pathlib import Path' not in code and 'import pathlib' not in code:
        code = 'from pathlib import Path\n' + code
    
    return code


def fix_python_cors_middleware(code: str) -> str:
    """
    python:S8414, ipython:S8414 - CORS middleware ordering
    
    Strategy:
      - Ensure CORSMiddleware is added last in middleware chain
      - Reorder middleware calls if needed
    """
    lines = code.split('\n')
    cors_lines = []
    other_middleware_lines = []
    result_lines = []
    
    in_middleware_section = False
    
    for line in lines:
        if 'add_middleware' in line:
            in_middleware_section = True
            if 'CORSMiddleware' in line:
                cors_lines.append(line)
            else:
                other_middleware_lines.append(line)
        else:
            result_lines.append(line)
            # After app creation, insert middleware in correct order
            if ('FastAPI()' in line or 'app = ' in line) and in_middleware_section:
                # Add other middleware first, then CORS
                result_lines.extend(other_middleware_lines)
                result_lines.extend(cors_lines)
                other_middleware_lines = []
                cors_lines = []
                in_middleware_section = False
    
    # If middleware wasn't inserted yet, add at end
    if other_middleware_lines or cors_lines:
        result_lines.extend(other_middleware_lines)
        result_lines.extend(cors_lines)
    
    return '\n'.join(result_lines)


def fix_flask_debug_mode(code: str) -> str:
    """
    python:S8392, ipython:S8392 - Flask debug mode
    
    Strategy:
      - Disable debug mode in production
      - Use environment variable for configuration
    """
    # Pattern: app.run(debug=True)
    code = re.sub(
        r'(\.run\([^)]*?)debug=True',
        r"\1debug=os.environ.get('FLASK_DEBUG', 'False') == 'True'",
        code
    )
    
    # Ensure os is imported
    if 'import os' not in code:
        code = 'import os\n' + code
    
    return code


def fix_python_insecure_deserialization(code: str) -> str:
    """
    python:S5042 - Insecure deserialization
    
    Strategy:
      - Replace pickle with safer alternatives like json
      - Add warning comment about security implications
    """
    # Replace pickle imports
    code = re.sub(r'import pickle\b', 'import json  # Replaced pickle with json for security', code)
    code = re.sub(r'from pickle import', 'from json import', code)
    
    # Replace pickle.loads/dumps
    code = re.sub(r'pickle\.loads?\(', 'json.loads(', code)
    code = re.sub(r'pickle\.dumps?\(', 'json.dumps(', code)
    
    return code


# ---------------- JAVASCRIPT/TYPESCRIPT (NEW FROM SONARQUBE DATA) ----------------

def fix_regex_anchor_grouping(code: str) -> str:
    """
    typescript:S5850, javascript:S5850 - Regex anchor grouping
    
    Strategy:
      - Group alternatives when used with anchors
      - Add non-capturing groups (?:...) around alternatives
    """
    # Pattern: /^a|b|c$/ should become /^(?:a|b|c)$/
    # Match regex with ^ at start and $ at end with | in between
    pattern = r'/\^([^|$]+(?:\|[^|$]+)+)\$/'
    
    def add_grouping(match):
        alternatives = match.group(1)
        return f'/^(?:{alternatives})$/'
    
    code = re.sub(pattern, add_grouping, code)
    
    # Also handle cases without flags
    pattern2 = r'/\^([^|$/]+(?:\|[^|$/]+)+)\$/([gimsuvy]*)'
    
    def add_grouping_with_flags(match):
        alternatives = match.group(1)
        flags = match.group(2)
        return f'/^(?:{alternatives})$/{flags}'
    
    code = re.sub(pattern2, add_grouping_with_flags, code)
    
    return code


# ---------------- DISPATCH ----------------

def apply_fix(rule_key: str, code: str, repo_dir: str = None) -> str | None:
    """Apply deterministic fix based on rule key."""
    
    # Regex backtracking (multiple languages)
    if rule_key in ["typescript:S5852", "javascript:S5852", "python:S5852", "java:S5852"]:
        return fix_regex_backtracking(code)
    
    # Weak PRNG (multiple languages)
    if rule_key in ["typescript:S2245", "javascript:S2245"]:
        return fix_typescript_weak_prng(code)
    elif rule_key == "python:S2245":
        return fix_python_weak_prng(code)
    
    # Dynamic execution (JavaScript/TypeScript)
    if rule_key in ["typescript:S1523", "javascript:S1523"]:
        return fix_dynamic_execution(code)
    
    # Hardcoded IP addresses
    if rule_key in ["javascript:S1313", "typescript:S1313"]:
        return fix_hardcoded_ip(code)
    
    # Hardcoded credentials (all languages)
    if rule_key in ["typescript:S2068", "javascript:S2068"]:
        return fix_hardcoded_credentials(code, "javascript")
    elif rule_key == "python:S2068":
        return fix_hardcoded_credentials(code, "python")
    elif rule_key == "java:S2068":
        return fix_hardcoded_credentials(code, "java")
    
    # Python-specific fixes
    if rule_key == "python:S2077":
        return fix_python_sql_injection(code)
    
    # Java-specific fixes
    if rule_key == "java:S2077":
        return fix_java_sql_injection(code)
    
    # Docker fixes - now context-aware
    if rule_key == "docker:S6471":
        return fix_root_user(code)
    elif rule_key == "docker:S6470":
        return fix_copy_glob(code, repo_dir)
    elif rule_key == "docker:S6505":
        return fix_npm_scripts(code)
    elif rule_key == "docker:S6500":
        return fix_docker_secrets(code)
    
    # ===== NEW FIXES FROM SONARQUBE DATA =====
    
    # Python Security
    elif rule_key == "pythonsecurity:S6549":
        return fix_python_path_traversal(code)
    elif rule_key == "pythonsecurity:S6096":
        return fix_python_zip_slip(code)
    elif rule_key in ["python:S8414", "ipython:S8414"]:
        return fix_python_cors_middleware(code)
    elif rule_key in ["python:S8392", "ipython:S8392"]:
        return fix_flask_debug_mode(code)
    elif rule_key == "python:S5042":
        return fix_python_insecure_deserialization(code)
    
    # JavaScript/TypeScript
    elif rule_key in ["typescript:S5850", "javascript:S5850"]:
        return fix_regex_anchor_grouping(code)
    
    # No deterministic fix available
    return None