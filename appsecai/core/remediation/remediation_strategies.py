# strategies.py

from typing import Dict, Any

FIX_STRATEGIES: Dict[str, Dict[str, Any]] = {
    # ---------------- REGEX PERFORMANCE ----------------
    "typescript:S5852": {
        "type": "snippet_replace",
        "description": "Harden regex to avoid catastrophic backtracking",
        "constraints": [
            "Avoid unbounded repetitions like .* or \\s*",
            "Prefer explicit character classes",
            "Ensure linear-time regex",
            "Preserve original behavior",
        ],
    },

    # ---------------- DOCKER SECURITY ----------------
    "docker:S6471": {
        "type": "snippet_replace",
        "description": "Drop root user in runtime container",
        "constraints": [
            "Add non-root user",
            "Switch USER to non-root",
            "Do not break build",
        ],
    },

    "docker:S6470": {
        "type": "snippet_replace",
        "description": "Restrict COPY scope to avoid leaking secrets (context-aware)",
        "constraints": [
            "Analyze project type (Go, Node.js, Python, Java) before fixing",
            "Copy only required build files and source directories",
            "Preserve all directories needed for build process",
            "Consider using .dockerignore as alternative",
        ],
    },

    "docker:S6505": {
        "type": "snippet_replace",
        "description": "Prevent script execution during npm install",
        "constraints": [
            "Use --ignore-scripts where safe",
        ],
    },

    "docker:S6500": {
        "type": "snippet_replace",
        "description": "Secure secret handling in Docker builds",
        "constraints": [
            "Remove hardcoded secrets from Dockerfile",
            "Use build arguments for sensitive data",
            "Add .dockerignore for secret files",
            "Use Docker secrets for runtime secrets",
        ],
    },

    "python:S5852": {
        "type": "snippet_replace",
        "language": "python",
        "description": "Harden Python regex against catastrophic backtracking",
        "constraints": [
            "Avoid nested quantifiers",
            "Avoid unbounded .* or .+",
            "Use explicit character classes",
            "Prefer re.fullmatch or re.match when possible",
            "Preserve functional behavior",
        ],
    },

    "python:S2245": {
        "type": "snippet_replace",
        "language": "python",
        "description": "Replace weak PRNG with cryptographically secure generator",
        "constraints": [
            "Use secrets or os.urandom",
            "Preserve API behavior",
        ],
    },

    # ---------------- JAVASCRIPT/TYPESCRIPT SECURITY ----------------
    "typescript:S2245": {
        "type": "snippet_replace",
        "description": "Replace weak PRNG with cryptographically secure generator",
        "constraints": [
            "Use crypto.getRandomValues() instead of Math.random()",
            "Preserve API behavior and range",
            "Add security comment",
        ],
    },

    "javascript:S2245": {
        "type": "snippet_replace",
        "description": "Replace weak PRNG with cryptographically secure generator",
        "constraints": [
            "Use crypto.getRandomValues() instead of Math.random()",
            "Preserve API behavior and range",
            "Add security comment",
        ],
    },

    "javascript:S5852": {
        "type": "snippet_replace",
        "description": "Harden JavaScript regex against catastrophic backtracking",
        "constraints": [
            "Avoid nested quantifiers",
            "Replace .* with [^\\n]* for single-line matching",
            "Replace \\s* with [ \\t]* for whitespace",
            "Preserve functional behavior",
        ],
    },

    "typescript:S2068": {
        "type": "snippet_replace",
        "description": "Remove hardcoded credentials",
        "constraints": [
            "Replace hardcoded passwords with environment variables",
            "Use process.env.PASSWORD or similar",
            "Add TODO comment for configuration",
        ],
    },

    "javascript:S2068": {
        "type": "snippet_replace",
        "description": "Remove hardcoded credentials",
        "constraints": [
            "Replace hardcoded passwords with environment variables",
            "Use process.env.PASSWORD or similar",
            "Add TODO comment for configuration",
        ],
    },

    "typescript:S1523": {
        "type": "snippet_replace",
        "description": "Remove dynamic code execution",
        "constraints": [
            "Replace eval() with safer alternatives",
            "Use JSON.parse() for data",
            "Disable Function constructor",
            "Add security comment",
        ],
    },

    "javascript:S1523": {
        "type": "snippet_replace",
        "description": "Remove dynamic code execution",
        "constraints": [
            "Replace eval() with safer alternatives",
            "Use JSON.parse() for data",
            "Disable Function constructor",
            "Add security comment",
        ],
    },

    "typescript:S1313": {
        "type": "snippet_replace",
        "description": "Remove hardcoded IP addresses",
        "constraints": [
            "Replace with environment variables",
            "Use configuration files",
            "Add TODO for configuration",
        ],
    },

    "javascript:S1313": {
        "type": "snippet_replace",
        "description": "Remove hardcoded IP addresses",
        "constraints": [
            "Replace with environment variables",
            "Use configuration files",
            "Add TODO for configuration",
        ],
    },

    # ---------------- PYTHON SECURITY ----------------
    "python:S2068": {
        "type": "snippet_replace",
        "language": "python",
        "description": "Remove hardcoded credentials",
        "constraints": [
            "Replace hardcoded passwords with os.environ.get()",
            "Use environment variables or config files",
            "Add TODO comment for configuration",
        ],
    },

    "python:S2077": {
        "type": "snippet_replace",
        "language": "python",
        "description": "Fix SQL injection vulnerability",
        "constraints": [
            "Use parameterized queries",
            "Avoid string formatting in SQL",
            "Use ORM or prepared statements",
        ],
    },

    # ---------------- JAVA SECURITY ----------------
    "java:S5852": {
        "type": "snippet_replace",
        "language": "java",
        "description": "Harden Java regex against catastrophic backtracking",
        "constraints": [
            "Avoid nested quantifiers",
            "Use Pattern.compile with flags if needed",
            "Prefer bounded repetitions",
            "Preserve functional behavior",
        ],
    },

    "java:S2068": {
        "type": "snippet_replace",
        "language": "java",
        "description": "Remove hardcoded credentials",
        "constraints": [
            "Replace hardcoded passwords with System.getenv()",
            "Use configuration properties",
            "Add TODO comment for configuration",
        ],
    },

    "java:S2077": {
        "type": "snippet_replace",
        "language": "java",
        "description": "Fix SQL injection vulnerability",
        "constraints": [
            "Use PreparedStatement with parameters",
            "Avoid string concatenation in SQL",
            "Validate and sanitize inputs",
        ],
    },



    # ---------------- DEFAULT ----------------
    "__default__": {
        "type": "snippet_replace",  # Changed from manual_review to attempt AI fix
        "description": "Generic security fix using AI",
        "constraints": [
            "Fix the security vulnerability described in the issue",
            "Preserve existing functionality",
            "Follow language best practices",
            "Add security comment if needed",
        ],
    },

}


def get_strategy(rule_key: str) -> Dict[str, Any]:
    return FIX_STRATEGIES.get(rule_key, FIX_STRATEGIES["__default__"])