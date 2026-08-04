"""
Mock SAST Analyzer - Fallback scanner when SonarQube is unavailable.
Performs basic static analysis by scanning Python, JS, TS, and Java source files
for common security anti-patterns using regex-based rules.
"""

import os
import re
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class MockSASTAnalyzer:
    """
    Lightweight regex-based SAST analyzer used as a fallback when SonarQube
    is not reachable. Detects common security vulnerabilities in source code.
    """

    # Security rules: (rule_key, description, severity, pattern)
    RULES = [
        ("mock:S001", "Hardcoded password detected", "High",
         re.compile(r'password\s*=\s*["\'][^"\']{3,}["\']', re.IGNORECASE)),
        ("mock:S002", "Hardcoded secret or token detected", "High",
         re.compile(r'(secret|api_key|token)\s*=\s*["\'][^"\']{8,}["\']', re.IGNORECASE)),
        ("mock:S003", "Use of eval() - code injection risk", "Critical",
         re.compile(r'\beval\s*\(', re.IGNORECASE)),
        ("mock:S004", "SQL query built with string concatenation", "High",
         re.compile(r'(execute|query)\s*\(\s*["\'].*\+', re.IGNORECASE)),
        ("mock:S005", "Insecure use of subprocess with shell=True", "High",
         re.compile(r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True', re.IGNORECASE)),
        ("mock:S006", "Insecure random number generation", "Medium",
         re.compile(r'\brandom\.(random|randint|choice)\b', re.IGNORECASE)),
        ("mock:S007", "Use of MD5 hashing (weak)", "Medium",
         re.compile(r'hashlib\.md5\b', re.IGNORECASE)),
        ("mock:S008", "Use of SHA1 hashing (weak)", "Medium",
         re.compile(r'hashlib\.sha1\b', re.IGNORECASE)),
        ("mock:S009", "Broad exception catch (Exception)", "Low",
         re.compile(r'except\s+Exception\s*:', re.IGNORECASE)),
        ("mock:S010", "Debugger statement in code", "Medium",
         re.compile(r'\bdebugger\b|import\s+pdb|pdb\.set_trace\(\)', re.IGNORECASE)),
        ("mock:S011", "TODO / FIXME security comment", "Low",
         re.compile(r'#\s*(TODO|FIXME|HACK)\s*:?\s*(security|auth|vuln)', re.IGNORECASE)),
        ("mock:S012", "Insecure deserialization (pickle)", "Critical",
         re.compile(r'pickle\.(load|loads)\s*\(', re.IGNORECASE)),
        ("mock:S013", "Potential path traversal", "High",
         re.compile(r'open\s*\([^)]*\.\./[^)]*\)', re.IGNORECASE)),
        ("mock:S014", "HTTP instead of HTTPS URL", "Low",
         re.compile(r'http://(?!localhost|127\.0\.0\.1)', re.IGNORECASE)),
        ("mock:S015", "assert used for security check", "Medium",
         re.compile(r'\bassert\b.*(auth|permission|admin|role)', re.IGNORECASE)),
    ]

    SUPPORTED_EXTENSIONS = {'.py', '.js', '.ts', '.java', '.go', '.rb', '.php'}

    def scan_repository(self, target_dir: str) -> List[Dict[str, Any]]:
        """
        Scan a directory for security vulnerabilities.

        Args:
            target_dir: Path to the directory to scan

        Returns:
            List of vulnerability dictionaries
        """
        vulnerabilities = []
        scanned_files = 0

        if not os.path.isdir(target_dir):
            logger.warning(f"Target directory does not exist: {target_dir}")
            return vulnerabilities

        for root, dirs, files in os.walk(target_dir):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if d not in {
                '.git', 'node_modules', '__pycache__', '.venv', 'venv',
                'dist', 'build', '.tox', 'vendor', 'target'
            }]

            for filename in files:
                ext = os.path.splitext(filename)[1].lower()
                if ext not in self.SUPPORTED_EXTENSIONS:
                    continue

                filepath = os.path.join(root, filename)
                file_vulns = self._scan_file(filepath)
                vulnerabilities.extend(file_vulns)
                scanned_files += 1

        logger.info(f"Mock SAST: Scanned {scanned_files} files, found {len(vulnerabilities)} issues.")
        return vulnerabilities

    def _scan_file(self, filepath: str) -> List[Dict[str, Any]]:
        """Scan a single file against all security rules."""
        findings = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            logger.debug(f"Could not read {filepath}: {e}")
            return findings

        for line_num, line in enumerate(lines, start=1):
            for rule_key, description, severity, pattern in self.RULES:
                if pattern.search(line):
                    rel_path = filepath.replace('\\', '/')
                    findings.append({
                        'id': f"mock_{rule_key}_{line_num}",
                        'type': 'sast',
                        'severity': severity,
                        'title': description,
                        'description': description,
                        'file_path': rel_path,
                        'line_number': line_num,
                        'rule_key': rule_key,
                        'component': rel_path,
                        'message': f"{description} at line {line_num}: {line.strip()[:120]}",
                        'risk_score': self._severity_to_score(severity),
                    })

        return findings

    @staticmethod
    def _severity_to_score(severity: str) -> float:
        return {'Critical': 9.0, 'High': 7.5, 'Medium': 5.0, 'Low': 2.5}.get(severity, 2.5)
