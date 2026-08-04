"""
Configuration Management for CazeAppSecAI CLI

Handles loading, merging, and validation of configuration from multiple sources:
- YAML configuration files
- Environment variables  
- Command-line arguments
"""

import os
import sys
import yaml
import logging
import json
from typing import Dict, Any, Tuple, List, Optional
from appsecai.common.utils import get_resource_path, load_appsec_json_data

logger = logging.getLogger(__name__)


class ConfigManager:
    """Centralized configuration management with multi-source support."""
    
    def __init__(self, config_file: Optional[str] = None, force_json_priority: bool = False):
        """
        Initialize configuration manager.
        
        Args:
            config_file: Path to YAML configuration file
            force_json_priority: If True, appsec_config.json overrides everything (Source of Truth)
        """
        if config_file and not os.path.isabs(config_file) and not os.path.exists(config_file):
            candidate = get_resource_path(config_file)
            if os.path.exists(candidate):
                config_file = candidate

        self.config_file = config_file or get_resource_path("appsecai/risk_profiles/app_config.yaml")
        self.force_json_priority = force_json_priority
        
        # Determine the correct directory for appsec_config.json
        import sys
        if getattr(sys, 'frozen', False):
            # If running as PyInstaller .exe, write next to the executable
            base_dir = os.path.dirname(sys.executable)
        else:
            # Otherwise write to the current working directory
            base_dir = os.getcwd()
            
        self.appsec_json_file = os.path.join(base_dir, "appsec_config.json")
        self.config = self._load_config()
        
    def reload(self) -> Dict[str, Any]:
        """
        Reload configuration from all sources (disk and env).
        Ensures appsec_config.json is re-parsed.
        """
        self.config = self._load_config()
        return self.config
        
    def _load_config(self) -> Dict[str, Any]:
        """
        Load and merge configuration from multiple sources.
        
        Priority order (if NOT force_json_priority):
        1. Actual Environment Variables (Active Wizard Session)
        2. appsec_config.json 
        3. .env file
        4. appsecai/risk_profiles/app_config.yaml
        
        Priority order (if force_json_priority):
        1. appsec_config.json (Absolute Source of Truth)
        2. Actual Environment Variables
        3. .env file
        4. appsecai/risk_profiles/app_config.yaml
        """
        # Start with default configuration
        config = self._get_default_config()
        
        # 4. appsecai/risk_profiles/app_config.yaml (System Defaults)
        if os.path.exists(self.config_file):
            try:
                yaml_config = self._load_yaml_config(self.config_file)
                config = self._merge_configs(config, yaml_config)
            except Exception: pass

        # 3. .env file (Lowest priority override)
        saved_session = self._load_dotenv_file()
        for key, val in saved_session.items():
            if key not in os.environ:
                os.environ[key] = val

        # Handle the two different priority modes
        if self.force_json_priority:
            # MODE: JSON IS SOURCE OF TRUTH
            # Load environment first
            env_config = self._load_env_config()
            config = self._merge_configs(config, env_config)
            
            # Load JSON last (overwrites everything)
            if os.path.exists(self.appsec_json_file):
                appsec_config = self._load_appsec_json_config(force_env_update=True)
                config = self._merge_configs(config, appsec_config)
        else:
            # MODE: INTERACTIVE SESSION IS SOURCE OF TRUTH
            # Load JSON first
            if os.path.exists(self.appsec_json_file):
                appsec_config = self._load_appsec_json_config(force_env_update=False)
                config = self._merge_configs(config, appsec_config)
            
            # Load environment last (overwrites JSON with memory session)
            env_config = self._load_env_config()
            config = self._merge_configs(config, env_config)
        
        return config
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration values."""
        return {
            "output_dir": "AppSecAI_output",
            "log_level": "INFO",
            "max_concurrent_scans": 3,
            
            # Security tools configuration
            "security_tools": {
                "sonarqube": {
                    "enabled": True,
                    "url": "http://localhost:9000",
                    "username": "",
                    "password": "",
                    "project_key": ""
                },
                "zap": {
                    "enabled": True,
                    "installation_path": "",
                    "scan_policy": "Default Policy",
                    "max_scan_time": 3600,
                    "spider_max_depth": 5
                }
            },
            
            # DAST Authentication settings
            "dast_auth": {
                "enabled": False,
                "method": "browser",
                "username": "",
                "password": "",
                "login_page_url": "",
                "login_request_url": "",
                "login_request_body": "",
                "browser_id": "firefox",
                "logged_in_regex": "",
                "logged_out_regex": ""
            },
            
            # DAST API specification scan settings
            "dast_api": {
                "enabled": False,
                "spec_url": "",
                "spec_type": "openapi"
            },
            
            # AI/LLM configuration
            "llm": {
                "model": "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B",
                "url": "http://4.247.140.236:11434",
                "timeout": 300,
                "max_retries": 3,
                "batch_size": 10
            },
            
            # GitHub integration
            "github": {
                "token": "",
                "repo": "",
                "repositories": [], # List of {repo: "owner/repo", branch: "main"}
                "base_branch": "main",
                "pr_title_prefix": "AI Security Fixes",
                "create_issues": True,
                "issue_labels": ["security", "ai-fix"],
                "link_issues_to_pr": True,
                "commit_batch_size": 10,
                "pr_batch_size": 10
            },
            
            # Enhanced vulnerability scoring framework
            "vulnerability_scoring": {
                "threshold_score": 5,
                "framework_file": "appsecai/risk_profiles/context_modifiers/vulnerability_framework.json",
                "compliance_file": "appsecai/risk_profiles/context_modifiers/risk_context_template.json"
            },
            
            # Reporting configuration
            "reporting": {
                "formats": ["html", "csv", "json"],
                "include_executive_summary": True,
                "template_dir": "./templates"
            },
            
            # CI/CD integration
            "ci_cd": {
                "fail_on_threshold": True,
                "webhook_url": "",
                "cache_results": True,
                "cache_duration_hours": 24
            }
        }
    
    def _load_yaml_config(self, config_file: str) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in {config_file}: {e}")
        except Exception as e:
            raise ValueError(f"Could not read {config_file}: {e}")
            
    def _load_appsec_json_config(self, force_env_update: bool = False) -> Dict[str, Any]:
        """Load configuration from appsec_config.json and map to config schema."""
        try:
            data = load_appsec_json_data(self.appsec_json_file)
                
            config_override = {}
            
            # Map values from appsec_config.json to our internal config schema
            if "github_token" in data and data["github_token"]:
                self._set_nested_config(config_override, ("github", "token"), data["github_token"])
                if force_env_update or 'GITHUB_TOKEN' not in os.environ:
                    os.environ['GITHUB_TOKEN'] = data["github_token"]
            if "github_repo" in data and data["github_repo"]:
                self._set_nested_config(config_override, ("github", "repo"), data["github_repo"])
                if force_env_update or 'GITHUB_REPO' not in os.environ:
                    os.environ['GITHUB_REPO'] = data["github_repo"]
            if "github_branch" in data and data["github_branch"]:
                self._set_nested_config(config_override, ("github", "base_branch"), data["github_branch"])
                if force_env_update or 'GITHUB_BASE_BRANCH' not in os.environ:
                    os.environ['GITHUB_BASE_BRANCH'] = data["github_branch"]
            if "github_repositories" in data and data["github_repositories"]:
                self._set_nested_config(config_override, ("github", "repositories"), data["github_repositories"])
                if force_env_update or 'GITHUB_REPOSITORIES' not in os.environ:
                    os.environ['GITHUB_REPOSITORIES'] = data["github_repositories"]
                
            if "sonar_url" in data and data["sonar_url"]:
                self._set_nested_config(config_override, ("security_tools", "sonarqube", "url"), data["sonar_url"])
                if force_env_update or 'SONAR_URL' not in os.environ:
                    os.environ['SONAR_URL'] = data["sonar_url"]
            if "sonar_username" in data and data["sonar_username"]:
                self._set_nested_config(config_override, ("security_tools", "sonarqube", "username"), data["sonar_username"])
                if force_env_update or 'SONAR_USERNAME' not in os.environ:
                    os.environ['SONAR_USERNAME'] = data["sonar_username"]
            if "sonar_password" in data and data["sonar_password"]:
                self._set_nested_config(config_override, ("security_tools", "sonarqube", "password"), data["sonar_password"])
                if force_env_update or 'SONAR_PASSWORD' not in os.environ:
                    os.environ['SONAR_PASSWORD'] = data["sonar_password"]
            if "sonar_project_key" in data and data["sonar_project_key"]:
                self._set_nested_config(config_override, ("security_tools", "sonarqube", "project_key"), data["sonar_project_key"])
                if force_env_update or 'SONAR_PROJECT_KEY' not in os.environ:
                    os.environ['SONAR_PROJECT_KEY'] = data["sonar_project_key"]
            if "sonar_auto_setup" in data:
                self._set_nested_config(config_override, ("security_tools", "sonarqube", "auto_setup"), data["sonar_auto_setup"])
                if force_env_update or 'SONAR_AUTO_SETUP' not in os.environ:
                    os.environ['SONAR_AUTO_SETUP'] = str(data["sonar_auto_setup"]).lower()
                
            if "dast_url" in data and data["dast_url"]:
                self._set_nested_config(config_override, ("security_tools", "zap", "target_url"), data["dast_url"])
                if force_env_update or 'DAST_URL' not in os.environ:
                    os.environ['DAST_URL'] = data["dast_url"]
            if "zap_report_path" in data and data["zap_report_path"]:
                if force_env_update or 'ZAP_REPORT_PATH' not in os.environ:
                    os.environ['ZAP_REPORT_PATH'] = data["zap_report_path"]
            if "dast_urls" in data and data["dast_urls"]:
                if force_env_update or 'DAST_URLS' not in os.environ:
                    os.environ['DAST_URLS'] = json.dumps(data["dast_urls"])

            if "llm_url" in data and data["llm_url"]:
                self._set_nested_config(config_override, ("llm", "url"), data["llm_url"])
                if force_env_update or 'LLM_URL' not in os.environ:
                    os.environ['LLM_URL'] = data["llm_url"]
            if "llm_model" in data and data["llm_model"]:
                self._set_nested_config(config_override, ("llm", "model"), data["llm_model"])
                if force_env_update or 'LLM_MODEL' not in os.environ:
                    os.environ['LLM_MODEL'] = data["llm_model"]
            if "llm_timeout" in data:
                self._set_nested_config(config_override, ("llm", "timeout"), data["llm_timeout"])
                if force_env_update or 'LLM_TIMEOUT' not in os.environ:
                    os.environ['LLM_TIMEOUT'] = str(data["llm_timeout"])
            if "output_dir" in data and data["output_dir"]:
                self._set_nested_config(config_override, ("output_dir",), data["output_dir"])
                if force_env_update or 'OUTPUT_DIR' not in os.environ:
                    os.environ['OUTPUT_DIR'] = data["output_dir"]
            if "ai_batch_size" in data:
                if force_env_update or 'AI_BATCH_SIZE' not in os.environ:
                    os.environ['AI_BATCH_SIZE'] = str(data["ai_batch_size"])
            if "pr_batch_size" in data:
                if force_env_update or 'PR_BATCH_SIZE' not in os.environ:
                    os.environ['PR_BATCH_SIZE'] = str(data["pr_batch_size"])
            if "commit_batch_size" in data:
                if force_env_update or 'COMMIT_BATCH_SIZE' not in os.environ:
                    os.environ['COMMIT_BATCH_SIZE'] = str(data["commit_batch_size"])
                
            if "sca_target_type" in data and data["sca_target_type"]:
                if force_env_update or 'TRIVY_TARGET_TYPE' not in os.environ:
                    os.environ['TRIVY_TARGET_TYPE'] = data["sca_target_type"]
                
            if "sca_target_path" in data and data["sca_target_path"]:
                self._set_nested_config(config_override, ("sca", "target"), data["sca_target_path"])
                if force_env_update or 'TRIVY_TARGET' not in os.environ:
                    os.environ['TRIVY_TARGET'] = data["sca_target_path"]
                
            if "vulnerability_threshold" in data:
                self._set_nested_config(config_override, ("vulnerability_scoring", "threshold_score"), data["vulnerability_threshold"])
                if force_env_update or 'VULNERABILITY_THRESHOLD' not in os.environ:
                    os.environ['VULNERABILITY_THRESHOLD'] = str(data["vulnerability_threshold"])
                
            # DAST Auth Parsing
            if "dast_auth" in data and isinstance(data["dast_auth"], dict):
                auth_data = data["dast_auth"]
                key_map = {
                    "enabled": "DAST_USE_AUTH",
                    "method": "DAST_AUTH_METHOD",
                    "username": "DAST_AUTH_USERNAME",
                    "password": "DAST_AUTH_PASSWORD",
                    "login_page_url": "DAST_AUTH_LOGIN_URL",
                    "login_request_url": "DAST_AUTH_REQUEST_URL",
                    "login_request_body": "DAST_AUTH_REQUEST_BODY",
                    "browser_id": "DAST_AUTH_BROWSER_ID",
                    "logged_in_regex": "DAST_AUTH_LOGGED_IN_REGEX",
                    "logged_out_regex": "DAST_AUTH_LOGGED_OUT_REGEX"
                }
                for k, env_key in key_map.items():
                    if k in auth_data:
                        self._set_nested_config(config_override, ("dast_auth", k), auth_data[k])
                        if force_env_update or env_key not in os.environ:
                            os.environ[env_key] = str(auth_data[k]).lower() if isinstance(auth_data[k], bool) else str(auth_data[k])

            # DAST API Parsing
            if "dast_api" in data and isinstance(data["dast_api"], dict):
                api_data = data["dast_api"]
                key_map = {
                    "enabled": "DAST_USE_API",
                    "spec_url": "DAST_API_SPEC_URL",
                    "spec_type": "DAST_API_SPEC_TYPE"
                }
                for k, env_key in key_map.items():
                    if k in api_data:
                        self._set_nested_config(config_override, ("dast_api", k), api_data[k])
                        if force_env_update or env_key not in os.environ:
                            os.environ[env_key] = str(api_data[k]).lower() if isinstance(api_data[k], bool) else str(api_data[k])

            return config_override
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {self.appsec_json_file}: {e}")
            return {}
        except Exception as e:
            logger.error(f"Could not read {self.appsec_json_file}: {e}")
            return {}
    
    def _load_env_config(self) -> Dict[str, Any]:
        """Load configuration from active environment variables ONLY (not .env file)."""
        env_config = {}
        
        # Map environment variables to config paths
        env_mappings = {
            # SonarQube
            "SONAR_URL": ("security_tools", "sonarqube", "url"),
            "SONAR_USERNAME": ("security_tools", "sonarqube", "username"),
            "SONAR_PASSWORD": ("security_tools", "sonarqube", "password"),
            "SONAR_PROJECT_KEY": ("security_tools", "sonarqube", "project_key"),
            "SONAR_AUTO_SETUP": ("security_tools", "sonarqube", "auto_setup"),
            
            # ZAP
            "ZAP_INSTALLATION_PATH": ("security_tools", "zap", "installation_path"),
            "ZAP_MAX_SCAN_TIME": ("security_tools", "zap", "max_scan_time"),
            
            # LLM
            "LLM_MODEL": ("llm", "model"),
            "LLM_URL": ("llm", "url"),
            "LLM_TIMEOUT": ("llm", "timeout"),
            
            # GitHub
            "GITHUB_TOKEN": ("github", "token"),
            "GITHUB_REPO": ("github", "repo"),
            "GITHUB_REPOSITORIES": ("github", "repositories"),
            "GITHUB_BASE_BRANCH": ("github", "base_branch"),
            
            # General
            "OUTPUT_DIR": ("output_dir",),
            "LOG_LEVEL": ("log_level",),
            "VULNERABILITY_THRESHOLD": ("vulnerability_scoring", "threshold_score"),

            # DAST Auth Mapping
            "DAST_USE_AUTH": ("dast_auth", "enabled"),
            "DAST_AUTH_METHOD": ("dast_auth", "method"),
            "DAST_AUTH_USERNAME": ("dast_auth", "username"),
            "DAST_AUTH_PASSWORD": ("dast_auth", "password"),
            "DAST_AUTH_LOGIN_URL": ("dast_auth", "login_page_url"),
            "DAST_AUTH_REQUEST_URL": ("dast_auth", "login_request_url"),
            "DAST_AUTH_REQUEST_BODY": ("dast_auth", "login_request_body"),
            "DAST_AUTH_BROWSER_ID": ("dast_auth", "browser_id"),
            "DAST_AUTH_LOGGED_IN_REGEX": ("dast_auth", "logged_in_regex"),
            "DAST_AUTH_LOGGED_OUT_REGEX": ("dast_auth", "logged_out_regex"),

            # DAST API Mapping
            "DAST_USE_API": ("dast_api", "enabled"),
            "DAST_API_SPEC_URL": ("dast_api", "spec_url"),
            "DAST_API_SPEC_TYPE": ("dast_api", "spec_type")
        }
        
        for env_var, config_path in env_mappings.items():
            value = os.getenv(env_var)
            if value is not None:
                # Special handling for GITHUB_REPOSITORIES list
                if env_var == "GITHUB_REPOSITORIES" and isinstance(value, str):
                    try:
                        # Expected format: repo1|branch1|project_key;repo2|branch2|project_key
                        repos = []
                        for item in value.split(';'):
                            if not item.strip(): continue
                            parts = [p.strip() for p in item.split('|')]
                            repo_info = {"repo": parts[0], "branch": "main", "project_key": ""}
                            if len(parts) > 1:
                                repo_info["branch"] = parts[1]
                            if len(parts) > 2:
                                repo_info["project_key"] = parts[2]
                            repos.append(repo_info)
                        value = repos
                    except Exception as e:
                        logger.warning(f"Failed to parse GITHUB_REPOSITORIES: {e}")
                        continue

                # Convert string values to appropriate types
                if env_var in ["ZAP_MAX_SCAN_TIME", "LLM_TIMEOUT", "VULNERABILITY_THRESHOLD"]:
                    try:
                        value = int(value)
                    except (ValueError, TypeError):
                        logger.debug(f"Invalid integer value for {env_var}: {value}")
                
                if env_var in ["DAST_USE_AUTH", "DAST_USE_API"]:
                    value = str(value).lower() in ["true", "1", "yes"]

                # Set nested configuration value
                self._set_nested_config(env_config, config_path, value)
        
        return env_config
    
    def _set_nested_config(self, config: Dict[str, Any], path: Tuple[str, ...], value: Any):
        """Set a nested configuration value."""
        current = config
        for key in path[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        current[path[-1]] = value
    
    def _merge_configs(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recursively merge two configuration dictionaries.
        
        Args:
            base: Base configuration
            override: Configuration to merge in (takes precedence)
            
        Returns:
            Merged configuration
        """
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
                
        return result
    
    def validate_config(self, scan_type: Optional[str] = None) -> Tuple[bool, List[str]]:
        """
        Validate the current configuration.
        
        Args:
            scan_type: Type of scan ('sast', 'dast', 'both', or None for full validation)
        
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Validate base required fields (depends on scan type)
        # For SCA (Trivy) analysis we don't require LLM configuration,
        # only an output directory and the scoring framework files.
        if scan_type == 'sca':
            base_required_fields = [
                ("output_dir",),
            ]
        else:
            base_required_fields = [
                ("output_dir",),
                ("llm", "url"),
                ("llm", "model")
            ]
        
        for field_path in base_required_fields:
            if not self._get_nested_value(self.config, field_path):
                field_name = ".".join(field_path)
                errors.append(f"Missing required configuration: {field_name}")
        
        # Conditionally validate SonarQube configuration (only for SAST scans)
        if scan_type in ['sast', 'both', None]:  # None means validate everything
            if self.config.get("security_tools", {}).get("sonarqube", {}).get("enabled", False):
                sonar_config = self.config["security_tools"]["sonarqube"]
                if not sonar_config.get("username") or not sonar_config.get("password"):
                    errors.append("SonarQube is enabled but missing username/password")
                if not sonar_config.get("project_key"):
                    errors.append("SonarQube is enabled but missing project_key")
        
        # Validate GitHub configuration if token is provided (primarily for SAST bounds)
        if scan_type in ['sast', 'both', None]:
            github_token = self.config.get("github", {}).get("token")
            if github_token and not self.config.get("github", {}).get("repo"):
                errors.append("GitHub token provided but missing repository configuration")
        
        # Validate output directory
        output_dir = self.config.get("output_dir")
        if output_dir:
            try:
                os.makedirs(output_dir, exist_ok=True)
            except Exception as e:
                errors.append(f"Cannot create output directory {output_dir}: {e}")
        
        # Validate enhanced vulnerability scoring framework files
        framework_rel = "appsecai/risk_profiles/context_modifiers/vulnerability_framework.json"
        compliance_rel = "appsecai/risk_profiles/context_modifiers/risk_context_template.json"
        framework_file = get_resource_path(framework_rel)
        compliance_file = get_resource_path(compliance_rel)
        
        if not os.path.exists(framework_file):
            errors.append(f"Enhanced vulnerability framework not found: {framework_rel}")
        
        if not os.path.exists(compliance_file):
            errors.append(f"Enhanced compliance configuration not found: {compliance_rel}")
        
        # Legacy vul.json is no longer required (enhanced framework is primary)
        
        return len(errors) == 0, errors
    
    def _get_nested_value(self, config: Dict[str, Any], path: Tuple[str, ...]) -> Any:
        """Get a nested configuration value."""
        current = config
        for key in path:
            if not isinstance(current, dict) or key not in current:
                return None
            current = current[key]
        return current
    
    def get_scanner_config(self, scanner_type: str) -> Dict[str, Any]:
        """
        Get configuration for a specific scanner.
        
        Args:
            scanner_type: Type of scanner ('sonarqube' or 'zap')
            
        Returns:
            Scanner-specific configuration
        """
        return self.config.get("security_tools", {}).get(scanner_type, {})
    
    def get_github_config(self) -> Dict[str, Any]:
        """Get GitHub integration configuration."""
        return self.config.get("github", {})
    
    def get_llm_config(self) -> Dict[str, Any]:
        """Get LLM service configuration."""
        return self.config.get("llm", {})
    
    def get_reporting_config(self) -> Dict[str, Any]:
        """Get reporting configuration."""
        return self.config.get("reporting", {})
    
    def save_config(self, config_file: Optional[str] = None) -> bool:
        """
        Save current configuration to YAML file.
        
        Args:
            config_file: Path to save configuration (defaults to current config file)
            
        Returns:
            True if successful, False otherwise
        """
        target_file = config_file or self.config_file
        
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(target_file) or ".", exist_ok=True)
            
            with open(target_file, 'w', encoding='utf-8') as f:
                yaml.dump(self.config, f, default_flow_style=False, indent=2)
            
            logger.info(f"Configuration saved to {target_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save configuration to {target_file}: {e}")
            return False
    
    def create_template_config(self, config_file: str) -> bool:
        """
        Create a template configuration file with comments.
        
        Args:
            config_file: Path to create template file
            
        Returns:
            True if successful, False otherwise
        """
        template_content = """# Caze AppSecAI CLI Configuration Template
# Copy this file to appsecai/risk_profiles/app_config.yaml and customize for your environment

# Output directory for scan results and reports
output_dir: "AppSecAI_output"

# Logging level (DEBUG, INFO, WARNING, ERROR)
log_level: "INFO"

# Maximum number of concurrent scans
max_concurrent_scans: 3

# Security scanning tools configuration
security_tools:
  # SonarQube SAST configuration
  sonarqube:
    enabled: true
    url: "http://localhost:9000"
    username: "admin"  # Or use SONAR_USERNAME environment variable
    password: "admin"  # Or use SONAR_PASSWORD environment variable
    project_key: "my-project"  # Or use SONAR_PROJECT_KEY environment variable
    
  # OWASP ZAP DAST configuration  
  zap:
    enabled: true
    installation_path: ""  # Auto-detect if empty
    scan_policy: "Default Policy"
    max_scan_time: 3600  # seconds
    spider_max_depth: 5

# AI/LLM configuration for vulnerability remediation
llm:
  model: "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B"
  url: "http://4.247.140.236:11434"  # Ollama endpoint
  timeout: 300  # seconds
  max_retries: 3
  batch_size: 10

# GitHub integration for automated PR creation
github:
  token: ""  # Use GITHUB_TOKEN environment variable
  repo: "owner/repository-name"  # Or use GITHUB_REPO environment variable
  base_branch: "main"
  pr_title_prefix: "AI Security Fixes"
  create_issues: true
  issue_labels: ["security", "ai-fix"]
  link_issues_to_pr: true
  commit_batch_size: 10
  pr_batch_size: 10

# Enhanced vulnerability scoring configuration
vulnerability_scoring:
  threshold_score: 7
  framework_file: "appsecai/risk_profiles/context_modifiers/vulnerability_framework.json"
  compliance_file: "appsecai/risk_profiles/context_modifiers/risk_context_template.json"

# Report generation settings
reporting:
  formats: ["html", "csv", "json"]
  include_executive_summary: true
  template_dir: "./templates"

# CI/CD integration settings
ci_cd:
  fail_on_threshold: true  # Exit with error code if vulnerabilities exceed threshold
  webhook_url: ""  # Optional webhook for notifications
  cache_results: true
  cache_duration_hours: 24
"""
        
        try:
            with open(config_file, 'w', encoding='utf-8') as f:
                f.write(template_content)
            
            print(f"✅ Configuration template created: {config_file}")
            print("💡 Edit the file with your specific settings before running scans")
            return True
            
        except Exception as e:
            print(f"❌ Failed to create template: {e}")
            return False
            
    def generate_default_appsec_json(self) -> bool:
        """Create the default appsec_config.json template if it doesn't exist."""
        if os.path.exists(self.appsec_json_file):
            return True
            
        template_content = """{
  "github_token": "", // [String] GitHub token for accessing repositories and raising PRs
  "github_repo": "", // [String] Target repository in 'owner/repo' format
  "github_branch": "main", // [String] Branch to raise PRs against (defaults to main)
  
  "sonar_auto_setup": false, // [Boolean] Automatically provisions SonarQube using Docker if True
  "dast_url": "", // [String] URL of the target application for DAST scans
  "zap_report_path": "", // [String] Custom path to look for existing ZAP XML reports
  "sca_target_type": "fs", // [String] SCA target environment (e.g. 'fs' or 'image')
  "sca_target_path": "./", // [String] Directory or resource to be scanned for dependencies
  "vulnerability_threshold": 5.0, // [Float] Base risk score threshold needed to generate an alert/fix, range from 0-10 
  
  "dast_auth": {
    "enabled": false, // [Boolean] True to enable authentication for DAST scans
    "method": "browser", // [String] Auth method: 'browser', 'form', 'json', or 'http'
    "username": "admin", // [String] Username credential for scan authentication
    "password": "password123", // [String] Password credential for scan authentication
    "login_page_url": "https://www.saucedemo.com/", // [String] URL of the login portal page
    "login_request_url": "", // [String] POST request URL (for 'form'/'json' auth; optional if same as login page)
    "login_request_body": "", // [String] Request POST payload template, e.g. "username={%username%}&password={%password%}"
    "browser_id": "firefox", // [String] Browser to open visually: 'firefox', 'chrome', 'firefox-headless', 'chrome-headless'
    "logged_in_regex": "", // [String] Regex indicator on responses confirming a logged-in session, e.g. "\\\\QLogout\\\\E"
    "logged_out_regex": "" // [String] Regex indicator on responses confirming a logged-out session, e.g. "\\\\QLogin\\\\E"
  },
  "dast_api": {
    "enabled": false, // [Boolean] True to enable API security scanning via specification import
    "spec_url": "", // [String] URL or local path to OpenAPI/GraphQL/SOAP specification file
    "spec_type": "openapi" // [String] Type of API definition: 'openapi', 'graphql', or 'soap'
  },
  "llm_url": "http://4.247.140.236:11434", // [String] Address of the AI orchestrator/model running locally
  "llm_model": "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B", // [String] Specific language model identifier to be queried
  "llm_timeout": 300, // [Integer] Maximum wait time for LLM processing in seconds
  "output_dir": "AppSecAI_output", // [String] Directory where reports and outputs will be saved
  "ai_batch_size": 5, // [Integer] Batch count for AI processing arrays
  "pr_batch_size": 5, // [Integer] Maximum amount of PRs to open at once
  "commit_batch_size": 5, // [Integer] Maximum amount of commits pushed in a single batch
  
  "AppSecAI": {
    "product": "Test-Product", // [String] Name of the product being analyzed
    "version": "v1.0.1", // [String] Current application version
    
    "environment": {
      "deployment_type": "public", // [String] Target scope of the deployment (Range: 'public'/'internal'/'internal_only')
      "internet_exposure": false, // [Boolean] True if the application is accessible from the internet
      "api_type": "rest", // [String] Paradigm of the backend interface (Range: 'rest'/'graphql'/'soap'/'internal'/'public_api')
      "https_enabled": false, // [Boolean] True if transport layer security (HTTPS) is mandated
      "data_classification": "confidential", // [String] Confidentiality level of the system data (Range: 'confidential'/'internal'/'public'/'restricted')
      "pii_present": false, // [Boolean] True if Personally Identifiable Information is processed
      "logging_audit_required": false, // [Boolean] True if systemic access logging is legally or technically required
      "encryption_in_transit_required": false, // [Boolean] True if the connection mandates transit encryption
      "encryption_at_rest_required": false, // [Boolean] True if static stored volumes mandate at-rest encryption
      "system_criticality": "high" // [String] Business impact criticality level (Range: 'high'/'medium'/'low'/'business_critical')
    },
    
    "runtime": {
      "containerized": false, // [Boolean] True if the application runs inside Docker/K8s
      "root_container": false, // [Boolean] True if the container engine executes with root user privileges
      "container_sig_enforced": false, // [Boolean] True if signatures must match for containers to execute
      "runtime_monitoring_enabled": false, // [Boolean] True if live execution anomalies are tracked
      
      "language_runtime": {
        "python_version": "3.10", // [String] Specified Python version constraint
        "node_version": "18", // [String] Specified NodeJS version constraint
        "go": "1.24.2", // [String] Specified GoLang version constraint
        "python": "3.10" // [String] Fallback python identifier
      },
      
      "service_authn": false, // [Boolean] True if internal services require valid authentication (zero-trust)
      "rate_limiting_enabled": false, // [Boolean] True if requests per second are capped natively
      "memory_limits_enforced": false, // [Boolean] True if the container memory gets physically capped 
      "cpu_limits_enforced": false // [Boolean] True if CPU cycles are physically capped
    },
    
    "security_controls": {
      "rbac_enabled": false, // [Boolean] True if Role-Based Access Controls dictate permissions
      "waf_enabled": false, // [Boolean] True if a Web Application Firewall screens connections
      "ids_enabled": false, // [Boolean] True if Intrusion Detection Systems track events
      "nfw_enabled": false, // [Boolean] True if a Network Firewall protects traffic boundaries
      "sso_enabled": false, // [Boolean] True if Single Sign-On federation is mandatory
      "mfa_required_for_admin": false, // [Boolean] True if administrative portals require Multi-Factor Auth
      "infrastructure_as_code_scan_enabled": false, // [Boolean] True if IaC templates are statically scanned 
      "dependency_vulnerability_scan_enabled": false, // [Boolean] True if OSS libraries are checked periodically
      "container_image_scan_enabled": false, // [Boolean] True if container layers are analyzed for CVEs
      "api_input_validation": false, // [Boolean] True if programmatic APIs validate input securely
      "api_authentication_required": false, // [Boolean] True if all APIs deny unauthenticated requests
      "secrets_vault_enabled": false, // [Boolean] True if secrets are fetched from vaults (e.g. AWS Secrets Manager)
      "cloud_security_posture_management": false, // [Boolean] True if cloud policies are analyzed directly
      "business_logic_testing": false, // [Boolean] True if complex business flows undergo rigorous security checks
      "data_loss_prevention": false, // [Boolean] True if strict DLP filters prevent exfiltration
      "network_segmentation": false, // [Boolean] True if lateral movement is inhibited on the network 
      "privileged_access_management": false, // [Boolean] True if PAM regulates admin workflows
      "api_security_gateway": false, // [Boolean] True if dedicated API gateways intercept logic
      "third_party_risk_assessment": false, // [Boolean] True if third-party components undergo regular verification
      "input_validation": false, // [Boolean] True if general form inputs are sanitized
      "key_management_system": false // [Boolean] True if a cryptographic Key Management System rotates material
    },
    
    "sca_context": {
      "dependency_management": {
        "dependency_update_frequency": "monthly", // [String] Cadence at which teams review and bump versions (Range: 'daily'/'weekly'/'monthly'/'quarterly'/'rarely')
        "lock_files_enforced": false, // [Boolean] True if lockfiles (like package-lock.json) are strictly analyzed
        "automated_dependency_updates": false, // [Boolean] True if Dependabot/Renovate auto-bumps dependencies
        "dependency_review_process": "none", // [String] Style in which software bills of material are created (Range: 'none'/'manual'/'automated')
        "dependency_pinning_strategy": "minor", // [String] Standard fallback mapping for pinned packages
        "dependency_approval_required": false, // [Boolean] True if new libraries must be approved by security
        "sbom_generation_enabled": false, // [Boolean] True if an SBOM is mapped during the pipeline
        "license_compliance_checking": false, // [Boolean] True if open-source licenses are screened
        "dependency_pinning": false, // [Boolean] True if floating/caret dependency usage is banned
        "transitive_dependency_analysis": false, // [Boolean] True if the scan investigates sub-dependencies profoundly
        "sbom_format": "none" // [String] Specified format for SBOM outputs (e.g. 'cyclonedx')
      },
      "package_sources": {
        "private_registry_used": false, // [Boolean] True if enterprise artifactory sources replace standard ones
        "registry_mirrors_used": false, // [Boolean] True if public registries are proxied locally
        "package_signature_verification": false, // [Boolean] True if checksums strictly authorize binary execution
        "trusted_sources_only": false, // [Boolean] True if unvetted ecosystem packages cannot be used
        "allow_public_registries": false, // [Boolean] True if default registries like standard PyPI are authorized
        "registry_scanning_enabled": false, // [Boolean] True if artifact registries perform passive scanning 
        "package_provenance_tracking": false // [Boolean] True if binaries map back to exact source commit histories
      },
      "dependency_usage": {
        "unused_dependencies_present": false, // [Boolean] True if stale packages linger in package definitions
        "dev_dependencies_in_production": false, // [Boolean] True if tester tools/linters accidentally ship alongside prod binary
        "optional_dependencies_used": false, // [Boolean] True if conditional modules are requested lazily
        "peer_dependencies_managed": false // [Boolean] True if dependencies dictate host requirements strictly 
      },
      "vulnerability_response": {
        "mean_time_to_patch": "> 30d", // [String] Average duration in days to complete a patch sprint (Range: '< 24h'/'< 7d'/'> 30d')
        "vulnerability_monitoring": "daily", // [String] Rhythm at which CVE scanners run (Range: 'daily'/'weekly'/'monthly'/'real-time')
        "emergency_patch_process": false, // [Boolean] True if a dedicated procedure handles out-of-band hotfixes
        "vulnerability_disclosure_policy": false, // [Boolean] True if external researchers can officially submit reports
        "security_champion_assigned": false, // [Boolean] True if specific engineers directly advocate for security
        "vulnerability_sla_defined": false // [Boolean] True if specific SLAs govern patch timetables
      },
      "build_pipeline": {
        "dependency_caching_used": false, // [Boolean] True if runner builds use locally cached binaries
        "build_reproducibility": false, // [Boolean] True if source builds create identical binaries constantly
        "dependency_hash_verification": false, // [Boolean] True if downloaded sources run through digest validations
        "isolated_build_environment": false, // [Boolean] True if compilation containers are hermetic offline vaults
        "build_artifact_signing": false, // [Boolean] True if compilation outputs are signed cryptographically
        "supply_chain_levels_for_software_artifacts": "slsa3" // [String] Specific tier within SLSA supply-chain requirements (Range: 'none'/'slsa1'/'slsa2'/'slsa3'/'slsa4')
      },
      "runtime_behavior": {
        "dependency_isolation": false, // [Boolean] True if system resources dynamically partition libraries natively 
        "sandboxing_enabled": false, // [Boolean] True if logic executes inside kernel restricted spaces
        "runtime_dependency_monitoring": false, // [Boolean] True if memory calls from libraries are tracked live
        "dynamic_loading_restricted": false, // [Boolean] True if dynamic library insertion (like dlopen) is rejected
        "native_code_dependencies": false, // [Boolean] True if C/C++ native integrations are bundled
        "network_access_by_dependencies": "restricted" // [String] Permission limits applied to library connection sockets (Range: 'restricted'/'unrestricted'/'blocked')
      },
      "ecosystem": {
        "primary_language": "javascript", // [String] System's predominant programming language 
        "package_manager": "npm", // [String] Identifier of the module download orchestrator 
        "language_version_eol": false, // [Boolean] True if runtime language is physically retired/unsupported
        "package_manager_version": "latest", // [String] Requested build runner engine target version
        "ecosystem_security_tools": [
          "snyk",
          "dependabot",
          "renovate"
        ], // [Array] List of active vulnerability monitoring plugins
        "monorepo": false // [Boolean] True if all sub-services sit within the same repository
      },
      "compliance": {
        "soc2_compliance_required": false, // [Boolean] True if systems mandate strict logical data partitioning for SOC2 
        "hipaa_compliance_required": false, // [Boolean] True if healthcare datasets regulate system flows (HIPAA)
        "pci_dss_compliance_required": false, // [Boolean] True if financial credit elements route through application (PCI)
        "gdpr_compliance_required": false, // [Boolean] True if data retention allows the 'Right To Be Forgotten' natively
        "iso_27001_compliance_required": false // [Boolean] True if an ISO auditor mandates the information security structure
      }
    }
  }
}"""
        
        try:
            with open(self.appsec_json_file, 'w', encoding='utf-8') as f:
                f.write(template_content)
            logger.info(f"Generated default {self.appsec_json_file}")
            print(f"\n✅ Generated {self.appsec_json_file} configuration file.")
            print("💡 Opening this file for you automatically...")
            
            # Auto-open the file based on the OS
            import platform
            import subprocess
            try:
                if platform.system() == "Windows":
                    os.startfile(self.appsec_json_file)
                elif platform.system() == "Darwin":
                    subprocess.call(["open", self.appsec_json_file])
                else:
                    subprocess.call(["xdg-open", self.appsec_json_file])
            except Exception as e:
                pass
                
            print("👉 You can fill in your tokens now. If you don't want to, you can just close the file.")
            input("Press Enter here in the terminal to continue...")
            
            # Reload the configuration in case they made changes!
            appsec_config = self._load_appsec_json_config()
            self.config = self._merge_configs(self.config, appsec_config)
            
            return True
        except Exception as e:
            logger.error(f"Failed to generate {self.appsec_json_file}: {e}")
            return False
    
    def _load_dotenv_file(self) -> Dict[str, Any]:
        """Load environment variables from .env file as a dictionary."""
        env_data = {}
        
        if getattr(sys, 'frozen', False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.getcwd()
            
        env_path = os.path.join(base_dir, ".env")
        if os.path.exists(env_path):
            try:
                with open(env_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            parts = line.split('=', 1)
                            if len(parts) == 2:
                                env_data[parts[0].strip()] = parts[1].strip()
            except Exception: pass
        return env_data