import os
import re
import csv
import json
import shutil
import requests
import subprocess
from datetime import datetime

class Config:
    """Configuration class for SonarQube and GitHub integration."""
    SONARQUBE_URL = "http://localhost:9000"
    USERNAME = "admin"
    PASSWORD = ""
    OUTPUT_DIR = ""
    PROJECT_KEY = ""  # Specify the project key here
    
    # GitHub configuration
    GITHUB_REPO = ""  # Replace with your GitHub repository
    GITHUB_URL = f"https://github.com/{GITHUB_REPO}.git"
    CLONE_DIR = ""  # Directory where the repo will be cloned
    
    # Vulnerability scoring configuration
    CONFIG_JSON_PATH = r""  # Path to vulnerability config JSON
    THRESHOLD_SCORE = 15  # Minimum score to include vulnerabilities
    
    def __init__(self):
        os.makedirs(self.OUTPUT_DIR, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.EXTRACTED_CODE_JSON = os.path.join(self.OUTPUT_DIR, f"hotspots_with_code_{timestamp}.json")
        self.EXTRACTED_CODE_CSV = os.path.join(self.OUTPUT_DIR, f"hotspots_with_code_{timestamp}.csv")
        self.FILTERED_VULNERABILITIES_JSON = os.path.join(self.OUTPUT_DIR, f"filtered_vulnerabilities_{timestamp}.json")
        self.FILTERED_VULNERABILITIES_CSV = os.path.join(self.OUTPUT_DIR, f"filtered_vulnerabilities_{timestamp}.csv")

class VulnerabilityScorer:
    """Class to score vulnerabilities based on predefined criteria."""
    
    def __init__(self, config, vulnerabilities):
        """
        Initialize the VulnerabilityScorer.
        
        Args:
            config (Config): Configuration instance
            vulnerabilities (list): List of vulnerabilities to score
        """
        self.config = config
        self.vulnerabilities = vulnerabilities
        self.threshold_score = config.THRESHOLD_SCORE
        self.config_json_path = config.CONFIG_JSON_PATH
        
        # Severity mapping for vulnerabilityProbability
        self.severity_mapping = {
            "HIGH": 10,
            "MEDIUM": 6,
            "LOW": 3
        }
        
        # Load vulnerability configuration
        self.load_vulnerability_config()
    
    def load_vulnerability_config(self):
        """Load vulnerability configuration from JSON file."""
        print(f"📝 Loading vulnerability configuration from {self.config_json_path}...")
        try:
            with open(self.config_json_path, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
                self.vulnerability_config = {}
                
                for item in config_data.get("questionnaire", []):
                    vul_type = item["vulnerabilityType"]
                    if vul_type == "Default":
                        # Skip the default entry, it will be used as fallback
                        self.default_config = item
                        continue
                        
                    # Create a dictionary for each vulnerability type with scores by category
                    self.vulnerability_config[vul_type] = {}
                    for category_score in item["vulCategoryScores"]:
                        category = category_score["vulCategory"]
                        score = category_score["score"]
                        self.vulnerability_config[vul_type][category] = score
                
            print(f"✅ Loaded configuration for {len(self.vulnerability_config)} vulnerability types")
            
        except Exception as e:
            print(f"❌ Error loading vulnerability configuration: {str(e)}")
            raise
    
    def map_vulnerability_type(self, message):
        """
        Map a vulnerability message to a vulnerability type from the configuration.
        
        Args:
            message (str): Vulnerability message from SonarQube.
            
        Returns:
            str: Matched vulnerability type or "Default" if no match found.
        """
        message = message.lower()
        
        # Map common vulnerability patterns to configured types
        mapping_patterns = {
            "hard-coded credential": ["password", "credential", "secret", "key", "token"],
            "regex denial of service": ["regex", "dos", "denial of service", "catastrophic backtracking"],
            "docker container runs as root": ["docker", "container", "root", "privilege"],
            "clear-text protocol usage": ["clear text", "cleartext", "plain text", "unencrypted", "http://"],
            "publicly writable directory": ["directory", "writable", "permission", "write access", "upload"]
        }
        
        for vul_type, patterns in mapping_patterns.items():
            for pattern in patterns:
                if pattern in message:
                    # Check if this vulnerability type exists in our config
                    for config_vul_type in self.vulnerability_config.keys():
                        if vul_type.lower() in config_vul_type.lower():
                            return config_vul_type
        
        # If no match is found, return "Default"
        return "Default"
    
    def get_vulnerability_scores(self, vul_type):
        """
        Get vulnerability category scores for a given vulnerability type.
        
        Args:
            vul_type (str): The vulnerability type.
            
        Returns:
            dict: Dictionary of category scores.
        """
        # If vulnerability type is in config, return its scores
        if vul_type in self.vulnerability_config:
            return self.vulnerability_config[vul_type]
        
        # Otherwise, create a default score dictionary from the default config
        default_scores = {}
        for category_score in self.default_config["vulCategoryScores"]:
            default_scores[category_score["vulCategory"]] = category_score["score"]
        
        return default_scores
    
    def calculate_vulnerability_score(self, vulnerability):
        """
        Calculate the vulnerability score based on the formula:
        Score = (Severity + Potential Impact + EaseOfExploitation + AssetExposure + RealWorldAttackLikelihood) - SecurityControlDeployment
        
        Args:
            vulnerability (dict): Vulnerability data.
            
        Returns:
            int: The calculated vulnerability score.
        """
        # Map vulnerability probability to severity score
        severity = self.severity_mapping.get(vulnerability.get("vulnerabilityProbability", "LOW").upper(), 3)
        
        # Map message to vulnerability type
        message = vulnerability.get("message", "")
        vul_type = self.map_vulnerability_type(message)
        
        # Get category scores for this vulnerability type
        category_scores = self.get_vulnerability_scores(vul_type)
        
        # Calculate total score using the formula
        total_score = severity
        
        # Add category scores to total
        categories = ["Potential Impact", "EaseOfExploitation", "AssetExposure", "RealWorldAttackLikelihood"]
        for category in categories:
            score = category_scores.get(category, 0)
            total_score += score
        
        # Subtract security control deployment score
        security_control_score = category_scores.get("SecurityControlDeployment", 0)
        total_score -= security_control_score
        
        # Add score to vulnerability data
        # vulnerability["score"] = total_score
        # vulnerability["vulnerability_type"] = vul_type
        
        return total_score
    
    def filter_vulnerabilities(self):
        """Filter vulnerabilities based on score threshold."""
        print(f"🔍 Filtering vulnerabilities based on threshold score {self.threshold_score}...")
        
        filtered_vulnerabilities = []
        for vulnerability in self.vulnerabilities:
            score = self.calculate_vulnerability_score(vulnerability)
            
            # Only include vulnerabilities above the threshold
            if score >= self.threshold_score:
                filtered_vulnerabilities.append(vulnerability)
        
        print(f"✅ Found {len(filtered_vulnerabilities)} vulnerabilities above threshold score {self.threshold_score}")
        return filtered_vulnerabilities

def clone_repository(config):
    """Clone the GitHub repository locally."""
    print(f"🔄 Cloning repository {config.GITHUB_REPO}...")
    
    # Remove existing clone directory if it exists
    if os.path.exists(config.CLONE_DIR):
        print(f"Repo is already present")
        return True
    
    # Clone the repository
    try:
        subprocess.run(["git", "clone", config.GITHUB_URL, config.CLONE_DIR], 
                      check=True, capture_output=True)
        print(f"✅ Repository cloned successfully to {config.CLONE_DIR}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to clone repository: {e}")
        print(f"Error output: {e.stderr.decode('utf-8')}")
        return False

def fetch_hotspots(config):
    """Fetch security hotspots from SonarQube API for a specific project."""
    print(f"🔍 Fetching security hotspots for project {config.PROJECT_KEY}...")
    api_url = f"{config.SONARQUBE_URL}/api/hotspots/search"
    params = {"projectKey": config.PROJECT_KEY, "status": "TO_REVIEW"}
    hotspots = []
    page = 1
    while True:
        params["p"] = page
        response = requests.get(api_url, params=params, auth=(config.USERNAME, config.PASSWORD))
        if response.status_code != 200:
            print(f"❌ Failed to fetch hotspots: {response.status_code}")
            break
        data = response.json()
        page_hotspots = data.get("hotspots", [])
        if not page_hotspots:
            break
        hotspots.extend(page_hotspots)
        print(f"📄 Fetched {len(page_hotspots)} hotspots from page {page}")
        page += 1
    print(f"✅ Total hotspots fetched for {config.PROJECT_KEY}: {len(hotspots)}")
    return hotspots

def extract_function_code(hotspots, config):
    """Extract complete function code for each hotspot from local clone."""
    print("📝 Extracting function code for each hotspot from local repository...")
    
    for hotspot in hotspots:
        # Extract the relative file path from the component field
        file_path = hotspot.get("component", "").split(":")[-1]
        local_file_path = os.path.join(config.CLONE_DIR, file_path)
        
        try:
            # Check if file exists in the local clone
            if not os.path.exists(local_file_path):
                raise FileNotFoundError(f"File not found: {local_file_path}")
                
            # Read file content
            with open(local_file_path, 'r', encoding='utf-8') as file:
                file_content = file.read()
                
            lines = file_content.splitlines()
            
            line_num = hotspot.get("line", 1)
            if line_num > len(lines):
                line_num = min(len(lines), 1)
                
            start_line = None
            function_pattern = re.compile(r"^\s*def\s+\w+\(.*\):")  # Python function pattern
            
            # Try to find the start of the function
            for i in range(line_num - 1, -1, -1):
                if function_pattern.match(lines[i]):
                    start_line = i
                    break
                    
            if start_line is None:
                # If no function definition found, extract context around the hotspot
                start_line = max(0, line_num - 5)
                end_line = min(len(lines), line_num + 5)
                extracted_code = "\n".join(lines[start_line:end_line])
                
                hotspot["extracted_code"] = extracted_code.strip()
                hotspot["context_type"] = "lines"
                hotspot["start_line"] = start_line + 1
                hotspot["end_line"] = end_line
                continue
                
            # Find the end of the function based on indentation
            indent_level = len(lines[start_line]) - len(lines[start_line].lstrip())
            end_line = len(lines)
            
            for i in range(start_line + 1, len(lines)):
                if not lines[i].strip() or lines[i].strip().startswith('#'):
                    continue
                curr_indent = len(lines[i]) - len(lines[i].lstrip())
                if curr_indent <= indent_level:
                    end_line = i
                    break
                    
            extracted_code = "\n".join(lines[start_line:end_line])
            
            hotspot["extracted_code"] = extracted_code.strip()
            hotspot["context_type"] = "function"
            hotspot["start_line"] = start_line + 1
            hotspot["end_line"] = end_line
            
        except Exception as e:
            print(f"⚠️ Error extracting code from file {file_path}: {str(e)}")
            hotspot["extracted_code"] = f"Error: {str(e)}"
            hotspot["context_type"] = "error"
            hotspot["start_line"] = line_num
            hotspot["end_line"] = line_num

def save_hotspots_raw(config, hotspots):
    """Save raw hotspots with extracted code to JSON and CSV."""
    with open(config.EXTRACTED_CODE_JSON, 'w') as f:
        json.dump(hotspots, f, indent=4)
    print(f"📝 Saved raw hotspots to {config.EXTRACTED_CODE_JSON}")
    
    fieldnames = ['key', 'component', 'line', 'message', 'ruleKey', 'vulnerabilityProbability', 
                  'extracted_code', 'context_type', 'start_line', 'end_line']
    with open(config.EXTRACTED_CODE_CSV, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for hotspot in hotspots:
            row = {k: hotspot.get(k, '') for k in fieldnames}
            writer.writerow(row)
    print(f"📝 Saved raw hotspots to {config.EXTRACTED_CODE_CSV}")

def save_filtered_vulnerabilities(config, filtered_vulnerabilities):
    """Save filtered vulnerabilities to JSON and CSV with specific fields only."""
    # Define only the fields you want to include
    desired_fields = ['key', 'component', 'line', 'message', 'ruleKey', 'vulnerabilityProbability', 
                      'extracted_code', 'context_type', 'start_line', 'end_line']
    
    # Create filtered data with only desired fields
    filtered_data = []
    for vuln in filtered_vulnerabilities:
        filtered_item = {field: vuln.get(field, '') for field in desired_fields}
        filtered_data.append(filtered_item)
    
    # Save filtered data to JSON
    with open(config.FILTERED_VULNERABILITIES_JSON, 'w') as f:
        json.dump(filtered_data, f, indent=4)
    print(f"📝 Saved filtered vulnerabilities to {config.FILTERED_VULNERABILITIES_JSON}")
    
    if filtered_data:
        with open(config.FILTERED_VULNERABILITIES_CSV, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=desired_fields)
            writer.writeheader()
            writer.writerows(filtered_data)
        print(f"📝 Saved filtered vulnerabilities to {config.FILTERED_VULNERABILITIES_CSV}")
    else:
        print("⚠️ No filtered vulnerabilities to save")

def main():
    """Main function to run the security analysis process."""
    print("🚀 Starting security analysis process...")
    
    # Initialize configuration
    config = Config()
    
    # Validate required configuration
    if not config.PROJECT_KEY:
        print("❌ No project key specified. Please set PROJECT_KEY in the Config class.")
        return
    
    if not config.GITHUB_REPO:
        print("❌ No GitHub repository specified. Please set GITHUB_REPO in the Config class.")
        return
    
    if not config.CONFIG_JSON_PATH:
        print("❌ No vulnerability config JSON file specified. Please set CONFIG_JSON_PATH in the Config class.")
        return
    
    # Clone the repository locally
    if not clone_repository(config):
        print("❌ Failed to clone repository. Exiting.")
        return
    
    # Fetch hotspots from SonarQube
    hotspots = fetch_hotspots(config)
    if not hotspots:
        print(f"⚠️ No hotspots found for project {config.PROJECT_KEY}.")
        return
    
    # Extract code from local files
    extract_function_code(hotspots, config)
    
    # Save raw hotspots data
    # save_hotspots_raw(config, hotspots)
    
    # Score and filter vulnerabilities
    print("⚖️ Scoring and filtering vulnerabilities...")
    scorer = VulnerabilityScorer(config, hotspots)
    filtered_vulnerabilities = scorer.filter_vulnerabilities()
    
    # Save filtered vulnerabilities
    save_filtered_vulnerabilities(config, filtered_vulnerabilities)
    
    print(f"✨ Security analysis complete! Results saved in {config.OUTPUT_DIR}")
    print(f"Raw hotspots data:")
    print(f"  - JSON: {config.EXTRACTED_CODE_JSON}")
    print(f"  - CSV: {config.EXTRACTED_CODE_CSV}")
    print(f"Filtered vulnerabilities:")
    print(f"  - JSON: {config.FILTERED_VULNERABILITIES_JSON}")
    print(f"  - CSV: {config.FILTERED_VULNERABILITIES_CSV}")

if __name__ == "__main__":
    main()
