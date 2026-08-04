#!/usr/bin/env python3
"""
SonarQube Tag-to-Category Mapper

Automatically fetches SonarQube rules and creates comprehensive tag-to-category mappings.
Supports auto-refresh and expandable mappings.
"""

import json
import os
import requests
import logging
from typing import Dict, List, Tuple, Set
from datetime import datetime, timedelta
from requests.auth import HTTPBasicAuth
from appsecai.common.utils import get_resource_path

logger = logging.getLogger(__name__)

class SonarTagMapper:
    """Manages SonarQube tag-to-category mappings with auto-refresh capability"""
    
    def __init__(self, compliance_config_path: str = "appsecai/risk_profiles/context_modifiers/risk_context_template.json"):
        """
        Initialize SonarQube tag mapper.
        
        Args:
            compliance_config_path: Path to enhanced compliance configuration
        """
        self.compliance_config_path = compliance_config_path
        self.compliance_config = self._load_compliance_config()
        
        # Get SonarQube configuration
        app_config = self.compliance_config.get('AppSecAI', {})
        self.sonar_config = app_config.get('sonar_auto_mapping', {})
        
        # Current mappings
        self.current_mappings = {
            item['tag']: item['category'] 
            for item in self.sonar_config.get('tag_to_category', [])
        }
        
        # Comprehensive tag-to-category mappings
        self.comprehensive_mappings = self._get_comprehensive_mappings()
    
    def _load_compliance_config(self) -> Dict:
        """Load compliance configuration"""
        try:
            with open(self.compliance_config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading compliance config: {e}")
            return {}
    
    def _get_comprehensive_mappings(self) -> Dict[str, str]:
        """Get comprehensive tag-to-category mappings"""
        return {
            # Injection vulnerabilities
            "injection": "Injection",
            "sql": "Injection", 
            "sqli": "Injection",
            "xss": "Injection",
            "script": "Injection",
            "command": "Injection",
            "ldap": "Injection",
            "xpath": "Injection",
            "xml": "Injection",
            "nosql": "Injection",
            "serialization": "Injection",
            "deserialization": "Injection",
            
            # Cryptography
            "crypto": "Cryptography",
            "cryptography": "Cryptography",
            "encryption": "Cryptography",
            "hash": "Cryptography",
            "password": "Cryptography",
            "secret": "Cryptography",
            "secrets": "Cryptography",
            "key": "Cryptography",
            "certificate": "Cryptography",
            "ssl": "Transport Security",
            "tls": "Transport Security",
            "random": "Cryptography",
            "weak-crypto": "Cryptography",
            
            # Transport Security
            "transport": "Transport Security",
            "https": "Transport Security",
            "http": "Transport Security",
            "network": "Transport Security",
            "protocol": "Transport Security",
            "communication": "Transport Security",
            "insecure-transport": "Transport Security",
            
            # HTTP Security Headers
            "header": "HTTP Security Headers",
            "headers": "HTTP Security Headers",
            "csp": "HTTP Security Headers",
            "hsts": "HTTP Security Headers",
            "cors": "HTTP Security Headers",
            "content-type": "HTTP Security Headers",
            "x-frame-options": "HTTP Security Headers",
            "clickjacking": "HTTP Security Headers",
            "referrer": "HTTP Security Headers",
            
            # API Security
            "api": "API Security",
            "rest": "API Security",
            "auth": "API Security",
            "authentication": "API Security",
            "authorization": "API Security",
            "oauth": "API Security",
            "jwt": "API Security",
            "session": "API Security",
            "csrf": "API Security",
            "cors": "API Security",
            "rate-limit": "API Security",
            
            # Infrastructure Security
            "infrastructure": "Infrastructure Security",
            "config": "Infrastructure Security",
            "configuration": "Infrastructure Security",
            "permission": "Infrastructure Security",
            "access": "Infrastructure Security",
            "privilege": "Infrastructure Security",
            "file": "Infrastructure Security",
            "directory": "Infrastructure Security",
            "path": "Infrastructure Security",
            "traversal": "Infrastructure Security",
            "inclusion": "Infrastructure Security",
            
            # Cloud Security
            "cloud": "Cloud Security Posture",
            "aws": "Cloud Security Posture",
            "azure": "Cloud Security Posture",
            "gcp": "Cloud Security Posture",
            "kubernetes": "Cloud Security Posture",
            "docker": "Cloud Security Posture",
            "container": "Cloud Security Posture",
            "iam": "Cloud Security Posture",
            "s3": "Cloud Security Posture",
            
            # Supply Chain Security
            "supply-chain": "Supply Chain Security",
            "dependency": "Supply Chain Security",
            "dependencies": "Supply Chain Security",
            "package": "Supply Chain Security",
            "library": "Supply Chain Security",
            "third-party": "Third-Party Integration Security",
            "vendor": "Third-Party Integration Security",
            "external": "Third-Party Integration Security",
            
            # DevSecOps Pipeline Security
            "devops": "DevSecOps Pipeline Security",
            "ci": "DevSecOps Pipeline Security",
            "cd": "DevSecOps Pipeline Security",
            "pipeline": "DevSecOps Pipeline Security",
            "build": "DevSecOps Pipeline Security",
            "deployment": "DevSecOps Pipeline Security",
            "artifact": "DevSecOps Pipeline Security",
            
            # Business Logic Vulnerabilities
            "business-logic": "Business Logic Vulnerabilities",
            "workflow": "Business Logic Vulnerabilities",
            "race": "Business Logic Vulnerabilities",
            "concurrency": "Business Logic Vulnerabilities",
            "timing": "Business Logic Vulnerabilities",
            "datetime": "Business Logic Vulnerabilities",
            "logic": "Business Logic Vulnerabilities",
            
            # Data Protection & Privacy
            "privacy": "Data Protection & Privacy",
            "gdpr": "Data Protection & Privacy",
            "pii": "Data Protection & Privacy",
            "personal-data": "Data Protection & Privacy",
            "data-protection": "Data Protection & Privacy",
            "consent": "Data Protection & Privacy",
            "retention": "Data Protection & Privacy",
            
            # Mobile Security
            "mobile": "Mobile Security",
            "android": "Mobile Security",
            "ios": "Mobile Security",
            "app": "Mobile Security",
            
            # AI/ML Security
            "ai": "AI/ML Security",
            "ml": "AI/ML Security",
            "machine-learning": "AI/ML Security",
            "model": "AI/ML Security",
            
            # Information Disclosure
            "disclosure": "Infrastructure Security",
            "information": "Infrastructure Security",
            "leak": "Infrastructure Security",
            "exposure": "Infrastructure Security",
            "error": "Infrastructure Security",
            "debug": "Infrastructure Security",
            "logging": "Infrastructure Security",
            "log": "Infrastructure Security",
            
            # Input Validation
            "validation": "Injection",
            "input": "Injection",
            "sanitization": "Injection",
            "encoding": "Injection",
            "regex": "Injection",
            "dos": "Injection",
            "redos": "Injection",
            
            # Generic Security
            "security": "Infrastructure Security",
            "vulnerability": "Infrastructure Security",
            "weakness": "Infrastructure Security",
            "flaw": "Infrastructure Security",
            
            # Language-specific tags
            "java": "Infrastructure Security",
            "python": "Infrastructure Security", 
            "javascript": "Infrastructure Security",
            "typescript": "Infrastructure Security",
            "csharp": "Infrastructure Security",
            "php": "Infrastructure Security",
            "ruby": "Infrastructure Security",
            "go": "Infrastructure Security",
            "rust": "Infrastructure Security",
            "cpp": "Infrastructure Security",
        }
    
    def fetch_sonarqube_rules(self, sonar_url: str, username: str, password: str) -> List[Dict]:
        """
        Fetch all rules from SonarQube API.
        
        Args:
            sonar_url: SonarQube server URL
            username: SonarQube username
            password: SonarQube password
            
        Returns:
            List of SonarQube rules with tags
        """
        try:
            api_url = f"{sonar_url}/api/rules/search"
            all_rules = []
            page = 1
            page_size = 500
            
            while True:
                params = {
                    'p': page,
                    'ps': page_size,
                    'f': 'name,langName,tags,type,severity'
                }
                
                response = requests.get(
                    api_url, 
                    params=params,
                    auth=HTTPBasicAuth(username, password),
                    timeout=30
                )
                response.raise_for_status()
                
                data = response.json()
                rules = data.get('rules', [])
                
                if not rules:
                    break
                
                all_rules.extend(rules)
                
                # Check if we've fetched all rules
                total = data.get('total', 0)
                if len(all_rules) >= total:
                    break
                
                page += 1
                
                # Safety break
                if page > 100:
                    logger.warning("Reached page limit (100) while fetching SonarQube rules")
                    break
            
            logger.info(f"Fetched {len(all_rules)} rules from SonarQube")
            return all_rules
            
        except Exception as e:
            logger.error(f"Error fetching SonarQube rules: {e}")
            return []
    
    def analyze_rule_tags(self, rules: List[Dict]) -> Dict[str, int]:
        """
        Analyze tags from SonarQube rules to find unmapped tags.
        
        Args:
            rules: List of SonarQube rules
            
        Returns:
            Dictionary of tag frequencies
        """
        tag_counts = {}
        
        for rule in rules:
            tags = rule.get('tags', [])
            for tag in tags:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1
        
        return tag_counts
    
    def get_unmapped_tags(self, tag_counts: Dict[str, int]) -> List[Tuple[str, int]]:
        """
        Get tags that are not yet mapped to categories.
        
        Args:
            tag_counts: Dictionary of tag frequencies
            
        Returns:
            List of (tag, count) tuples for unmapped tags
        """
        unmapped = []
        
        for tag, count in tag_counts.items():
            if tag not in self.comprehensive_mappings and tag not in self.current_mappings:
                unmapped.append((tag, count))
        
        # Sort by frequency (most common first)
        unmapped.sort(key=lambda x: x[1], reverse=True)
        
        return unmapped
    
    def suggest_category_for_tag(self, tag: str) -> str:
        """
        Suggest a category for an unmapped tag based on keywords.
        
        Args:
            tag: Tag to categorize
            
        Returns:
            Suggested category name
        """
        tag_lower = tag.lower()
        
        # Keyword-based suggestions
        if any(keyword in tag_lower for keyword in ['inject', 'sql', 'xss', 'script']):
            return "Injection"
        elif any(keyword in tag_lower for keyword in ['crypto', 'encrypt', 'hash', 'secret']):
            return "Cryptography"
        elif any(keyword in tag_lower for keyword in ['transport', 'ssl', 'tls', 'http']):
            return "Transport Security"
        elif any(keyword in tag_lower for keyword in ['header', 'csp', 'cors']):
            return "HTTP Security Headers"
        elif any(keyword in tag_lower for keyword in ['api', 'auth', 'oauth', 'jwt']):
            return "API Security"
        elif any(keyword in tag_lower for keyword in ['cloud', 'aws', 'azure', 'docker']):
            return "Cloud Security Posture"
        elif any(keyword in tag_lower for keyword in ['mobile', 'android', 'ios']):
            return "Mobile Security"
        elif any(keyword in tag_lower for keyword in ['ai', 'ml', 'model']):
            return "AI/ML Security"
        elif any(keyword in tag_lower for keyword in ['privacy', 'gdpr', 'pii']):
            return "Data Protection & Privacy"
        else:
            return "Infrastructure Security"  # Default category
    
    def update_tag_mappings(self, sonar_url: str = None, username: str = None, password: str = None) -> bool:
        """
        Update tag-to-category mappings by fetching from SonarQube.
        
        Args:
            sonar_url: SonarQube server URL (optional, uses config if not provided)
            username: SonarQube username (optional, uses config if not provided)  
            password: SonarQube password (optional, uses config if not provided)
            
        Returns:
            True if update was successful, False otherwise
        """
        try:
            # Use provided credentials or fall back to environment/config
            if not sonar_url:
                sonar_url = os.getenv('SONAR_URL', 'http://localhost:9000')
            if not username:
                username = os.getenv('SONAR_USERNAME', 'admin')
            if not password:
                password = os.getenv('SONAR_PASSWORD', 'admin')
            
            logger.info(f"Updating tag mappings from SonarQube: {sonar_url}")
            
            # Fetch rules from SonarQube
            rules = self.fetch_sonarqube_rules(sonar_url, username, password)
            
            if not rules:
                logger.warning("No rules fetched from SonarQube, keeping existing mappings")
                return False
            
            # Analyze tags
            tag_counts = self.analyze_rule_tags(rules)
            unmapped_tags = self.get_unmapped_tags(tag_counts)
            
            logger.info(f"Found {len(tag_counts)} unique tags, {len(unmapped_tags)} unmapped")
            
            # Create new mappings
            new_mappings = []
            
            # Add existing mappings
            for tag, category in self.current_mappings.items():
                new_mappings.append({"tag": tag, "category": category})
            
            # Add comprehensive mappings for tags found in SonarQube
            for tag in tag_counts.keys():
                if tag in self.comprehensive_mappings and tag not in self.current_mappings:
                    new_mappings.append({
                        "tag": tag, 
                        "category": self.comprehensive_mappings[tag]
                    })
            
            # Suggest mappings for unmapped tags (top 20 most frequent)
            for tag, count in unmapped_tags[:20]:
                suggested_category = self.suggest_category_for_tag(tag)
                new_mappings.append({
                    "tag": tag,
                    "category": suggested_category,
                    "suggested": True,  # Mark as suggested for review
                    "frequency": count
                })
            
            # Update compliance configuration
            app_config = self.compliance_config.get('AppSecAI', {})
            sonar_auto_mapping = app_config.get('sonar_auto_mapping', {})
            sonar_auto_mapping['tag_to_category'] = new_mappings
            sonar_auto_mapping['last_updated'] = datetime.now().isoformat()
            sonar_auto_mapping['total_rules_analyzed'] = len(rules)
            sonar_auto_mapping['total_tags_found'] = len(tag_counts)
            
            # Save updated configuration
            with open(self.compliance_config_path, 'w', encoding='utf-8') as f:
                json.dump(self.compliance_config, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Updated tag mappings: {len(new_mappings)} total mappings")
            return True
            
        except Exception as e:
            logger.error(f"Error updating tag mappings: {e}")
            return False
    
    def should_auto_refresh(self) -> bool:
        """
        Check if auto-refresh is needed based on configuration.
        
        Returns:
            True if refresh is needed, False otherwise
        """
        try:
            if not self.sonar_config.get('enabled', False):
                return False
            
            auto_refresh_days = self.sonar_config.get('auto_refresh_days', 7)
            last_updated_str = self.sonar_config.get('last_updated')
            
            if not last_updated_str:
                return True  # Never updated, needs refresh
            
            last_updated = datetime.fromisoformat(last_updated_str.replace('Z', '+00:00'))
            days_since_update = (datetime.now() - last_updated).days
            
            return days_since_update >= auto_refresh_days
            
        except Exception as e:
            logger.debug(f"Error checking auto-refresh: {e}")
            return False
    
    def get_mapping_statistics(self) -> Dict:
        """Get statistics about current tag mappings"""
        stats = {
            'total_mappings': len(self.current_mappings),
            'categories_used': len(set(self.current_mappings.values())),
            'comprehensive_available': len(self.comprehensive_mappings),
            'last_updated': self.sonar_config.get('last_updated', 'Never'),
            'auto_refresh_enabled': self.sonar_config.get('enabled', False),
            'auto_refresh_days': self.sonar_config.get('auto_refresh_days', 7)
        }
        
        return stats

def main():
    """Test the SonarQube tag mapper"""
    mapper = SonarTagMapper()
    
    print("🏷️ SonarQube Tag Mapper Test")
    print("=" * 50)
    
    # Show current statistics
    stats = mapper.get_mapping_statistics()
    print(f"📊 Current Statistics:")
    print(f"   Total mappings: {stats['total_mappings']}")
    print(f"   Categories used: {stats['categories_used']}")
    print(f"   Comprehensive available: {stats['comprehensive_available']}")
    print(f"   Last updated: {stats['last_updated']}")
    print(f"   Auto-refresh: {stats['auto_refresh_enabled']} (every {stats['auto_refresh_days']} days)")
    
    # Check if refresh is needed
    if mapper.should_auto_refresh():
        print(f"\n🔄 Auto-refresh needed!")
        print(f"💡 Run: mapper.update_tag_mappings() to refresh from SonarQube")
    else:
        print(f"\n✅ Tag mappings are up to date")
    
    # Show some example mappings
    print(f"\n🏷️ Example Tag Mappings:")
    for i, (tag, category) in enumerate(list(mapper.current_mappings.items())[:10]):
        print(f"   {tag} → {category}")
    
    if len(mapper.current_mappings) > 10:
        print(f"   ... and {len(mapper.current_mappings) - 10} more")

if __name__ == "__main__":
    main()
