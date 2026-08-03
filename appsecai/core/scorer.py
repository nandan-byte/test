#!/usr/bin/env python3
"""
Enhanced Vulnerability Scorer

Uses comprehensive vulnerability framework and enhanced compliance for context-aware scoring.
Implements Multiplicative Scoring Model: BaseScore * ContextMultiplier
"""

import json
import os
import logging
import re
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass
from appsecai.common.utils import get_resource_path, load_appsec_json_data
from enum import Enum

logger = logging.getLogger(__name__)

class RiskLevel(Enum):
    """Risk level enumeration"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"

@dataclass
class EnhancedVulnerabilityScore:
    """Enhanced vulnerability score with detailed breakdown"""
    vulnerability_type: str
    category: str
    base_severity: float
    context_multiplier: float
    applied_modifiers: Dict[str, float]
    final_score: float
    risk_level: RiskLevel
    justifications: List[str]
    ai_justification: Optional[str] = None

class EnhancedVulnerabilityScorer:
    """Enhanced vulnerability scorer using comprehensive framework"""
    
    def __init__(self,
                 framework_config_path: str = "appsecai/risk_profiles/context_modifiers/vulnerability_framework.json",
                 compliance_config_path: str = "appsecai/risk_profiles/context_modifiers/risk_context_template.json"):
        """
        Initialize enhanced vulnerability scorer.
        """
        self.framework_config_path = framework_config_path
        self.compliance_config_path = compliance_config_path
        
        # Load configurations
        self.framework_config = self._load_json_config(framework_config_path)
        self.compliance_config = self._load_json_config(compliance_config_path)
        
        # Initialize scoring components
        self._initialize_scoring_system()
        
    def _deep_merge_dict(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge two dictionaries."""
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge_dict(result[key], value)
            else:
                result[key] = value
        return result
    
    def _load_json_config(self, config_path: str) -> Dict[str, Any]:
        """Load JSON configuration file with error handling"""
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            else:
                logger.warning(f"Configuration file not found: {config_path}")
                return {}
        except Exception as e:
            logger.error(f"Error loading {config_path}: {e}")
            return {}
    
    def _initialize_scoring_system(self):
        """Initialize the enhanced scoring system"""
        try:
            # Get framework components
            self.framework = self.framework_config.get('vulnerability_scoring_framework', {})
            self.vulnerability_categories = self.framework.get('vulnerability_categories', {})
            self.global_context_rules = self.framework.get('global_context_rules', [])
            
            # Scoring methodology
            methodology = self.framework.get('scoring_methodology', {})
            self.max_score = methodology.get('max_score', 5.0)
            
            # Load thresholds with safe defaults matching the new 0-5 scale
            default_thresholds = {"critical": 4.5, "high": 3.5, "medium": 2.5, "low": 1.0, "informational": 0.0}
            self.risk_thresholds = methodology.get('risk_thresholds', default_thresholds)
            
            # Get compliance components
            app_config = self.compliance_config.get('AppSecAI', {})
            
            # Determine the correct directory for appsec_config.json
            import sys
            if getattr(sys, 'frozen', False):
                base_dir = os.path.dirname(sys.executable)
            else:
                base_dir = os.getcwd()
                
            # Load from appsec_config.json if it exists and merge over the default compliance config
            appsec_json_path = os.path.join(base_dir, "appsec_config.json")
            if os.path.exists(appsec_json_path):
                try:
                    custom_config = load_appsec_json_data(appsec_json_path)
                    if "AppSecAI" in custom_config:
                        # Deep merge the user's custom compliance settings
                        logger.info(f"Merging context modifiers from {appsec_json_path}")
                        app_config = self._deep_merge_dict(app_config, custom_config["AppSecAI"])
                except Exception as e:
                    logger.warning(f"Failed to merge {appsec_json_path}: {e}")
            
            self.environment = app_config.get('environment', {})
            self.runtime = app_config.get('runtime', {})
            self.security_controls = app_config.get('security_controls', {})
            self.scoring_config = app_config.get('scoring', {})
            
            # NEW: Add SCA-specific context
            self.sca_context = app_config.get('sca_context', {})
            
            # Get severity mappings - UPDATED to include common variants
            default_sonar_map = {
                "BLOCKER": 8.5, "CRITICAL": 7.5, "MAJOR": 5.0, "MINOR": 2.5, "INFO": 1.0,
                "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5, "INFORMATIONAL": 1.0
            }
            self.sonar_severity_map = self.scoring_config.get('sonar_severity_map', default_sonar_map)
            
            # Ensure merged defaults if config provides partial map
            for k, v in default_sonar_map.items():
                if k not in self.sonar_severity_map:
                    self.sonar_severity_map[k] = v

            self.zap_risk_map = self.scoring_config.get('zap_risk_map', 
                {"High": 7.5, "Medium": 5.0, "Low": 2.5, "Informational": 1.0}
            )
            
            # Get SonarQube auto-mapping
            self.sonar_auto_mapping = app_config.get('sonar_auto_mapping', {})
            self.tag_to_category = {item['tag']: item['category']
                                  for item in self.sonar_auto_mapping.get('tag_to_category', [])}
            
            logger.info("Enhanced scoring system initialized successfully (Multiplicative Model)")
            
            self.max_score = methodology.get('max_score', 10.0)
            
            # Load thresholds with safe defaults matching the 0-10 scale
            default_thresholds = {"critical": 8.5, "high": 7.5, "medium": 5.0, "low": 2.5, "informational": 1.0}
            self.risk_thresholds = methodology.get('risk_thresholds', default_thresholds)
            
        except Exception as e:
            logger.error(f"Error initializing enhanced scoring system: {e}")
            self.vulnerability_categories = {}
            self.global_context_rules = []
            self.max_score = 10.0
            self.risk_thresholds = {"critical": 8.5, "high": 7.5, "medium": 5.0, "low": 2.5, "informational": 1.0}

    def score_sonarqube_vulnerability(self, vulnerability: Dict[str, Any]) -> EnhancedVulnerabilityScore:
        """Score a SonarQube vulnerability."""
        # Extract basic information
        rule_key = vulnerability.get('ruleKey', '')
        
        # Check both 'severity' (Issues) and 'vulnerabilityProbability' (Hotspots)
        severity_str = vulnerability.get('severity') or vulnerability.get('vulnerabilityProbability') or 'LOW'
        severity_str = str(severity_str).upper()
        
        securityCategory = vulnerability.get('securityCategory', '')
        
        # 1. Base Score
        base_severity = self.sonar_severity_map.get(severity_str, 3.0)
        
        # 2. Determine Category
        # 2. Determine Category
        category = self._map_sonarqube_to_category(securityCategory, rule_key)
        category_config = self.vulnerability_categories.get(category, {})
        
        # 3. Calculate Score Components
        base_sev, eff_impact, eff_exploit, exposure_mult, modifiers = self._calculate_score_components(
            category_config, 
            vulnerability, 
            base_severity
        )
        
        # 4. Calculate Final Score
        # Formula: (BaseSev + EffImpact + EffExploitability) * ExposureMultiplier
        raw_final_score = (base_sev + eff_impact + eff_exploit) * exposure_mult
        final_score = min(raw_final_score, self.max_score)
        
        # 5. Determine Risk Level
        risk_level = self._determine_risk_level(final_score)
        
        # Build justifications
        justifications = self._build_justifications(
            category, 
            base_severity, 
            exposure_mult, 
            modifiers, 
            final_score,
            components={
                "base": base_sev,
                "impact": eff_impact,
                "exploitability": eff_exploit
            }
        )
        justifications.append(f"Input Sev: {severity_str}")
        
        # 6. Generate AI Justification for ALL Findings (narrative explanation)
        sast_message = vulnerability.get('message', vulnerability.get('name', rule_key))
        sast_description = vulnerability.get('description', '')
        ai_justification = self._generate_expert_justification(
            v_type="SAST",
            vuln_name=sast_message,
            base_sev=base_severity,
            final_score=final_score,
            modifiers=modifiers,
            description=sast_description,
            scanner_category=category
        )

            
        return EnhancedVulnerabilityScore(
            vulnerability_type=sast_message,
            category=category,
            base_severity=base_severity,
            context_multiplier=exposure_mult, # Using exposure mult as the primary multiplier context
            applied_modifiers=modifiers,
            final_score=round(final_score, 2),
            risk_level=risk_level,
            justifications=justifications,
            ai_justification=ai_justification
        )

    def score_zap_vulnerability(self, vulnerability: Dict[str, Any]) -> EnhancedVulnerabilityScore:
        """Score a ZAP vulnerability."""
        # Extract basic information
        alert_name = vulnerability.get('name', vulnerability.get('Alert', ''))
        risk_level = vulnerability.get('risk', vulnerability.get('Risk', 'Low'))
        alert_id = vulnerability.get('alert_id') or vulnerability.get('id')
        
        # 1. Base Score
        base_severity = self.zap_risk_map.get(risk_level, 3.0)
        
        # 2. Determine Category
        category = self._map_zap_to_category(alert_name, alert_id)
        category_config = self.vulnerability_categories.get(category, {})
        
        # 3. Calculate Score Components
        base_sev, eff_impact, eff_exploit, exposure_mult, modifiers = self._calculate_score_components(
            category_config, 
            vulnerability, 
            base_severity
        )
        
        # 4. Calculate Final Score
        raw_final_score = (base_sev + eff_impact + eff_exploit) * exposure_mult
        final_score = min(raw_final_score, self.max_score)
        
        # 5. Determine Risk Level
        risk_level = self._determine_risk_level(final_score)
        
        # Build justifications
        justifications = self._build_justifications(
            category, 
            base_severity, 
            exposure_mult, 
            modifiers, 
            final_score,
            components={
                "base": base_sev,
                "impact": eff_impact,
                "exploitability": eff_exploit
            }
        )
        
        # 6. Generate AI Justification for ALL Findings (narrative explanation)
        dast_description = vulnerability.get('description', vulnerability.get('desc', ''))
        ai_justification = self._generate_expert_justification(
            v_type="DAST",
            vuln_name=alert_name,
            base_sev=base_severity,
            final_score=final_score,
            modifiers=modifiers,
            description=dast_description,
            scanner_category=category
        )

            
        return EnhancedVulnerabilityScore(
            vulnerability_type=alert_name,
            category=category,
            base_severity=base_severity,
            context_multiplier=exposure_mult,
            applied_modifiers=modifiers,
            final_score=round(final_score, 2),
            risk_level=risk_level,
            justifications=justifications,
            ai_justification=ai_justification
        )

    def score_sca_vulnerability(self, vulnerability: Dict[str, Any], base_score: float, category: str) -> EnhancedVulnerabilityScore:
        """Score an SCA / Trivy vulnerability."""
        alert_name = vulnerability.get('name', vulnerability.get('title', ''))
        severity_str = str(vulnerability.get('risk', vulnerability.get('severity', 'LOW'))).upper()
        
        category_config = self.vulnerability_categories.get(category, {})
        
        # 1. Base Score is passed in for SCA because it's calculated from CVSS in the scanner
        base_severity = base_score
        
        # 2. Calculate Score Components
        base_sev, eff_impact, eff_exploit, exposure_mult, modifiers = self._calculate_score_components(
            category_config, 
            vulnerability, 
            base_severity
        )
        
        # 3. Calculate Final Score
        raw_final_score = (base_sev + eff_impact + eff_exploit) * exposure_mult
        final_score = min(raw_final_score, self.max_score)
        
        # 4. Determine Risk Level
        risk_level = self._determine_risk_level(final_score)
        
        # 5. Build justifications
        justifications = self._build_justifications(
            category, 
            base_severity, 
            exposure_mult, 
            modifiers, 
            final_score,
            components={
                "base": base_sev,
                "impact": eff_impact,
                "exploitability": eff_exploit
            },
            original_level=severity_str
        )
        
        # 6. Generate AI Justification for ALL Findings (narrative explanation)
        sca_description = vulnerability.get('description', vulnerability.get('desc', vulnerability.get('title', '')))
        ai_justification = self._generate_expert_justification(
            v_type="SCA",
            vuln_name=alert_name,
            base_sev=base_severity,
            final_score=final_score,
            modifiers=modifiers,
            description=sca_description,
            scanner_category=category
        )

            
        return EnhancedVulnerabilityScore(
            vulnerability_type=alert_name,
            category=category,
            base_severity=base_severity,
            context_multiplier=exposure_mult,
            applied_modifiers=modifiers,
            final_score=round(final_score, 2),
            risk_level=risk_level,
            justifications=justifications,
            ai_justification=ai_justification
        )

    def _calculate_score_components(self, category_config: Dict[str, Any], vulnerability: Dict[str, Any], base_score: float) -> Tuple[float, float, float, float, Dict[str, float]]:
        """
        Calculate the three components of the score:
        - Adjusted Severity (Base)
        - Effective Impact
        - Effective Exploitability
        
        Returns (adj_severity, eff_impact, eff_exploitability, modifiers)
        """
        modifiers = {}
        
        # 1. Decompose Base Score
        # Check if this is an SCA vulnerability
        is_sca = vulnerability.get('type') == 'sca' or 'package_name' in vulnerability
        
        if is_sca:
            # Custom Ratio for SCA (Trivy): Sev 35%, Imp 32.5%, Exp 32.5%
            base_severity_component = base_score * 0.35
            base_impact_component = base_score * 0.325
            base_exploitability_component = base_score * 0.325
        else:
            # Ratio for SAST (Sonar) & DAST (ZAP): Sev 50%, Imp 25%, Exp 25%
            # This ensures Sev + Imp + Exp approx equals Base Score initially
            base_severity_component = base_score * 0.5
            base_impact_component = base_score * 0.25
            base_exploitability_component = base_score * 0.25
        
        # 2. Calculate Effective Exploitability
        exploit_mult, exploit_reasons = self._calculate_mitigation_multiplier(
            category_config.get('exploit_mitigations', {}), 
            vulnerability, 
            "Exploitability"
        )
        effective_exploitability = base_exploitability_component * exploit_mult
        modifiers.update(exploit_reasons)
        
        # 3. Calculate Effective Impact
        impact_mult, impact_reasons = self._calculate_mitigation_multiplier(
            category_config.get('impact_mitigations', {}), 
            vulnerability, 
            "Impact"
        )
        effective_impact = base_impact_component * impact_mult
        modifiers.update(impact_reasons)
        
        # 4. Calculate Exposure Multiplier (Global & Context Context)
        # We treat these as general multipliers on the Sum
        exposure_mult = 1.0
        
        # Category-specific context modifiers
        # Support both string conditions (SAST/DAST) and object conditions (SCA)
        context_modifiers = category_config.get('context_modifiers', [])
        for mod in context_modifiers:
            # Handle both string and object formats
            if isinstance(mod, str):
                # SAST/DAST format: string condition
                condition = mod
                # For string conditions, we need to extract the justification from the condition itself
                # This is a fallback - ideally all conditions should be objects
                if self._evaluate_condition(condition, vulnerability):
                    # Default multiplier for string conditions (shouldn't happen in new framework)
                    exposure_mult *= 0.9
                    modifiers["Context Modifier"] = 0.9
            elif isinstance(mod, dict):
                # New format: object with condition, adjust, justification
                condition = mod.get('condition', '')
                adjust = mod.get('adjust', {})
                justification = mod.get('justification', 'Context Modifier')
                mult = adjust.get('multiplier')
                
                if mult is not None and self._evaluate_condition(condition, vulnerability):
                    exposure_mult *= float(mult)
                    modifiers[justification] = float(mult)
        
        # Global context rules
        # Skip applying global exposure multipliers for Informational/very low risk findings
        if base_score > 1.5:
            for rule in self.global_context_rules:
                if self._evaluate_condition(rule.get('condition', ''), vulnerability):
                    adjust = rule.get('adjust', {})
                    mult = adjust.get('multiplier')
                    if mult is not None:
                        exposure_mult *= float(mult)
                        modifiers[rule.get('justification', 'Global Rule')] = float(mult)
        
        # CUMULATIVE MULTIPLIER CAP: Prevents extreme score volatility
        # We cap total environmental adjustment between 0.7x and 1.6x
        original_exposure_mult = exposure_mult
        exposure_mult = max(0.70, min(1.60, exposure_mult))
        
        if abs(original_exposure_mult - exposure_mult) > 0.01:
            modifiers['Cumulative Context Cap'] = round(exposure_mult / original_exposure_mult, 2)
        
        # NEW: Apply one-level cap for SCA vulnerabilities only
        is_sca = vulnerability.get('type') == 'sca' or 'package_name' in vulnerability
        if is_sca:
            # Calculate sum of components before exposure multiplier
            components_sum = base_severity_component + effective_impact + effective_exploitability

            # Calculate what the final score would be
            raw_final = components_sum * exposure_mult
            
            # Use Trivy's own severity string to anchor the cap
            sca_severity_str = str(
                vulnerability.get('severity') or vulnerability.get('risk', '')
            ).upper()
            sca_level_map = {
                "CRITICAL": RiskLevel.CRITICAL,
                "HIGH":     RiskLevel.HIGH,
                "MEDIUM":   RiskLevel.MEDIUM,
                "LOW":      RiskLevel.LOW,
            }
            if sca_severity_str in sca_level_map:
                # Use Trivy's severity label as the reliable starting point for the cap
                current_level = sca_level_map[sca_severity_str]
            else:
                # Fallback to mathematical derivation only if no severity string is present
                current_level = self._determine_risk_level(base_score)
            
            # Calculate allowed multiplier range for one-level shift
            # Use components_sum to ensure the cap applies to the final sum of all factors
            min_mult, max_mult = self._calculate_one_level_shift_range(components_sum, current_level)
            
            # Cap the exposure multiplier
            original_mult = exposure_mult
            exposure_mult = max(min_mult, min(max_mult, exposure_mult))
            
            if abs(original_mult - exposure_mult) > 0.01:  # Only log if actually capped
                modifiers['SCA One-Level Cap Applied'] = exposure_mult / original_mult if original_mult != 0 else 1.0
                    
        return base_severity_component, effective_impact, effective_exploitability, exposure_mult, modifiers

    def _calculate_mitigation_multiplier(self, mitigation_model: Dict[str, Any], vulnerability: Dict[str, Any], component_name: str) -> Tuple[float, Dict[str, float]]:
        """
        Calculate multiplier for a specific component (Exploitability or Impact).
        Returns (multiplier, reasons_dict)
        
        Supports both formats:
        - String conditions (SAST/DAST): ["condition_string"]
        - Object conditions (SCA): [{"condition": "...", "adjust": {...}, "justification": "..."}]
        """
        if not mitigation_model:
            return 1.0, {}
            
        multiplier = 1.0
        reasons = {}
        
        # Check if this is an SCA vulnerability
        is_sca = vulnerability.get('type') == 'sca' or 'package_name' in vulnerability
        
        # 1. Check Blocking Controls (Forces near-zero component)
        blocking_controls = mitigation_model.get('blocking_controls', [])
        for item in blocking_controls:
            # Handle both string and object formats
            if isinstance(item, str):
                # SAST/DAST format: string condition
                condition = item
                if self._evaluate_condition(condition, vulnerability):
                    return 0.1, {f"Blocking {component_name} Control": 0.1}
            elif isinstance(item, dict):
                # SCA format: object with condition, adjust, justification
                condition = item.get('condition', '')
                adjust = item.get('adjust', {})
                justification = item.get('justification', f"Blocking {component_name} Control")
                mult = adjust.get('multiplier', 0.1)
                
                if self._evaluate_condition(condition, vulnerability):
                    return mult, {justification: mult}
        
        # 2. Apply Strong Mitigations
        # For SCA: use 0.7 (30% reduction) to prevent extreme shifts
        # For SAST/DAST: keep 0.5 (50% reduction) for backward compatibility
        strong_mult = 0.7 if is_sca else 0.5
        strong_mitigations = mitigation_model.get('strong_mitigations', [])
        for item in strong_mitigations:
            # Handle both string and object formats
            if isinstance(item, str):
                # SAST/DAST format: string condition
                condition = item
                if self._evaluate_condition(condition, vulnerability):
                    multiplier *= strong_mult
                    reasons[f"Strong {component_name} Mitigation"] = strong_mult
            elif isinstance(item, dict):
                # SCA format: object with condition, adjust, justification
                condition = item.get('condition', '')
                adjust = item.get('adjust', {})
                justification = item.get('justification', f"Strong {component_name} Mitigation")
                mult = adjust.get('multiplier', strong_mult)
                
                if self._evaluate_condition(condition, vulnerability):
                    multiplier *= mult
                    reasons[justification] = mult
        
        # 3. Apply Weak/Moderate Mitigations
        # For SCA: use 0.9 (10% reduction) to prevent extreme shifts
        # For SAST/DAST: keep 0.8 (20% reduction) for backward compatibility
        weak_mult = 0.9 if is_sca else 0.8
        weak_mitigations = mitigation_model.get('weak_mitigations', [])
        for item in weak_mitigations:
            # Handle both string and object formats
            if isinstance(item, str):
                # SAST/DAST format: string condition
                condition = item
                if self._evaluate_condition(condition, vulnerability):
                    multiplier *= weak_mult
                    reasons[f"Weak {component_name} Mitigation"] = weak_mult
            elif isinstance(item, dict):
                # SCA format: object with condition, adjust, justification
                condition = item.get('condition', '')
                adjust = item.get('adjust', {})
                justification = item.get('justification', f"Weak {component_name} Mitigation")
                mult = adjust.get('multiplier', weak_mult)
                
                if self._evaluate_condition(condition, vulnerability):
                    multiplier *= mult
                    reasons[justification] = mult
        
        # 4. Apply Moderate Mitigations (SCA-specific, typically not present in SAST/DAST)
        moderate_mitigations = mitigation_model.get('moderate_mitigations', [])
        for item in moderate_mitigations:
            # Handle both string and object formats
            if isinstance(item, str):
                # String format
                condition = item
                if self._evaluate_condition(condition, vulnerability):
                    multiplier *= 0.8
                    reasons[f"Moderate {component_name} Mitigation"] = 0.8
            elif isinstance(item, dict):
                # SCA format: object with condition, adjust, justification
                condition = item.get('condition', '')
                adjust = item.get('adjust', {})
                justification = item.get('justification', f"Moderate {component_name} Mitigation")
                mult = adjust.get('multiplier', 0.8)
                
                if self._evaluate_condition(condition, vulnerability):
                    multiplier *= mult
                    reasons[justification] = mult
                
        return multiplier, reasons
    def _calculate_one_level_shift_range(self, components_sum: float, current_level: RiskLevel) -> Tuple[float, float]:
        """
        Calculate the allowed multiplier range for SCA to ensure only one-level risk shifts.

        Args:
            components_sum: The sum of score components (base + impact + exploitability) before exposure multiplier
            current_level: The original risk level reported by the scanner

        Returns:
            Tuple of (min_multiplier, max_multiplier) to cap the exposure multiplier
        """
        # Define risk level boundaries
        level_boundaries = {
            RiskLevel.CRITICAL: (self.risk_thresholds.get('critical', 4.5), self.max_score),
            RiskLevel.HIGH: (self.risk_thresholds.get('high', 3.5), self.risk_thresholds.get('critical', 4.5)),
            RiskLevel.MEDIUM: (self.risk_thresholds.get('medium', 2.0), self.risk_thresholds.get('high', 3.5)),
            RiskLevel.LOW: (self.risk_thresholds.get('low', 1.0), self.risk_thresholds.get('medium', 2.0)),
            RiskLevel.INFORMATIONAL: (0.0, self.risk_thresholds.get('low', 1.0))
        }

        # Get current level boundaries
        current_min, current_max = level_boundaries.get(current_level, (0.0, self.max_score))

        # Calculate one level up and one level down boundaries
        level_order = [RiskLevel.INFORMATIONAL, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        current_index = level_order.index(current_level)

        # One level down (if possible)
        if current_index > 0:
            one_level_down = level_order[current_index - 1]
            down_min, down_max = level_boundaries.get(one_level_down, (0.0, current_min))
        else:
            down_min, down_max = (0.0, current_min)

        # One level up (if possible)
        if current_index < len(level_order) - 1:
            one_level_up = level_order[current_index + 1]
            up_min, up_max = level_boundaries.get(one_level_up, (current_max, self.max_score))
        else:
            up_min, up_max = (current_max, self.max_score)

        # Calculate multiplier range
        # Minimum multiplier: allows dropping to one level down (but not lower)
        # Maximum multiplier: allows rising to one level up (but not higher)

        if components_sum > 0:
            # For downward shift: we want final_score to stay above down_min
            # final_score = components_sum * multiplier
            min_multiplier = down_min / components_sum if down_min > 0 else 0.1

            # For upward shift: we want final_score to stay strictly below up_max
            # Subtracted 0.01 to prevent the score from mathematically bleeding into the boundary
            # of the next higher risk level.
            max_multiplier = (up_max - 0.01) / components_sum
        else:
            # Edge case: components_sum is 0
            min_multiplier = 0.1
            max_multiplier = 2.0

        # Ensure reasonable bounds (don't allow extreme multipliers)
        min_multiplier = max(0.5, min_multiplier)  # Don't reduce by more than 50%
        max_multiplier = min(2.0, max_multiplier)  # Don't increase by more than 2x

        return min_multiplier, max_multiplier


    def _evaluate_condition(self, condition: str, vulnerability: Dict[str, Any] = None) -> bool:
        """
        Evaluate condition string safely with support for nested object paths.
        
        Supports conditions like:
        - environment.internet_exposure == 'internal_only'
        - sca_context.runtime_behavior.sandboxing_enabled == true
        - vulnerability.type == 'sca'
        """
        try:
            # Create evaluation context
            context = {
                'environment': self.environment,
                'security_controls': self.security_controls,
                'runtime': self.runtime,
                'sca_context': self.sca_context,
                'vulnerability': vulnerability or {},
                'true': True, 'false': False, 'null': None
            }
            
            # Helper function to navigate nested paths and return the value
            def get_nested_value(path_str: str) -> Any:
                """Navigate nested dictionary path like 'sca_context.runtime_behavior.sandboxing_enabled'"""
                parts = path_str.split('.')
                obj = context.get(parts[0], {})
                
                # Navigate through nested structure
                for part in parts[1:]:
                    if isinstance(obj, dict):
                        obj = obj.get(part)
                        if obj is None:
                            return None
                    else:
                        return None
                
                return obj
            
            # Replace object paths with their values
            # Match patterns like: root.field or root.nested.field or root.nested.deeply.field
            # We need to match the longest path first to handle nested structures correctly
            def replace_lookup(match):
                path = match.group(0)
                value = get_nested_value(path)
                
                # Format the value for eval
                if isinstance(value, str):
                    return f"'{value}'"
                elif isinstance(value, bool):
                    return str(value)
                elif value is None:
                    return 'None'
                elif isinstance(value, (int, float)):
                    return str(value)
                else:
                    return 'None'
            
            # Parse the condition and replace all object paths
            # Pattern matches: word.word or word.word.word or word.word.word.word etc.
            # This handles nested paths like sca_context.runtime_behavior.sandboxing_enabled
            parsed_condition = condition
            
            # Match any path starting with known root objects
            # Pattern: (root)\.([\w\.]+) matches root.anything.with.dots
            for root in ['environment', 'security_controls', 'runtime', 'sca_context', 'vulnerability']:
                # Use a more specific pattern that captures the entire nested path
                # This regex matches root.field or root.field.subfield or root.field.subfield.deepfield
                pattern = rf'\b{root}\.[\w\.]+'
                parsed_condition = re.sub(pattern, replace_lookup, parsed_condition)
            
            # Allow clean evaluation
            safe_locals = {'true': True, 'false': False, 'null': None, 'True': True, 'False': False, 'None': None}
            result = eval(parsed_condition, {"__builtins__": None}, safe_locals)
            return bool(result)
            
        except Exception as e:
            logger.debug(f"Condition evaluation failed for '{condition}': {e}")
            return False

    def _determine_risk_level(self, score: float) -> RiskLevel:
        """Determine risk level based on final score."""
        # Ensure scores like 0.0 don't cause issues
        if score >= self.risk_thresholds.get("critical", 4.5):
            return RiskLevel.CRITICAL
        elif score >= self.risk_thresholds.get('high', 3.5):
            return RiskLevel.HIGH
        elif score >= self.risk_thresholds.get('medium', 2.0):
            return RiskLevel.MEDIUM
        elif score >= self.risk_thresholds.get('low', 1.0):
            return RiskLevel.LOW
        else:
            return RiskLevel.INFORMATIONAL

    def _build_justifications(self, category: str, base_severity: float, total_multiplier: float, 
                            modifiers: Dict[str, float], final: float, components: Dict[str, float] = None,
                            original_level: str = None) -> List[str]:
        """Build distinct list of score justifications with smart filtering."""
        justs = []
        justs.append(f"Category: {category}")
        
        if components:
            justs.append(f"Base Severity Component: {round(components['base'], 2)}")
            justs.append(f"Effective Impact: {round(components['impact'], 2)}")
            justs.append(f"Effective Exploitability: {round(components['exploitability'], 2)}")
            justs.append(f"Exposure Multiplier: x{total_multiplier}")
        else:
            justs.append(f"Base Severity Score: {base_severity}")
            justs.append(f"Total Context Multiplier: x{total_multiplier}")
        
        # Smart filtering: Show only relevant modifiers based on risk direction
        if modifiers:
            # Determine if risk increased or decreased
            # 1. First check if the standard risk level increased (e.g. Low -> Medium)
            
            # Use provided original_level if available (preferred for alignment with scanner labels)
            if original_level:
                # Normalize and map to RiskLevel enum if possible
                try:
                    base_level = RiskLevel(original_level.title())
                except:
                    # Fallback to mathematical determination if string mapping fails
                    base_level = self._determine_risk_level(base_severity)
            else:
                base_level = self._determine_risk_level(base_severity)
                
            final_level = self._determine_risk_level(final)
            
            # Map levels to numeric for comparison
            level_ranks = {'Informational': 0, 'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
            base_rank = level_ranks.get(base_level.value if hasattr(base_level, 'value') else str(base_level), 0)
            final_rank = level_ranks.get(final_level.value, 0)
            
            risk_increased = final_rank > base_rank or (final > base_severity and final_rank >= base_rank)
            risk_decreased = final_rank < base_rank or (final < base_severity and final_rank <= base_rank)
            
            # Filter modifiers based on direction
            # Exclude internal system modifiers from user-facing report
            INTERNAL_MODIFIERS = {'SCA One-Level Cap Applied'}
            increasing_mods = {k: v for k, v in modifiers.items() if v > 1.0 and k not in INTERNAL_MODIFIERS}
            decreasing_mods = {k: v for k, v in modifiers.items() if v < 1.0 and k not in INTERNAL_MODIFIERS}
            
            if risk_increased and increasing_mods:
                # Show only factors that INCREASED risk
                justs.append("Risk Increasing Factors:")
                for reason, m in increasing_mods.items():
                    justs.append(f"  • {reason}")
            elif risk_decreased and decreasing_mods:
                # Show only factors that DECREASED risk
                justs.append("Risk Decreasing Factors:")
                for reason, m in decreasing_mods.items():
                    justs.append(f"  • {reason}")
            elif not risk_increased and not risk_decreased:
                # Risk stayed the same, show all modifiers (excluding internal)
                visible_mods = {k: v for k, v in modifiers.items() if k not in INTERNAL_MODIFIERS}
                if visible_mods:
                    justs.append("Applied Modifiers:")
                    for reason, m in visible_mods.items():
                        justs.append(f"  • {reason}")
        
        if components:
            justs.append(f"Final Score: {final} ((Sev+Imp+Exp) * Exposure)")
        else:
            justs.append(f"Final Score: {final} (Base * Multiplier)")
            
        return justs

    # Keep helper methods for mapping
    def _map_sonarqube_to_category(self, securityCategory: str, rule_key: str = None) -> str:
        # Simplistic mapping for brevity, same as before
        if rule_key and 'S5852' in rule_key: return 'Denial of Service (DoS)'
        if securityCategory:
            best_match = None
            max_len = 0
            
            for tag, category in self.tag_to_category.items():
                if tag.lower() in securityCategory.lower():
                    if len(tag) > max_len:
                        max_len = len(tag)
                        best_match = category
            
            if best_match:
                return best_match
                
        return 'Infrastructure Security'

    def _map_zap_to_category(self, alert_name: str, alert_id: str = None) -> str:
        name_lower = alert_name.lower()
        if 'injection' in name_lower or 'xss' in name_lower: return 'Injection'
        if 'csrf' in name_lower: return 'API Security'
        if 'header' in name_lower: return 'HTTP Security Headers'
        return 'Infrastructure Security'

    def get_framework_justification(self, category: str, vulnerability: Dict[str, Any]) -> str:
        """Get context-aware framework justification."""
        enhanced_justs = vulnerability.get('enhanced_justifications', [])
        
        # If we have detailed justifications, use the most relevant one as a summary
        if enhanced_justs:
            # Look for specific risk factors first
            priority_factors = [j for j in enhanced_justs if 'Risk Increasing Factors:' in j or 'Risk Decreasing Factors:' in j or 'Applied Modifiers:' in j]
            if priority_factors:
                # Take the first one and clean it up as the primary summary
                summary = priority_factors[0].strip()
                # Remove the prefix for a cleaner summary
                summary = re.sub(r'^(Risk Increasing Factors:|Risk Decreasing Factors:|Applied Modifiers:)\s*', '', summary)
                # Remove any trailing scores/multipliers
                summary = re.sub(r'\s*\(\s*x\d+(\.\d+)?\s*\)\s*$', '', summary)
                return f"{category}: {summary}"
            
            # Fallback to the first bullet point if exists
            bullets = [j for j in enhanced_justs if '•' in j]
            if bullets:
                summary = bullets[0].replace('•', '').strip()
                return f"{category}: {summary}"

        # Default fallback if no detailed justifications are found
        return f"{category} vulnerability requiring attention based on risk assessment."

    def _auto_refresh_tag_mappings(self):
        pass

    def _generate_expert_justification(self, v_type: str, vuln_name: str, base_sev: float, final_score: float, modifiers: Dict[str, float], description: str = "", scanner_category: str = "") -> str:
        """
        Generate a professional technical justification paragraph without using an LLM.
        Uses a Semantic Context-Aware Template Engine for highly accurate reporting.
        Searches BOTH the package/finding name AND the CVE/finding description for keywords
        to ensure 100% accurate classification for SCA, SAST, and DAST findings.
        """
        # Combine name + description for maximum keyword coverage
        vuln_lower = (vuln_name + " " + description).lower()
        
        # 1. Determine Vuln Type (Expanded Keywords)
        is_dos = any(k in vuln_lower for k in [
            "dos", "denial of service", "exhaustion", "decompression",
            "zip bomb", "infinite loop", "memory exhaustion", "cpu exhaustion",
            "control flow", "abort signal", "pending state", "hang indefinitely"
        ])
        is_injection = any(k in vuln_lower for k in [
            "sqli", "injection", "xss", "cross-site", "prototype pollution",
            "rce", "command execution", "path traversal", "xml external entity",
            "crlf", "ssrf", "server-side request forgery", "arbitrary code",
            "arbitrary file read", "file disclosure", "code execution", "code evaluation",
            "null byte", "encoding bypass", "eval(", "unsafe deserialization",
            "template injection", "sourcemappingurl"
        ])
        is_supply_chain = any(k in vuln_lower for k in [
            "dependency", "supply chain", "malicious package", "typosquatting", "hijack"
        ])
        is_auth = any(k in vuln_lower for k in [
            "auth", "credential", "signature", "forgery", "secret", "token",
            "mitm", "proxy leak", "memory disclosure", "uninitialized memory",
            "information disclosure", "sensitive data", "sensitive information",
            "certificate", "cryptographic"
        ])
        
        # Determine category based on matched keywords (priority order matters)
        if is_injection:
            vuln_category = "Injection / RCE"
        elif is_dos:
            vuln_category = "Resource Exhaustion / DoS"
        elif is_supply_chain:
            vuln_category = "Supply Chain"
        elif is_auth:
            vuln_category = "Authentication / Data Security"
        else:
            vuln_category = "Business Logic"

        # Fallback: if keyword engine still lands on Business Logic, trust the scanner-provided category
        if vuln_category == "Business Logic" and scanner_category:
            cat_lower = scanner_category.lower()
            if any(k in cat_lower for k in ["injection", "xss", "rce", "traversal", "command"]):
                vuln_category = "Injection / RCE"
            elif any(k in cat_lower for k in ["dos", "denial", "exhaustion"]):
                vuln_category = "Resource Exhaustion / DoS"
            elif any(k in cat_lower for k in ["supply", "dependency", "chain"]):
                vuln_category = "Supply Chain"
            elif any(k in cat_lower for k in ["auth", "crypto", "credential", "sensitive", "data"]):
                vuln_category = "Authentication / Data Security"

        is_business_logic = vuln_category == "Business Logic"
        
        # 2. Extract Active Context
        deployment = self.environment.get('deployment_type', 'internal')
        internet = self.environment.get('internet_exposure', False)
        pii = self.environment.get('pii_present', False)
        data_class = self.environment.get('data_classification', 'internal')
        
        # 3. Categorize Controls
        preventive = []
        detective = []
        governance = []
        
        is_prototype_pollution = "prototype pollution" in vuln_lower
        
        if self.security_controls.get('waf_enabled') and (is_injection or is_dos):
            if is_prototype_pollution:
                preventive.append("WAF (limited protection for pollution)")
            else:
                preventive.append("WAF")
                
        if self.runtime.get('cpu_limits_enforced') and is_dos:
            preventive.append("CPU limits")
        if self.runtime.get('memory_limits_enforced') and is_dos:
            preventive.append("memory limits")
        if self.runtime.get('rate_limiting_enabled') and is_dos:
            preventive.append("rate limiting")
            
        if self.security_controls.get('api_input_validation') and is_injection:
            preventive.append("API input validation")
            
        if self.runtime.get('sandboxing_enabled') and (is_injection or is_supply_chain or is_business_logic):
            preventive.append("container sandboxing")
            
        if self.environment.get('https_enabled') and is_auth:
            if "forge" in vuln_lower or "signature" in vuln_lower:
                preventive.append("cryptographic transport protections (requires robust key management)")
            else:
                preventive.append("enforced HTTPS")
                
        if self.runtime.get('runtime_monitoring_enabled'):
            detective.append("runtime monitoring")
        if self.security_controls.get('ids_enabled'):
            detective.append("IDS")
            
        if self.sca_context.get('dependency_management', {}).get('sbom_generation_enabled') and is_supply_chain:
            governance.append("SBOM tracking")
            
        # 4. Construct Mechanism Clause
        mechanism = "mitigates direct exploitability"
        if is_injection:
            mechanism = "mitigates direct exploitability by intercepting malicious payloads at the application boundary and strictly containing the post-exploitation blast radius."
        elif is_dos:
            mechanism = "mitigates direct exploitability by capping available system resources and aggressively throttling anomalous request floods to ensure continuous availability."
        elif is_supply_chain:
            mechanism = "mitigates direct exploitability by validating artifact provenance and restricting execution environments to prevent untrusted code execution."
        elif is_auth:
            mechanism = "mitigates direct exploitability by enforcing strict cryptographic transport and access validation, eliminating transit interception vectors."

        # 5. Build Narrative
        prev_str = " and ".join(preventive) if len(preventive) <= 2 else ", ".join(preventive[:-1]) + ", and " + preventive[-1] if preventive else ""
        det_str = " and ".join(detective) if len(detective) <= 2 else ", ".join(detective[:-1]) + ", and " + detective[-1] if detective else ""
        gov_str = " and ".join(governance) if len(governance) <= 2 else ", ".join(governance[:-1]) + ", and " + governance[-1] if governance else ""
        
        direction = "lowered" if final_score < base_sev else "elevated"
        if abs(final_score - base_sev) < 0.2:
            direction = "validated"
            
        clean_vuln_name = vuln_name.strip() if vuln_name else "Unspecified vulnerability"
        
        justification = f"The identified {vuln_category} finding '{clean_vuln_name}' poses a distinct risk to the environment. "
        justification += f"Operating within a {deployment} context" + (" (Internet-facing)" if internet else "") + f" handling {data_class} data" + (", including PII, " if pii else ", ")
        
        if prev_str:
            justification += f"the direct exploitability of this issue is actively mitigated by the presence of {prev_str}, which {mechanism} "
        else:
            justification += f"there are currently limited active preventive controls tailored specifically to block this class of attack. "
            
        if det_str:
            justification += f"Furthermore, compensating detective controls (including {det_str}) provide critical threat visibility to facilitate rapid incident response. "
            
        if gov_str:
            justification += f"Additionally, governance mechanisms such as {gov_str} reinforce technical hygiene, though they do not actively reduce direct exploitability. "
            
        base_lvl = self._determine_risk_level(base_sev).name.title()
        final_lvl = self._determine_risk_level(final_score).name.title()
        
        # Guard: if both bands are the same, always say "validated" regardless of raw score delta
        if final_lvl == base_lvl:
            direction = "validated"
        
        if final_score < base_sev and final_lvl != base_lvl:
            justification += f"By successfully containing the potential blast radius, the residual risk was definitively {direction} to {final_lvl} (Base: {base_lvl})."
        elif direction == "validated":
            justification += f"The residual risk was validated at {final_lvl}."
        else:
            justification += f"The residual risk was explicitly {direction} to {final_lvl}."
            
        return justification

def main():
    """Test the enhanced vulnerability scorer"""
    scorer = EnhancedVulnerabilityScorer()
    
    # Test SonarQube vulnerability
    sonar_vuln = {
        'ruleKey': 'java:S2068',
        'message': 'Hard-coded password found',
        'severity': 'HIGH',  # Issue Field
        'securityCategory': 'security-features'
    }
    
    score = scorer.score_sonarqube_vulnerability(sonar_vuln)
    print("\n🧪 Test: SonarQube High Severity (Severity Field)")
    print(f"Base: {score.base_severity}")
    print(f"Multiplier: {score.context_multiplier}")
    print(f"Final: {score.final_score}")
    print(f"Risk: {score.risk_level.value}")
    
    # Test Fallback
    sonar_vuln_2 = {
        'ruleKey': 'java:S2068', 
        'vulnerabilityProbability': 'MEDIUM', # Hotspot Field
        'securityCategory': 'security-features'
    }
    score2 = scorer.score_sonarqube_vulnerability(sonar_vuln_2)
    print("\n🧪 Test: SonarQube Medium (Hotspot Field)")
    print(f"Base: {score2.base_severity}")
    print(f"Final: {score2.final_score}")
    print(f"Risk: {score2.risk_level.value}")

if __name__ == "__main__":
    main()