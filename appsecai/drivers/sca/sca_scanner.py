"""
Trivy SCA Scanner / Analyzer

Ingests Trivy JSON reports (SCA / image / filesystem scans), normalizes
vulnerabilities into the common AppSecAI format, and applies the existing
enhanced vulnerability scoring framework for risk-based reprioritization.
"""

import json
import os
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from appsecai.core.scorer import (
    EnhancedVulnerabilityScorer,
    RiskLevel,
)
from appsecai.drivers.sca.sca_category_mapper import SCACategoryMapper

logger = logging.getLogger(__name__)


@dataclass
class SCAScanResult:
    """Result of Trivy SCA analysis."""

    scan_id: str
    target: str
    scan_source: str
    start_time: datetime
    end_time: datetime
    vulnerabilities: List[Dict[str, Any]]
    summary: Dict[str, Any]
    input_report_path: str
    success: bool
    error_message: Optional[str] = None


class TrivySCAScanner:
    """
    Adapter that reads Trivy JSON reports and converts them into
    AppSecAI's normalized vulnerability representation with risk scores.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.scorer = EnhancedVulnerabilityScorer()
        self.category_mapper = SCACategoryMapper()

    def analyze_report(
        self,
        trivy_report_path: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> SCAScanResult:
        """
        Analyze a Trivy JSON report and reprioritize vulnerabilities.

        Args:
            trivy_report_path: Path to Trivy JSON report.
            options: Optional analysis options (threshold, output_dir, etc.).
        """
        options = options or {}
        scan_id = f"sca_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        start_time = datetime.now()

        logger.info(f"Starting Trivy SCA analysis {scan_id} for: {trivy_report_path}")

        try:
            trivy_path = Path(trivy_report_path)
            if not trivy_path.exists():
                raise FileNotFoundError(f"Trivy report not found: {trivy_report_path}")

            with trivy_path.open("r", encoding="utf-8") as f:
                report_data = json.load(f)

            artifact_name = report_data.get("ArtifactName") or report_data.get("Target") or "unknown-artifact"
            scan_source = report_data.get("Scanner", {}).get("Name", "trivy")

            normalized_vulns: List[Dict[str, Any]] = []

            results = report_data.get("Results", [])
            
            # First, count total vulnerabilities across all results
            total_vulns = 0
            for result in results:
                total_vulns += len(result.get("Vulnerabilities") or [])
                total_vulns += len(result.get("Misconfigurations") or [])
                total_vulns += len(result.get("Secrets") or [])
            
            print(f"\n[PRIORITIZATION] Processing {total_vulns} vulnerabilities with threshold: {self._resolve_threshold(options)}")
            
            vuln_counter = 0
            for result in results:
                target = result.get("Target", artifact_name)
                # Trivy uses both "Vulnerabilities" and (in some modes) "Vulnerabilities" inside each result
                all_findings = []
                all_findings.extend(result.get("Vulnerabilities") or [])
                
                # Incorporate Misconfigurations to ensure total count parity
                for m in (result.get("Misconfigurations") or []):
                    m["VulnerabilityID"] = m.get("ID")
                    m["PkgName"] = m.get("Type") or target
                    m["Title"] = m.get("Title") or m.get("Message") or "Configuration Flaw"
                    all_findings.append(m)
                    
                # Incorporate Secrets
                for s in (result.get("Secrets") or []):
                    s["VulnerabilityID"] = s.get("RuleID")
                    s["PkgName"] = s.get("Category") or "Secret"
                    s["Title"] = s.get("Title") or "Exposed Secret"
                    all_findings.append(s)

                for idx, v in enumerate(all_findings, start=1):
                    vuln_counter += 1
                    print(f"\n--- Vulnerability {vuln_counter}/{total_vulns} ---")
                    norm = self._normalize_trivy_vulnerability(v, target, artifact_name, idx)
                    scored = self._score_sca_vulnerability(norm)
                    normalized_vulns.append(scored)

            # Apply threshold-based prioritization using the same environment variable
            threshold = self._resolve_threshold(options)
            prioritized_vulns = [v for v in normalized_vulns if v.get("risk_score", 0) >= threshold]

            prioritized_vulns.sort(key=lambda x: x.get("risk_score", 0), reverse=True)

            summary = self._create_summary(normalized_vulns, prioritized_vulns, threshold, artifact_name)

            end_time = datetime.now()

            logger.info(
                f"Trivy SCA analysis completed: {len(prioritized_vulns)} prioritized "
                f"of {len(normalized_vulns)} total vulnerabilities"
            )

            return SCAScanResult(
                scan_id=scan_id,
                target=artifact_name,
                scan_source=scan_source,
                start_time=start_time,
                end_time=end_time,
                vulnerabilities=normalized_vulns,
                summary=summary,
                input_report_path=str(trivy_path),
                success=True,
            )

        except Exception as e:
            logger.error(f"Trivy SCA analysis failed: {e}", exc_info=True)
            end_time = datetime.now()
            return SCAScanResult(
                scan_id=scan_id,
                target="unknown",
                scan_source="trivy",
                start_time=start_time,
                end_time=end_time,
                vulnerabilities=[],
                summary={},
                input_report_path=trivy_report_path,
                success=False,
                error_message=str(e),
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _normalize_trivy_vulnerability(
        self,
        vuln: Dict[str, Any],
        target: str,
        artifact_name: str,
        index: int,
    ) -> Dict[str, Any]:
        """
        Map a single Trivy vulnerability entry into the common vulnerability model.
        """
        vuln_id = vuln.get("VulnerabilityID") or vuln.get("ID") or f"{artifact_name}_{index}"
        pkg_name = vuln.get("PkgName") or vuln.get("PackageName") or "unknown-package"
        installed = vuln.get("InstalledVersion") or vuln.get("InstalledVersion", "")
        fixed = vuln.get("FixedVersion") or vuln.get("FixedVersion", "")
        severity = (vuln.get("Severity") or "LOW").capitalize()

        title = vuln.get("Title") or vuln.get("Description") or vuln_id
        description = vuln.get("Description") or ""

        primary_url = vuln.get("PrimaryURL") or ""
        references = vuln.get("References") or []

        cvss_score = self._extract_cvss_score(vuln)
        
        # Extract CWE IDs for accurate category mapping
        cwe_ids = vuln.get("CweIDs") or []
        cwe_id = cwe_ids[0] if cwe_ids else None

        normalized = {
            "id": f"sca_{vuln_id}",
            "source_id": vuln_id,
            "type": "sca",
            "scanner": "trivy",
            "target": target,
            "artifact": artifact_name,
            "severity": severity,
            "title": title,
            "description": description,
            "package_name": pkg_name,
            "installed_version": installed,
            "fixed_version": fixed,
            "cvss_score": cvss_score,
            "cwe_id": cwe_id,
            "cwe_ids": cwe_ids,
            "data_source": vuln.get("DataSource"),
            "primary_url": primary_url,
            "references": references,
            "raw_data": vuln,
        }

        return normalized

    def _extract_cvss_score(self, vuln: Dict[str, Any]) -> Optional[float]:
        """
        Extract the most relevant CVSS v3 score from Trivy vulnerability entry.
        """
        cvss = vuln.get("CVSS") or {}
        if isinstance(cvss, dict):
            # Trivy often nests by source name (e.g. "nvd", "redhat") -> {V3Score: ...}
            for source_data in cvss.values():
                if isinstance(source_data, dict):
                    v3 = source_data.get("V3Score") or source_data.get("V2Score")
                    if isinstance(v3, (int, float)):
                        return float(v3)
        # Fallback: some formats may have a flat "CVSS" numeric field
        if isinstance(cvss, (int, float)):
            return float(cvss)
        return None

    def _score_sca_vulnerability(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply the enhanced scoring framework to an SCA / Trivy vulnerability.

        We map SCA findings into a generic "Dependency" category so that the
        same prioritization engine used for SAST/DAST can be reused.
        """
        # Derive a base score in the same 0–20 range used by the framework
        cvss = vuln.get("cvss_score")
        severity = str(vuln.get("severity", "Low")).upper()
        
        if isinstance(cvss, (int, float)):
            base_score = float(cvss)
        else:
            # Reasonable defaults on a 0-10 scale
            sev_map = {
                "CRITICAL": 8.5,
                "HIGH": 7.5,
                "MEDIUM": 5.0,
                "LOW": 2.5,
            }
            base_score = sev_map.get(severity, 2.5)

        # Log scoring context to CLI similar to SAST/DAST scorer
        source_id = vuln.get("source_id") or vuln.get("id")
        logger.info("🧮 [SCA SCORER] Starting calculation for: '%s'", source_id)
        logger.info("✅ [ENHANCED] Using enhanced vulnerability scorer")
        if isinstance(cvss, (int, float)):
            logger.info(
                "📊 [BASE SEVERITY] CVSS %.1f mapped to base score %.1f",
                float(cvss),
                base_score,
            )
        else:
            logger.info(
                "📊 [BASE SEVERITY] '%s' mapped to base score %.1f",
                vuln.get("severity", "Low"),
                base_score,
            )

        # Build a minimal vulnerability dict for the scorer API
        dep_vuln = {
            "type": "sca",  # CRITICAL: Mark this as an SCA vulnerability for context-aware scoring
            "name": vuln.get("title", vuln.get("source_id")),
            "risk": vuln.get("severity", "Low"),
            "description": vuln.get("description", ""),
            "package_name": vuln.get("package_name"),
            "installed_version": vuln.get("installed_version"),
            "fixed_version": vuln.get("fixed_version"),
            "cwe_id": vuln.get("cwe_id"),
            "raw_data": vuln.get("raw_data"),
        }

        # Use intelligent category mapping based on vulnerability characteristics
        try:
            # Map vulnerability to appropriate category using CWE, description, and package analysis
            category = self.category_mapper.map_vulnerability_to_category(dep_vuln)
            
            # Get category justification for transparency
            category_justification = self.category_mapper.get_category_justification(dep_vuln, category)
            
            # Log the mapping decision
            logger.info(f"🏷️  [CATEGORY MAPPING] {category} - {category_justification}")

            category_config = self.scorer.vulnerability_categories.get(category, {})

            # Use the centralized SCA scoring method from the scorer
            # This method handles the One-Level Cap and AI justification generation
            scored_result = self.scorer.score_sca_vulnerability(
                vulnerability=dep_vuln,
                base_score=base_score,
                category=category
            )

            # Extract fields for CLI logging and result storage
            final_score = scored_result.final_score
            risk_level_enum = scored_result.risk_level
            modifiers = scored_result.applied_modifiers
            justifications = scored_result.justifications
            ai_just = scored_result.ai_justification
            exposure_mult = scored_result.context_multiplier

            # Human-readable logging mirroring SAST scorer output
            logger.info("🏷️  [CATEGORY] '%s'", category)
            if modifiers:
                modifier_summary = ", ".join(
                    f"{name}: x{multiplier}" for name, multiplier in modifiers.items()
                )
            else:
                modifier_summary = "No additional context modifiers applied"

            logger.info(
                "🧩 [ADJUSTMENTS] Exposure multiplier %.2f, Modifiers: %s",
                exposure_mult,
                modifier_summary,
            )
            
            logger.info(
                "🎯 [FINAL RESULT] Score: %.1f → Risk: %s",
                final_score,
                risk_level_enum.value,
            )

            if ai_just:
                logger.info(f"🤖 [AI JUSTIFICATION] {ai_just}")

            vuln["risk_score"] = round(float(final_score), 2)
            vuln["risk_level"] = risk_level_enum.value
            vuln["enhanced_justifications"] = justifications
            vuln["ai_justification"] = ai_just
            vuln["category"] = category

        except Exception as e:
            logger.warning(f"Enhanced scoring for SCA vulnerability failed, using fallback: {e}")
            # Fallback: simple mapping based on severity
            severity = str(vuln.get("severity", "Low")).capitalize()
            fallback_scores = {
                "Critical": 8.5,
                "High": 7.5,
                "Medium": 5.0,
                "Low": 2.5,
            }
            score = fallback_scores.get(severity, 2.5)
            vuln["risk_score"] = score
            vuln["risk_level"] = "High" if score >= 7.5 else "Medium"

        return vuln

    def _resolve_threshold(self, options: Dict[str, Any]) -> float:
        """
        Determine the vulnerability threshold score, mirroring SAST/DAST logic.
        """
        if "threshold" in options and options["threshold"] is not None:
            return float(options["threshold"])

        # Prefer config threshold if provided
        cfg_threshold = None
        try:
            cfg_threshold = (
                self.config.get("vulnerability_scoring", {}).get("threshold_score")
                or self.config.get("threshold_score")
            )
        except Exception:
            cfg_threshold = None

        if cfg_threshold is not None:
            try:
                return float(cfg_threshold)
            except (ValueError, TypeError):
                pass

        env_thresh = os.environ.get("VULNERABILITY_THRESHOLD")
        if env_thresh:
            try:
                return float(env_thresh)
            except (ValueError, TypeError):
                pass

        # Safe default if nothing is configured
        return 5.0

    def _create_summary(
        self,
        all_vulns: List[Dict[str, Any]],
        prioritized_vulns: List[Dict[str, Any]],
        threshold: int,
        artifact_name: str,
    ) -> Dict[str, Any]:
        """Build a simple summary for CLI output and JSON metadata."""
        severity_counts_all: Dict[str, int] = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
        }
        severity_counts_prioritized = severity_counts_all.copy()

        for v in all_vulns:
            sev = str(v.get("severity", "Low")).capitalize()
            if sev in severity_counts_all:
                severity_counts_all[sev] += 1

        for v in prioritized_vulns:
            sev = str(v.get("severity", "Low")).capitalize()
            if sev in severity_counts_prioritized:
                severity_counts_prioritized[sev] += 1

        print("\n📊 SCA (Trivy) VULNERABILITY ANALYSIS:")
        print(f"   Target artifact: {artifact_name}")
        print(f"   Total vulnerabilities parsed: {len(all_vulns)}")
        print(f"   Prioritization threshold (risk_score): {threshold}")
        print(f"   Prioritized vulnerabilities: {len(prioritized_vulns)}")

        return {
            "artifact": artifact_name,
            "total_vulnerabilities": len(all_vulns),
            "prioritized_vulnerabilities": len(prioritized_vulns),
            "threshold": threshold,
            "severity_distribution_all": severity_counts_all,
            "severity_distribution_prioritized": severity_counts_prioritized,
        }
