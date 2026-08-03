# zap_processor_test.py (Complete and Updated)

import os
from appsecai.common.utils import get_resource_path
import re
import glob
import logging
import datetime
import time
import requests
import json
import pandas as pd
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from typing import Dict, Any, List

# --- Vulnerability Scorer for ZAP ---
class VulnerabilityScorerZAP:
    def __init__(self, config_path=None, threshold_score=None):
        if config_path is None:
            config_path = get_resource_path("appsecai/risk_profiles/context_modifiers/vulnerability_framework.json")
        if threshold_score is None:
            raw = os.environ.get('VULNERABILITY_THRESHOLD', '').strip()
            try:
                threshold_score = float(raw) if raw else 2.5
            except (ValueError, TypeError):
                threshold_score = 2.5
        self.config_path = config_path
        self.threshold_score = threshold_score
        self.vulnerability_config = {}
        self.default_config = {}
        self.severity_mapping = {
            "Critical":     4.5,
            "High":         3.5,
            "Medium":       2.5,
            "Low":          1.0,
            "Informational": 0.5,
        }
        
        # Try to use enhanced scoring system first
        self.enhanced_scorer = None
        try:
            from appsecai.core.scorer import EnhancedVulnerabilityScorer
            self.enhanced_scorer = EnhancedVulnerabilityScorer()
            print("[DAST] ✅ Enhanced vulnerability scoring system loaded")
        except Exception as e:
            print(f"[DAST] ⚠️ Enhanced scoring not available ({e}), using fallback")
            self.load_vulnerability_config()

    def load_vulnerability_config(self):
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                config_data = json.load(f)
                for item in config_data.get("questionnaire", []):
                    vul_type = item["vulnerabilityType"]
                    if vul_type == "Default":
                        self.default_config = item
                        continue
                    self.vulnerability_config[vul_type] = {
                        cat_score["vulCategory"]: cat_score["score"]
                        for cat_score in item["vulCategoryScores"]
                    }
        except Exception as e:
            print(f"[Scorer] Failed to load config {self.config_path}: {e}")

    def map_vulnerability_type(self, alert_name):
        name_lower = alert_name.lower()
        for vul_type in self.vulnerability_config.keys():
            if vul_type.lower() in name_lower:
                return vul_type
        return "Default"

    def get_vulnerability_scores(self, vul_type):
        if vul_type in self.vulnerability_config:
            return self.vulnerability_config[vul_type]
        return {
            cat_score["vulCategory"]: cat_score["score"]
            for cat_score in self.default_config.get("vulCategoryScores", [])
        } if self.default_config else {}

    def calculate_score(self, zap_alert):
        alert_name = zap_alert.get('name', 'unknown')
        original_risk = zap_alert.get('risk', 'N/A')
        print(f"\n🔄 [ZAP SCORER] Starting calculation for: '{alert_name}' (Original Risk: {original_risk})")
        
        # Try enhanced scoring first
        if self.enhanced_scorer:
            try:
                logger.info(f"✅ [ENHANCED] Using enhanced vulnerability scorer")
                enhanced_score = self.enhanced_scorer.score_zap_vulnerability(zap_alert)
                
                # Detailed logging matching SAST format
                logger.info(f"📊 [BASE SEVERITY] '{zap_alert.get('risk', 'Unknown')}' → Score: {enhanced_score.base_severity}")
                logger.info(f"🏷️  [CATEGORY] '{enhanced_score.category}'")
                
                # Log context adjustments/modifiers
                if enhanced_score.applied_modifiers:
                    applied_mods_str = ", ".join([f"{k}: x{v}" for k,v in enhanced_score.applied_modifiers.items()]) or "None"
                    logger.info(f"⚙️  [ADJUSTMENTS] Context: {{{applied_mods_str}}}")
                
                # Log calculation formula
                logger.info(f"🧮 [CALCULATION] {enhanced_score.base_severity} * {enhanced_score.context_multiplier} = {enhanced_score.final_score}")
                logger.info(f"🎯 [FINAL RESULT] Score: {enhanced_score.final_score} → Risk: {enhanced_score.risk_level.value}")
                
                # Add enhanced data to alert
                zap_alert['enhanced_score'] = enhanced_score.final_score
                zap_alert['enhanced_category'] = enhanced_score.category
                zap_alert['enhanced_risk_level'] = enhanced_score.risk_level.value
                zap_alert['enhanced_justifications'] = enhanced_score.justifications
                zap_alert['ai_justification'] = enhanced_score.ai_justification
                zap_alert['context_adjustments'] = enhanced_score.applied_modifiers
                
                if enhanced_score.ai_justification:
                    logger.info(f"🤖 [AI JUSTIFICATION] {enhanced_score.ai_justification}")
                
                # Add framework-based cybersecurity justification
                framework_justification = self.enhanced_scorer.get_framework_justification(
                    enhanced_score.category, zap_alert
                )
                zap_alert['framework_justification'] = framework_justification
                
                return enhanced_score.final_score, enhanced_score.category
                
            except Exception as e:
                logger.info(f"❌ [ENHANCED ERROR] Enhanced scoring failed for {alert_name}: {e}")
                # Fall through to simple scoring
        
        # Fallback to simple scoring
        logger.info(f"⚠️  [FALLBACK] Using simple scoring system")
        severity = self.severity_mapping.get(zap_alert.get("risk", "N/A"), 0)
        vul_type = self.map_vulnerability_type(zap_alert.get("name", ""))
        category_scores = self.get_vulnerability_scores(vul_type)
        
        logger.info(f"📊 [SIMPLE CALC] Base severity: {severity}, Type: {vul_type}")
        logger.info(f"📊 [SIMPLE CALC] Category scores: {category_scores}")

        total_score = severity
        total_score += category_scores.get("Potential Impact", 0)
        total_score += category_scores.get("EaseOfExploitation", 0)
        total_score += category_scores.get("AssetExposure", 0)
        total_score += category_scores.get("RealWorldAttackLikelihood", 0)
        total_score -= category_scores.get("SecurityControlDeployment", 0)

        logger.info(f"✅ [SIMPLE RESULT] Total score: {total_score}, Type: {vul_type}")
        return total_score, vul_type

# --- Setup Logging ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Find the latest zap_report.html dynamically ---
def find_latest_report():
    try:
        report_dirs = sorted(
            glob.glob("zap_reports/zap_*"),
            key=os.path.getmtime,
            reverse=True
        )
        for report_dir in report_dirs:
            candidate = os.path.join(report_dir, "zap_report.html")
            if os.path.exists(candidate):
                print(f"[Processor] Reading ZAP report from: {candidate}")
                return candidate
        return None
    except Exception as e:
        print(f"[Processor] Warning: Could not find ZAP reports: {e}")
        return None

# --- Core Parsing Functions ---
def parse_html_report(file_path):
    """
    Universal ZAP HTML report parser.
    
    KEY DESIGN NOTE: run_zap_command() is a BLOCKING subprocess call, meaning
    ZAP has fully finished writing the report before this function is ever called.
    There is no race condition on the write side. We simply read and parse the file.
    
    Handles:
    - JDK17 vs JDK21 encoding differences (UTF-8, UTF-16 BOM, latin-1)
    - html5lib / lxml / html.parser parser fallback chain
    - All ZAP versions (2.11.x through 2.16.x)
    """
    try:
        if not file_path or not os.path.exists(file_path):
            logger.error(f"[HTML Parser] Report file not found: {file_path}")
            return None

        # ── Read with encoding fallback chain ──
        # ZAP is a Java process. JDK17 writes UTF-8; JDK21 on some Windows locales
        # may produce UTF-16 BOM. latin-1 is the ultimate fallback (never raises).
        content = ""
        for encoding in ["utf-8", "utf-16", "latin-1"]:
            try:
                with open(file_path, "r", encoding=encoding) as f:
                    content = f.read()
                if content.strip():
                    logger.info(f"[HTML Parser] Read report ({encoding}): {len(content)} chars")
                    break
            except UnicodeDecodeError:
                continue
            except Exception as e:
                logger.error(f"[HTML Parser] Error reading file with {encoding}: {e}")
                continue

        if not content.strip():
            logger.error("[HTML Parser] Report file is empty or unreadable.")
            return None

        # ── Parse with best available parser ──
        for parser in ["html5lib", "lxml", "html.parser"]:
            try:
                soup = BeautifulSoup(content, parser)
                return soup
            except Exception:
                continue

        logger.error("[HTML Parser] All parsers (html5lib, lxml, html.parser) failed.")
        return None

    except Exception as e:
        logger.error(f"[HTML Parser] Unexpected error: {e}")
        return None

def extract_target_url(soup):
    """Extract the target URL from ZAP HTML report."""
    try:
        # Strategy 1: Look for the <h2> tag containing "Site: "
        h2_tags = soup.find_all('h2')
        for h2 in h2_tags:
            text = h2.get_text(strip=True)
            if text.startswith('Site:'):
                # Extract URL after "Site: "
                target_url = text.replace('Site:', '').strip()
                print(f"[Processor] Extracted target URL from Site header: {target_url}")
                return target_url
        
        # Strategy 2: Look for URLs in the alerts table (actual scan targets)
        # These are more reliable than random links in the report
        alerts_table = soup.find("table", class_="alerts")
        if alerts_table:
            rows = alerts_table.find_all("tr")
            for row in rows[1:]:  # Skip header row
                cells = row.find_all("td")
                if len(cells) >= 2:
                    # URL is typically in the second column
                    url_cell = cells[1]
                    url_text = url_cell.get_text(strip=True)
                    if url_text.startswith('http'):
                        from urllib.parse import urlparse
                        parsed = urlparse(url_text)
                        target_url = f"{parsed.scheme}://{parsed.netloc}/"
                        print(f"[Processor] Extracted target URL from alerts table: {target_url}")
                        return target_url
        
        # Strategy 3: Look for URLs in vulnerability instances
        # Check for URL patterns in the report body
        from urllib.parse import urlparse
        import re
        
        # Find all URLs in the document
        url_pattern = r'https?://[^\s<>"]+\.[^\s<>"]+'
        all_text = soup.get_text()
        urls = re.findall(url_pattern, all_text)
        
        # Filter out common reference URLs (documentation, tools, CDNs, etc.)
        excluded_domains = ['checkmarx.com', 'owasp.org', 'cwe.mitre.org', 'github.com', 
                           'mozilla.org', 'mozilla.com', 'mozilla.net', 'w3.org', 'zaproxy.org', 'portswigger.net',
                           'firefox.settings.services.mozilla.com', 'firefox-settings-attachments.cdn.mozilla.net',
                           'services.mozilla.com', 'cdn.mozilla.net']
        
        for url in urls:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Skip excluded domains
            if any(excluded in domain for excluded in excluded_domains):
                continue
            
            # This is likely the scan target
            target_url = f"{parsed.scheme}://{parsed.netloc}/"
            print(f"[Processor] Extracted target URL from document text: {target_url}")
            return target_url
        
        # Strategy 4: Fallback to first non-excluded link
        links = soup.find_all('a', href=True)
        for link in links:
            href = link.get('href', '')
            if href.startswith('http'):
                parsed = urlparse(href)
                domain = parsed.netloc.lower()
                
                # Skip excluded domains
                if any(excluded in domain for excluded in excluded_domains):
                    continue
                
                target_url = f"{parsed.scheme}://{parsed.netloc}/"
                print(f"[Processor] Extracted target URL from link (fallback): {target_url}")
                return target_url
        
        print("[Processor] Could not extract target URL from report")
        return "Not specified"
    except Exception as e:
        print(f"[Processor] Error extracting target URL: {e}")
        return "Not specified"

def extract_alerts(soup):
    alerts = []
    alerts_table = soup.find("table", class_="alerts") or soup.find("table", class_="alert-type-counts-table")
    alert_id_map = {}
    if alerts_table:
        rows = alerts_table.find_all("tr")
        for row in rows[1:]:
            try:
                cells = row.find_all(["td", "th"])
                if len(cells) >= 3:
                    name_link = cells[0].find("a")
                    if name_link:
                        alert_name = name_link.get_text(strip=True)
                        alert_id = name_link.get("href", "").replace("#", "")
                    else:
                        alert_name = cells[0].get_text(strip=True)
                        alert_id = ""
                    
                    if alert_name.lower() == "total" or not alert_id:
                        continue
                    
                    # Modern/Risk-Confidence templates use alert-type-X IDs instead of plugin-X
                    if alert_id.startswith("alert-type-"):
                        # We want to match it to plugin-X or reference IDs in details segment
                        # Let's map it as is, and walk-up will resolve it using details section href
                        pass

                    risk_cell = cells[1]
                    risk_class = risk_cell.get("class", [])
                    risk_level = "N/A"
                    if "risk-3" in risk_class:
                        risk_level = "High"
                    elif "risk-2" in risk_class:
                        risk_level = "Medium"
                    elif "risk-1" in risk_class:
                        risk_level = "Low"
                    elif "risk-0" in risk_class:
                        risk_level = "Informational"
                    elif "risk--1" in risk_class:
                        risk_level = "False Positive"
                    
                    if risk_level == "N/A":
                        risk_level = risk_cell.get_text(strip=True)

                    instances_count = cells[2].get_text(strip=True)
                    alert = {
                        "id": alert_id,
                        "name": alert_name,
                        "risk": risk_level,
                        "instances": [],
                        "instances_count": instances_count,
                        "description": f"{alert_name} - {risk_level} risk with {instances_count} instances",
                    }
                    alerts.append(alert)
                    if alert_id:
                        alert_id_map[alert_id] = alert
            except Exception as e:
                print(f"[WARN] Error parsing alert row: {e}")
                continue

    results_tables = soup.find_all("table", class_="results")
    for table in results_tables:
        alert_id = None
        for th in table.find_all("th"):
            a = th.find("a")
            if a and a.has_attr("id"):
                alert_id = a["id"]
                break
        if not alert_id or alert_id not in alert_id_map:
            continue

        rows = table.find_all("tr")
        instances = []
        i = 0
        while i < len(rows):
            row = rows[i]
            tds = row.find_all("td")
            if len(tds) == 2 and tds[0].get_text(strip=True) == "URL":
                instance = {"URL": tds[1].get_text(strip=True)}
                i += 1
                while i < len(rows):
                    next_row = rows[i]
                    next_tds = next_row.find_all("td")
                    if len(next_tds) == 2:
                        label = next_tds[0].get_text(strip=True)
                        value = next_tds[1].get_text(strip=True)
                        if label == "URL":
                            break
                        instance[label] = value
                    else:
                        break
                    i += 1
                instances.append(instance)
            else:
                i += 1
        alert_id_map[alert_id]["instances"] = instances
        alert_id_map[alert_id]["instances_count"] = str(len(instances))
        
        # Extract Solution and other details from the alert section
        if alert_id:
            alert_section = soup.find(id=alert_id)
            if alert_section:
                # Find the parent table that contains alert details
                parent_table = alert_section.find_parent("table")
                if parent_table:
                    detail_rows = parent_table.find_all("tr")
                    for row in detail_rows:
                        cells = row.find_all("td")
                        if len(cells) >= 2:
                            label = cells[0].get_text(strip=True)
                            value = cells[1].get_text(strip=True)
                            
                            # Extract specific fields from the detail row
                            if label == "Description":
                                alert_id_map[alert_id]["description"] = value
                            elif label == "Solution":
                                alert_id_map[alert_id]["solution"] = value
                            elif label == "Reference":
                                alert_id_map[alert_id]["reference"] = value
                            elif label == "CWE Id":
                                alert_id_map[alert_id]["cwe_id"] = value
                            elif label == "WASC Id":
                                alert_id_map[alert_id]["wasc_id"] = value
    
    # ── ZAP 2.16.x NEW FORMAT: <section class="alert"> ──────────────────────
    # ZAP 2.16.1 (auto-downloaded) uses section tags instead of a summary table.
    # We fall back to this parser when the old table-based format yields 0 results.
    if not alerts:
        risk_text_map = {
            "high": "High", "medium": "Medium", "low": "Low",
            "informational": "Informational", "info": "Informational",
            "false positive": "False Positive"
        }
        for section in soup.find_all("section", class_="alert"):
            try:
                heading = section.find(["h2", "h3", "h4"])
                alert_name = heading.get_text(strip=True) if heading else "Unknown Alert"

                # ── Multi-strategy risk extraction (works across ALL ZAP versions) ──
                risk_level = "Informational"  # safe default

                # Strategy A: CSS class on any child element (ZAP 2.14/2.15 style)
                risk_tag = section.find(class_=lambda c: c and any(
                    r in " ".join(c if isinstance(c, list) else [c]).lower()
                    for r in ["risk-high", "risk-medium", "risk-low", "risk-3", "risk-2", "risk-1"]
                ))
                if risk_tag:
                    cls_str = " ".join(risk_tag.get("class", [])).lower()
                    if "high" in cls_str or "risk-3" in cls_str:
                        risk_level = "High"
                    elif "medium" in cls_str or "risk-2" in cls_str:
                        risk_level = "Medium"
                    elif "low" in cls_str or "risk-1" in cls_str:
                        risk_level = "Low"

                # Strategy B: <td>Risk</td><td>Medium</td> row (ZAP 2.16 style)
                if risk_level == "Informational":
                    for row in section.find_all("tr"):
                        tds = row.find_all(["td", "th"])
                        if len(tds) >= 2 and tds[0].get_text(strip=True).lower() == "risk":
                            risk_level = risk_text_map.get(tds[1].get_text(strip=True).lower(), "Informational")
                            break

                # Strategy C: section's own id/class contains risk keyword (ZAP 2.16.1 style)
                if risk_level == "Informational":
                    sec_classes = " ".join(section.get("class", [])).lower()
                    sec_id = (section.get("id") or "").lower()
                    for token, mapped in [("high", "High"), ("medium", "Medium"), ("low", "Low")]:
                        if token in sec_classes or token in sec_id:
                            risk_level = mapped
                            break

                # Strategy D: plain-text scan of the section heading (e.g. "[Medium] CSP Header Not Set")
                if risk_level == "Informational" and heading:
                    heading_text = heading.get_text(strip=True).lower()
                    if "high" in heading_text:
                        risk_level = "High"
                    elif "medium" in heading_text:
                        risk_level = "Medium"
                    elif "low" in heading_text:
                        risk_level = "Low"

                description = ""
                solution = ""
                for row in section.find_all("tr"):
                    tds = row.find_all("td")
                    if len(tds) >= 2:
                        label = tds[0].get_text(strip=True).lower()
                        value = tds[1].get_text(strip=True)
                        if label == "description":
                            description = value
                        elif label == "solution":
                            solution = value

                instances = []
                instance = None
                for row in section.find_all("tr"):
                    tds = row.find_all("td")
                    if len(tds) >= 2:
                        label = tds[0].get_text(strip=True)
                        value = tds[1].get_text(strip=True)
                        if label == "URL":
                            if instance:
                                instances.append(instance)
                            instance = {"URL": value}
                        elif instance is not None:
                            instance[label] = value
                if instance:
                    instances.append(instance)

                alerts.append({
                    "id": section.get("id", ""),
                    "name": alert_name,
                    "risk": risk_level,
                    "instances": instances,
                    "instances_count": str(len(instances)),
                    "description": description or f"{alert_name} - {risk_level} risk",
                    "solution": solution,
                })
            except Exception as e:
                print(f"[WARN] Error parsing ZAP 2.16 alert section: {e}")
                continue

    # ---- Fallback for risk-confidence-html instances ----
    has_instances = any(len(a.get("instances", [])) > 0 for a in alerts)
    if alerts and not has_instances:
        instances = soup.find_all("span", class_="request-method-n-url")
        for inst in instances:
            method_url_text = inst.get_text(strip=True)
            parts = method_url_text.split(" ", 1)
            method = parts[0] if len(parts) > 1 else "GET"
            url = parts[1] if len(parts) > 1 else method_url_text
            
            # Find the alert ID / alert name associated with this instance
            h5 = inst.find_previous("h5")
            alert_id = None
            if h5:
                a_tag = h5.find("a")
                if a_tag:
                    href = a_tag.get("href", "")
                    if href.startswith("#"):
                        alert_id = href.replace("#", "")
            
            if alert_id and alert_id in alert_id_map:
                parameter = ""
                attack = ""
                evidence = ""
                
                # Find the alerts-table in details container
                parent_li = inst.find_parent("li")
                if parent_li:
                    table = parent_li.find("table", class_="alerts-table")
                    if table:
                        for row in table.find_all("tr"):
                            th = row.find("th")
                            if th:
                                th_text = th.get_text(strip=True).lower()
                                td = row.find("td")
                                if td:
                                    td_text = td.get_text(strip=True)
                                    if "parameter" in th_text:
                                        parameter = td_text
                                    elif "attack" in th_text:
                                        attack = td_text
                                    elif "evidence" in th_text:
                                        evidence = td_text
                
                alert_id_map[alert_id]["instances"].append({
                    "URL": url,
                    "Method": method,
                    "Parameter": parameter,
                    "Attack": attack,
                    "Evidence": evidence
                })
        
        # Recalculate instances_count and descriptions
        for a in alerts:
            a["instances_count"] = str(len(a["instances"]))
            a["description"] = f"{a['name']} - {a['risk']} risk with {a['instances_count']} instances"

    return alerts

def analyze_alerts(alerts):
    risk_levels = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0, "N/A": 0}
    for alert in alerts:
        risk = alert["risk"]
        if risk in risk_levels:
            risk_levels[risk] += 1
    return risk_levels

# --- CSV Parsing for ZAP ---
def parse_zap_csv(csv_path):
    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        logger.error(f"Error reading ZAP CSV: {e}")
        return []

    # Normalize column names for flexible matching
    normalized_cols = {c.lower().strip(): c for c in df.columns}
    get_col = lambda *names: next((normalized_cols[n] for n in names if n in normalized_cols), None)

    col_alert = get_col("alert", "title", "name")
    col_risk = get_col("risk", "risklevel", "risk_level")
    col_desc = get_col("description", "desc")
    col_url = get_col("url")
    col_param = get_col("parameter", "param")

    alerts = []
    for _, row in df.iterrows():
        name = str(row.get(col_alert, "Unknown")).strip() if col_alert else "Unknown"
        risk = str(row.get(col_risk, "Unknown")).strip() if col_risk else "Unknown"
        description = str(row.get(col_desc, "")).strip() if col_desc else ""
        url = str(row.get(col_url, "")).strip() if col_url else ""
        parameter = str(row.get(col_param, "")).strip() if col_param else ""

        if not description:
            parts = []
            if url:
                parts.append(f"URL: {url}")
            if parameter:
                parts.append(f"Parameter: {parameter}")
            description = "; ".join(parts) if parts else name

        alerts.append({
            "id": "",
            "name": name,
            "risk": risk if risk else "Unknown",
            "instances": [],
            "instances_count": "0",
            "description": description
        })
    return alerts

# --- Whiterabbit LLM Integration ---
class WhiterabbitRecommendationGenerator:
    def __init__(self, whiterabbit_url="http://4.247.140.236:11434", model="WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B", config_context: str | None = None):
        # Allow env overrides
        env_url = os.environ.get("WHITERABBIT_URL")
        env_model = os.environ.get("WHITERABBIT_MODEL")
        self.whiterabbit_url = (env_url or whiterabbit_url).rstrip('/')
        self.model = env_model or model
        self.api_endpoint = f"{self.whiterabbit_url}/api/generate"
        self.max_retries = 3
        self.retry_delay = 2
        self.timeout = int(os.environ.get("OLLAMA_TIMEOUT", "300"))
        # Optional context (e.g., contents of vul.json) to guide LLM
        self.config_context = config_context
        # A balanced and safe concurrency level for performance and stability.
        try:
            default_workers = 4
            self.max_workers = int(os.environ.get("OLLAMA_CONCURRENCY", str(default_workers)))
        except Exception:
            self.max_workers = 4
        try:
            # Reduced from 3 to 2 for better stability with slow LLM servers
            default_inflight = 2
            self.max_inflight = int(os.environ.get("OLLAMA_MAX_INFLIGHT", str(default_inflight)))
        except Exception:
            self.max_inflight = 2
        # Reuse HTTP connections
        try:
            import requests
            from requests.adapters import HTTPAdapter
            from urllib3.util.retry import Retry
            self.session = requests.Session()
            retry_strategy = Retry(
                total=3,
                backoff_factor=2,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["HEAD", "GET", "POST", "OPTIONS"]
            )
            adapter = HTTPAdapter(
                pool_connections=self.max_workers,
                pool_maxsize=self.max_workers,
                max_retries=retry_strategy
            )
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)
        except Exception:
            self.session = requests

    def test_connection(self):
        try:
            r = requests.get(f"{self.whiterabbit_url}/api/tags", timeout=10)
            if r.status_code != 200:
                logger.warning(f"Whiterabbit API returned status {r.status_code}")
                return False
            return self.ensure_model_available()
        except requests.exceptions.Timeout:
            logger.warning(f"Connection to {self.whiterabbit_url} timed out")
            return False
        except requests.exceptions.ConnectionError:
            logger.warning(f"Could not connect to {self.whiterabbit_url}")
            return False
        except Exception as e:
            logger.warning(f"Connection test failed: {e}")
            return False

    def get_available_models(self):
        try:
            r = requests.get(f"{self.whiterabbit_url}/api/tags", timeout=10)
            r.raise_for_status()
            data = r.json() or {}
            return [m.get("name") for m in data.get("models", []) if isinstance(m, dict)]
        except Exception as e:
            logger.debug(f"Failed to list Whiterabbit models: {e}")
            return []

    def ensure_model_available(self):
        try:
            models = self.get_available_models()
            if self.model in models:
                return True
            logger.info(f"Model '{self.model}' not found in Whiterabbit. Attempting to pull...")
            pull_payload = {"name": self.model, "stream": False}
            res = requests.post(f"{self.whiterabbit_url}/api/pull", json=pull_payload, timeout=600)
            if res.status_code not in (200, 201):
                logger.warning(f"Model pull request failed with status {res.status_code}: {res.text[:200]}")
                return False
            models_after = self.get_available_models()
            available = self.model in models_after
            if available:
                logger.info(f"Model '{self.model}' is now available in Whiterabbit.")
            else:
                logger.warning(f"Model '{self.model}' still not available after pull attempt.")
            return available
        except Exception as e:
            logger.warning(f"Error ensuring model availability: {e}")
            return False

    def _parse_recommendation(self, reply):
        fields = {"impact": "Not provided", "fix": "Not provided", "justification": "Not provided"}
        reply = reply.strip()
        if not reply:
            return fields

        patterns = {
            "impact": r"IMPACT:\s*(.*?)(?=\nFIX:|\nJUSTIFICATION:|$)",
            "fix": r"FIX:\s*(.*?)(?=\nIMPACT:|\nJUSTIFICATION:|$)",
            "justification": r"JUSTIFICATION:\s*(.*?)(?=\nIMPACT:|\nFIX:|$)"
        }

        for key, pattern in patterns.items():
            match = re.search(pattern, reply, re.IGNORECASE | re.DOTALL)
            if match:
                value = match.group(1).strip()
                if value:
                    fields[key] = value

        if all(fields[k] == "Not provided" for k in ["impact", "fix", "justification"]):
            fields["raw"] = reply
        else:
            fields["raw"] = ""

        return fields

    def generate_recommendations_stream(self, vulnerabilities, batch_size=5):
        connection_available = self.test_connection()
        
        if not connection_available:
            logger.warning(f"LLM unavailable at {self.whiterabbit_url}, using ZAP Solutions from HTML report where available")
            
            # Process each vulnerability - use solution if available
            results = []
            for vuln in vulnerabilities:
                # Check for solution from ZAP HTML report
                existing_solution = vuln.get('solution', '').strip()
                
                if existing_solution:
                    # Solution found in ZAP HTML - use it, but note that impact won't be generated since LLM is down
                    logger.info(f"✅ Using ZAP Solution for '{vuln.get('name', 'Unknown')}' (LLM unavailable for impact)")
                    results.append({
                        'vulnerability': vuln,
                        'recommendation': {
                            "impact": "Impact analysis unavailable (LLM service down)",
                            "fix": existing_solution,  # From ZAP HTML
                            "justification": "Not provided",
                            "source": "zap_html_report_llm_unavailable"
                        },
                        'status': 'success'
                    })
                else:
                    # No solution in ZAP HTML and LLM is down
                    logger.error(f"❌ No ZAP Solution for '{vuln.get('name', 'Unknown')}' and LLM unavailable")
                    results.append({
                        'vulnerability': vuln,
                        'recommendation': {
                            "impact": "Not provided",
                            "fix": "No fix details available",
                            "justification": "Not provided",
                            "raw": "No solution in ZAP report and LLM unavailable"
                        },
                        'status': 'error'
                    })
            
            yield results
            return

        total_vulns = len(vulnerabilities)
        all_results = [None] * total_vulns
        # Increased cooldown from 5s to 8s to reduce server load
        cool_down_seconds = 8
        # Delay between individual requests within a batch
        request_delay = 1.5

        logger.info(f"Starting batched recommendation generation for {total_vulns} findings...")

        for i in range(0, total_vulns, batch_size):
            batch_vulns = vulnerabilities[i:i + batch_size]
            num_batches = (total_vulns + batch_size - 1) // batch_size
            logger.info(f"Processing batch {i//batch_size + 1}/{num_batches} (vulnerabilities {i+1}-{min(i+batch_size, total_vulns)})...")

            semaphore = threading.Semaphore(self.max_inflight)

            def worker(vuln_data, original_index):
                title_key = str(vuln_data.get('name') or 'Unknown').strip()
                try:
                    with semaphore:
                        # Add small delay before each request to prevent overwhelming the server
                        time.sleep(request_delay)
                        rec = self._get_single_recommendation(vuln_data)
                    result_dict = {'vulnerability': vuln_data, 'recommendation': rec, 'status': 'success'}
                except Exception as e:
                    logger.error(f"Error in worker for '{title_key}': {e}")
                    fail_rec = {
                        "impact": "Not provided", "fix": "Not provided", "justification": "Not provided",
                        "raw": "Failed to generate a complete recommendation from the AI model."
                    }
                    result_dict = {'vulnerability': vuln_data, 'recommendation': fail_rec, 'status': 'error'}
                return original_index, result_dict

            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = [executor.submit(worker, batch_vulns[j], i + j) for j in range(len(batch_vulns))]
                batch_results = [None] * len(batch_vulns)
                for fut in as_completed(futures):
                    original_idx, res = fut.result()
                    if (original_idx - i) < len(batch_results):
                        batch_results[original_idx - i] = res
                    if original_idx < len(all_results):
                        all_results[original_idx] = res
                yield [r for r in batch_results if r is not None]

            if (i + batch_size) < total_vulns:
                logger.info(f"Batch complete. Cooling down for {cool_down_seconds} seconds...")
                time.sleep(cool_down_seconds)

        logger.info("All batches processed.")

    # Keep the original generate_recommendations for backward compatibility
    def generate_recommendations(self, vulnerabilities, batch_size=20):
        # This version returns all results at once (non-streaming)
        results = []
        for batch in self.generate_recommendations_stream(vulnerabilities, batch_size=batch_size):
            results.extend(batch)
        return results


    def _get_single_recommendation(self, vuln):
        # Check if Solution already exists in the vulnerability data from ZAP HTML report
        existing_solution = vuln.get('solution', '').strip()
        
        if existing_solution:
            # Use ZAP Solution for Fix, but call LLM for Impact
            logger.info(f"Using ZAP Solution for '{vuln.get('name', 'Unknown')}', calling LLM for Impact")
            
            # Simplified prompt for Impact only
            impact_prompt = (
                "Analyze this vulnerability and provide ONLY the impact in 1-2 sentences. "
                "Do not include any headers, labels, or extra text.\n\n"
                f"Vulnerability: {vuln.get('name', 'Unknown')}\n"
                f"Risk Level: {vuln.get('risk', 'Unknown')}\n"
                f"Description: {vuln.get('description', '')}\n\n"
                "Write only the impact description:"
            )
            
            impact_text = "Not provided"
            try:
                payload = {
                    "model": self.model,
                    "prompt": impact_prompt,
                    "stream": False,
                    "options": {"num_predict": 200}
                }
                # Increased timeout from 30s to 60s for slow LLM servers
                res = self.session.post(self.api_endpoint, json=payload, timeout=60)
                res.raise_for_status()
                result = res.json()
                reply = result.get('response', '').strip()
                
                # Clean up response - remove common prefixes
                import re
                reply = re.sub(r'^IMPACT:\s*', '', reply, flags=re.IGNORECASE).strip()
                reply = re.sub(r'^Impact:\s*', '', reply, flags=re.IGNORECASE).strip()
                reply = re.sub(r'^The impact is:\s*', '', reply, flags=re.IGNORECASE).strip()
                
                if reply:
                    impact_text = reply
                    logger.info(f"✅ Generated impact for '{vuln.get('name', 'Unknown')}'")
            except Exception as e:
                logger.warning(f"⚠️ Failed to get impact from LLM for '{vuln.get('name', 'Unknown')}': {e}")
            
            return {
                "impact": impact_text,
                "fix": existing_solution,
                "justification": "Not provided",
                "source": "hybrid_zap_solution_llm_impact"
            }
        
        # Only call LLM for everything if Solution is missing
        logger.info(f"No ZAP Solution found for '{vuln.get('name', 'Unknown')}', calling LLM for all fields...")
        
        # Compose optional configuration context to guide the LLM without leaking numeric scores in output
        context_block = ""
        try:
            if isinstance(self.config_context, str) and self.config_context.strip():
                # Cap very large contexts to a safe size
                snippet = self.config_context.strip()
                if len(snippet) > 6000:
                    snippet = snippet[:6000] + "\n..."
                context_block = (
                    "CONFIG CONTEXT (for reasoning only, do not repeat numbers in your answer):\n" + snippet + "\n\n"
                )
        except Exception:
            context_block = ""

        base_prompt = (
            "You are a security expert. Analyze the following vulnerability and return ONLY the fields below. "
            "No extra text, no numeric scores.\n\n"
            + context_block +
            "IMPACT: [1-2 sentences on business/security impact in plain language.]\n\n"
            "FIX: [Specific, actionable remediation steps. Prefer secure defaults and code/config examples.]\n\n"
            "JUSTIFICATION: [1-2 sentences explaining WHY this vulnerability is prioritized from a cybersecurity perspective. Focus on primary threat vector and business risk. Keep concise.]\n\n"
            "--- VULNERABILITY DETAILS ---\n"
            f"Title: {vuln.get('name', 'Unknown')}\n"
            f"Original Risk Level: {vuln.get('risk', 'Unknown')}\n"
            f"Description: {vuln.get('description', '')}"
        )

        for attempt in range(self.max_retries):
            prompt = base_prompt
            if attempt > 0:
                prompt += f"\n\n[Retry {attempt+1}: Your previous response was incomplete. Please provide all three fields: IMPACT, FIX, and JUSTIFICATION, following the format precisely.]"

            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": { "num_predict": 1024 }
            }
            try:
                res = self.session.post(self.api_endpoint, json=payload, timeout=self.timeout)
                res.raise_for_status()
                result = res.json()
                reply = result.get('response', '').strip()

                if reply:
                    fields = self._parse_recommendation(reply)
                    if all(fields[k] != "Not provided" for k in ["impact", "fix", "justification"]):
                        fields["source"] = "llm"  # Mark as LLM-generated
                        return fields
                    else:
                        logger.warning(f"Incomplete parse for '{vuln.get('name')}' on attempt {attempt+1}. Retrying...")
                else:
                    logger.error(f"Empty response from LLM on attempt {attempt+1} for '{vuln.get('name')}'")

            except Exception as e:
                logger.error(f"LLM request failed on attempt {attempt+1} for '{vuln.get('name')}': {e}")

            if attempt < self.max_retries - 1:
                time.sleep(self.retry_delay)

        raise Exception(f"Failed to get a complete recommendation after {self.max_retries} attempts.")


# --- Analyzer ---
class ZAPReportAnalyzer:
    def __init__(self, html_file_path=None, ollama_url="http://4.247.140.236:11434", model="WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B", output_dir=None, threshold_score=None, config_path="vul.json", target_url=None):
        if threshold_score is None:
            raw = os.environ.get('VULNERABILITY_THRESHOLD', '').strip()
            try:
                threshold_score = float(raw) if raw else 2.5
            except (ValueError, TypeError):
                threshold_score = 2.5
        self.html_file_path = html_file_path or find_latest_report()
        self.explicit_target_url = target_url  # Store explicitly provided target URL
        # Load config context for LLM from the provided config_path
        config_context = None
        try:
            with open(config_path or "vul.json", "r", encoding="utf-8") as f:
                config_context = f.read()
        except Exception:
            config_context = None

        self.whiterabbit_generator = WhiterabbitRecommendationGenerator(ollama_url, model, config_context=config_context)
        self.scorer = VulnerabilityScorerZAP(config_path=config_path or "vul.json", threshold_score=threshold_score)
        self.output_dir = output_dir or os.path.abspath("AppSecAI_output")
        print(f"🔧 [ZAP ANALYZER] Initialized with threshold: {threshold_score}, config: {config_path}")
        if target_url:
            print(f"🎯 [ZAP ANALYZER] Using explicit target URL: {target_url}")
        try:
            os.makedirs(self.output_dir, exist_ok=True)
        except Exception:
            self.output_dir = os.getcwd()

    def analyze_and_recommend(self, output_file=None, generate_llm=True):
        if not self.html_file_path or not os.path.exists(self.html_file_path):
            return {"success": False, "error": "ZAP report not found", "vulnerabilities": []}

        soup = parse_html_report(self.html_file_path)
        if not soup:
            return {"success": False, "error": "Failed to parse ZAP HTML", "vulnerabilities": []}

        # Use explicit target URL if provided, otherwise extract from report
        if self.explicit_target_url:
            target_url = self.explicit_target_url
            print(f"[Processor] Using explicit target URL: {target_url}")
        else:
            # Extract target URL from the report
            target_url = extract_target_url(soup)
        
        alerts = extract_alerts(soup)
        
        # Fallback: If target_url is still not correct, extract from actual vulnerability instances
        # Check if it's a known reference/CDN domain
        reference_domains = [
            'firefox.settings.services.mozilla.com',
            'firefox-settings-attachments.cdn.mozilla.net',
            'checkmarx.com',
            'mozilla.net',
            'mozilla.org',
            'mozilla.com'
        ]
        
        is_reference_url = any(domain in target_url.lower() for domain in reference_domains)
        
        if target_url == "Not specified" or is_reference_url:
            print(f"[Processor] Target URL '{target_url}' seems incorrect (reference/CDN URL), extracting from vulnerability instances...")
            # Look for the most common URL in vulnerability instances
            from collections import Counter
            from urllib.parse import urlparse
            
            instance_urls = []
            for alert in alerts:
                instances = alert.get('instances', [])
                for instance in instances:
                    url = instance.get('URL', '')
                    if url and url.startswith('http'):
                        parsed = urlparse(url)
                        base_url = f"{parsed.scheme}://{parsed.netloc}/"
                        
                        # Skip if this is also a reference URL
                        if not any(domain in base_url.lower() for domain in reference_domains):
                            instance_urls.append(base_url)
            
            if instance_urls:
                # Get the most common URL (the actual scan target)
                url_counts = Counter(instance_urls)
                most_common_url = url_counts.most_common(1)[0][0]
                target_url = most_common_url
                print(f"[Processor] Corrected target URL from instances: {target_url}")
            else:
                print(f"[Processor] WARNING: Could not find valid target URL in instances, keeping: {target_url}")
        
        # Summary before prioritization (ZAP original risks)
        original_summary = analyze_alerts(alerts)

        if not alerts:
            return {"success": True, "error": "No vulnerabilities found", "vulnerabilities": [], "recommendations": [], "summary": original_summary, "original_summary": original_summary, "prioritized_summary": original_summary}

        # Apply scoring and prioritization logic to ALL vulnerabilities
        print(f"\n🎯 [PRIORITIZATION] Processing {len(alerts)} vulnerabilities with threshold: {self.scorer.threshold_score}")
        
        for i, alert in enumerate(alerts, 1):
            print(f"\n--- Vulnerability {i}/{len(alerts)} ---")
            score, vul_type = self.scorer.calculate_score(alert)
            alert["score"] = score
            alert["mapped_type"] = vul_type
            # Preserve original risk for UI comparison and reasoning
            original_risk = alert.get("risk", "N/A")
            alert["original_risk"] = original_risk

            # Use the mathematically computed risk level from the enhanced scorer if available
            computed_risk = alert.get("enhanced_risk_level")
            
            if computed_risk:
                alert["risk"] = computed_risk
                # Set priority flag based on whether it meets threshold
                if score >= self.scorer.threshold_score:
                    alert["is_priority"] = True
                    alert["priority_reason"] = f"Priority elevated due to business impact and exploitability per configuration (score: {score})."
                    if original_risk.lower() != computed_risk.lower():
                        if score > self.scorer.severity_mapping.get(original_risk, 0):
                            logger.info(f"UPGRADING RISK for '{alert['name']}' from {original_risk} to {computed_risk} based on score ({score} >= {self.scorer.threshold_score})")
                        else:
                            logger.info(f"DOWNGRADING RISK for '{alert['name']}' from {original_risk} to {computed_risk} based on score ({score} < {self.scorer.severity_mapping.get(original_risk, 0)})")
                else:
                    alert["is_priority"] = False
                    alert["priority_reason"] = f"Risk mitigated below threshold (score: {score})."
            else:
                # Fallback to simple logic
                if score >= self.scorer.threshold_score:
                    if original_risk.lower() not in ["high", "critical"]:
                        logger.info(f"UPGRADING RISK for '{alert['name']}' from {original_risk} to High based on score ({score} >= {self.scorer.threshold_score})")
                    alert["risk"] = "High"
                    alert["is_priority"] = True
                    alert["priority_reason"] = f"Priority elevated from {original_risk} to High due to business impact and exploitability per configuration (score: {score})."
                else:
                    alert["is_priority"] = False
                    alert["priority_reason"] = f"Priority aligns with ZAP risk level based on current configuration (score: {score})."

        # Only generate AI recommendations for vulnerabilities that exceed threshold (now marked as High priority)
        filtered_alerts = [a for a in alerts if a.get("is_priority", False)]
        print(f"\n📋 [FILTERING] {len(filtered_alerts)}/{len(alerts)} vulnerabilities marked as priority for AI analysis")

        # Summary after prioritization (post-logic risks)
        prioritized_summary = analyze_alerts(alerts)
        print(f"📊 [SUMMARY] Original: {original_summary}, After prioritization: {prioritized_summary}")

        recommendations = []
        if generate_llm:
            recommendations = self.whiterabbit_generator.generate_recommendations(filtered_alerts)
            try:
                recommendations = sorted(
                    recommendations,
                    key=lambda r: int(r.get('vulnerability', {}).get('score', 0)),
                    reverse=True
                )
            except Exception:
                pass

        result = {
            "success": True,
            "target_url": target_url,
            "total_vulnerabilities": len(alerts),
            "vulnerabilities": alerts,
            "recommendations": recommendations,
            # Keep backward-compatible 'summary' while also providing both views explicitly
            "summary": original_summary,
            "original_summary": original_summary,
            "prioritized_summary": prioritized_summary,
            "whiterabbit_model": self.whiterabbit_generator.model,
            "report_path": self.html_file_path,
            "timestamp": datetime.datetime.now().isoformat()
        }

        # Write JSON results. If no path provided, write to output_dir by default
        try:
            if not output_file:
                output_file = os.path.join(self.output_dir, "security_recommendations.json")
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            logger.info(f"Results saved to {output_file}")
            # Also write a timestamped snapshot for history
            try:
                ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                snapshot = os.path.join(self.output_dir, f"security_recommendations_{ts}.json")
                with open(snapshot, 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=2, ensure_ascii=False)
            except Exception:
                pass
        except Exception:
            logger.warning("Failed to write security recommendations JSON file")

        # Only write CSV if we have recommendations
        if generate_llm and recommendations:
            timestamp_str = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            df = pd.DataFrame([{
                "Title": r['vulnerability'].get('name', 'Unknown'),
                "Risk": r['vulnerability'].get('risk', r['vulnerability'].get('risk_level', 'Unknown')),
                "Score": r['vulnerability'].get('score', 0),
                "MappedType": r['vulnerability'].get('mapped_type', 'Unknown'),
                "Status": r.get('status'),
                "Impact": r.get('recommendation', {}).get('impact', '') or 'Impact analysis not available',
                "Fix": r.get('recommendation', {}).get('fix', '') or r['vulnerability'].get('solution', 'No fix details available'),
                "Justification": self._combine_justifications(r)
            } for r in recommendations])
            csv_filename = f"security_recommendations_summary_{timestamp_str}.csv"
            csv_path = os.path.join(self.output_dir, csv_filename)
            df.to_csv(csv_path, index=False)
            logger.info(f"CSV summary saved to: {csv_path}")
            logger.info("✅ Completed analysis and prioritization for ZAP report.")

        return result
    
    def _combine_justifications(self, recommendation_data: Dict[str, Any]) -> str:
        """Combine AI and framework justifications into concise explanation"""
        ai_justification = recommendation_data.get('recommendation', {}).get('justification', '')
        framework_justification = recommendation_data.get('vulnerability', {}).get('framework_justification', '')
        enhanced_justs = recommendation_data.get('vulnerability', {}).get('enhanced_justifications', [])
        
        # If we have enhanced justifications, we can build a very specific summary
        if enhanced_justs:
            relevant = [j for j in enhanced_justs if 'Risk Increasing Factors:' in j or 'Risk Decreasing Factors:' in j or 'Applied Modifiers:' in j or '•' in j or '\u2022' in j]
            if relevant:
                summary = " | ".join(relevant)
                summary = re.sub(r'\s*\(\s*x\d+(\.\d+)?\s*\)', '', summary)
                if len(summary) < 300:
                    return summary

        # If we have framework justification, use it
        if framework_justification and 'separation model' not in framework_justification:
            if ai_justification and len(ai_justification) <= 150:
                return f"{framework_justification} {ai_justification}"
            else:
                return framework_justification
        
        # Fallback to AI justification
        if ai_justification:
            if len(ai_justification) > 250:
                return ai_justification[:247] + "..."
            return ai_justification
        
        return framework_justification or "Security vulnerability requiring attention based on risk assessment"


class ZAPCSVAnalyzer:
    def __init__(self, csv_file_path, ollama_url="http://4.247.140.236:11434", model="WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B", output_dir=None, quiet_mode=True, threshold_score=None, config_path="vul.json"):
        if threshold_score is None:
            threshold_score = int(os.environ.get('VULNERABILITY_THRESHOLD'))
            if not threshold_score:
                raise ValueError("VULNERABILITY_THRESHOLD must be set in environment or passed as parameter")
        self.csv_file_path = csv_file_path
        self.quiet_mode = quiet_mode
        config_context = None
        try:
            with open(config_path or "vul.json", "r", encoding="utf-8") as f:
                config_context = f.read()
        except Exception:
            config_context = None

        self.whiterabbit_generator = WhiterabbitRecommendationGenerator(ollama_url, model, config_context=config_context)
        self.whiterabbit_generator.quiet_mode = quiet_mode
        self.scorer = VulnerabilityScorerZAP(config_path=config_path or "vul.json", threshold_score=threshold_score)
        self.output_dir = output_dir or os.path.abspath("AppSecAI_output")
        try:
            os.makedirs(self.output_dir, exist_ok=True)
        except Exception:
            self.output_dir = os.getcwd()

    def analyze_and_recommend(self, output_file=None, generate_llm=True):
        if not self.csv_file_path or not os.path.exists(self.csv_file_path):
            return {"success": False, "error": "ZAP CSV not found", "vulnerabilities": []}

        alerts = parse_zap_csv(self.csv_file_path)
        if not alerts:
            return {"success": False, "error": "No vulnerabilities found in CSV", "vulnerabilities": []}

        original_summary = analyze_alerts(alerts)

        for alert in alerts:
            score, vul_type = self.scorer.calculate_score(alert)
            alert["score"] = score
            alert["mapped_type"] = vul_type
            original_risk = alert.get("risk", "N/A")
            alert["original_risk"] = original_risk

            if score >= self.scorer.threshold_score:
                if original_risk.lower() not in ["high", "critical"]:
                    logger.info(f"UPGRADING RISK for '{alert['name']}' from {original_risk} to High based on score ({score} >= {self.scorer.threshold_score})")
                alert["risk"] = "High"
                alert["is_priority"] = True
                alert["priority_reason"] = (
                    f"Priority elevated from {original_risk} to High due to business impact and exploitability per configuration (score: {score})."
                )
            else:
                alert["is_priority"] = False
                alert["priority_reason"] = f"Priority aligns with ZAP risk level based on current configuration (score: {score})."

        filtered_alerts = [a for a in alerts if a.get("is_priority", False)]

        if self.quiet_mode:
            print(f"🚀 Starting recommendation generation for {len(filtered_alerts)} priority High/Critical findings...")

        recommendations = []
        if generate_llm:
            recommendations = self.whiterabbit_generator.generate_recommendations(filtered_alerts)
            if recommendations:
                try:
                    recommendations = sorted(
                        recommendations,
                        key=lambda r: int(r.get('vulnerability', {}).get('score', 0)),
                        reverse=True
                    )
                except Exception:
                    pass
        prioritized_summary = analyze_alerts(alerts)

        result = {
            "success": True,
            "total_vulnerabilities": len(alerts),
            "vulnerabilities": alerts,
            "recommendations": recommendations,
            "summary": original_summary,
            "original_summary": original_summary,
            "prioritized_summary": prioritized_summary,
            "whiterabbit_model": self.whiterabbit_generator.model,
            "report_path": self.csv_file_path,
            "timestamp": datetime.datetime.now().isoformat()
        }

        try:
            if not output_file:
                output_file = os.path.join(self.output_dir, "security_recommendations.json")
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            logger.info(f"Results saved to {output_file}")
            try:
                ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                snapshot = os.path.join(self.output_dir, f"security_recommendations_{ts}.json")
                with open(snapshot, 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=2, ensure_ascii=False)
            except Exception:
                pass
        except Exception:
            pass

        if generate_llm and recommendations:
            try:
                timestamp_str = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                df = pd.DataFrame([
                    {
                        "Title": r['vulnerability'].get('name', 'Unknown'),
                        "Risk": r['vulnerability'].get('risk', 'Unknown'),
                        "Score": r['vulnerability'].get('score', 0),
                        "MappedType": r['vulnerability'].get('mapped_type', 'Unknown'),
                        "Status": r.get('status'),
                        "Impact": r.get('recommendation', {}).get('impact', ''),
                        "Fix": r.get('recommendation', {}).get('fix', ''),
                        "Justification": r.get('recommendation', {}).get('justification', ''),
                        "RawRecommendation": r.get('recommendation', {}).get('raw', '')
                    }
                    for r in recommendations
                ])
                csv_filename = f"security_recommendations_summary_{timestamp_str}.csv"
                csv_path = os.path.join(self.output_dir, csv_filename)
                df.to_csv(csv_path, index=False)
                logger.info(f"CSV summary saved to: {csv_path}")
                logger.info("✅ Completed analysis and prioritization for ZAP CSV report.")
            except Exception:
                pass

        return result

def main():
    logger.info("Starting ZAP report analysis with Whiterabbit...")
    report_path = find_latest_report()
    if not report_path:
        print("Error: No ZAP report found. Please run a ZAP scan first.")
        return

    analyzer = ZAPReportAnalyzer(report_path)
    results = analyzer.analyze_and_recommend(output_file="security_recommendations.json")

    if not results.get("success"):
        print(f"❌ Error: {results.get('error')}")
        return

    print("\n🎯 ANALYSIS COMPLETE")
    print(f"📊 Total vulnerabilities: {results['total_vulnerabilities']}")
    print(f"📈 Risk levels: {results['summary']}")
    print(f"💾 Results saved to: security_recommendations.json")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Analysis failed: {str(e)}")
        logger.exception("Unhandled exception during analysis")
