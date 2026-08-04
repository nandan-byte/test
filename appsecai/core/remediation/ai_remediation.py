import os
import logging
import tempfile
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime

from appsecai.core.remediation.pr_generator import (
    FixerConfig,
    load_csv_vulnerabilities,
    process_vulnerabilities_in_batches,
)

logger = logging.getLogger(__name__)






@dataclass
class RemediationResult:
    remediation_id: str
    input_file: str
    start_time: datetime
    end_time: datetime
    fixes: List[dict]
    pull_requests: List[tuple]
    issues: List[str]
    summary: Dict[str, Any]
    success: bool
    error_message: Optional[str] = None



class AIRemediationEngine:
    """
    Deterministic AI remediation engine.
    Sole backend: pr_generator.py
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config

    def is_available(self) -> bool:
        """
        CLI compatibility hook.
        Since pr_generator.py is now the only backend,
        AI remediation is available as long as this class loads.
        """
        return True



    def process_vulnerabilities(self, input_file: str, options: Dict[str, Any]) -> RemediationResult:
        remediation_id = f"remediation_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        start_time = datetime.now()

        try:
            # 1. Create temp config for fixer_pr
            temp_cfg_path = self._create_temp_config(input_file, options)

            # 2. Load fixer config
            cfg = FixerConfig(temp_cfg_path)

            # 3. Load vulnerabilities
            vulnerabilities = load_csv_vulnerabilities(cfg.INPUT_CSV)

            if not vulnerabilities:
                raise RuntimeError("No vulnerabilities loaded from CSV")

            # 4. Execute remediation
            processed, pr_urls = process_vulnerabilities_in_batches(cfg, vulnerabilities)

            # 5. Build summary
            total = len(processed)
            fixed = sum(v["status"] == "Fixed" for v in processed)
            failed = sum(v["status"] == "Failed" for v in processed)
            skipped = sum(v["status"] == "Skipped" for v in processed)

            summary = {
                "total": total,
                "fixed": fixed,
                "failed": failed,
                "skipped": skipped,
                "success_rate": fixed / total if total else 0.0,
            }

            return RemediationResult(
                remediation_id=remediation_id,
                input_file=input_file,
                start_time=start_time,
                end_time=datetime.now(),
                fixes=processed,
                pull_requests=pr_urls,
                issues=[],
                summary=summary,
                success=True,
            )

        except Exception as e:
            logger.error("AI remediation failed", exc_info=True)
            return RemediationResult(
                remediation_id=remediation_id,
                input_file=input_file,
                start_time=start_time,
                end_time=datetime.now(),
                fixes=[],
                pull_requests=[],
                issues=[],
                summary={},
                success=False,
                error_message=str(e),
            )

    def _create_temp_config(self, input_file: str, options: Dict[str, Any]) -> str:
        import yaml

        temp_config = {
            "input_csv": input_file,
            "output_dir": options.get("output_dir", "AppSecAI_output"),
            "batch_size": options.get("batch_size", 5),
            "commit_batch_size": options.get("commit_batch_size", 5),
            "pr_batch_size": options.get("pr_batch_size", 5),
            "github": self.config.get("github", {}),
            "llm": self.config.get("llm", {}),
            "clone_dir": options.get("clone_dir")  # Pass existing clone_dir if available
        }

        fd, path = tempfile.mkstemp(prefix="ai_remediation_", suffix=".yaml")
        with os.fdopen(fd, "w") as f:
            yaml.safe_dump(temp_config, f)

        return path
