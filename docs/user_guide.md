# AppSecAI CLI — User Guide

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Installation & Requirements](#2-installation--requirements)
3. [Quick Start](#3-quick-start)
4. [Configuration Methods](#4-configuration-methods)
   - 4.1 [Method 1 — JSON Configuration Mode](#41-method-1--json-configuration-mode)
   - 4.2 [Method 2 — Interactive CLI Wizard](#42-method-2--interactive-cli-wizard)
5. [Navigation Basics](#5-navigation-basics)
6. [Main Menu Overview](#6-main-menu-overview)
7. [SAST Analysis](#7-sast-analysis)
   - 7.1 [Prerequisites](#71-prerequisites)
   - 7.2 [Generate a GitHub Personal Access Token](#72-generate-a-github-personal-access-token)
   - 7.3 [Set Up SonarQube](#73-set-up-sonarqube)
   - 7.4 [Configure SAST Settings](#74-configure-sast-settings)
   - 7.5 [Running the SAST Pipeline](#75-running-the-sast-pipeline)
   - 7.6 [SAST Output & Report Fields](#76-sast-output--report-fields)
   - 7.7 [Troubleshooting](#77-troubleshooting)
8. [DAST Analysis](#8-dast-analysis)
   - 8.1 [Prerequisites](#81-prerequisites)
   - 8.2 [Configure DAST Settings](#82-configure-dast-settings)
   - 8.3 [Running a DAST Scan](#83-running-a-dast-scan)
   - 8.4 [DAST Output & Report Fields](#84-dast-output--report-fields)
9. [SCA Analysis](#9-sca-analysis)
   - 9.1 [Prerequisites](#91-prerequisites)
   - 9.2 [Configure SCA Settings](#92-configure-sca-settings)
   - 9.3 [SCA Context (Optional but Recommended)](#93-sca-context-optional-but-recommended)
   - 9.4 [Running an SCA Scan](#94-running-an-sca-scan)
   - 9.5 [SCA Output & Report Fields](#95-sca-output--report-fields)
10. [Reports & Output Files](#10-reports--output-files)
11. [CLI Reference](#11-cli-reference)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Introduction

AppSecAI is an AI-powered security scanning platform delivered as a standalone CLI application (`python -m appsecai.cli.menu`). It bundles three scanning engines into a single tool:

- **SAST** — Static Application Security Testing via SonarQube
- **DAST** — Dynamic Application Security Testing via OWASP ZAP 2.16.1 (bundled, no install needed)
- **SCA** — Software Composition Analysis via Trivy (bundled, no install needed)

All three engines apply AI-powered vulnerability prioritization and risk scoring, and can generate automated GitHub pull requests with remediation suggestions.

---

## 2. Installation & Requirements

| Requirement | Details |
|---|---|
| Python | 3.10 or higher |
| AppSecAI application | In a writable folder on your machine |
| GitHub Personal Access Token | Required for SAST cloning and PR creation |
| SonarQube instance | Local or remote (SAST only) |
| Internet access | For cloning repos and Trivy vulnerability DB updates |

> **Note:** OWASP ZAP (DAST) and Trivy (SCA) are bundled inside AppSecAI. No separate installation is required for either tool.

**To launch AppSecAI:**

```bash
cd caze-code-sec-ai
python -m appsecai.cli.menu
```

> If you see `ModuleNotFoundError: No module named 'appsecai'`, you are running the command from the wrong directory. Navigate into the `caze-code-sec-ai` folder first.

---

## 3. Quick Start

### JSON Mode (Recommended for Automation)

1. Edit `appsec_config.json` with your targets and credentials
2. Run:

```bash
python -m appsecai.cli.menu
```

3. Press **Enter** (or type `1`) to select JSON Mode
4. From the Main Menu, select the scan type (`1` = SAST, `2` = DAST, `3` = SCA)

Example output:

```
✅ SCA scan completed
📄 Results saved to AppSecAI_output/
```

---

### Interactive CLI Mode (Recommended for First-Time Setup)

1. Run `python -m appsecai.cli.menu`
2. Select `2` — Configure & Run Scan (Interactive Setup)
3. Follow the Advanced CLI Configuration Wizard to configure modules
4. Select `0` to finish configuration and proceed to scans

---

## 4. Configuration Methods

### 4.1 Method 1 — JSON Configuration Mode

Recommended for:
- CI/CD pipelines
- Automation and repeatable scans
- Headless environments

All settings are read from `appsec_config.json` in the same folder as the application. Edit the file once and run scans immediately.

**Minimal JSON example (sanitized):**

```json
{
  "github_repo": "username/repository",
  "github_token": "ghp_xxxxxxxxxxxxxxxxx",
  "github_branch": "main",
  "sonar_url": "http://localhost:9000",
  "sonar_username": "admin",
  "sonar_password": "your_sonar_password",
  "sonar_project_key": "my-app-key",
  "dast_url": "https://your-target-app.com",
  "sca_target_type": "fs",
  "sca_target_path": "./",
  "output_dir": "AppSecAI_output"
}
```

**Configuration key reference:**

| Key | Description |
|---|---|
| `github_repo` | GitHub repository in `owner/repo` format |
| `github_token` | GitHub Personal Access Token |
| `github_branch` | Branch to scan (default: `main`) |
| `sonar_url` | SonarQube server URL |
| `sonar_username` | SonarQube username |
| `sonar_password` | SonarQube password or project token |
| `sonar_project_key` | SonarQube project key |
| `dast_url` | Target URL for DAST scanning |
| `sca_target_type` | Scan target type: `fs`, `image`, `repo`, `k8s`, `vm`, `rootfs` |
| `sca_target_path` | Path or URL of the SCA scan target |
| `output_dir` | Directory where output files are saved |

> **Security note:** Never commit `appsec_config.json` containing real tokens or passwords to version control.

---

### 4.2 Method 2 — Interactive CLI Wizard

Recommended for:
- First-time setup
- Manual and ad-hoc scans
- Guided configuration

Select `2` at the startup menu. The **Advanced CLI Configuration Wizard** opens:

```
Main Menu > Advanced Setup Wizard

┌─────────────────────────────────────────────────────────────┐
│             ADVANCED CLI CONFIGURATION WIZARD               │
├─────────────────────────────────────────────────────────────┤
│  1. SAST Configuration                                      │
│  2. DAST Configuration                                      │
│  3. SCA Configuration                                       │
│  0. Finish Configuration & Continue to Scans                │
└─────────────────────────────────────────────────────────────┘

👉 Select option (0-3):
```

Select the module you want to configure (`1` for SAST, `2` for DAST, `3` for SCA). When done, press `0` to proceed to scans.

> Every setting you change in Interactive Mode is **auto-saved to `.env` immediately** — no manual save step is needed.

**Configuration priority (highest to lowest):**

1. Active environment variables / CLI flags
2. `appsec_config.json`
3. `.env` file (auto-saved interactive settings)
4. `app_config.yaml` (system defaults)

---

## 5. Navigation Basics

AppSecAI uses a `cd`-style navigation system. At any prompt you can type a `cd` command instead of a menu number.

A breadcrumb is shown at every screen indicating your current location:

```
Main Menu > Settings Menu > SAST Configuration
```

**Navigation commands:**

| Command | Action |
|---|---|
| `cd settings` | Go to Settings Menu |
| `cd sast` | Go to SAST Configuration |
| `cd dast` | Go to DAST Configuration |
| `cd sca` | Go to SCA Configuration |
| `cd sonar` | Go to SonarQube Settings |
| `cd scan` | Go to Security Analysis menu |
| `cd output` | Configure Output Directory |
| `cd about` | Show About screen |
| `cd ..` or `cd/back` | Go back one level |
| `cd /` or `cd/main` | Go to Main Menu |
| `cd/list` | Show available menus from current location |
| `cd/help` | Show navigation help |

> **Tip:** Press **Tab** after `cd ` to autocomplete menu names. Command history is stored in `~/.caze_cli_history` (navigate with Up/Down arrow keys).

---

## 6. Main Menu Overview

After selecting your mode, the Main Menu appears:

```
Main Menu

┌─────────────────────────────────────────────────────────────┐
│                         MAIN MENU                           │
├─────────────────────────────────────────────────────────────┤
│  1.  Run SAST Risk Analysis                                 │
│  2.  Run DAST Risk Analysis                                 │
│  3.  Run SCA Risk Analysis                                  │
│  4.  View Configuration                                     │
│  0.  Exit                                                   │
└─────────────────────────────────────────────────────────────┘

Active Configuration:
- Mode: JSON (appsec_config.json)
- Repository: username/repository-name
- Target URL: https://your-target-app.com
- GitHub Token: ✅ Set
- Context Profile: Default

👉 Select option (0-4) or command (cd <menu>, cd/, cd ..):
```

- **Option 1** — Run SAST: analyzes source code for security issues via SonarQube
- **Option 2** — Run DAST: scans a running web application via OWASP ZAP
- **Option 3** — Run SCA: scans dependencies and packages via Trivy
- **Option 4** — View Configuration: displays all active settings
- **Option 0** — Exit

---

## 7. SAST Analysis

### 7.1 Prerequisites

| Requirement | Details |
|---|---|
| GitHub repository | Public or private repo to scan |
| GitHub Personal Access Token | `repo` scope required; `workflow` scope if using GitHub Actions |
| SonarQube instance | Local or remote (see Section 7.3) |

> If SonarQube is not reachable, AppSecAI automatically falls back to a **mock SAST analysis** so you can still explore the workflow.

---

### 7.2 Generate a GitHub Personal Access Token

1. Log in to https://github.com
2. Click your profile picture → **Settings**
3. Scroll to **Developer settings** → **Personal access tokens** → **Tokens (classic)**
4. Click **Generate new token (classic)**
5. Name it (e.g. `AppSecAI-Token`), set expiration (90 days recommended)
6. Select scopes: `repo` (required), `workflow` (if the repo uses GitHub Actions)
7. Click **Generate token** — **copy it immediately**, it won't be shown again

---

### 7.3 Set Up SonarQube

The easiest way to run SonarQube locally is with Docker:

```bash
docker run -d --name sonarqube -p 9000:9000 sonarqube:community
```

Wait ~60 seconds then open `http://localhost:9000`.
Default credentials: `admin` / `admin` (you will be prompted to change the password on first login).

**Create a SonarQube project:**

1. Click **Create Project** → **Manually**
2. Enter a **Project display name** and a **Project key** (e.g. `my-app-key`) — note the key down
3. Click **Set Up** → **Locally** and generate a project token when prompted

> The **Project Key** is what you enter in AppSecAI as `sonar_project_key`.

**Configure and run the scanner** (optional — AppSecAI can trigger this automatically):

Create `sonar-project.properties` in your project root:

```properties
sonar.projectKey=my-app-key
sonar.projectName=My Application
sonar.projectVersion=1.0
sonar.sources=.
sonar.host.url=http://localhost:9000
sonar.login=<your-sonarqube-project-token>
```

Then run:

```bash
sonar-scanner
```

---

### 7.4 Configure SAST Settings

#### JSON Mode

Add SAST fields to `appsec_config.json`:

```json
{
  "github_token": "ghp_yourTokenHere",
  "github_repo": "username/repository-name",
  "github_branch": "main",
  "sonar_url": "http://localhost:9000",
  "sonar_username": "admin",
  "sonar_password": "your_sonar_password",
  "sonar_project_key": "my-app-key"
}
```

#### Interactive CLI Mode

From the Main Menu, type `cd settings` then select `1` or type `cd sast`.

The SAST Configuration menu opens:

```
Main Menu > Settings Menu > SAST Configuration

┌─────────────────────────────────────────────────────────────┐
│                [SAST] STATIC ANALYSIS SETTINGS              │
├─────────────────────────────────────────────────────────────┤
│  1.  Configure GitHub Repository                            │
│  2.  Configure GitHub Token                                 │
│  3.  Configure SonarQube Settings                           │
│  0.  Back to Settings Menu                                  │
└─────────────────────────────────────────────────────────────┘

👉 Select option (0-3):
```

Select `3` or type `cd sonar` for SonarQube settings:

```
Main Menu > Settings Menu > SAST Configuration > SonarQube Settings

┌─────────────────────────────────────────────────────────────┐
│                    SONARQUBE SETTINGS                       │
├─────────────────────────────────────────────────────────────┤
│  1.  Configure SonarQube URL                                │
│  2.  Configure Username                                     │
│  3.  Configure Password                                     │
│  4.  Configure Project Key                                  │
│  5.  View Current Settings                                  │
│  0.  Back to Settings Menu                                  │
└─────────────────────────────────────────────────────────────┘

👉 Select option (0-5) or command (cd <menu>, cd/, cd ..):
```

- **Option 1** — Enter your SonarQube URL (e.g. `http://localhost:9000`). Must include `http://` or `https://`
- **Option 2** — Enter your SonarQube username (default: `admin`)
- **Option 3** — Enter your SonarQube password or project token (input hidden)
- **Option 4** — Enter your SonarQube project key (e.g. `my-app-key`)
- **Option 5** — View all current SonarQube settings (password masked)

---

### 7.5 Running the SAST Pipeline

#### JSON Config Mode

1. Ensure `appsec_config.json` has GitHub and SonarQube fields filled in
2. Ensure DOCKER running and sonar-project.properties saved inside proper local project folder
3. Launch the app and press Enter (Mode 1)
4. From the Main Menu select **1. Run SAST Risk Analysis**

The pipeline will clone your repository, run SonarQube analysis, fetch vulnerability data, apply AI-powered risk scoring, filter by your threshold, and save output to `CazeAppSecReport/AppSecAI_output/`.

#### Interactive CLI Mode

From the scan menu, select **1. Run SAST Risk Analysis**.

#### Direct CLI Command

```bash
python -m appsecai.cli.menu scan --type sast --target https://github.com/username/repo.git
```

With options:

```bash
python -m appsecai.cli.menu scan --type sast --target https://github.com/username/repo.git --branch develop --export --output-dir my_results
```

**All `scan` flags for SAST:**

| Flag | Description |
|---|---|
| `--type sast` | Run SAST scan |
| `--target` | GitHub repository URL (required) |
| `--branch` | Branch to scan (e.g. `main`, `develop`) |
| `--project-key` | SonarQube project key (overrides config) |
| `--github-token` | GitHub token (overrides config) |
| `--sonar-username` | SonarQube username (overrides config) |
| `--sonar-password` | SonarQube password (overrides config) |
| `--clone-dir` | Directory for cloning the repo (default: `cloned_repos`) |
| `--export` | Export results to files |
| `--output-dir` | Output directory (overrides config) |
| `--auto-fix` | Automatically run AI remediation after scan |
| `--interactive-pr` | Ask for confirmation before creating PRs (use with `--auto-fix`) |

---

### 7.6 SAST Output & Report Fields

SAST Analysis report will be genereated in  generated_report folder in .pdf format.  
Output files are saved to `CazeAppSecReport/AppSecAI_output/`.

| File | Description |
|---|---|
| `raw_vulnerabilities.csv` | All SonarQube results before filtering |
| `filtered_vulnerabilities.csv` | Results that passed the threshold |
| `sast_report_<timestamp>.html` | HTML report (with `--export`) |
| `sast_report_<timestamp>.json` | JSON data (with `--export`) |

**Key report fields:**

| Field | Description |
|---|---|
| `id` | Unique vulnerability identifier |
| `type` | `BUG`, `VULNERABILITY`, or `CODE_SMELL` |
| `severity` | `Critical`, `High`, `Medium`, `Low` |
| `title` | Short description |
| `file_path` | Source file |
| `line_number` | Line number |
| `rule_key` | SonarQube rule ID |
| `risk_score` | AI-computed risk score (higher = more critical) |

---

### 7.7 Troubleshooting

**SonarQube connection fails**
- Verify SonarQube is running and accessible at the configured URL
- Check username and password are correct
- Use Option 5 (View Current Settings) in SonarQube Settings to confirm values

**Repository clone fails**
- Verify your GitHub PAT has `repo` scope
- Confirm the repository format is `username/repo-name` (no `https://github.com/` prefix in JSON config)
- Check internet connection

**No vulnerabilities found**
- Lower `vulnerability_threshold` (try `1` or `2`)
- Verify the SonarQube project has completed analysis
- Confirm the correct `sonar_project_key` is configured

**Mock SAST running instead of real SonarQube**
- SonarQube credentials or URL are missing or invalid
- Reconfigure via `cd sonar` or update `appsec_config.json`

---

## 8. DAST Analysis

### 8.1 Prerequisites

| Requirement | Details |
|---|---|
| Running web application | Accessible via HTTP or HTTPS |
| Target URL | Full URL of the app to scan (e.g. `https://app.example.com`) |

> OWASP ZAP 2.16.1 is **bundled inside AppSecAI** — no separate installation is needed.

---

### 8.2 Configure DAST Settings

#### JSON Mode

Add the DAST field to `appsec_config.json`:

```json
{
  "dast_url": "https://your-target-app.com",
  "output_dir": "AppSecAI_output"
}
```

To analyze an existing ZAP HTML report instead of running a live scan, also set:

```json
{
  "zap_report_path": "C:\\path\\to\\security_recommendations.html"
}
```

#### Interactive CLI Mode

From the Main Menu, navigate to `Main Menu > Advanced Setup Wizard > DAST Config`, or at any time type `cd dast`.

The DAST Configuration menu:

```
Main Menu > Settings Menu > DAST Configuration

┌─────────────────────────────────────────────────────────────┐
│               [DAST] DYNAMIC ANALYSIS SETTINGS              │
├─────────────────────────────────────────────────────────────┤
│  1.  Configure DAST Target URL(s)                           │
│  2.  Configure ZAP Scanner Settings                         │
│  3.  Configure ZAP Report Path (Upload)                     │
│  0.  Back to Settings Menu                                  │
└─────────────────────────────────────────────────────────────┘

👉 Select option (0-3):
```

**Option 1 — Configure DAST Target URL(s)**

```
📍 Configure DAST Target URL(s)

Options:
1. Set single URL
2. Set multiple URLs (one by one)
3. Set multiple URLs (comma-separated)
4. View current URLs
5. Clear all URLs

Select option (1-5):
```

The URL must include the protocol (`http://` or `https://`). Invalid formats are rejected with an error.

**Option 2 — Configure ZAP Scanner Settings**

Displays the current ZAP configuration:

```
🔧 ZAP Scanner Configuration:
• ZAP installation path: external/ZAP_2.16.1/
• Default scan policy: Default Policy
• Max scan time: 3600 seconds
• Spider max depth: 5
💡 These settings can be modified in app_config.yaml
```

Advanced ZAP settings (scan policy, max scan time, spider depth) can be tuned in `app_config.yaml`.

**Option 3 — Configure ZAP Report Path (Upload)**

Use this if you already have a ZAP HTML report and want AppSecAI to analyze it without running a live scan:

```
📤 Configure ZAP Report Path (Upload for Analysis)
Current Path: Not set

Enter path to ZAP security_recommendations.html (or '0' to back):
```

**Context Modifiers — Deployment Settings**

From the DAST Config wizard, select `2` (Context Modifiers) to configure deployment context that improves AI scoring accuracy:

| Sub-menu | Command | Description |
|---|---|---|
| product and version | `cd product` | App name & version |
| environment | `cd env` | Deployment type, compliance |
| runtime | `cd runtime` | Container, monitoring & resource limits |
| service | `cd service` | Service auth & rate limiting |
| security controls | `cd security` | RBAC, WAF, MFA, etc. |

---

### 8.3 Running a DAST Scan

#### JSON Config Mode

1. Set `dast_url` in `appsec_config.json`
2. Launch the app and press Enter (Mode 1)
3. From the Main Menu select **2. Run DAST Risk Analysis**

The pipeline will launch ZAP in headless mode, spider crawl the target, perform passive and active scanning, apply AI risk scoring, filter by threshold, and save output to `CazeAppSecReport/AppSecAI_output/`.

#### Interactive CLI Mode

From the scan menu, select **2. Run DAST Risk Analysis**.

#### Direct CLI Command

```bash
python -m appsecai.cli.menu scan --type dast --target https://your-target-app.com
```

With options:

```bash
python -m appsecai.cli.menu scan --type dast --target https://your-target-app.com --timeout 1800 --export --output-dir dast_results
```

**Combined SAST + DAST scan:**

```bash
python -m appsecai.cli.menu scan --type both --target https://github.com/username/repo.git --dast-url https://your-target-app.com
```

**All `scan` flags for DAST:**

| Flag | Description |
|---|---|
| `--type dast` | Run DAST scan |
| `--target` | Target web application URL (required) |
| `--timeout` | Scan timeout in seconds (overrides config) |
| `--export` | Export results to files |
| `--output-dir` | Output directory (overrides config) |
| `--auto-fix` | Automatically run AI remediation after scan |
| `--interactive-pr` | Ask for confirmation before creating PRs (use with `--auto-fix`) |

---

### 8.4 DAST Output & Report Fields

Output files are saved to `CazeAppSecReport/AppSecAI_output/`.

| File | Description |
|---|---|
| `zap_report_<timestamp>.html` | Full ZAP HTML report |
| `dast_vulnerabilities_<timestamp>.csv` | Normalized vulnerability list |
| `dast_report_<timestamp>.json` | JSON data (with `--export`) |

**Key report fields:**

| Field | Description |
|---|---|
| `id` | Unique vulnerability identifier |
| `severity` | `Critical`, `High`, `Medium`, `Low` |
| `title` | Vulnerability name (e.g. `SQL Injection`, `XSS`) |
| `url` | Affected URL |
| `parameter` | Affected parameter or input field |
| `confidence` | ZAP confidence level |
| `solution` | Recommended fix |
| `cwe_id` | CWE identifier |
| `risk_score` | AI-computed risk score |
| `ai_recommendation` | AI-generated remediation advice |

---

## 9. SCA Analysis

### 9.1 Prerequisites

| Requirement | Details |
|---|---|
| Project to scan | Local directory, container image, or repository |
| Internet access | For Trivy to download vulnerability databases |

> Trivy is **bundled inside AppSecAI** — no separate installation is needed.

---

### 9.2 Configure SCA Settings

#### JSON Mode

Add SCA fields to `appsec_config.json`:

```json
{
  "sca_target_type": "fs",
  "sca_target_path": "./",
  "vulnerability_threshold": 4.0
}
```

For a GitHub repository scan:

```json
{
  "sca_target_type": "repo",
  "sca_target_path": "https://github.com/username/repo"
}
```

#### Interactive CLI Mode

From the Main Menu type `cd settings`, then select `3` or type `cd sca`. The SCA Configuration menu opens:

```
Main Menu > Settings Menu > SCA Configuration

┌─────────────────────────────────────────────────────────────┐
│             [SCA] SOFTWARE COMPOSITION SETTINGS             │
├─────────────────────────────────────────────────────────────┤
│  1.  Configure SCA (Trivy) Scan Settings                    │
│  2.  Configure GitHub Token                                 │
│  0.  Back to Settings Menu                                  │
└─────────────────────────────────────────────────────────────┘

👉 Select option (0-2):
```

Select `1` to set the scan target:

```
📦 Configure SCA (Trivy) Scan Settings
Current Target Type: fs
Current Target Path: ./

Enter target type (fs, image, repo, k8s, container, vm, rootfs) [fs]:
```

**Target types:**

| Type | Description | Example |
|---|---|---|
| `fs` | Local filesystem directory | `./my-project` or `.` |
| `image` | Container image | `python:3.9`, `ubuntu:latest` |
| `repo` | Remote Git repository | `https://github.com/user/repo` or `user/repo` |
| `k8s` | Kubernetes cluster | `cluster` |
| `container` | Running container | `<container_id>` |
| `vm` | Virtual machine image | `<vm_image_path>` |
| `rootfs` | Root filesystem | `<rootfs_path>` |

---

### 9.3 SCA Context (Optional but Recommended)

The SCA context provides AppSecAI with information about your project environment, which improves AI-powered risk scoring accuracy.

Navigate directly with:

```
cd settings
cd sca context
```

The SCA Context Settings menu:

```
Main Menu > Settings Menu > SCA Context Settings

┌──────────────────────────────────────────────────────────────────────┐
│                  CONFIGURE SCA CONTEXT SETTINGS                      │
├──────────────────────────────────────────────────────────────────────┤
│  1. dependency management  - Update frequency, SBOM, lock files      │
│  2. package sources        - Registry, signature verification        │
│  3. vulnerability response - Patching, monitoring, emergency process │
│  4. build pipeline         - SLSA, hash verification, reproducibility│
│  5. runtime behavior       - Sandboxing, isolation, network access   │
│  6. ecosystem              - Language version, package manager       │
│  7. compliance             - Standards (SOC2, HIPAA, PCI-DSS, etc.)  │
│  0. back or cd/..          - Return to Settings Menu                 │
└──────────────────────────────────────────────────────────────────────┘

👉 Select option (0-7), command, or cd navigation:
```

Each sub-menu configures context that influences vulnerability scoring:

- **Dependency Management** — Update frequency, lock file enforcement, SBOM generation, pinning strategy
- **Package Sources** — Private registry use, package signature verification, trusted sources
- **Vulnerability Response** — Mean time to patch, monitoring frequency, emergency patch process
- **Build Pipeline** — SLSA level, hash verification, reproducible builds, dependency caching
- **Runtime Behavior** — Dependency isolation, sandboxing, dynamic loading restrictions
- **Ecosystem** — Primary language, package manager, monorepo flag
- **Compliance** — SOC2, HIPAA, PCI-DSS, GDPR, ISO 27001 requirements

These settings are stored in the `AppSecAI.sca_context` section of `appsec_config.json`.

---

### 9.4 Running an SCA Scan

#### JSON Config Mode

1. Ensure `appsec_config.json` has `sca_target_type` and `sca_target_path` set
2. Launch the app and press Enter (Mode 1)
3. From the Main Menu select **3. Run SCA Risk Analysis**

The pipeline will run Trivy against your target, parse the report, apply AI-powered risk scoring using your SCA context, filter by threshold, and save output to `CazeAppSecReport/AppSecAI_output/`.

Example terminal summary:

```
🔍 Starting SCA scan
📦 Executing native Trivy scan
🧮 Applying AppSecAI prioritization engine

SCA Analysis Complete
   Scan ID: sca_20260512_162323
   Total findings in report: 142
   Prioritized findings: 38
   Critical: 6  |  High: 18  |  Medium: 12  |  Low: 2
   Output: CazeAppSecReport/AppSecAI_output/sca_prioritized_20260512_162323.csv

✅ SCA scan completed
📄 Results saved to AppSecAI_output/
```

#### Interactive CLI Mode

From the scan menu, select **3. Run SCA Risk Analysis**.

#### Direct CLI Command

```bash
python -m appsecai.cli.menu scan --type sca --target ./my-project
```

With options:

```bash
python -m appsecai.cli.menu scan --type sca --target ./my-project --target-type fs --export --output-dir sca_results
```

**All `scan --type sca` flags:**

| Flag | Description |
|---|---|
| `--type sca` | Run SCA scan |
| `--target` | Target path or URL to scan |
| `--target-type` | Target type: `fs`, `image`, `repo`, `k8s`, `vm`, `rootfs` (default: `fs`) |
| `--export` | Export results to files |
| `--output-dir` | Output directory (overrides config) |

**Analyzing an existing Trivy report (sca subcommand):**

```bash
python -m appsecai.cli.menu sca --trivy-report trivy_report.json
```

With export options:

```bash
python -m appsecai.cli.menu sca --trivy-report trivy_report.json --output-dir sca_results --export-json --export-pdf
```

| Flag | Description |
|---|---|
| `--trivy-report` | Path to Trivy JSON report file (required) |
| `--output-dir` | Output directory for SCA results |
| `--export-json` | Export prioritized SCA findings to JSON |
| `--export-pdf` | Generate SCA security posture PDF report |

---

### 9.5 SCA Output & Report Fields

Output files are saved to `CazeAppSecReport/AppSecAI_output/`.

| File | Description |
|---|---|
| `sca_prioritized_<timestamp>.csv` | Prioritized vulnerability list |
| `sca_findings_<timestamp>.json` | JSON findings (with `--export-json`) |
| `sca_report_<timestamp>.pdf` | PDF security posture report (with `--export-pdf`) |

**What AppSecAI analyzes:**

| Finding Type | Description |
|---|---|
| Vulnerabilities | Known CVEs in package dependencies |
| Misconfigurations | Infrastructure and configuration issues |
| Secrets | Exposed credentials, API keys, tokens |

**Key report fields:**

| Field | Description |
|---|---|
| `id` | Unique vulnerability identifier |
| `source_id` | CVE or finding ID from Trivy |
| `scanner` | Scanner that found the issue (e.g. `trivy`) |
| `target` | File or component where the issue was found |
| `severity` | `Critical`, `High`, `Medium`, `Low` |
| `package_name` | Affected package name |
| `installed_version` | Currently installed version |
| `fixed_version` | Version that fixes the vulnerability |
| `cvss_score` | CVSS base score |
| `cwe_id` | CWE identifier |
| `risk_score` | AI-computed risk score (higher = more critical) |
| `risk_level` | `Critical`, `High`, `Medium`, `Low`, `Info` |
| `category` | Vulnerability category (e.g. `injection`, `crypto`, `auth`) |
| `ai_justification` | AI-generated explanation of why this is prioritized |

---

## 10. Reports & Output Files

All output files are saved to `CazeAppSecReport/AppSecAI_output/` by default (configurable via `output_dir`).

| Module | File | Description |
|---|---|---|
| SAST | `raw_vulnerabilities.csv` | All SonarQube results before filtering |
| SAST | `filtered_vulnerabilities.csv` | Results that passed the threshold |
| SAST | `sast_report_<timestamp>.html/json` | Formatted reports (with `--export`) |
| DAST | `zap_report_<timestamp>.html` | Full ZAP HTML report |
| DAST | `dast_vulnerabilities_<timestamp>.csv` | Normalized vulnerability list |
| DAST | `dast_report_<timestamp>.json` | JSON data (with `--export`) |
| SCA | `sca_prioritized_<timestamp>.csv` | Prioritized vulnerability list |
| SCA | `sca_findings_<timestamp>.json` | JSON findings (with `--export-json`) |
| SCA | `sca_report_<timestamp>.pdf` | PDF posture report (with `--export-pdf`) |

---

## 11. CLI Reference

### Startup

```bash
python -m appsecai.cli.menu
```

```
How would you like to configure AppSecAI?
1. Run Scan using Configuration File (appsec_config.json)
2. Configure & Run Scan (Interactive Setup)
3. Help / Usage Guide
4. About AppSecAI

Select mode (1-4) [Default: 1]:
```

### Global Flags

| Flag | Short | Description |
|---|---|---|
| `--config` | `-c` | Config file path (default: `app_config.yaml`) |
| `--verbose` | `-v` | Enable verbose output |
| `--quiet` | `-q` | Suppress non-essential output |
| `--output-dir` | `-o` | Output directory (default: `AppSecAI_output`) |
| `--format` | `-f` | Output format: `json`, `csv`, `html`, `pdf` |

### Available Commands

| Command | Description |
|---|---|
| `app` | Launch the interactive menu-driven application |
| `scan` | Run a security scan (SAST, DAST, SCA, or combined) |
| `fix` | Generate and apply AI-powered vulnerability fixes |
| `report` | Generate security reports in multiple formats |
| `config` | Manage and validate configuration |
| `sca` | Analyze a Trivy JSON report directly |

### Example Commands

```bash
# SAST scan
python -m appsecai.cli.menu scan --type sast --target https://github.com/user/repo.git

# DAST scan
python -m appsecai.cli.menu scan --type dast --target https://example.com

# Combined SAST + DAST
python -m appsecai.cli.menu scan --type both --target https://github.com/user/repo.git --dast-url https://app.example.com

# SCA scan
python -m appsecai.cli.menu scan --type sca --target ./my-project

# Analyze existing Trivy report
python -m appsecai.cli.menu sca --trivy-report trivy_output.json --export-json --export-pdf

# AI fix generation
python -m appsecai.cli.menu fix --input filtered_vulnerabilities.csv --create-prs

# Generate report
python -m appsecai.cli.menu report --input results.json --format html,pdf

# Config management
python -m appsecai.cli.menu config --validate
python -m appsecai.cli.menu config --init
python -m appsecai.cli.menu config --show
```

---

## 12. Troubleshooting

### ModuleNotFoundError: No module named 'appsecai'

Running the command from outside the project root directory.

```bash
cd caze-code-sec-ai
python -m appsecai.cli.menu
```

### SonarQube Connection Failed

- Verify SonarQube is running and accessible at the configured URL
- Check that username and password are correct
- Use `cd sonar` → Option 5 to view current settings

### Repository Clone Fails

- Verify your GitHub PAT has `repo` scope
- Confirm the repository format is `username/repo-name` (no `https://github.com/` prefix in JSON config)
- Check internet connection

### No Vulnerabilities Found

- Verify the SonarQube project has completed analysis (SAST)
- Confirm the correct `sonar_project_key` is configured
- Check that the scan completed without errors in the terminal output

### Trivy Not Found / SCA Scan Fails

- Ensure the app is running from inside the `caze-code-sec-ai` directory
- Trivy is bundled — no separate installation is needed
- Check terminal output for the exact error message

### Output Files Not Found

- Reports save to `CazeAppSecReport/AppSecAI_output/` next to the application
- Check the terminal output after the scan for the exact file path printed

### Mock SAST Running Instead of Real SonarQube

- SonarQube credentials or URL are missing or invalid
- Reconfigure via `cd sonar` or update `appsec_config.json`

---

*AppSecAI is built by CazeLabs. For support, refer to the built-in Help Guide (option `3` at the startup menu) or type `cd about` from inside the application.*
