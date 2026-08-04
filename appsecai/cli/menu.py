#!/usr/bin/env python3
"""
Interactive CLI Application for Caze AppSecAI

Provides a menu-driven interface for security scanning, configuration, and AI remediation.
"""

import os
import subprocess
import sys
import json
import atexit
from typing import Dict, Any, Optional
from pathlib import Path
from appsecai.common.utils import get_resource_path, load_appsec_json_data, get_executable_path

from difflib import get_close_matches

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Setup readline for tab completion (platform-specific)
try:
    if sys.platform == 'win32':
        try:
            # pyrefly: ignore [missing-import]
            import pyreadline3 as readline
        except ImportError:
            import readline
    else:
        import readline
    READLINE_AVAILABLE = True
except ImportError:
    READLINE_AVAILABLE = False

def get_base_directory():
    """Get the base directory where reports should be saved."""
    if getattr(sys, 'frozen', False):
        # Running as EXE - create dedicated CazeAppSecReport folder
        # CRITICAL: Don't use os.getcwd() as it returns temp extraction folder
        # Use the directory where the EXE is located instead
        exe_path = Path(sys.executable)
        exe_dir = exe_path.parent
        
        # If exe_dir contains _MEI (temp folder), use Desktop as fallback
        if '_MEI' in str(exe_dir):
            # EXE is in temp extraction folder, use Desktop
            base_path = Path.home() / "Desktop"
        else:
            # EXE is in a real directory
            base_path = exe_dir
        
        report_folder = base_path / "CazeAppSecReport"
        
        # Create the folder if it doesn't exist
        report_folder.mkdir(exist_ok=True)
        
        return report_folder
    else:
        # Running as Python CLI - use current working directory (no change)
        return Path.cwd()

class InteractiveCLI:
    """Interactive menu-driven CLI application."""
    
    def __init__(self):
        self.config_manager = None
        self.current_settings = {}
        self.scan_results = []
        # Navigation breadcrumb tracking
        self.navigation_stack = ["Main Menu"]
        self.base_path = str(get_base_directory())
        # Navigation control - track how many levels to exit
        self.exit_levels = 0
        # Menu name mapping for cd command
        self._init_menu_map()
        # Setup tab completion
        self._setup_autocomplete()
        # Track if initial setup check was performed
        self.setup_checked = False
        
    def _is_valid_url(self, url: str) -> bool:
        """Validate if a string is a properly formatted URL with protocol and host."""
        if not url:
            return False
        try:
            from urllib.parse import urlparse
            result = urlparse(url)
            # Must have scheme (http/https) and netloc (host)
            return all([result.scheme in ['http', 'https'], result.netloc])
        except Exception:
            return False
        
    def start(self):
        """Start the interactive CLI application."""
        self._show_banner()
        self._load_initial_config()
        
        # Startup loop
        while True:
            print("\nHow would you like to configure AppSecAI?")
            print("1. Run Scan using Configuration File (appsec_config.json)")
            print("2. Configure & Run Scan (Interactive Setup)")
            print("3. Help / Usage Guide")
            print("4. About AppSecAI")
            
            mode_choice = input("\nSelect mode (1-4) [Default: 1]: ").strip()
            
            if mode_choice == '3':
                self._show_help()
                continue
            elif mode_choice == '4':
                self._show_about_appsecai()
                continue
            elif mode_choice == '2':
                self.cli_mode = True
                print("\n🔄 Booting Interactive CLI Wizard...")
                self._advanced_cli_setup()
                break
            elif mode_choice == '1' or mode_choice == '':
                self.cli_mode = False
                print("\n🚀 Booting Streamlined JSON Mode...")
                from appsecai.common.config import ConfigManager
                self.config_manager = ConfigManager(force_json_priority=True)
                self.config_manager.generate_default_appsec_json()
                self._refresh_settings()
                break
            else:
                print("❌ Invalid choice. Please enter 1, 2, 3, or 4.")
        
        while True:
            try:
                if getattr(self, 'cli_mode', False):
                    # CLI Mode is dropped straight into the Scan Menu
                    choice = self._scan_menu_inline()
                    
                    if choice == '1': self._run_sast_scan()
                    elif choice == '2': self._run_dast_scan()
                    elif choice == '3': self._run_sca_scan()
                    elif choice == '4':
                        print("\n🔄 Returning to Interactive CLI Wizard...")
                        self._advanced_cli_setup()
                    elif choice == '0':
                        print("\n👋 Thank you for using Caze AppSecAI CLI!")
                        break
                    elif choice == '':
                        continue
                    else:
                        print("❌ Invalid choice. Please try again.")
                else:
                    # JSON Mode Main Menu
                    choice = self._show_main_menu()
                    
                    if choice == '1': self._run_sast_scan()
                    elif choice == '2': self._run_dast_scan()
                    elif choice == '3': self._run_sca_scan()
                    elif choice == '4': self._view_active_configuration()
                    elif choice == '5':
                        print("\n🔄 Booting Interactive CLI Wizard...")
                        self._advanced_cli_setup()
                    elif choice == '0':
                        print("\n👋 Thank you for using Caze AppSecAI CLI!")
                        break
                    elif choice == '':
                        continue
                    else:
                        print("❌ Invalid choice. Please try again.")
                    
            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"\n❌ Error: {e}")
                input("Press Enter to continue...")
    
    def _show_banner(self):
        """Display application banner."""
        print("""
╔══════════════════════════════════════════════════════════════╗
║                      CazeAppSecAI CLI                        ║
╚══════════════════════════════════════════════════════════════╝
        """)
    
    def _display_breadcrumb(self):
        """Display current location breadcrumb."""
        breadcrumb = " > ".join(self.navigation_stack)
        print(f"\n{self.base_path}> {breadcrumb}\n")
    
    def _init_menu_map(self):
        """Initialize menu name mapping for cd command."""
        self.menu_map = {
            # Main menu variations
            'main': 'Main Menu',
            'main menu': 'Main Menu',
            
            # Exit variations
            'exit': 'Exit',
            'quit': 'Exit',
            'q': 'Exit',
            'bye': 'Exit',
            
            # Settings variations
            'settings': 'Settings Menu',
            'setting': 'Settings Menu',
            'settings menu': 'Settings Menu',
            'settings & configuration': 'Settings Menu',
            'config': 'Settings Menu',
            'configuration': 'Settings Menu',
            
            # Category variations
            'sast config': 'SAST Configuration',
            'sast settings': 'SAST Configuration',
            'sast': 'SAST Configuration',
            
            'dast config': 'DAST Configuration',
            'dast settings': 'DAST Configuration',
            'dast': 'DAST Configuration',
            
            'sca config': 'SCA Configuration',
            'sca settings': 'SCA Configuration',
            'sca': 'SCA Configuration',
            
            'general config': 'General Settings',
            'general settings': 'General Settings',
            'general': 'General Settings',
            
            # Save configuration variation
            'save': 'Save Configuration',
            'save config': 'Save Configuration',
            'persist': 'Save Configuration',
            
            # Connection testing shortcuts
            'test sast': 'Test SAST Connections',
            'test dast': 'Test DAST Connections',
            'test connections': 'Settings Menu', # Redirect legacy command to top settings for save/load options
            'testing': 'Settings Menu',
            
            # Scanning variations
            'scanning': 'Security Analysis',
            'scan': 'Security Analysis',
            'security scanning': 'Security Analysis',
            'security': 'Security Analysis',
            'analysis': 'Security Analysis',
            'security analysis': 'Security Analysis',
            
            # How To variations
            'how': 'How To',
            'howto': 'How To',
            'how to': 'How To',
            'how-to': 'How To',
            'guide': 'How To',
            'tutorial': 'How To',
            
            # Help variations
            'help': 'Help',
            '?': 'Help',
            'info': 'Help',
            
            # About Us variations
            'about': 'About Us',
            'about us': 'About Us',
            'aboutus': 'About Us',
            'company': 'About Us',
            'caze': 'About Us',
            'cazelabs': 'About Us',
            'caze labs': 'About Us',
            
            # Reports variations
            'reports': 'Reports & Analysis',
            'report': 'Reports & Analysis',
            'reports & analysis': 'Reports & Analysis',
            
            # Remediation variations
            'remediation': 'AI Remediation',
            'ai remediation': 'AI Remediation',
            'ai': 'AI Remediation',
            'fixes': 'AI Remediation',
            'fix': 'AI Remediation',
            
            # Sub-menu variations
            'sonarqube': 'SonarQube Settings',
            'sonarqube settings': 'SonarQube Settings',
            'sonar': 'SonarQube Settings',
            'configure sonarqube': 'SonarQube Settings',
            'configure sonarqube settings': 'SonarQube Settings',
            
            
            'deployment': 'Deployment Settings',
            'deployment settings': 'Deployment Settings',
            'configure deployment': 'Deployment Settings',
            'configure deployment settings': 'Deployment Settings',
            
            # Settings Menu options
            'github': 'GitHub Repository',
            'github repo': 'GitHub Repository',
            'github repository': 'GitHub Repository',
            'configure github': 'GitHub Repository',
            'configure github repository': 'GitHub Repository',
            'configure github repo': 'GitHub Repository',
            'repository': 'GitHub Repository',
            'repo': 'GitHub Repository',
            
            'token': 'GitHub Token',
            'github token': 'GitHub Token',
            'configure token': 'GitHub Token',
            'configure github token': 'GitHub Token',
            
            'llm': 'AI/LLM Settings',
            'ai settings': 'AI/LLM Settings',
            'llm settings': 'AI/LLM Settings',
            'configure llm': 'AI/LLM Settings',
            'configure ai/llm settings': 'AI/LLM Settings',
            'configure ai settings': 'AI/LLM Settings',
            'configure llm settings': 'AI/LLM Settings',
            'ai/llm': 'AI/LLM Settings',
            
            'dast': 'DAST Settings',
            'dast settings': 'DAST Settings',
            'configure dast': 'DAST Settings',
            'configure dast settings': 'DAST Settings',
            
            'sca context': 'SCA Context Settings',
            'sca settings': 'SCA Context Settings',
            'sca context settings': 'SCA Context Settings',
            'configure sca context': 'SCA Context Settings',
            'configure sca context settings': 'SCA Context Settings',
            
            'output': 'Output Directory',
            'output directory': 'Output Directory',
            'configure output': 'Output Directory',
            'configure output directory': 'Output Directory',
            
            # SCA Context sub-menu variations
            'dependency management': 'Dependency Management',
            'dependency': 'Dependency Management',
            'dependencies': 'Dependency Management',
            
            'package sources': 'Package Sources',
            'packages': 'Package Sources',
            'sources': 'Package Sources',
            
            'vulnerability response': 'Vulnerability Response',
            'vuln response': 'Vulnerability Response',
            'response': 'Vulnerability Response',
            
            'build pipeline': 'Build Pipeline',
            'build': 'Build Pipeline',
            'pipeline': 'Build Pipeline',
            
            'runtime behavior': 'Runtime Behavior',
            'runtime': 'Runtime Behavior',
            'behavior': 'Runtime Behavior',
            
            'ecosystem': 'Ecosystem',
            'eco': 'Ecosystem',
            
            'compliance': 'Compliance',
            'standards': 'Compliance',
            
            # Deployment sub-menu variations
            'product': 'Product and Version',
            'product and version': 'Product and Version',
            'product version': 'Product and Version',
            'app name': 'Product and Version',
            
            'environment': 'Environment',
            'env': 'Environment',
            'deployment type': 'Environment',
            
            'runtime': 'Runtime',
            'container': 'Runtime',
            'monitoring': 'Runtime',
            
            'service': 'Service',
            'service auth': 'Service',
            'rate limiting': 'Service',
            
            'security controls': 'Security Controls',
            'security': 'Security Controls',
            'controls': 'Security Controls',
            'rbac': 'Security Controls',
            'waf': 'Security Controls',
            'mfa': 'Security Controls',
            
            'sast': 'SAST Reports',
            'sast reports': 'SAST Reports',
            
            'dast': 'DAST Reports',
            'dast reports': 'DAST Reports',
        }
    
    def _setup_autocomplete(self):
        """Setup tab completion for cd commands."""
        if not READLINE_AVAILABLE:
            return
        
        try:
            # Get all available menu names for autocomplete
            menu_names = list(self.menu_map.keys()) + ['..', '/', '~', 'main', 'home']
            
            def completer(text, state):
                """Tab completion function."""
                line = readline.get_line_buffer()
                
                # Check if we're completing a cd command
                if line.startswith('cd ') or line.startswith('cd/'):
                    # Extract what comes after cd
                    if line.startswith('cd/'):
                        prefix = line[3:]
                    else:
                        prefix = line[3:]
                    
                    # Filter menu names that match
                    options = [name for name in menu_names if name.startswith(prefix.lower())]
                    options.sort()
                    
                    if state < len(options):
                        return options[state]
                
                return None
            
            # Enable tab completion
            readline.set_completer(completer)
            if sys.platform == 'win32':
                readline.parse_and_bind('tab: complete')
            else:
                readline.parse_and_bind('tab: complete')
            
            # Enable history
            histfile = os.path.join(os.path.expanduser("~"), ".caze_cli_history")
            try:
                readline.read_history_file(histfile)
                readline.set_history_length(1000)
            except FileNotFoundError:
                pass
            
            atexit.register(readline.write_history_file, histfile)
            
        except Exception as e:
            # Silently fail if autocomplete setup fails
            pass
    
    def _find_closest_menu(self, target):
        """Find closest matching menu using fuzzy matching."""
        matches = get_close_matches(target, self.menu_map.keys(), n=3, cutoff=0.6)
        return matches
    
    def _show_available_menus(self):
        """Show available menus from current location."""
        current_menu = self.navigation_stack[-1]
        
        print(f"\n📋 Available menus from '{current_menu}':")
        print("=" * 60)
        
        if current_menu == "Main Menu":
            print("  • settings, setting, config - Settings & Configuration")
            print("  • scan, scanning, security, analysis - Security Analysis")
            print("  • how, howto, guide - How To")
            print("  • help, ? - Help")
            print("  • about, company, cazelabs - About Us")
            print("  • reports, report - Reports & Analysis")
            print("  • remediation, ai, fix - AI Remediation")
        elif current_menu == "Settings Menu":
            print("  • sonar, sonarqube - SonarQube Settings")
            print("  • deployment - Deployment Settings")
            print("\n  📌 Quick shortcuts:")
            print("  • cd github, cd token, cd llm, cd output, etc.")
        elif current_menu == "Reports & Analysis":
            print("  • sast - SAST Reports")
            print("  • dast - DAST Reports")
            print("\n  📌 Quick shortcuts:")
            print("  • cd security, cd posture, cd trends")
        elif current_menu == "Security Analysis":
            print("  📌 Quick shortcuts:")
            print("  • cd sast, cd 'sast scan' - Run SAST Scan")
            print("  • cd dast, cd 'dast scan' - Run DAST Scan")
            print("  • cd sca, cd trivy - Run SCA (Trivy) Analysis")
            print("  • cd combined, cd both - Run Combined SAST + DAST Scan")
            print("  • cd/.. - Go back to Main Menu")
        elif current_menu == "SonarQube Settings":
            print("  📌 Quick shortcuts:")
            print("  • cd url, cd username, cd password, cd project")
        elif current_menu == "AI Remediation":
            print("  📌 Quick shortcuts:")
            print("  • cd process, cd fix - Process vulnerabilities")
            print("  • cd batch, cd pr - Configure settings")
        else:
            print("  • Use cd/.. to go back")
            print("  • Use cd/ to go to main menu")
        
        print("\n💡 Navigation commands:")
        print("  • cd/.. or cd/back - Go back one level")
        print("  • cd/ or cd/main - Go to main menu")
        print("  • cd/<menu> - Navigate to menu")
        print("  • cd/<shortcut> - Quick select option")
        print("  • cd/<number> - Select option number")
        print("  • cd/list - Show this help")
        input("\nPress Enter to continue...")
    
    def _handle_cd_command(self, command):
        """Handle cd command for navigation."""
        # Extract target - handle both "cd " and "cd/"
        if command.startswith('cd/'):
            target = command[3:].strip()
        elif command.startswith('cd '):
            target = command[3:].strip()
        else:
            target = command[2:].strip()
        
        # Handle multi-level back navigation (cd/../.., cd/../../, cd.., cd../.., etc.)
        # Count how many ".." appear in the target
        if '..' in target:
            # Count occurrences of ".." - handle both "../.." and "../../" formats
            levels = target.count('..')
            actual_levels = 0
            for _ in range(levels):
                if len(self.navigation_stack) > 1:
                    self.navigation_stack.pop()
                    actual_levels += 1
            print(f"✅ Navigated back to: {self.navigation_stack[-1]}")
            # Set exit levels to trigger menu exits
            self.exit_levels = actual_levels
            return True
        
        # cd .. or cd/back - go back one level
        if target in ['..', 'back', 'return']:
            if len(self.navigation_stack) > 1:
                self.navigation_stack.pop()
                print(f"✅ Navigated back to: {self.navigation_stack[-1]}")
                self.exit_levels = 1
            else:
                print("ℹ️  Already at Main Menu")
            return True
        
        # cd / or cd ~ - go to main menu
        if target in ['/', '~', 'main', 'home', '']:
            if len(self.navigation_stack) > 1:
                # Count how many levels we're going back
                levels_to_exit = len(self.navigation_stack) - 1
                # Pop all except Main Menu
                while len(self.navigation_stack) > 1:
                    self.navigation_stack.pop()
                print("✅ Navigated to Main Menu")
                self.exit_levels = levels_to_exit
            else:
                print("ℹ️  Already at Main Menu")
            return True
        
        # cd/list or cd/ls - show available menus
        if target in ['list', 'ls', 'help', '?']:
            self._show_available_menus()
            return True
        
        # cd <menu_name> - navigate to specific menu
        target_lower = target.lower().strip()
        
        # Try exact match first
        if target_lower in self.menu_map:
            menu_name = self.menu_map[target_lower]
            return self._navigate_to_menu(menu_name)
        
        # Try partial match - check if any key contains the target or target contains the key
        for key, menu_name in self.menu_map.items():
            if target_lower in key or key in target_lower:
                print(f"💡 Matched '{target}' to '{key}'")
                return self._navigate_to_menu(menu_name)
        
        # No match found - show error with suggestions
        print(f"❌ Unknown menu: {target}")
        
        # Try to find close matches
        suggestions = self._find_closest_menu(target_lower)
        if suggestions:
            print(f"💡 Did you mean: {', '.join(suggestions)}?")
        else:
            print("💡 Available menus: settings, scanning, reports, remediation")
        
        print("💡 Use 'cd ..' to go back, 'cd /' to go to main menu")
        return False
    
    def _navigate_to_menu(self, menu_name):
        """Navigate to a specific menu by name."""
        # Check if already at this menu
        if self.navigation_stack[-1] == menu_name:
            print(f"ℹ️  Already at {menu_name}")
            return True
        
        # Navigate to the menu
        print(f"✅ Navigating to: {menu_name}")
        
        # Handle navigation based on menu type
        if menu_name == 'Exit':
            # Exit the application
            print("\n👋 Thank you for using Caze AppSecAI CLI!")
            import sys
            sys.exit(0)
        elif menu_name == 'Main Menu':
            # Go back to main menu
            levels_to_exit = len(self.navigation_stack) - 1
            while len(self.navigation_stack) > 1:
                self.navigation_stack.pop()
            self.exit_levels = levels_to_exit
        elif menu_name == 'Settings Menu':
            self._settings_menu()
        elif menu_name == 'SAST Configuration':
            self._sast_settings_menu()
        elif menu_name == 'DAST Configuration':
            self._dast_settings_menu()
        elif menu_name == 'SCA Configuration':
            self._sca_settings_menu()
        elif menu_name == 'General Settings':
            self._general_settings_menu()
        elif menu_name == 'System Tools':
            self._system_tools_menu()
        elif menu_name == 'Security Analysis':
            self._scan_menu()
        elif menu_name == 'How To':
            self._show_how_to()
        elif menu_name == 'Help':
            self._show_help()
        elif menu_name == 'About Us':
            self._show_about_appsecai()
        elif menu_name == 'Reports & Analysis':
            self._reports_menu()
        elif menu_name == 'AI Remediation':
            self._remediation_menu()
        elif menu_name == 'SonarQube Settings':
            # Need to be in Settings Menu first
            if self.navigation_stack[-1] != 'Settings Menu':
                print("ℹ️  Note: SonarQube Settings is accessed from Settings Menu")
            self._configure_sonarqube()
        elif menu_name == 'Deployment Settings':
            self._configure_deployment_settings()
        elif menu_name == 'SAST Reports':
            if self.navigation_stack[-1] != 'Reports & Analysis':
                print("ℹ️  Note: SAST Reports is accessed from Reports & Analysis")
            self._sast_reports_menu()
        elif menu_name == 'DAST Reports':
            if self.navigation_stack[-1] != 'Reports & Analysis':
                print("ℹ️  Note: DAST Reports is accessed from Reports & Analysis")
            self._dast_reports_menu()
        # Deployment sub-menus
        elif menu_name == 'Product and Version':
            if self.navigation_stack[-1] != 'Deployment Settings':
                print("ℹ️  Note: Product and Version is accessed from Deployment Settings")
            self._configure_product_version()
        elif menu_name == 'Environment':
            if self.navigation_stack[-1] != 'Deployment Settings':
                print("ℹ️  Note: Environment is accessed from Deployment Settings")
            self._configure_environment()
        elif menu_name == 'Runtime':
            if self.navigation_stack[-1] != 'Deployment Settings':
                print("ℹ️  Note: Runtime is accessed from Deployment Settings")
            self._configure_runtime()
        elif menu_name == 'Service':
            if self.navigation_stack[-1] != 'Deployment Settings':
                print("ℹ️  Note: Service is accessed from Deployment Settings")
            self._configure_service()
        elif menu_name == 'Security Controls':
            if self.navigation_stack[-1] != 'Deployment Settings':
                print("ℹ️  Note: Security Controls is accessed from Deployment Settings")
            self._configure_security_controls_new()
        # Settings Menu options
        elif menu_name == 'GitHub Repository':
            if self.navigation_stack[-1] != 'Settings Menu':
                print("ℹ️  Note: GitHub Repository is accessed from Settings Menu")
            self._configure_github_repo()
        elif menu_name == 'GitHub Token':
            if self.navigation_stack[-1] != 'Settings Menu':
                print("ℹ️  Note: GitHub Token is accessed from Settings Menu")
            self._configure_github_token()
        elif menu_name == 'AI/LLM Settings':
            if self.navigation_stack[-1] != 'Settings Menu':
                print("ℹ️  Note: AI/LLM Settings is accessed from Settings Menu")
            self._configure_llm()
        elif menu_name == 'DAST Settings':
            if self.navigation_stack[-1] != 'Settings Menu':
                print("ℹ️  Note: DAST Settings is accessed from Settings Menu")
            self._configure_dast()
        elif menu_name == 'Output Directory':
            if self.navigation_stack[-1] != 'Settings Menu':
                print("ℹ️  Note: Output Directory is accessed from Settings Menu")
            self._configure_output_dir()
        # SCA Context sub-menus
        elif menu_name == 'SCA Context Settings':
            if self.navigation_stack[-1] != 'Settings Menu':
                print("ℹ️  Note: SCA Context Settings is accessed from Settings Menu")
            self._configure_sca_context_settings()
        elif menu_name == 'Dependency Management':
            if self.navigation_stack[-1] != 'SCA Context Settings':
                print("ℹ️  Note: Dependency Management is accessed from SCA Context Settings")
            self._configure_sca_dependency_management()
        elif menu_name == 'Package Sources':
            if self.navigation_stack[-1] != 'SCA Context Settings':
                print("ℹ️  Note: Package Sources is accessed from SCA Context Settings")
            self._configure_sca_package_sources()
        elif menu_name == 'Vulnerability Response':
            if self.navigation_stack[-1] != 'SCA Context Settings':
                print("ℹ️  Note: Vulnerability Response is accessed from SCA Context Settings")
            self._configure_sca_vulnerability_response()
        elif menu_name == 'Build Pipeline':
            if self.navigation_stack[-1] != 'SCA Context Settings':
                print("ℹ️  Note: Build Pipeline is accessed from SCA Context Settings")
            self._configure_sca_build_pipeline()
        elif menu_name == 'Runtime Behavior':
            if self.navigation_stack[-1] != 'SCA Context Settings':
                print("ℹ️  Note: Runtime Behavior is accessed from SCA Context Settings")
            self._configure_sca_runtime_behavior()
        elif menu_name == 'Ecosystem':
            if self.navigation_stack[-1] != 'SCA Context Settings':
                print("ℹ️  Note: Ecosystem is accessed from SCA Context Settings")
            self._configure_sca_ecosystem()
        elif menu_name == 'Compliance':
            if self.navigation_stack[-1] != 'SCA Context Settings':
                print("ℹ️  Note: Compliance is accessed from SCA Context Settings")
            self._configure_sca_compliance()
        
        return True
    
    def _parse_input(self, prompt):
        """Parse user input to handle both numeric choices and cd commands."""
        user_input = input(prompt).strip()
        
        # Check if it's a cd command - support "cd ", "cd/", and "cd.." variations
        if user_input.lower().startswith('cd'):
            # Extract the target - handle all variations
            if user_input.lower().startswith('cd/'):
                target = user_input[3:].strip()
            elif user_input.lower().startswith('cd '):
                target = user_input[3:].strip()
            elif len(user_input) > 2:
                # Handle "cd..", "cd~", etc. (no space or slash)
                target = user_input[2:].strip()
            else:
                # Just "cd" with nothing after
                target = ''
            
            # Check if target is numeric (cd/1, cd/2, cd1, etc.)
            if target.isdigit():
                # Return the numeric choice directly
                return target
            
            # Check for context-specific shortcuts (menu option shortcuts)
            current_menu = self.navigation_stack[-1]
            target_lower = target.lower().strip()
            
            # Security Analysis menu shortcuts
            if current_menu == "Security Analysis":
                scan_shortcuts = {
                    'sast': '1', 'sast scan': '1', 'static': '1', 'static analysis': '1',
                    'dast': '2', 'dast scan': '2', 'dynamic': '2', 'dynamic analysis': '2',
                    'sca': '3', 'sca scan': '3', 'trivy': '3', 'trivy scan': '3',
                    'combined': '4', 'both': '4', 'combined scan': '4', 'sast + dast': '4',
                    'sast+dast': '4', 'sastdast': '4'
                }
                if target_lower in scan_shortcuts:
                    print(f"✅ Selecting: {target}")
                    return scan_shortcuts[target_lower]
            
            # Settings Menu shortcuts - Removed numeric overrides to favor semantic navigation (cd <name>)
            elif current_menu == "Settings Menu":
                pass
            
            # AI Remediation menu shortcuts
            elif current_menu == "AI Remediation":
                remediation_shortcuts = {
                    'process': '1', 'process vulnerabilities': '1', 'fix': '1',
                    'batch': '2', 'batch settings': '2',
                    'pr': '3', 'pr settings': '3', 'pull request': '3',
                    'select': '4', 'select results': '4', 'select scan': '4'
                }
                if target_lower in remediation_shortcuts:
                    print(f"✅ Selecting: {target}")
                    return remediation_shortcuts[target_lower]
            
            # Reports & Analysis menu shortcuts
            elif current_menu == "Reports & Analysis":
                reports_shortcuts = {
                    'sast': '1', 'sast reports': '1',
                    'dast': '2', 'dast reports': '2',
                    'security': '3', 'security posture': '3', 'posture': '3',
                    'trends': '4', 'vulnerability trends': '4'
                }
                if target_lower in reports_shortcuts:
                    print(f"✅ Selecting: {target}")
                    return reports_shortcuts[target_lower]
            
            # SonarQube Settings menu shortcuts
            elif current_menu == "SonarQube Settings":
                sonar_shortcuts = {
                    'url': '1', 'sonar url': '1',
                    'username': '2', 'user': '2',
                    'password': '3', 'pass': '3', 'pwd': '3',
                    'project': '4', 'project key': '4',
                    'test': '5', 'test connection': '5',
                    'show': '6', 'show settings': '6', 'view': '6'
                }
                if target_lower in sonar_shortcuts:
                    print(f"✅ Selecting: {target}")
                    return sonar_shortcuts[target_lower]
            
            # SAST Reports menu shortcuts
            elif current_menu == "SAST Reports":
                sast_reports_shortcuts = {
                    'view': '1', 'view latest': '1', 'latest': '1',
                    'list': '2', 'list all': '2', 'all': '2',
                    'export': '3', 'export report': '3',
                    'clean': '4', 'clean old': '4', 'cleanup': '4'
                }
                if target_lower in sast_reports_shortcuts:
                    print(f"✅ Selecting: {target}")
                    return sast_reports_shortcuts[target_lower]
            
            # DAST Reports menu shortcuts
            elif current_menu == "DAST Reports":
                dast_reports_shortcuts = {
                    'view': '1', 'view latest': '1', 'latest': '1',
                    'list': '2', 'list all': '2', 'all': '2',
                    'export': '3', 'export report': '3',
                    'clean': '4', 'clean old': '4', 'cleanup': '4'
                }
                if target_lower in dast_reports_shortcuts:
                    print(f"✅ Selecting: {target}")
                    return dast_reports_shortcuts[target_lower]
            
            # If no shortcut matched, handle as menu navigation
            self._handle_cd_command('cd ' + target)
            return None  # Signal that cd command was handled
        
        return user_input
    
    def _ensure_setup(self):
        """Check if essential configuration is missing."""
        essential_sections = {
            "SAST": ["GITHUB_TOKEN", "SONAR_URL"],
            "DAST": ["DAST_URL"],
            "SCA": ["TRIVY_TARGET"]
        }
        
        missing_sections = []
        for section, keys in essential_sections.items():
            section_missing = False
            for key in keys:
                val = os.environ.get(key, "").strip()
                # Special case for SCA: if it's the default './', treat as not configured
                if not val or (section == "SCA" and val == "./"):
                    section_missing = True
                    break
            
            if section_missing:
                missing_sections.append(f"{section}: Configurations")
        
        if missing_sections:
            print("\n🔍 Essential configuration missing:")
            for item in missing_sections:
                print(f"  • {item}")
            
            choice = input("\nWould you like to run the Setup Wizard now? (Y/n): ").strip().lower()
            if choice != 'n':
                self._run_startup_wizard()
            else:
                print("⚠️  Warning: Some features may not work without full configuration.")
                input("Press Enter to continue to the main menu...")

    def _run_startup_wizard(self):
        """Step-by-step guided configuration wizard."""
        print("\n" + "="*60)
        print("🚀 Caze AppSecAI - Startup Setup Wizard")
        print("="*60)
        print("This wizard will help you configure essential settings.")
        print("Press Enter to keep current/default value.")

        # 1. SAST / GitHub
        print("\n--- Step 1: SAST - GitHub Configuration ---")
        repo = input(f"GitHub Repository (e.g., cazelabs/Caze_Test) [{os.environ.get('GITHUB_REPO', 'Not Set')}]: ").strip()
        if repo:
            os.environ['GITHUB_REPO'] = repo
            self._update_env_file('GITHUB_REPO', repo)

        token = input(f"GitHub Token [{'✅ Set' if os.environ.get('GITHUB_TOKEN') else 'Not Set'}]: ").strip()
        if token:
            os.environ['GITHUB_TOKEN'] = token
            self._update_env_file('GITHUB_TOKEN', token)

        # 2. SAST / SonarQube
        print("\n--- Step 2: SAST - SonarQube Configuration ---")
        while True:
            sonar_url = input(f"SonarQube URL [{os.environ.get('SONAR_URL', 'http://localhost:9000')}]: ").strip()
            if not sonar_url:
                # Keep default/current
                break
            if self._is_valid_url(sonar_url):
                os.environ['SONAR_URL'] = sonar_url
                self._update_env_file('SONAR_URL', sonar_url)
                break
            else:
                print("❌ Invalid URL format! Please include protocol (http:// or https://) and port.")
                print("   Example: http://localhost:9000")

        sonar_user = input(f"SonarQube Username [{os.environ.get('SONAR_USERNAME', 'admin')}]: ").strip()
        if sonar_user:
            os.environ['SONAR_USERNAME'] = sonar_user
            self._update_env_file('SONAR_USERNAME', sonar_user)

        import getpass
        sonar_pass = getpass.getpass(f"SonarQube Password [{'✅ Set' if os.environ.get('SONAR_PASSWORD') else 'Not Set'}]: ").strip()
        if sonar_pass:
            os.environ['SONAR_PASSWORD'] = sonar_pass
            self._update_env_file('SONAR_PASSWORD', sonar_pass)

        sonar_project = input(f"SonarQube Project Key [{os.environ.get('SONAR_PROJECT_KEY', 'Not Set')}]: ").strip()
        if sonar_project:
            os.environ['SONAR_PROJECT_KEY'] = sonar_project
            self._update_env_file('SONAR_PROJECT_KEY', sonar_project)

        # 3. DAST
        print("\n--- Step 3: DAST - Configuration ---")
        while True:
            dast_url = input(f"DAST (ZAP) URL [{os.environ.get('DAST_URL', 'http://localhost:8080')}]: ").strip()
            if not dast_url:
                # Keep default/current
                break
            if self._is_valid_url(dast_url):
                os.environ['DAST_URL'] = dast_url
                self._update_env_file('DAST_URL', dast_url)
                break
            else:
                print("❌ Invalid URL format! Please include protocol (http:// or https://) and port.")
                print("   Example: http://localhost:8080")

        # 4. SCA
        print("\n--- Step 4: SCA - Configuration ---")
        self._configure_trivy_scan_settings()


        # 5. Thresholds
        print("\n--- Step 5: GENERAL - Vulnerability Threshold ---")
        threshold = input(f"Vulnerability Threshold Score (0.0 - 10.0) [{os.environ.get('VULNERABILITY_THRESHOLD', '7.0')}]: ").strip()
        if threshold:
            os.environ['VULNERABILITY_THRESHOLD'] = threshold
            self._update_env_file('VULNERABILITY_THRESHOLD', threshold)

        print("\n✅ Setup complete! Environment variables updated in .env")
        self._refresh_settings()
        input("Press Enter to continue to the main menu...")

    def _load_initial_config(self):
        """Load initial configuration."""
        try:
            from appsecai.common.config import ConfigManager
            self.config_manager = ConfigManager()
            
            # Load current settings
            self.current_settings = {
                'github_repo': os.environ.get('GITHUB_REPO', ''),
                'github_repositories': os.environ.get('GITHUB_REPOSITORIES', ''),
                'github_token': '✅ Set' if os.environ.get('GITHUB_TOKEN') else ' Not Set',
                'github_branch': os.environ.get('GITHUB_BASE_BRANCH', 'main'),
                'sonar_url': os.environ.get('SONAR_URL', 'http://localhost:9000'),
                'sonar_username': os.environ.get('SONAR_USERNAME', 'admin'),
                'sonar_password': '✅ Set' if os.environ.get('SONAR_PASSWORD') else ' Not Set',
                'sonar_project': os.environ.get('SONAR_PROJECT_KEY', ''),
                'llm_model': os.environ.get('LLM_MODEL', 'WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest'),
                'llm_url': os.environ.get('LLM_URL', 'http://74.225.200.165:11434'),
                'dast_url': os.environ.get('DAST_URL', 'http://localhost:8080'),
                'output_dir': os.environ.get('OUTPUT_DIR', 'AppSecAI_output'),
                'trivy_report': os.environ.get('TRIVY_TARGET', os.environ.get('TRIVY_REPORT_PATH', ''))
            }
            
        except Exception as e:
            print(f"⚠️  Warning: Could not load configuration: {e}")
    
    def _refresh_settings(self):
        """Refresh current settings from configuration file and environment."""
        # Force a reload from disk if config manager exists
        # But we must be careful: ConfigManager now respects os.environ if already set.
        if self.config_manager:
            self.config_manager.reload()
            
        self.current_settings = {
            'github_repo': os.environ.get('GITHUB_REPO', ''),
            'github_repositories': os.environ.get('GITHUB_REPOSITORIES', ''),
            'github_token': '✅ Set' if os.environ.get('GITHUB_TOKEN') else ' Not Set',
            'github_branch': os.environ.get('GITHUB_BASE_BRANCH', 'main'),
            'sonar_url': os.environ.get('SONAR_URL', 'http://localhost:9000'),
            'sonar_username': os.environ.get('SONAR_USERNAME', 'admin'),
            'sonar_password': '✅ Set' if os.environ.get('SONAR_PASSWORD') else ' Not Set',
            'sonar_project': os.environ.get('SONAR_PROJECT_KEY', ''),
            'llm_model': os.environ.get('LLM_MODEL', 'WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest'),
            'llm_url': os.environ.get('LLM_URL', 'http://localhost:11434'),
            'dast_url': os.environ.get('DAST_URL', 'http://localhost:8080'),
            'output_dir': os.environ.get('OUTPUT_DIR', 'AppSecAI_output'),
            'trivy_report': os.environ.get('TRIVY_TARGET', os.environ.get('TRIVY_REPORT_PATH', '')),
            'trivy_target_type': os.environ.get('TRIVY_TARGET_TYPE', 'fs')
        }
    
    def _scan_menu_inline(self) -> str:
        """Inline scan menu for CLI mode."""
        self._display_breadcrumb()
        print("""
┌─────────────────────────────────────────────────────────────┐
│                    SECURITY ANALYSIS                        │
├─────────────────────────────────────────────────────────────┤
│  1.  Run SAST Risk Analysis                                 │
│  2.  Run DAST Risk Analysis                                 │
│  3.  Run SCA Risk Analysis                                  │
│  4.  Back to Advanced Setup Wizard                          │
│  0.  Exit                                                   │
└─────────────────────────────────────────────────────────────┘
        """)
        choice = self._parse_input("👉 Select scan type (0-4) or command (cd <menu>, cd/, cd ..): ")
        return choice if choice is not None else ''

    def _advanced_cli_setup(self):
        """Modular setup wizard for CLI mode."""
        self.navigation_stack.append("Advanced Setup Wizard")
        while True:
            self._display_breadcrumb()
            print("""
┌─────────────────────────────────────────────────────────────┐
│             ADVANCED CLI CONFIGURATION WIZARD               │
├─────────────────────────────────────────────────────────────┤
│  1. SAST Configuration                                      │
│  2. DAST Configuration                                      │
│  3. SCA Configuration                                       │
│  0. Finish Configuration & Continue to Scans                │
└─────────────────────────────────────────────────────────────┘
            """)
            choice = self._parse_input("👉 Select option (0-3): ")
            if choice == '1':
                self._advanced_sast_setup()
            elif choice == '2':
                self._advanced_dast_setup()
            elif choice == '3':
                self._advanced_sca_setup()
            elif choice == '0':
                self.navigation_stack.pop()
                break
            else:
                print("❌ Invalid choice.")

    def _advanced_sast_setup(self):
        self.navigation_stack.append("SAST Config")
        while True:
            self._display_breadcrumb()
            print("""
  1. Basic Config (GitHub Repo, Token, SonarQube)
  2. Context Modifiers (Deployment, Settings)
  0. Back
            """)
            choice = self._parse_input("👉 Select option (0-2): ")
            if choice == '1':
                self._sast_settings_menu()
            elif choice == '2':
                self._configure_deployment_settings()
            elif choice == '0':
                self.navigation_stack.pop()
                break

    def _advanced_dast_setup(self):
        self.navigation_stack.append("DAST Config")
        while True:
            self._display_breadcrumb()
            print("""
  1. Basic Config (ZAP Target)
  2. Context Modifiers (Deployment, Settings)
  0. Back
            """)
            choice = self._parse_input("👉 Select option (0-2): ")
            if choice == '1':
                self._dast_settings_menu()
            elif choice == '2':
                self._configure_deployment_settings()
            elif choice == '0':
                self.navigation_stack.pop()
                break

    def _advanced_sca_setup(self):
        self.navigation_stack.append("SCA Config")
        while True:
            self._display_breadcrumb()
            print("""
  1. Basic Config (Trivy Target)
  2. Context Modifiers (Deployment, Settings)
  0. Back
            """)
            choice = self._parse_input("👉 Select option (0-2): ")
            if choice == '1':
                self._sca_settings_menu()
            elif choice == '2':
                self._configure_deployment_settings()
            elif choice == '0':
                self.navigation_stack.pop()
                break

    def _show_main_menu(self) -> str:
        """Display main menu and get user choice for JSON Mode."""
        # Refresh settings to ensure the banner shows latest values
        self._refresh_settings()
        self._display_breadcrumb()
        
        print(f"""
┌─────────────────────────────────────────────────────────────┐
│                         MAIN MENU                           │
├─────────────────────────────────────────────────────────────┤
│  1.  Run SAST Risk Analysis                                 │
│  2.  Run DAST Risk Analysis                                 │
│  3.  Run SCA Risk Analysis                                  │
│  4.  View Configuration                                     │
│  5.  Advanced Setup Wizard                                  │
│  0.  Exit                                                   │
└─────────────────────────────────────────────────────────────┘

Active Configuration:
- Mode: JSON (appsec_config.json)
- Repository: {self.current_settings.get('github_repo', 'Not Set')}
- Target URL: {self.current_settings.get('dast_url', 'Not Set')}
- GitHub Token: {'✅ Set' if os.environ.get('GITHUB_TOKEN') else 'Not Set'}
- Context Profile: Default
        """)
        
        choice = self._parse_input("👉 Select option (0-5) or command (cd <menu>, cd/, cd ..): ")
        return choice if choice is not None else ''
    
    def _view_active_configuration(self):
        """Display the active configuration in a read-only view for JSON Mode."""
        self.navigation_stack.append("View Configuration")
        self._display_breadcrumb()
        
        print("\n" + "═"*60)
        print("🔍 ACTIVE CONFIGURATION DETAILS")
        print("═"*60)
        
        # Refresh settings to ensure they are current
        self._refresh_settings()
        
        # GitHub Settings
        print("\n[GITHUB SETTINGS]")
        repos_str = self.current_settings.get('github_repositories', 'Not Set')
        if not repos_str or repos_str == 'Not Set':
            repos_str = self.current_settings.get('github_repo', 'Not Set')
        
        print(f"  • Repositories:  {repos_str}")
        print(f"  • GitHub Token:  {'✅ Set (configured in environment)' if os.environ.get('GITHUB_TOKEN') else ' Not Set'}")
        
        # SAST Settings
        print("\n[SAST RISK ANALYSIS] (SonarQube)")
        is_zero_touch = os.environ.get('SONAR_AUTO_SETUP') == 'true'
        print(f"  • Zero-Touch:    {'✅ ENABLED (Auto-Managed)' if is_zero_touch else '❌ Disabled'}")
        print(f"  • SonarQube URL: {self.current_settings.get('sonar_url', 'http://localhost:9000')}{' [Auto]' if is_zero_touch else ''}")
        print(f"  • Project Key:   {os.environ.get('SONAR_PROJECT_KEY', 'Auto-detected')}{' [Auto]' if is_zero_touch else ''}")
        
        # DAST Settings
        print("\n[DAST RISK ANALYSIS] (OWASP ZAP)")
        print(f"  • Target URL(s): {self.current_settings.get('dast_url', 'Not Set')}")
        print(f"  • Scanner:       OWASP ZAP 2.16.1")
        
        # SCA Settings
        print("\n[SCA RISK ANALYSIS] (Trivy)")
        print(f"  • Scan Target:   {os.environ.get('TRIVY_TARGET', './')}")
        print(f"  • Scan Type:     {os.environ.get('TRIVY_TARGET_TYPE', 'fs')}")
        
        print("\n" + "─"*60)
        print("💡 These settings are loaded from appsec_config.json")
        print("💡 To change them, edit the JSON file directly and restart.")
        print("─"*60)
        
        input("\nPress Enter to return to Main Menu...")
        self.navigation_stack.pop()
    
    def _sast_settings_menu(self):
        """Configure SAST related settings."""
        self.navigation_stack.append("SAST Configuration")
        while True:
            if self.exit_levels > 0:
                self.exit_levels -= 1
                break
            self._display_breadcrumb()
            print("""
┌─────────────────────────────────────────────────────────────┐
│                [SAST] STATIC ANALYSIS SETTINGS              │
├─────────────────────────────────────────────────────────────┤
│  1.  Configure GitHub Repository                            │
│  2.  Configure GitHub Token                                 │
│  3.  Configure SonarQube Settings                           │
│  0.  Back to Settings Menu                                  │
└─────────────────────────────────────────────────────────────┘
            """)
            choice = self._parse_input("👉 Select option (0-3): ")
            if choice is None: continue
            if choice == '1': self._configure_github_repo()
            elif choice == '2': self._configure_github_token()
            elif choice == '3': self._configure_sonarqube()
            elif choice == '0':
                self.navigation_stack.pop()
                break

    def _dast_settings_menu(self):
        """Configure DAST related settings."""
        self.navigation_stack.append("DAST Configuration")
        while True:
            if self.exit_levels > 0:
                self.exit_levels -= 1
                break
            self._display_breadcrumb()
            print("""
┌─────────────────────────────────────────────────────────────┐
│               [DAST] DYNAMIC ANALYSIS SETTINGS              │
├─────────────────────────────────────────────────────────────┤
│  1.  Configure DAST Target URL(s)                           │
│  2.  Configure ZAP Scanner Settings                         │
│  3.  Configure ZAP Report Path (Upload)                     │
│  0.  Back to Settings Menu                                  │
└─────────────────────────────────────────────────────────────┘
            """)
            choice = self._parse_input("👉 Select option (0-3): ")
            if choice is None: continue
            if choice == '1': self._configure_dast_urls()
            elif choice == '2': 
                self._configure_zap_scanner_settings()
            elif choice == '3': self._configure_zap_report_path()
            elif choice == '0':
                self.navigation_stack.pop()
                break

    def _sca_settings_menu(self):
        """Configure SCA related settings."""
        self.navigation_stack.append("SCA Configuration")
        while True:
            if self.exit_levels > 0:
                self.exit_levels -= 1
                break
            self._display_breadcrumb()
            print("""
┌─────────────────────────────────────────────────────────────┐
│             [SCA] SOFTWARE COMPOSITION SETTINGS             │
├─────────────────────────────────────────────────────────────┤
│  1.  Configure SCA (Trivy) Scan Settings                    │
│  2.  Configure GitHub Token                                 │
│  0.  Back to Settings Menu                                  │
└─────────────────────────────────────────────────────────────┘
            """)
            choice = self._parse_input("👉 Select option (0-2): ")
            if choice is None: continue
            if choice == '1': self._configure_trivy_scan_settings()
            elif choice == '2': self._configure_github_token()
            elif choice == '0':
                self.navigation_stack.pop()
                break

    def _general_settings_menu(self):
        """Configure general application settings."""
        self.navigation_stack.append("General Settings")
        while True:
            if self.exit_levels > 0:
                self.exit_levels -= 1
                break
            self._display_breadcrumb()
            print("""
┌─────────────────────────────────────────────────────────────┐
│                  GENERAL APPLICATION SETTINGS               │
├─────────────────────────────────────────────────────────────┤
│  1.  Configure AI/LLM Settings                              │
│  2.  Configure Output Directory                              │
│  3.  Configure Deployment & Environment Context             │
│  0.  Back to Settings Menu                                  │
└─────────────────────────────────────────────────────────────┘
            """)
            choice = self._parse_input("👉 Select option (0-3): ")
            if choice is None: continue
            if choice == '1': self._configure_llm()
            elif choice == '2': self._configure_output_dir()
            elif choice == '3': self._configure_deployment_settings()
            elif choice == '0':
                self.navigation_stack.pop()
                break



    def _settings_menu(self):
        """Handle settings and configuration menu."""
        self.navigation_stack.append("Settings Menu")
        
        while True:
            # Check if we should exit this menu
            if self.exit_levels > 0:
                self.exit_levels -= 1
                break
            
            self._display_breadcrumb()
            
            # Refresh settings to show current values
            self._refresh_settings()
            
            print(f"""
┌─────────────────────────────────────────────────────────────┐
│                    SETTINGS MENU                            │
├─────────────────────────────────────────────────────────────┤
│  1.  SAST Configurations                                    │
│  2.  DAST Configurations                                    │
│  3.  SCA  Configurations                                    │
│  4.  General Application Settings                           │
│  5.  Save Configuration to .env                             │
│  0.  Back to Main Menu                                      │
└─────────────────────────────────────────────────────────────┘

Current Settings:
  GitHub Repositories: {self._get_repo_count_display()}
  SonarQube URL:      {self.current_settings.get('sonar_url', 'Not Set')}
  DAST Target:        {self.current_settings.get('dast_url', 'Not Set')}
  LLM Model:          {self.current_settings.get('llm_model', 'Default')}
            """)
            
            choice = self._parse_input("👉 Select option (0-5) or command (cd <menu>, cd/, cd ..): ")
            if choice is None:
                continue
            
            if choice == '1':
                self._sast_settings_menu()
            elif choice == '2':
                self._dast_settings_menu()
            elif choice == '3':
                self._sca_settings_menu()
            elif choice == '4':
                self._general_settings_menu()
            elif choice == '5':
                self._save_configuration()
            elif choice == '0':
                self.navigation_stack.pop()
                break
            else:
                print("❌ Invalid choice. Please try again.")
    
    def _scan_menu(self):
        """Handle security analysis menu."""
        self.navigation_stack.append("Security Analysis")
        
        while True:
            # Check if we should exit this menu
            if self.exit_levels > 0:
                self.exit_levels -= 1
                break
            
            self._display_breadcrumb()
            
            print("""
┌─────────────────────────────────────────────────────────────┐
│                    SECURITY ANALYSIS                        │
├─────────────────────────────────────────────────────────────┤
│  1.  Run SAST Risk Analysis                                 │
│  2.  Run DAST Risk Analysis                                 │
│  3.  Run SCA Risk Analysis                                  │
│  0.  Back to Main Menu                                      │
└─────────────────────────────────────────────────────────────┘
            """)
            
            choice = self._parse_input("👉 Select scan type (0-4) or command (cd <menu>, cd/, cd ..): ")
            if choice is None:
                continue
            
            if choice == '1':
                self._run_sast_scan()
            elif choice == '2':
                self._run_dast_scan()
            elif choice == '3':
                self._run_sca_scan()
            elif choice == '0':
                self.navigation_stack.pop()
                break
            else:
                print("❌ Invalid choice. Please try again.")
    
    def _remediation_menu(self):
        """Handle AI remediation menu."""
        if not self.scan_results:
            print("\n⚠️  No scan results available. Please run a security scan first.")
            input("Press Enter to continue...")
            return
        
        self.navigation_stack.append("AI Remediation")
        
        while True:
            # Check if we should exit this menu
            if self.exit_levels > 0:
                self.exit_levels -= 1
                break
            
            self._display_breadcrumb()
            
            print(f"""
┌─────────────────────────────────────────────────────────────┐
│                 AI VULNERABILITY REMEDIATION                │
├─────────────────────────────────────────────────────────────┤
│  1.  Generate AI Fixes (Dry Run)                            │
│  2.  Generate Fixes + Create PRs                            │
│  3.  Configure Remediation Settings                         │
│  4.  Select Scan Results to Fix                             │
│  0.  Back to Main Menu                                      │
└─────────────────────────────────────────────────────────────┘

Available Scan Results: {len(self.scan_results)}
            """)
            
            choice = self._parse_input("👉 Select option (0-4) or command (cd <menu>, cd/, cd ..): ")
            if choice is None:
                continue
            
            if choice == '1':
                self._run_ai_fixes_dry_run()
            elif choice == '2':
                self._run_ai_fixes_with_prs()
            elif choice == '3':
                self._configure_remediation()
            elif choice == '4':
                self._select_scan_results()
            elif choice == '0':
                self.navigation_stack.pop()
                break
            else:
                print("❌ Invalid choice. Please try again.")
    
    def _reports_menu(self):
        """Handle reports and analysis menu."""
        self.navigation_stack.append("Reports & Analysis")
        
        while True:
            # Check if we should exit this menu
            if self.exit_levels > 0:
                self.exit_levels -= 1
                break
            
            self._display_breadcrumb()
            
            print("""
┌─────────────────────────────────────────────────────────────┐
│                    REPORTS & ANALYSIS                       │
├─────────────────────────────────────────────────────────────┤
│  1.  SAST Scan Reports                                      │
│  2.  DAST Scan Reports                                      │
│  3.  Security Posture Report                                │
│  4.  Vulnerability Trends                                   │
│  0.  Back to Main Menu                                      │
└─────────────────────────────────────────────────────────────┘
            """)
            
            choice = self._parse_input("👉 Select report section (0-4) or command (cd <menu>, cd/, cd ..): ")
            if choice is None:
                continue
            
            if choice == '1':
                self._sast_reports_menu()
            elif choice == '2':
                self._dast_reports_menu()
            elif choice == '3':
                self._generate_security_posture_report()
            elif choice == '4':
                self._vulnerability_trends()
            elif choice == '0':
                self.navigation_stack.pop()
                break
            else:
                print(" Invalid choice. Please try again.")
    
    def _configure_github_repo(self):
        """Configure GitHub repositories — supports multi-repo list for batch SAST scanning."""
        print("\n\U0001f527 Configure GitHub Repositories for SAST Scanning")

        while True:
            self._refresh_settings()

            # Parse stored repository list
            repos_str = self.current_settings.get('github_repositories', '')
            repos = []
            if repos_str:
                for item in repos_str.split(';'):
                    if not item.strip():
                        continue
                    parts = [p.strip() for p in item.split('|')]
                    repo_info = {"repo": parts[0], "branch": "main", "project_key": ""}
                    if len(parts) > 1:
                        repo_info["branch"] = parts[1]
                    if len(parts) > 2:
                        repo_info["project_key"] = parts[2]
                    repos.append(repo_info)

            # Backward-compatibility: migrate single github_repo into the list display
            if not repos and self.current_settings.get('github_repo'):
                repos.append({
                    "repo": self.current_settings.get('github_repo'),
                    "branch": self.current_settings.get('github_branch', 'main'),
                    "project_key": os.environ.get('SONAR_PROJECT_KEY', '')
                })

            print("\n\U0001f4cb Configured Repositories:")
            if not repos:
                print("  (None configured)")
            else:
                for i, r in enumerate(repos, 1):
                    pk_str = f" [Sonar Key: {r['project_key']}]" if r.get('project_key') else ""
                    print(f"  {i}. {r['repo']}  (branch: {r['branch']}){pk_str}")

            print("""
\u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510
\u2502             GITHUB REPOSITORY MANAGEMENT                    \u2502
\u251c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2524
\u2502  1.  Add New Repository                                     \u2502
\u2502  2.  Remove Repository                                      \u2502
\u2502  3.  Clear All Repositories                                 \u2502
\u2502  0.  Back to Settings Menu                                  \u2502
\u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518
            """)

            choice = input("\U0001f449 Select option (0-3): ").strip()

            if choice == '1':
                new_repo = input("\nEnter GitHub repository (e.g., cazelabs/Caze_Test): ").strip()
                if not new_repo:
                    print("\u274c No repository entered.")
                    continue
                if '/' not in new_repo:
                    print("\u274c Invalid format. Use owner/repo (e.g. cazelabs/appsecai)")
                    continue

                new_branch = input("  Enter branch name (default: main): ").strip() or "main"
                new_pk = input("  Enter SonarQube Project Key (optional, press Enter to skip): ").strip()

                repos.append({"repo": new_repo, "branch": new_branch, "project_key": new_pk})
                self._save_repos_to_config(repos)
                print(f"\u2705 Added: {new_repo} (branch: {new_branch})")

                # Offer to add more repositories in one session
                while True:
                    again = input("\nAdd another repository? (y/N): ").strip().lower()
                    if again == 'y':
                        next_repo = input("  Enter GitHub repository (e.g., cazelabs/Caze_Test): ").strip()
                        if next_repo and '/' in next_repo:
                            next_branch = input("  Enter branch name (default: main): ").strip() or "main"
                            next_pk = input("  Enter SonarQube Project Key (optional): ").strip()
                            repos.append({"repo": next_repo, "branch": next_branch, "project_key": next_pk})
                            self._save_repos_to_config(repos)
                            print(f"  \u2705 Added: {next_repo}")
                        else:
                            print("  \u274c Invalid repository name. Skipping.")
                    else:
                        break

            elif choice == '2':
                if not repos:
                    print("\u274c No repositories to remove.")
                    continue
                try:
                    idx = int(input(f"Enter number to remove (1-{len(repos)}): ")) - 1
                    if 0 <= idx < len(repos):
                        removed = repos.pop(idx)
                        self._save_repos_to_config(repos)
                        print(f"\u2705 Removed: {removed['repo']}")
                    else:
                        print("\u274c Invalid selection.")
                except ValueError:
                    print("\u274c Invalid input. Please enter a number.")

            elif choice == '3':
                confirm = input("\u26a0\ufe0f  Clear ALL repositories? (y/N): ").strip().lower()
                if confirm == 'y':
                    repos = []
                    self._save_repos_to_config(repos)
                    print("\u2705 All repositories cleared.")

            elif choice == '0':
                self._refresh_settings()
                break
            else:
                print("\u274c Invalid choice. Please try again.")

    def _save_repos_to_config(self, repos):
        """Serialize repository list and persist to environment and .env file.

        Storage format: owner/repo|branch|sonar_key;owner/repo2|branch2
        Also keeps GITHUB_REPO and GITHUB_BASE_BRANCH in sync with the
        first entry for full backward-compatibility.
        """
        repo_strings = []
        for r in repos:
            s = f"{r['repo']}|{r.get('branch', 'main')}"
            if r.get('project_key'):
                s += f"|{r['project_key']}"
            repo_strings.append(s)
        combined = ";".join(repo_strings)

        # Persist the full list
        self.current_settings['github_repositories'] = combined
        os.environ['GITHUB_REPOSITORIES'] = combined
        self._update_env_file('GITHUB_REPOSITORIES', combined)

        # Keep single-repo vars in sync (first repo = primary, for backward-compatibility)
        if repos:
            first_repo = repos[0]['repo']
            first_branch = repos[0].get('branch', 'main')
            os.environ['GITHUB_REPO'] = first_repo
            os.environ['GITHUB_BASE_BRANCH'] = first_branch
            self.current_settings['github_repo'] = first_repo
            self.current_settings['github_branch'] = first_branch
            self._update_env_file('GITHUB_REPO', first_repo)
            self._update_env_file('GITHUB_BASE_BRANCH', first_branch)
        else:
            os.environ['GITHUB_REPO'] = ''
            os.environ['GITHUB_BASE_BRANCH'] = 'main'
            self.current_settings['github_repo'] = ''
            self._update_env_file('GITHUB_REPO', '')
            self._update_env_file('GITHUB_BASE_BRANCH', 'main')
    
    def _configure_github_token(self):
        """Configure GitHub token."""
        print("\n🔑 Configure GitHub Token")
        print("You can get a token from: https://github.com/settings/tokens")
        
        token = input("Enter GitHub token (input hidden): ").strip()
        if token:
            self.current_settings['github_token'] = '✅ Set'
            os.environ['GITHUB_TOKEN'] = token
            self._update_env_file('GITHUB_TOKEN', token)
            print("✅ GitHub token configured successfully")
        
        # Refresh settings
        self._refresh_settings()
        input("Press Enter to continue...")
    
    def _configure_sonarqube(self):
        """Configure SonarQube settings."""
        # MOCKED: Hide Manual configuration out of sight
        print("\n🏢 SonarQube Settings (Zero-Touch SAST Auto-Configured)")
        os.environ['SONAR_AUTO_SETUP'] = 'true'
        print("✅ Zero-Touch Mode is enforced. Manual configuration is hidden.")
        input("\nPress Enter to return to Settings Menu...")
        return
        
        self.navigation_stack.append("SonarQube Settings")
        
        print("\n🏢 Configure SonarQube Settings")
        print("=" * 40)
        
        while True:
            # Check if we should exit this menu
            if self.exit_levels > 0:
                self.exit_levels -= 1
                break
            
            self._display_breadcrumb()
            
            print(f"""
┌─────────────────────────────────────────────────────────────┐
│                    SONARQUBE SETTINGS                       │
├─────────────────────────────────────────────────────────────┤
│  1.  Configure SonarQube URL                                │
│  2.  Configure Username                                     │
│  3.  Configure Password                                     │
│  4.  Configure Project Key                                  │
│  5.  View Current Settings                                  │
│  6.  Configure Zero-Touch (Auto-Docker Orchestration)       │
│  0.  Back to Settings Menu                                  │
└─────────────────────────────────────────────────────────────┘

  Zero-Touch: {'✅ ENABLED (Auto-Managed)' if os.environ.get('SONAR_AUTO_SETUP') == 'true' else '❌ Disabled'}
  URL:         {os.environ.get('SONAR_URL', 'http://localhost:9000')}{' [Auto]' if os.environ.get('SONAR_AUTO_SETUP') == 'true' else ''}
  Username:    {os.environ.get('SONAR_USERNAME', 'admin')}{' [Auto]' if os.environ.get('SONAR_AUTO_SETUP') == 'true' else ''}
  Password:    {'✅ Set' if os.environ.get('SONAR_PASSWORD') else ' Not Set'}{' [Auto]' if os.environ.get('SONAR_AUTO_SETUP') == 'true' else ''}
  Project Key: {os.environ.get('SONAR_PROJECT_KEY', 'Not Set')}{' [Auto]' if os.environ.get('SONAR_AUTO_SETUP') == 'true' else ''}
            """)
            
            choice = self._parse_input("👉 Select option (0-6) or command (cd <menu>, cd/, cd ..): ")
            if choice is None:
                continue
            
            if choice == '1':
                self._configure_sonar_url()
            elif choice == '2':
                self._configure_sonar_username()
            elif choice == '3':
                self._configure_sonar_password()
            elif choice == '4':
                self._configure_sonar_project()
            elif choice == '5':
                self._show_sonar_settings()
            elif choice == '6':
                self._configure_zero_touch()
            elif choice == '0':
                self.navigation_stack.pop()
                break
            else:
                print(" Invalid choice. Please try again.")
    
    def _configure_sonar_url(self):
        """Configure SonarQube URL."""
        print("\n🌐 Configure SonarQube URL")
        print("=" * 30)
        
        current_url = os.environ.get('SONAR_URL', 'http://localhost:9000')
        print(f"Current URL: {current_url}")
        print("\n💡 Examples:")
        print("   • http://localhost:9000 (local)")
        print("   • https://sonarqube.company.com (remote)")
        
        while True:
            new_url = input("\nEnter SonarQube URL (or press Enter to keep current): ").strip()
            if not new_url:
                print("ℹ️  URL unchanged")
                break
            
            if self._is_valid_url(new_url):
                os.environ['SONAR_URL'] = new_url
                self.current_settings['sonar_url'] = new_url
                self._update_env_file('SONAR_URL', new_url)
                print(f"✅ SonarQube URL updated to: {new_url}")
                break
            else:
                print("❌ Invalid URL format! Please include protocol (http:// or https://) and port.")
                print("   Example: http://localhost:9000")
        
        input("\nPress Enter to continue...")
    
    def _configure_sonar_username(self):
        """Configure SonarQube username."""
        print("\n👤 Configure SonarQube Username")
        print("=" * 35)
        
        current_username = os.environ.get('SONAR_USERNAME', 'admin')
        print(f"Current Username: {current_username}")
        print("\n💡 Options:")
        print("   • Use 'admin' for default SonarQube installation")
        print("   • Use your SonarQube username")
        print("   • Use a SonarQube token (recommended for production)")
        
        new_username = input("\nEnter SonarQube username (or press Enter to keep current): ").strip()
        if new_username:
            os.environ['SONAR_USERNAME'] = new_username
            self._update_env_file('SONAR_USERNAME', new_username)
            print(f"✅ SonarQube username updated to: {new_username}")
        else:
            print("ℹ️  Username unchanged")
        
        input("\nPress Enter to continue...")
    
    def _configure_sonar_password(self):
        """Configure SonarQube password."""
        print("\n🔑 Configure SonarQube Password")
        print("=" * 35)
        
        current_password = os.environ.get('SONAR_PASSWORD', '')
        password_status = '✅ Set' if current_password else ' Not Set'
        print(f"Current Password: {password_status}")
        
        print("\n💡 Security Options:")
        print("   1. Enter password (will be stored in .env file)")
        print("   2. Use SonarQube token (recommended)")
        print("   3. Keep current password")
        
        choice = input("\nSelect option (1-3): ").strip()
        
        if choice == '1':
            import getpass
            try:
                new_password = getpass.getpass("Enter SonarQube password (hidden): ")
                if new_password:
                    os.environ['SONAR_PASSWORD'] = new_password
                    self._update_env_file('SONAR_PASSWORD', new_password)
                    print("✅ SonarQube password updated")
                else:
                    print("ℹ️  Password unchanged")
            except KeyboardInterrupt:
                print("\n Password entry cancelled")
        elif choice == '2':
            print("\n🔐 To use a SonarQube token:")
            print("   1. Login to SonarQube web interface")
            print("   2. Go to User > My Account > Security")
            print("   3. Generate a new token")
            print("   4. Use the token as username and leave password empty")
            
            token = input("\nEnter SonarQube token (or press Enter to skip): ").strip()
            if token:
                os.environ['SONAR_USERNAME'] = token
                os.environ['SONAR_PASSWORD'] = ''
                self._update_env_file('SONAR_USERNAME', token)
                self._update_env_file('SONAR_PASSWORD', '')
                print("✅ SonarQube token configured")
            else:
                print("ℹ️  Token configuration skipped")
        else:
            print("ℹ️  Password unchanged")
        
        input("\nPress Enter to continue...")
    
    def _configure_zero_touch(self):
        """Configure Zero-Touch (Auto-Docker) settings."""
        print("\n🐳 Zero-Touch Infrastructure Orchestration")
        print("=" * 45)
        print("When enabled, AppSecAI will automatically start a SonarQube Docker container,")
        print("provision projects, and generate analysis tokens for you.")
        print("\nPrerequisites:")
        print("• Docker Engine/Desktop must be running locally.")
        print("• Port 9000 must be available.")
        
        current = os.environ.get('SONAR_AUTO_SETUP', 'false') == 'true'
        print(f"\nCurrent Status: {'✅ ENABLED' if current else '❌ DISABLED'}")
        
        enable = input("\nEnable Zero-Touch Auto-Setup? (y/n): ").strip().lower() == 'y'
        
        if enable:
            os.environ['SONAR_AUTO_SETUP'] = 'true'
            self._update_env_file('SONAR_AUTO_SETUP', 'true')
            # Set defaults that trigger auto-setup in the scanner
            os.environ['SONAR_URL'] = 'http://localhost:9000'
            self._update_env_file('SONAR_URL', 'http://localhost:9000')
            print("\n✅ Zero-Touch enabled! Scanning will now use managed Docker infrastructure.")
        else:
            os.environ['SONAR_AUTO_SETUP'] = 'false'
            self._update_env_file('SONAR_AUTO_SETUP', 'false')
            print("\n❌ Zero-Touch disabled. Using manual infrastructure settings.")
            
        input("\nPress Enter to continue...")

    def _configure_sonar_project(self):
        """Configure SonarQube project key."""
        print("\n📋 Configure SonarQube Project Key")
        print("=" * 40)
        
        current_project = os.environ.get('SONAR_PROJECT_KEY', '')
        print(f"Current Project Key: {current_project or 'Not Set'}")
        print("\n💡 The project key should match your project in SonarQube")
        print("   Example: cost-sense-ui, my-app, project-name")
        
        print("\n💡 Tip: The Project Key is a unique identifier you set in SonarQube for this project.")
        print("   It is NOT your SonarQube token or password.")
        new_project = input("\nEnter SonarQube project key: ").strip()
        if new_project:
            os.environ['SONAR_PROJECT_KEY'] = new_project
            self.current_settings['sonar_project'] = new_project
            self._update_env_file('SONAR_PROJECT_KEY', new_project)
            print(f"✅ SonarQube project key updated to: {new_project}")
        else:
            print("ℹ️  Project key unchanged")
        
        # Refresh settings
        self._refresh_settings()
        input("\nPress Enter to continue...")
    
    def _test_sonar_connection(self):
        """Test SonarQube connection with current settings."""
        print("\n🧪 Testing SonarQube Connection")
        print("=" * 35)
        
        sonar_url = os.environ.get('SONAR_URL', 'http://localhost:9000')
        sonar_username = os.environ.get('SONAR_USERNAME', 'admin')
        sonar_password = os.environ.get('SONAR_PASSWORD', '')
        sonar_project = os.environ.get('SONAR_PROJECT_KEY', '')
        
        print(f"Testing connection to: {sonar_url}")
        print(f"Username: {sonar_username}")
        print(f"Password: {'✅ Set' if sonar_password else ' Not Set'}")
        print(f"Project Key: {sonar_project or 'Not Set'}")
        print()
        
        try:
            import requests
            from requests.auth import HTTPBasicAuth
            
            # Test system status
            print("🔍 Testing system status...")
            auth = HTTPBasicAuth(sonar_username, sonar_password)
            response = requests.get(f"{sonar_url}/api/system/status", auth=auth, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                print(f"✅ SonarQube Status: {data.get('status', 'Unknown')}")
                print(f"   Version: {data.get('version', 'Unknown')}")
            else:
                print(f" System status check failed: HTTP {response.status_code}")
                if response.status_code == 401:
                    print("   🔑 Authentication failed - check username/password")
                return
            
            # Test project access if project key is set
            if sonar_project:
                print(f"\n🔍 Testing project access for '{sonar_project}'...")
                response = requests.get(
                    f"{sonar_url}/api/projects/search?projects={sonar_project}",
                    auth=auth,
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('components'):
                        project = data['components'][0]
                        print(f"✅ Project found: {project.get('name', sonar_project)}")
                        if 'lastAnalysisDate' in project:
                            print(f"   Last analysis: {project['lastAnalysisDate']}")
                    else:
                        print(f" Project '{sonar_project}' not found")
                else:
                    print(f" Project check failed: HTTP {response.status_code}")
            
            print(f"\n🎉 SonarQube connection test completed!")
            
        except requests.exceptions.ConnectionError:
            print(f" Connection failed: Cannot reach {sonar_url}")
            print("   💡 Check if SonarQube is running and URL is correct")
        except requests.exceptions.Timeout:
            print(f" Connection timeout: {sonar_url} is not responding")
        except Exception as e:
            print(f" Connection test failed: {e}")
        
        input("\nPress Enter to continue...")
    
    def _show_sonar_settings(self):
        """Show current SonarQube settings."""
        print("\n📄 Current SonarQube Settings")
        print("=" * 35)
        
        settings = {
            'URL': os.environ.get('SONAR_URL', 'http://localhost:9000'),
            'Username': os.environ.get('SONAR_USERNAME', 'admin'),
            'Password': '✅ Set' if os.environ.get('SONAR_PASSWORD') else ' Not Set',
            'Project Key': os.environ.get('SONAR_PROJECT_KEY', 'Not Set')
        }
        
        for key, value in settings.items():
            print(f"  {key}: {value}")
        
        input("\nPress Enter to continue...")
    
    def _update_env_file(self, key: str, value: str):
        """Update .env file with new value."""
        try:
            env_file = '.env'
            if os.path.exists(env_file):
                # Read current content
                with open(env_file, 'r') as f:
                    lines = f.readlines()
                
                # Update or add the key
                updated = False
                for i, line in enumerate(lines):
                    if line.startswith(f'{key}='):
                        lines[i] = f'{key}={value}\n'
                        updated = True
                        break
                
                if not updated:
                    lines.append(f'{key}={value}\n')
                
                # Write back to file
                with open(env_file, 'w') as f:
                    f.writelines(lines)
        except Exception as e:
            print(f"⚠️  Warning: Could not update .env file: {e}")

    def _update_appsec_json(self, key: str, value: Any):
        """Update appsec_config.json with new value."""
        try:
            import json
            from appsecai.cli.menu import get_base_directory
            base_dir = get_base_directory()
            config_file = base_dir / "appsec_config.json"
            
            if config_file.exists():
                data = load_appsec_json_data(config_file)
                
                # Map interactive keys to JSON keys
                mapping = {
                    'TRIVY_TARGET_TYPE': 'sca_target_type',
                    'TRIVY_TARGET': 'sca_target_path',
                    'VULNERABILITY_THRESHOLD': 'vulnerability_threshold',
                    'OUTPUT_DIR': 'output_dir',
                    'GITHUB_REPO': 'github_repo',
                    'GITHUB_TOKEN': 'github_token',
                    'DAST_URL': 'dast_url'
                }
                
                if '.' in key:
                    parts = key.split('.')
                    current = data
                    for part in parts[:-1]:
                        if part not in current or not isinstance(current[part], dict):
                            current[part] = {}
                        current = current[part]
                    current[parts[-1]] = value
                else:
                    json_key = mapping.get(key, key.lower())
                    data[json_key] = value
                
                with open(config_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)
                
                # Also sync back to config_manager
                if self.config_manager:
                    self.config_manager.reload()
        except Exception as e:
            print(f"⚠️  Warning: Could not update appsec_config.json: {e}")
    
    def _configure_llm(self):
        """Configure AI/LLM settings."""
        print("\n🤖 Configure AI/LLM Settings")
        
        current_model = os.environ.get('LLM_MODEL', 'WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest')
        current_url = os.environ.get('LLM_URL', 'http://74.225.200.165:11434')
        
        print(f"Current Model: {current_model}")
        print(f"Current URL: {current_url}")
        
        print("\nAvailable LLM Options:")
        print("1. WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B (Default)")
        print("2.  WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B")
        print("3. Custom Model")
        print("4. Change LLM URL")
        
        choice = input("Select option (1-4, or Enter to skip): ").strip()
        
        if choice == '1':
            model = 'WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest'
        elif choice == '2':
            model = ' WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B'
        elif choice == '3':
            model = input("Enter custom model name: ").strip()
        elif choice == '4':
            new_url = input("Enter LLM URL (e.g., http://74.225.200.165:11434): ").strip()
            if new_url:
                os.environ['LLM_URL'] = new_url
                self.current_settings['llm_url'] = new_url
                print(f"✅ LLM URL set to: {new_url}")
            input("Press Enter to continue...")
            return
        else:
            input("Press Enter to continue...")
            return
        
        if choice in ['1', '2', '3'] and model:
            os.environ['LLM_MODEL'] = model
            self.current_settings['llm_model'] = model
            print(f"✅ LLM model set to: {model}")
        
        input("Press Enter to continue...")
    
    def _configure_dast(self):
        """Configure DAST settings."""
        print("\n🌐 Configure DAST Settings")
        
        # Load current URLs
        current_urls = self._get_dast_urls()
        current_url = self.current_settings.get('dast_url', 'http://localhost:8080')
        
        print(f"\nCurrent DAST URL(s):")
        if len(current_urls) > 1:
            for i, url in enumerate(current_urls, 1):
                print(f"   {i}. {url}")
        else:
            print(f"   {current_url}")
        
        print("\nDASTConfiguration Options:")
        print("1. Set DAST Target URL(s)")
        print("2. Configure ZAP Scanner Settings")
        print("3. Configure ZAP Report Path (Upload)")
        print("4. Back to Settings Menu")
        
        choice = input("Select option (1-4): ").strip()
        
        if choice == '1':
            self._configure_dast_urls()
        elif choice == '2':
            print("🔧 ZAP Scanner Configuration:")
            print("• ZAP installation path: external/ZAP_2.16.1/")
            print("• Default scan policy: Default Policy")
            print("• Max scan time: 3600 seconds")
            print("• Spider max depth: 5")
            print("💡 These settings can be modified in appsecai/risk_profiles/app_config.yaml")
        elif choice == '3':
            self._configure_zap_report_path()
        elif choice == '4':
            return
        
        input("Press Enter to continue...")
    
    def _configure_dast_urls(self):
        """Configure single or multiple DAST target URLs."""
        print("\n📍 Configure DAST Target URL(s)")
        print("\nOptions:")
        print("1. Set single URL")
        print("2. Set multiple URLs (one by one)")
        print("3. Set multiple URLs (comma-separated)")
        print("4. View current URLs")
        print("5. Clear all URLs")
        
        choice = input("\nSelect option (1-5): ").strip()
        
        if choice == '1':
            # Single URL
            while True:
                new_url = input("Enter DAST target URL (e.g., http://localhost:8080): ").strip()
                if not new_url:
                    break
                
                if self._is_valid_url(new_url):
                    self.current_settings['dast_url'] = new_url
                    os.environ['DAST_URL'] = new_url
                    self._update_env_file('DAST_URL', new_url)
                    # Also update DAST_URLS with single URL
                    import json
                    urls_json = json.dumps([new_url])
                    os.environ['DAST_URLS'] = urls_json
                    self._update_env_file('DAST_URLS', urls_json)
                    self._refresh_settings()
                    print(f"✅ DAST URL set to: {new_url}")
                    break
                else:
                    print("❌ Invalid URL format! Please include protocol (http:// or https://) and port.")
                    print("   Example: http://localhost:8080")
        
        elif choice == '2':
            # Multiple URLs - one by one
            urls = []
            print("\nEnter URLs one by one (press Enter with empty input to finish):")
            while True:
                url = input(f"URL {len(urls) + 1}: ").strip()
                if not url:
                    break
                urls.append(url)
                print(f"   ✅ Added: {url}")
            
            if urls:
                import json
                urls_json = json.dumps(urls)
                os.environ['DAST_URLS'] = urls_json
                self._update_env_file('DAST_URLS', urls_json)
                # Set first URL as primary
                self.current_settings['dast_url'] = urls[0]
                os.environ['DAST_URL'] = urls[0]
                self._update_env_file('DAST_URL', urls[0])
                self._refresh_settings()
                print(f"\n✅ Configured {len(urls)} DAST URLs")
        
        elif choice == '3':
            # Multiple URLs - comma-separated
            urls_input = input("Enter URLs separated by commas: ").strip()
            if urls_input:
                urls = [url.strip() for url in urls_input.split(',') if url.strip()]
                if urls:
                    import json
                    urls_json = json.dumps(urls)
                    os.environ['DAST_URLS'] = urls_json
                    self._update_env_file('DAST_URLS', urls_json)
                    # Set first URL as primary
                    self.current_settings['dast_url'] = urls[0]
                    os.environ['DAST_URL'] = urls[0]
                    self._update_env_file('DAST_URL', urls[0])
                    self._refresh_settings()
                    print(f"\n✅ Configured {len(urls)} DAST URLs:")
                    for i, url in enumerate(urls, 1):
                        print(f"   {i}. {url}")
        
        elif choice == '4':
            # View current URLs
            current_urls = self._get_dast_urls()
            print(f"\n📋 Current DAST URLs ({len(current_urls)}):")
            for i, url in enumerate(current_urls, 1):
                print(f"   {i}. {url}")
        
        elif choice == '5':
            # Clear all URLs
            confirm = input("⚠️  Clear all DAST URLs? (y/N): ").strip().lower()
            if confirm == 'y':
                import json
                os.environ['DAST_URLS'] = json.dumps([])
                self._update_env_file('DAST_URLS', '[]')
                print("✅ All DAST URLs cleared")
    
        input("Press Enter to continue...")

    def _configure_zap_scanner_settings(self):
        """Configure general, API, and authentication settings for the ZAP scanner."""
        self.navigation_stack.append("ZAP Settings")
        while True:
            if self.exit_levels > 0:
                self.exit_levels -= 1
                break
            self._display_breadcrumb()
            print("""
┌─────────────────────────────────────────────────────────────┐
│                 OWASP ZAP SCANNER SETTINGS                  │
├─────────────────────────────────────────────────────────────┤
│  1.  Configure Scan Settings (Timeout, Spider Depth)        │
│  2.  Configure API Scan Settings                            │
│  3.  Configure Authentication Wizard                        │
│  0.  Back to DAST Menu                                      │
└─────────────────────────────────────────────────────────────┘
            """)
            choice = self._parse_input("👉 Select option (0-3): ")
            if choice is None: continue
            
            if choice == '1':
                # General scan settings
                print("\n🔧 Configure ZAP Scan Settings")
                current_timeout = int(os.environ.get('ZAP_MAX_SCAN_TIME', '3600'))
                print(f"Current Max Scan Time: {current_timeout // 60} minutes ({current_timeout} seconds)")
                timeout_input = input("Enter new Max Scan Time in minutes (or Enter to keep): ").strip()
                if timeout_input:
                    try:
                        timeout_seconds = int(timeout_input) * 60
                        os.environ['ZAP_MAX_SCAN_TIME'] = str(timeout_seconds)
                        self._update_env_file('ZAP_MAX_SCAN_TIME', str(timeout_seconds))
                        print(f"✅ Max Scan Time set to {timeout_input} minutes.")
                    except ValueError:
                        print("❌ Invalid input. Must be an integer.")
                
                # Spider max depth
                current_depth = os.environ.get('ZAP_SPIDER_MAX_DEPTH', '5')
                print(f"Current Spider Max Depth: {current_depth}")
                depth_input = input("Enter new Spider Max Depth (or Enter to keep): ").strip()
                if depth_input:
                    try:
                        depth_val = int(depth_input)
                        os.environ['ZAP_SPIDER_MAX_DEPTH'] = str(depth_val)
                        self._update_env_file('ZAP_SPIDER_MAX_DEPTH', str(depth_val))
                        print(f"✅ Spider Max Depth set to {depth_val}.")
                    except ValueError:
                        print("❌ Invalid input. Must be an integer.")
            
            elif choice == '2':
                # API Scan settings
                print("\n🔧 Configure API Scan Settings")
                use_api = input("Enable API spec scanning? (y/n, or Enter to keep): ").strip().lower()
                if use_api in ['y', 'n']:
                    enabled_bool = use_api == 'y'
                    enabled_str = 'true' if enabled_bool else 'false'
                    os.environ['DAST_USE_API'] = enabled_str
                    self._update_env_file('DAST_USE_API', enabled_str)
                    self._update_appsec_json('dast_api.enabled', enabled_bool)
                    print(f"✅ API scanning {'enabled' if enabled_bool else 'disabled'}.")
                
                if os.environ.get('DAST_USE_API', 'false') == 'true':
                    spec_url = input(f"Enter API specification URL or local file path (current: {os.environ.get('DAST_API_SPEC_URL', 'None')}): ").strip()
                    if spec_url:
                        os.environ['DAST_API_SPEC_URL'] = spec_url
                        self._update_env_file('DAST_API_SPEC_URL', spec_url)
                        self._update_appsec_json('dast_api.spec_url', spec_url)
                        print(f"✅ API Spec URL set to: {spec_url}")
                    
                    spec_type = input(f"Enter API spec type (openapi, graphql, soap - current: {os.environ.get('DAST_API_SPEC_TYPE', 'openapi')}): ").strip().lower()
                    if spec_type in ['openapi', 'graphql', 'soap']:
                        os.environ['DAST_API_SPEC_TYPE'] = spec_type
                        self._update_env_file('DAST_API_SPEC_TYPE', spec_type)
                        self._update_appsec_json('dast_api.spec_type', spec_type)
                        print(f"✅ API Spec Type set to: {spec_type}")
            
            elif choice == '3':
                # Authentication settings wizard
                print("\n🔑 DAST Authentication Wizard")
                use_auth = input("Enable authentication for DAST scans? (y/n, or Enter to keep): ").strip().lower()
                if use_auth in ['y', 'n']:
                    enabled_bool = use_auth == 'y'
                    enabled_str = 'true' if enabled_bool else 'false'
                    os.environ['DAST_USE_AUTH'] = enabled_str
                    self._update_env_file('DAST_USE_AUTH', enabled_str)
                    self._update_appsec_json('dast_auth.enabled', enabled_bool)
                    print(f"✅ Authentication {'enabled' if enabled_bool else 'disabled'}.")
                
                if os.environ.get('DAST_USE_AUTH', 'false') == 'true':
                    # Method
                    print("\nSelect Authentication Method:")
                    print("1. Browser-based (Selenium auto-login, opens visual browser)")
                    print("2. Form-based (Standard POST parameters)")
                    print("3. JSON-based (JSON login payload)")
                    print("4. HTTP (Basic/Digest/NTLM)")
                    method_choice = input("Select option (1-4, or Enter to keep): ").strip()
                    method = None
                    if method_choice == '1':
                        method = 'browser'
                    elif method_choice == '2':
                        method = 'form'
                    elif method_choice == '3':
                        method = 'json'
                    elif method_choice == '4':
                        method = 'http'
                        
                    if method:
                        os.environ['DAST_AUTH_METHOD'] = method
                        self._update_env_file('DAST_AUTH_METHOD', method)
                        self._update_appsec_json('dast_auth.method', method)
                        print(f"✅ Auth Method set to: {method}")
                    
                    # Username & Password
                    username = input(f"Enter username (current: {os.environ.get('DAST_AUTH_USERNAME', 'None')}): ").strip()
                    if username:
                        os.environ['DAST_AUTH_USERNAME'] = username
                        self._update_env_file('DAST_AUTH_USERNAME', username)
                        self._update_appsec_json('dast_auth.username', username)
                    
                    password = input("Enter password (or Enter to keep current): ").strip()
                    if password:
                        os.environ['DAST_AUTH_PASSWORD'] = password
                        self._update_env_file('DAST_AUTH_PASSWORD', password)
                        self._update_appsec_json('dast_auth.password', password)
                    
                    # Login Page URL
                    login_url = input(f"Enter Login Page URL (current: {os.environ.get('DAST_AUTH_LOGIN_URL', 'None')}): ").strip()
                    if login_url:
                        os.environ['DAST_AUTH_LOGIN_URL'] = login_url
                        self._update_env_file('DAST_AUTH_LOGIN_URL', login_url)
                        self._update_appsec_json('dast_auth.login_page_url', login_url)
                    
                    current_method = os.environ.get('DAST_AUTH_METHOD', 'browser')
                    
                    # Method specific parameters
                    if current_method in ['form', 'json']:
                        req_url = input(f"Enter Login Request POST URL (or Enter to use same as Login URL): ").strip()
                        if req_url:
                            os.environ['DAST_AUTH_REQUEST_URL'] = req_url
                            self._update_env_file('DAST_AUTH_REQUEST_URL', req_url)
                            self._update_appsec_json('dast_auth.login_request_url', req_url)
                        
                        req_body = input(f"Enter POST request body format (e.g. username={{%username%}}&password={{%password%}}): ").strip()
                        if req_body:
                            os.environ['DAST_AUTH_REQUEST_BODY'] = req_body
                            self._update_env_file('DAST_AUTH_REQUEST_BODY', req_body)
                            self._update_appsec_json('dast_auth.login_request_body', req_body)
                            
                    elif current_method == 'browser':
                        browser_id = input(f"Enter Browser ID to use (e.g. firefox, chrome, firefox-headless, chrome-headless, edge, edge-headless, safari - current: {os.environ.get('DAST_AUTH_BROWSER_ID', 'firefox')}): ").strip().lower()
                        if browser_id:
                            os.environ['DAST_AUTH_BROWSER_ID'] = browser_id
                            self._update_env_file('DAST_AUTH_BROWSER_ID', browser_id)
                            self._update_appsec_json('dast_auth.browser_id', browser_id)
                            print(f"✅ Browser ID set to: {browser_id}")
                    
                    # Verification Indicators
                    logged_in = input(f"Enter Logged In regex indicator (or Enter to keep current): ").strip()
                    if logged_in:
                        os.environ['DAST_AUTH_LOGGED_IN_REGEX'] = logged_in
                        self._update_env_file('DAST_AUTH_LOGGED_IN_REGEX', logged_in)
                        self._update_appsec_json('dast_auth.logged_in_regex', logged_in)
                        
                    logged_out = input(f"Enter Logged Out regex indicator (or Enter to keep current): ").strip()
                    if logged_out:
                        os.environ['DAST_AUTH_LOGGED_OUT_REGEX'] = logged_out
                        self._update_env_file('DAST_AUTH_LOGGED_OUT_REGEX', logged_out)
                        self._update_appsec_json('dast_auth.logged_out_regex', logged_out)
            
            elif choice == '0':
                self.navigation_stack.pop()
                break

    def _configure_zap_report_path(self):
        """Configure path to an existing ZAP scan report."""
        print("\n📤 Configure ZAP Report Path (Upload for Analysis)")
        current_path = os.environ.get('ZAP_REPORT_PATH', 'Not set')
        print(f"Current Path: {current_path}")
        
        raw_path = input("\nEnter path to ZAP security_recommendations.html (or '0' to back): ").strip()
        if not raw_path or raw_path == '0':
            return
            
        # Robust sanitization: remove quotes and multiple trailing spaces
        new_path = raw_path.strip().strip('"').strip("'").strip()
            
        if os.path.exists(new_path):
            os.environ['ZAP_REPORT_PATH'] = new_path
            self.current_settings['zap_report_path'] = new_path
            self._update_env_file('ZAP_REPORT_PATH', new_path)
            
            # CRITICAL: Synchronize metadata so this becomes the 'latest' report
            try:
                import json
                from datetime import datetime
                from pathlib import Path
                
                base_dir = self.get_base_directory() if hasattr(self, 'get_base_directory') else Path(os.getcwd())
                metadata_path = base_dir / "AppSecAI_output" / "uploaded_zap_latest.json"
                metadata_path.parent.mkdir(parents=True, exist_ok=True)
                
                metadata = {
                    "upload_timestamp": datetime.now().isoformat(),
                    "original_file": str(new_path),
                    "target_url": "Manually configured URL",
                    "total_vulnerabilities": 0,
                    "processed": False
                }
                
                with open(metadata_path, 'w', encoding='utf-8') as f:
                    json.dump(metadata, f, indent=2)
                
                print(f"✅ ZAP report path set and synchronized: {new_path}")
            except Exception as e:
                print(f"✅ ZAP report path set to: {new_path} (Metadata sync issue: {e})")
        else:
            print(f"❌ Error: Path does not exist: {new_path}")
            if raw_path != new_path:
                print(f"   (Original input was: {raw_path})")
            
        input("Press Enter to continue...")

    def _configure_trivy_scan_settings(self):
        """Configure default Trivy SCA scan target type and path."""
        print("\n📦 Configure SCA (Trivy) Scan Settings")
        
        current_type = os.environ.get('TRIVY_TARGET_TYPE', 'fs')
        current_target = os.environ.get('TRIVY_TARGET', './')
        
        print(f"Current Target Type: {current_type}")
        print(f"Current Target Path: {current_target}")

        valid_types = ['fs', 'image', 'repo', 'k8s', 'container', 'vm', 'rootfs']
        while True:
            new_type = self._parse_input(f"Enter target type ({', '.join(valid_types)}) [{current_type}]: ")
            if new_type is None:
                return
            new_type = new_type.strip().lower() or current_type
            if new_type in valid_types:
                break
            print(f"❌ Invalid target type. Please choose from: {', '.join(valid_types)}")

        while True:
            new_target = self._parse_input(f"Enter target path/name (e.g., ./ , python:3.9 , cluster , <container_id>) [{current_target}]: ")
            if new_target is None:
                return
            new_target = new_target.strip() or current_target

            if (new_target.startswith('"') and new_target.endswith('"')) or (
                new_target.startswith("'") and new_target.endswith("'")
            ):
                new_target = new_target[1:-1].strip()
                
            # Pattern-based validation based on target type
            import re
            if new_type == 'repo':
                # Must be a URL or owner/repo format
                if not re.match(r'^(https?://|git@|[\w-]+/[\w-]+)', new_target):
                    print("❌ Invalid repository target. Please enter a URL or 'owner/repo'.")
                    continue
            elif new_type == 'image':
                # Allow standard image names OR local archive paths (.tar, .tar.gz, .tgz)
                archive_extensions = ('.tar', '.tar.gz', '.tgz')
                is_archive = new_target.lower().endswith(archive_extensions)
                
                # Stricter image name validation for registry-based images
                image_regex = r'^([a-z0-9]+(?:[._-][a-z0-9]+)*\/)?([a-z0-9]+(?:[._-][a-z0-9]+)*)(?::[a-z0-9]+(?:[._-][a-z0-9]+)*)?(@sha256:[a-f0-9]{64})?$'
                
                if not is_archive and not re.match(image_regex, new_target, re.IGNORECASE):
                    print("❌ Invalid image name. Please use standard format (e.g., 'python:3.9', 'ubuntu') or a .tar archive path.")
                    continue
                
            if new_target:
                break
            print("❌ Target path cannot be empty.")

        os.environ['TRIVY_TARGET_TYPE'] = new_type
        os.environ['TRIVY_TARGET'] = new_target
        # Update both keys to ensure UI and Logic remain in sync
        self._update_env_file('TRIVY_TARGET_TYPE', new_type)
        self._update_env_file('TRIVY_TARGET', new_target)
        self._update_env_file('TRIVY_REPORT_PATH', new_target)
        
        # Sync to appsec_config.json
        self._update_appsec_json('TRIVY_TARGET_TYPE', new_type)
        self._update_appsec_json('TRIVY_TARGET', new_target)
        
        # Keep old value synchronized for UI backwards compatibility metrics if needed
        self.current_settings['trivy_report'] = new_target
        print(f"✅ Trivy target configuration updated to type '{new_type}', target '{new_target}'")

        input("Press Enter to continue...")

    def _configure_sca_context_settings(self):
        """Configure SCA context settings in risk_context_template.json."""
        self.navigation_stack.append("SCA Context Settings")
        
        while True:
            # Check if we should exit this menu
            if self.exit_levels > 0:
                self.exit_levels -= 1
                break
            
            self._display_breadcrumb()
            
            print("""
┌──────────────────────────────────────────────────────────────────────┐
│                  CONFIGURE SCA CONTEXT SETTINGS                      │
├──────────────────────────────────────────────────────────────────────┤
│  Options (type command or use cd):                                   │
│                                                                      │
│  1. dependency management  - Update frequency, SBOM, lock files      │                                                
│                                                                      │
│  2. package sources        - Registry, signature verification        │                                                    
│                                                                      │
│  3. vulnerability response - Patching, monitoring, emergency process │                                                    
│                                                                      │
│  4. build pipeline         - SLSA, hash verification, reproducibility│                                                       
│                                                                      │
│  5. runtime behavior       - Sandboxing, isolation, network access   │                                                     
│                                                                      │
│  6. ecosystem              - Language version, package manager       │                                                   
│                                                                      │
│  7. compliance             - Standards (SOC2, HIPAA, PCI-DSS, etc.)  │                                                  
│                                                                      │
│  0. back or cd/..          - Return to Settings Menu                 │
└──────────────────────────────────────────────────────────────────────┘
            """)
            
            choice = self._parse_input("👉 Select option (0-7), command, or cd navigation: ")
            if choice is None:
                continue
            
            if choice == '1':
                self._configure_sca_dependency_management()
            elif choice == '2':
                self._configure_sca_package_sources()
            elif choice == '3':
                self._configure_sca_vulnerability_response()
            elif choice == '4':
                self._configure_sca_build_pipeline()
            elif choice == '5':
                self._configure_sca_runtime_behavior()
            elif choice == '6':
                self._configure_sca_ecosystem()
            elif choice == '7':
                self._configure_sca_compliance()
            elif choice == '0' or choice == 'back':
                self.navigation_stack.pop()
                break
            else:
                print("❌ Invalid choice. Please try again.")
                print("💡 Available: 1-7, dependency, packages, response, build, runtime, ecosystem, compliance, back")

    def _validate_sca_field(self, field_name, value, field_type, valid_values=None):
        """
        Validate SCA context field with strict rules.
        
        Args:
            field_name: Name of the field
            value: User input value
            field_type: 'boolean' or 'enum'
            valid_values: List of valid values for enum type
        
        Returns:
            Tuple (is_valid, normalized_value)
        """
        value = value.strip().lower()
        
        if field_type == 'boolean':
            if value not in ['true', 'false']:
                print(f"❌ Invalid value for {field_name}")
                print(f"   Must be 'true' or 'false'")
                return False, None
            return True, value == 'true'
        
        elif field_type == 'enum':
            if value not in [v.lower() for v in valid_values]:
                print(f"❌ Invalid value for {field_name}")
                print(f"   Must be one of: {', '.join(valid_values)}")
                return False, None
            # Return original case from valid_values
            for v in valid_values:
                if v.lower() == value:
                    return True, v
        
        return False, None

    def _save_sca_context(self, category, field, value):
        """Save SCA context field to risk_context_template.json."""
        config = self._load_compliance_config()
        
        # Ensure structure exists
        if 'AppSecAI' not in config:
            config['AppSecAI'] = {}
        if 'sca_context' not in config['AppSecAI']:
            config['AppSecAI']['sca_context'] = {}
        if category not in config['AppSecAI']['sca_context']:
            config['AppSecAI']['sca_context'][category] = {}
        
        # Update field
        config['AppSecAI']['sca_context'][category][field] = value
        
        # Save
        self._save_compliance_config(config)
        print(f"✅ {field} updated to: {value}")

    def _configure_sca_dependency_management(self):
        """Configure SCA dependency management settings."""
        self.navigation_stack.append("Dependency Management")
        
        while True:
            if self.exit_levels > 0:
                self.exit_levels -= 1
                break
            
            self._display_breadcrumb()
            
            print("\n" + "="*70)
            print("DEPENDENCY MANAGEMENT CONFIGURATION")
            print("="*70)
            
            config = self._load_compliance_config()
            dep_mgmt = config.get('AppSecAI', {}).get('sca_context', {}).get('dependency_management', {})
            
            print("\nCurrent Settings:")
            print(f"  dependency_update_frequency:        {dep_mgmt.get('dependency_update_frequency', 'Not Set')}")
            print(f"  lock_files_enforced:                {dep_mgmt.get('lock_files_enforced', 'Not Set')}")
            print(f"  automated_dependency_updates:       {dep_mgmt.get('automated_dependency_updates', 'Not Set')}")
            print(f"  dependency_review_process:          {dep_mgmt.get('dependency_review_process', 'Not Set')}")
            print(f"  sbom_generation_enabled:            {dep_mgmt.get('sbom_generation_enabled', 'Not Set')}")
            print(f"  sbom_format:                        {dep_mgmt.get('sbom_format', 'Not Set')}")
            print(f"  dependency_pinning:                 {dep_mgmt.get('dependency_pinning', 'Not Set')}")
            print(f"  transitive_dependency_analysis:     {dep_mgmt.get('transitive_dependency_analysis', 'Not Set')}")
            
            print("\nConfigure Settings (press Enter to skip):")
            
            # dependency_update_frequency
            value = input("  dependency_update_frequency (daily/weekly/monthly/rarely): ").strip()
            if value:
                is_valid, normalized = self._validate_sca_field('dependency_update_frequency', value, 'enum', 
                                                                ['daily', 'weekly', 'monthly', 'rarely'])
                if is_valid:
                    self._save_sca_context('dependency_management', 'dependency_update_frequency', normalized)
            
            # lock_files_enforced
            value = input("  lock_files_enforced (true/false): ").strip()
            if value:
                is_valid, normalized = self._validate_sca_field('lock_files_enforced', value, 'boolean')
                if is_valid:
                    self._save_sca_context('dependency_management', 'lock_files_enforced', normalized)
            
            # automated_dependency_updates
            value = input("  automated_dependency_updates (true/false): ").strip()
            if value:
                is_valid, normalized = self._validate_sca_field('automated_dependency_updates', value, 'boolean')
                if is_valid:
                    self._save_sca_context('dependency_management', 'automated_dependency_updates', normalized)
            
            # dependency_review_process
            value = input("  dependency_review_process (automated/manual/none): ").strip()
            if value:
                is_valid, normalized = self._validate_sca_field('dependency_review_process', value, 'enum',
                                                                ['automated', 'manual', 'none'])
                if is_valid:
                    self._save_sca_context('dependency_management', 'dependency_review_process', normalized)
            
            # sbom_generation_enabled
            value = input("  sbom_generation_enabled (true/false): ").strip()
            if value:
                is_valid, normalized = self._validate_sca_field('sbom_generation_enabled', value, 'boolean')
                if is_valid:
                    self._save_sca_context('dependency_management', 'sbom_generation_enabled', normalized)
            
            # sbom_format
            value = input("  sbom_format (cyclonedx/spdx/none): ").strip()
            if value:
                is_valid, normalized = self._validate_sca_field('sbom_format', value, 'enum',
                                                                ['cyclonedx', 'spdx', 'none'])
                if is_valid:
                    self._save_sca_context('dependency_management', 'sbom_format', normalized)
            
            # dependency_pinning
            value = input("  dependency_pinning (true/false): ").strip()
            if value:
                is_valid, normalized = self._validate_sca_field('dependency_pinning', value, 'boolean')
                if is_valid:
                    self._save_sca_context('dependency_management', 'dependency_pinning', normalized)
            
            # transitive_dependency_analysis
            value = input("  transitive_dependency_analysis (true/false): ").strip()
            if value:
                is_valid, normalized = self._validate_sca_field('transitive_dependency_analysis', value, 'boolean')
                if is_valid:
                    self._save_sca_context('dependency_management', 'transitive_dependency_analysis', normalized)
            
            print("\n✅ Dependency Management settings updated")
            input("\nPress Enter to go back...")
            self.navigation_stack.pop()
            break

    def _configure_sca_package_sources(self):
        """Configure SCA package sources settings."""
        self.navigation_stack.append("Package Sources")
        
        while True:
            if self.exit_levels > 0:
                self.exit_levels -= 1
                break
            
            self._display_breadcrumb()
            
            print("\n" + "="*70)
            print("PACKAGE SOURCES CONFIGURATION")
            print("="*70)
            
            config = self._load_compliance_config()
            pkg_sources = config.get('AppSecAI', {}).get('sca_context', {}).get('package_sources', {})
            
            print("\nCurrent Settings:")
            print(f"  private_registry_used:              {pkg_sources.get('private_registry_used', 'Not Set')}")
            print(f"  package_signature_verification:     {pkg_sources.get('package_signature_verification', 'Not Set')}")
            print(f"  trusted_sources_only:               {pkg_sources.get('trusted_sources_only', 'Not Set')}")
            print(f"  mirror_repositories_used:           {pkg_sources.get('mirror_repositories_used', 'Not Set')}")
            
            print("\nConfigure Settings (press Enter to skip):")
            
            # private_registry_used
            value = input("  private_registry_used (true/false): ").strip()
            if value:
                is_valid, normalized = self._validate_sca_field('private_registry_used', value, 'boolean')
                if is_valid:
                    self._save_sca_context('package_sources', 'private_registry_used', normalized)
            
            # package_signature_verification
            value = input("  package_signature_verification (true/false): ").strip()
            if value:
                is_valid, normalized = self._validate_sca_field('package_signature_verification', value, 'boolean')
                if is_valid:
                    self._save_sca_context('package_sources', 'package_signature_verification', normalized)
            
            # trusted_sources_only
            value = input("  trusted_sources_only (true/false): ").strip()
            if value:
                is_valid, normalized = self._validate_sca_field('trusted_sources_only', value, 'boolean')
                if is_valid:
                    self._save_sca_context('package_sources', 'trusted_sources_only', normalized)
            
            # mirror_repositories_used
            value = input("  mirror_repositories_used (true/false): ").strip()
            if value:
                is_valid, normalized = self._validate_sca_field('mirror_repositories_used', value, 'boolean')
                if is_valid:
                    self._save_sca_context('package_sources', 'mirror_repositories_used', normalized)
            
            print("\n✅ Package Sources settings updated")
            input("\nPress Enter to go back...")
            self.navigation_stack.pop()
            break

    def _configure_sca_vulnerability_response(self):
        """Configure SCA vulnerability response settings."""
        self.navigation_stack.append("Vulnerability Response")
        
        while True:
            if self.exit_levels > 0:
                self.exit_levels -= 1
                break
            
            self._display_breadcrumb()
            
            print("\n" + "="*70)
            print("VULNERABILITY RESPONSE CONFIGURATION")
            print("="*70)
            
            config = self._load_compliance_config()
            vuln_resp = config.get('AppSecAI', {}).get('sca_context', {}).get('vulnerability_response', {})
            
            print("\nCurrent Settings:")
            print(f"  mean_time_to_patch:                 {vuln_resp.get('mean_time_to_patch', 'Not Set')}")
            print(f"  vulnerability_monitoring:           {vuln_resp.get('vulnerability_monitoring', 'Not Set')}")
            print(f"  emergency_patch_process:            {vuln_resp.get('emergency_patch_process', 'Not Set')}")
            print(f"  automated_vulnerability_remediation: {vuln_resp.get('automated_vulnerability_remediation', 'Not Set')}")
            
            print("\nConfigure Settings (press Enter to skip):")
            
            # mean_time_to_patch
            value = input("  mean_time_to_patch (< 24h/< 7d/< 30d/> 30d): ").strip()
            if value:
                is_valid, normalized = self._validate_sca_field('mean_time_to_patch', value, 'enum',
                                                                ['< 24h', '< 7d', '< 30d', '> 30d'])
                if is_valid:
                    self._save_sca_context('vulnerability_response', 'mean_time_to_patch', normalized)
            
            # vulnerability_monitoring
            value = input("  vulnerability_monitoring (real-time/daily/weekly/none): ").strip()
            if value:
                is_valid, normalized = self._validate_sca_field('vulnerability_monitoring', value, 'enum',
                                                                ['real-time', 'daily', 'weekly', 'none'])
                if is_valid:
                    self._save_sca_context('vulnerability_response', 'vulnerability_monitoring', normalized)
            
            # emergency_patch_process
            value = input("  emergency_patch_process (true/false): ").strip()
            if value:
                is_valid, normalized = self._validate_sca_field('emergency_patch_process', value, 'boolean')
                if is_valid:
                    self._save_sca_context('vulnerability_response', 'emergency_patch_process', normalized)
            
            # automated_vulnerability_remediation
            value = input("  automated_vulnerability_remediation (true/false): ").strip()
            if value:
                is_valid, normalized = self._validate_sca_field('automated_vulnerability_remediation', value, 'boolean')
                if is_valid:
                    self._save_sca_context('vulnerability_response', 'automated_vulnerability_remediation', normalized)
            
            print("\n✅ Vulnerability Response settings updated")
            input("\nPress Enter to go back...")
            self.navigation_stack.pop()
            break

    def _configure_sca_build_pipeline(self):
        """Configure SCA build pipeline settings."""
        self.navigation_stack.append("Build Pipeline")
        
        while True:
            if self.exit_levels > 0:
                self.exit_levels -= 1
                break
            
            self._display_breadcrumb()
            
            print("\n" + "="*70)
            print("BUILD PIPELINE CONFIGURATION")
            print("="*70)
            
            config = self._load_compliance_config()
            build_pipe = config.get('AppSecAI', {}).get('sca_context', {}).get('build_pipeline', {})
            
            print("\nCurrent Settings:")
            print(f"  dependency_hash_verification:       {build_pipe.get('dependency_hash_verification', 'Not Set')}")
            print(f"  supply_chain_levels_for_software_artifacts: {build_pipe.get('supply_chain_levels_for_software_artifacts', 'Not Set')}")
            print(f"  build_reproducibility:              {build_pipe.get('build_reproducibility', 'Not Set')}")
            print(f"  isolated_build_environment:         {build_pipe.get('isolated_build_environment', 'Not Set')}")
            print(f"  build_provenance_attestation:       {build_pipe.get('build_provenance_attestation', 'Not Set')}")
            
            print("\nConfigure Settings (press Enter to skip):")
            
            # dependency_hash_verification
            while True:
                value = input("  dependency_hash_verification (true/false): ").strip()
                if not value: break
                is_valid, normalized = self._validate_sca_field('dependency_hash_verification', value, 'boolean')
                if is_valid:
                    self._save_sca_context('build_pipeline', 'dependency_hash_verification', normalized)
                    break
                print("  ❌ Invalid value! Please enter 'true' or 'false'")
            
            # supply_chain_levels_for_software_artifacts
            value = input("  supply_chain_levels_for_software_artifacts (slsa1/slsa2/slsa3/slsa4/none): ").strip()
            if value:
                is_valid, normalized = self._validate_sca_field('supply_chain_levels_for_software_artifacts', value, 'enum',
                                                                ['slsa1', 'slsa2', 'slsa3', 'slsa4', 'none'])
                if is_valid:
                    self._save_sca_context('build_pipeline', 'supply_chain_levels_for_software_artifacts', normalized)
            
            # build_reproducibility
            while True:
                value = input("  build_reproducibility (true/false): ").strip()
                if not value: break
                is_valid, normalized = self._validate_sca_field('build_reproducibility', value, 'boolean')
                if is_valid:
                    self._save_sca_context('build_pipeline', 'build_reproducibility', normalized)
                    break
                print("  ❌ Invalid value! Please enter 'true' or 'false'")
            
            # isolated_build_environment
            while True:
                value = input("  isolated_build_environment (true/false): ").strip()
                if not value: break
                is_valid, normalized = self._validate_sca_field('isolated_build_environment', value, 'boolean')
                if is_valid:
                    self._save_sca_context('build_pipeline', 'isolated_build_environment', normalized)
                    break
                print("  ❌ Invalid value! Please enter 'true' or 'false'")
            
            # build_provenance_attestation
            while True:
                value = input("  build_provenance_attestation (true/false): ").strip()
                if not value: break
                is_valid, normalized = self._validate_sca_field('build_provenance_attestation', value, 'boolean')
                if is_valid:
                    self._save_sca_context('build_pipeline', 'build_provenance_attestation', normalized)
                    break
                print("  ❌ Invalid value! Please enter 'true' or 'false'")
            
            print("\n✅ Build Pipeline settings updated")
            input("\nPress Enter to go back...")
            self.navigation_stack.pop()
            break

    def _configure_sca_runtime_behavior(self):
        """Configure SCA runtime behavior settings."""
        self.navigation_stack.append("Runtime Behavior")
        
        while True:
            if self.exit_levels > 0:
                self.exit_levels -= 1
                break
            
            self._display_breadcrumb()
            
            print("\n" + "="*70)
            print("RUNTIME BEHAVIOR CONFIGURATION")
            print("="*70)
            
            config = self._load_compliance_config()
            runtime_beh = config.get('AppSecAI', {}).get('sca_context', {}).get('runtime_behavior', {})
            
            print("\nCurrent Settings:")
            print(f"  sandboxing_enabled:                 {runtime_beh.get('sandboxing_enabled', 'Not Set')}")
            print(f"  dependency_isolation:               {runtime_beh.get('dependency_isolation', 'Not Set')}")
            print(f"  network_access_by_dependencies:     {runtime_beh.get('network_access_by_dependencies', 'Not Set')}")
            print(f"  runtime_dependency_monitoring:      {runtime_beh.get('runtime_dependency_monitoring', 'Not Set')}")
            print(f"  file_system_access_by_dependencies: {runtime_beh.get('file_system_access_by_dependencies', 'Not Set')}")
            
            print("\nConfigure Settings (press Enter to skip):")
            
            # sandboxing_enabled
            while True:
                value = input("  sandboxing_enabled (true/false): ").strip()
                if not value: break
                is_valid, normalized = self._validate_sca_field('sandboxing_enabled', value, 'boolean')
                if is_valid:
                    self._save_sca_context('runtime_behavior', 'sandboxing_enabled', normalized)
                    break
                print("  ❌ Invalid value! Please enter 'true' or 'false'")
            
            # dependency_isolation
            while True:
                value = input("  dependency_isolation (true/false): ").strip()
                if not value: break
                is_valid, normalized = self._validate_sca_field('dependency_isolation', value, 'boolean')
                if is_valid:
                    self._save_sca_context('runtime_behavior', 'dependency_isolation', normalized)
                    break
                print("  ❌ Invalid value! Please enter 'true' or 'false'")
            
            # network_access_by_dependencies
            value = input("  network_access_by_dependencies (unrestricted/restricted/blocked): ").strip()
            if value:
                is_valid, normalized = self._validate_sca_field('network_access_by_dependencies', value, 'enum',
                                                                ['unrestricted', 'restricted', 'blocked'])
                if is_valid:
                    self._save_sca_context('runtime_behavior', 'network_access_by_dependencies', normalized)
            
            # runtime_dependency_monitoring
            while True:
                value = input("  runtime_dependency_monitoring (true/false): ").strip()
                if not value: break
                is_valid, normalized = self._validate_sca_field('runtime_dependency_monitoring', value, 'boolean')
                if is_valid:
                    self._save_sca_context('runtime_behavior', 'runtime_dependency_monitoring', normalized)
                    break
                print("  ❌ Invalid value! Please enter 'true' or 'false'")
            
            # file_system_access_by_dependencies
            value = input("  file_system_access_by_dependencies (unrestricted/restricted/blocked): ").strip()
            if value:
                is_valid, normalized = self._validate_sca_field('file_system_access_by_dependencies', value, 'enum',
                                                                ['unrestricted', 'restricted', 'blocked'])
                if is_valid:
                    self._save_sca_context('runtime_behavior', 'file_system_access_by_dependencies', normalized)
            
            print("\n✅ Runtime Behavior settings updated")
            input("\nPress Enter to go back...")
            self.navigation_stack.pop()
            break

    def _configure_sca_ecosystem(self):
        """Configure SCA ecosystem settings."""
        self.navigation_stack.append("Ecosystem")
        
        while True:
            if self.exit_levels > 0:
                self.exit_levels -= 1
                break
            
            self._display_breadcrumb()
            
            print("\n" + "="*70)
            print("ECOSYSTEM CONFIGURATION")
            print("="*70)
            
            config = self._load_compliance_config()
            ecosystem = config.get('AppSecAI', {}).get('sca_context', {}).get('ecosystem', {})
            
            print("\nCurrent Settings:")
            print(f"  language_version_eol:               {ecosystem.get('language_version_eol', 'Not Set')}")
            print(f"  package_manager_version:            {ecosystem.get('package_manager_version', 'Not Set')}")
            print(f"  ecosystem_security_advisories_enabled: {ecosystem.get('ecosystem_security_advisories_enabled', 'Not Set')}")
            
            print("\nConfigure Settings (press Enter to skip):")
            
            # language_version_eol
            while True:
                value = input("  language_version_eol (true/false): ").strip()
                if not value: break
                is_valid, normalized = self._validate_sca_field('language_version_eol', value, 'boolean')
                if is_valid:
                    self._save_sca_context('ecosystem', 'language_version_eol', normalized)
                    break
                print("  ❌ Invalid value! Please enter 'true' or 'false'")
            
            # package_manager_version
            value = input("  package_manager_version (latest/supported/unsupported): ").strip()
            if value:
                is_valid, normalized = self._validate_sca_field('package_manager_version', value, 'enum',
                                                                ['latest', 'supported', 'unsupported'])
                if is_valid:
                    self._save_sca_context('ecosystem', 'package_manager_version', normalized)
            
            # ecosystem_security_advisories_enabled
            while True:
                value = input("  ecosystem_security_advisories_enabled (true/false): ").strip()
                if not value: break
                is_valid, normalized = self._validate_sca_field('ecosystem_security_advisories_enabled', value, 'boolean')
                if is_valid:
                    self._save_sca_context('ecosystem', 'ecosystem_security_advisories_enabled', normalized)
                    break
                print("  ❌ Invalid value! Please enter 'true' or 'false'")
            
            print("\n✅ Ecosystem settings updated")
            input("\nPress Enter to go back...")
            self.navigation_stack.pop()
            break

    def _configure_sca_compliance(self):
        """Configure SCA compliance settings."""
        self.navigation_stack.append("Compliance")
        
        while True:
            if self.exit_levels > 0:
                self.exit_levels -= 1
                break
            
            self._display_breadcrumb()
            
            print("\n" + "="*70)
            print("COMPLIANCE CONFIGURATION")
            print("="*70)
            
            config = self._load_compliance_config()
            compliance = config.get('AppSecAI', {}).get('sca_context', {}).get('compliance', {})
            
            print("\nCurrent Settings:")
            print(f"  soc2_compliance_required:           {compliance.get('soc2_compliance_required', 'Not Set')}")
            print(f"  hipaa_compliance_required:          {compliance.get('hipaa_compliance_required', 'Not Set')}")
            print(f"  pci_dss_compliance_required:        {compliance.get('pci_dss_compliance_required', 'Not Set')}")
            print(f"  gdpr_compliance_required:           {compliance.get('gdpr_compliance_required', 'Not Set')}")
            print(f"  iso_27001_compliance_required:      {compliance.get('iso_27001_compliance_required', 'Not Set')}")
            print(f"  nist_compliance_required:           {compliance.get('nist_compliance_required', 'Not Set')}")
            print(f"  fedramp_compliance_required:        {compliance.get('fedramp_compliance_required', 'Not Set')}")
            print(f"  fisma_compliance_required:          {compliance.get('fisma_compliance_required', 'Not Set')}")
            print(f"  ccpa_compliance_required:           {compliance.get('ccpa_compliance_required', 'Not Set')}")
            print(f"  sox_compliance_required:            {compliance.get('sox_compliance_required', 'Not Set')}")
            
            print("\nConfigure Settings (press Enter to skip, type 'all' to see all 18 fields):")
            
            show_all = input("  Show all compliance fields? (yes/no): ").strip().lower()
            
            if show_all in ['yes', 'y', 'all']:
                # Show all 18 compliance fields
                compliance_fields = [
                    'soc2_compliance_required', 'hipaa_compliance_required', 'pci_dss_compliance_required',
                    'gdpr_compliance_required', 'iso_27001_compliance_required', 'nist_compliance_required',
                    'fedramp_compliance_required', 'fisma_compliance_required', 'ccpa_compliance_required',
                    'sox_compliance_required', 'glba_compliance_required', 'ferpa_compliance_required',
                    'coppa_compliance_required', 'pipeda_compliance_required', 'appi_compliance_required',
                    'lgpd_compliance_required', 'pdpa_compliance_required', 'dpa_compliance_required'
                ]
                
                for field in compliance_fields:
                    while True:
                        value = input(f"  {field} (true/false): ").strip()
                        if not value: break
                        is_valid, normalized = self._validate_sca_field(field, value, 'boolean')
                        if is_valid:
                            self._save_sca_context('compliance', field, normalized)
                            break
                        print("  ❌ Invalid value! Please enter 'true' or 'false'")
            else:
                # Configure top 10 most common compliance standards
                common_fields = [
                    'soc2_compliance_required', 'hipaa_compliance_required', 'pci_dss_compliance_required',
                    'gdpr_compliance_required', 'iso_27001_compliance_required', 'nist_compliance_required',
                    'fedramp_compliance_required', 'fisma_compliance_required', 'ccpa_compliance_required',
                    'sox_compliance_required'
                ]
                
                for field in common_fields:
                    while True:
                        value = input(f"  {field} (true/false): ").strip()
                        if not value: break
                        is_valid, normalized = self._validate_sca_field(field, value, 'boolean')
                        if is_valid:
                            self._save_sca_context('compliance', field, normalized)
                            break
                        print("  ❌ Invalid value! Please enter 'true' or 'false'")
            
            print("\n✅ Compliance settings updated")
            input("\nPress Enter to go back...")
            self.navigation_stack.pop()
            break

    def _get_dast_urls(self):
        """Get list of DAST URLs from environment."""
        import json
        urls_json = os.environ.get('DAST_URLS', '[]')
        try:
            urls = json.loads(urls_json)
            if not urls:
                # Fallback to single URL
                single_url = os.environ.get('DAST_URL', '')
                if single_url:
                    return [single_url]
            return urls if isinstance(urls, list) else []
        except json.JSONDecodeError:
            # Fallback to single URL
            single_url = os.environ.get('DAST_URL', '')
            return [single_url] if single_url else []
    def _get_repo_count_display(self):
        """Get a human-readable summary of configured repositories."""
        repos_str = self.current_settings.get('github_repositories', '')
        if not repos_str:
            single = self.current_settings.get('github_repo', '')
            return single if single else "Not Set"
        
        repos = [r for r in repos_str.split(';') if r.strip()]
        if not repos:
            return "Not Set"
            
        if len(repos) == 1:
            return repos[0].split('|')[0]
        else:
            return f"{len(repos)} repositories configured ({repos[0].split('|')[0]}...)"

    def _configure_output_dir(self):
        """Configure output directory."""
        print("\n📁 Configure Output Directory")
        
        current = self.current_settings.get('output_dir', 'AppSecAI_output')
        print(f"Current: {current}")
        
        new_dir = input("Enter output directory path: ").strip()
        if new_dir:
            self.current_settings['output_dir'] = new_dir
            os.environ['OUTPUT_DIR'] = new_dir
            self._update_env_file('OUTPUT_DIR', new_dir)
            print(f"✅ Output directory set to: {new_dir}")
        
        # Refresh settings
        self._refresh_settings()
        input("Press Enter to continue...")
    
    def _configure_thresholds(self):
        """Configure vulnerability thresholds using enhanced scoring framework."""
        self.navigation_stack.append("Vulnerability Thresholds")
        
        while True:
            # Check if we should exit this menu
            if self.exit_levels > 0:
                self.exit_levels -= 1
                break
            
            self._display_breadcrumb()
            
            current_threshold = os.environ.get('VULNERABILITY_THRESHOLD')
            if not current_threshold:
                current_threshold = "Not set - please configure"
            
            # Check enhanced framework files
            framework_file = "appsecai/risk_profiles/context_modifiers/vulnerability_framework.json"
            compliance_file = "appsecai/risk_profiles/context_modifiers/risk_context_template.json"
            framework_status = "✅ Found" if os.path.exists(framework_file) else " Missing"
            compliance_status = "✅ Found" if os.path.exists(compliance_file) else " Missing"
            
            print(f"""
┌─────────────────────────────────────────────────────────────┐
│                 VULNERABILITY THRESHOLDS                    │
├─────────────────────────────────────────────────────────────┤
│  1.  Set Vulnerability Threshold Score                      │
│  0.  Back to Settings Menu                                  │
└─────────────────────────────────────────────────────────────┘

Current Settings:
  Threshold Score: {current_threshold}
  Framework File: {framework_file} ({framework_status})
  Compliance File: {compliance_file} ({compliance_status})
            """)
            
            choice = self._parse_input("👉 Select menu option (1=Set, 0=Back): ")
            if choice is None:
                continue
            
            if choice == '1':
                print("\n📊 Vulnerability Threshold Score Configuration")
                print("This threshold determines which vulnerabilities are included in results.")
                print("Vulnerabilities with calculated scores ≥ threshold will be included.")
                
                while True:
                    new_threshold = input(f"\nEnter threshold score (0.0 - 10.0) [current: {current_threshold}]: ").strip()
                    if not new_threshold:
                        break
                    try:
                        # Allow float values for better precision
                        val = float(new_threshold)
                        if 0 <= val <= 10:
                            os.environ['VULNERABILITY_THRESHOLD'] = str(val)
                            self._update_env_file('VULNERABILITY_THRESHOLD', str(val))
                            self._update_appsec_json('VULNERABILITY_THRESHOLD', val)
                            print(f"✅ Vulnerability threshold set to: {val}")
                            input("Press Enter to continue...")
                            break
                        else:
                            print("❌ Invalid value! Please enter a number between 0 and 10.")
                    except ValueError:
                        print("❌ Invalid input! Please enter a numeric value (e.g., 4.5).")
                    
            elif choice == '0':
                self.navigation_stack.pop()
                break
            else:
                print(" Invalid choice. Please try again.")
    
    def _show_scoring_logic(self, threshold):
        """Show the current vulnerability scoring logic."""
        print("\n🔍 Current Vulnerability Scoring Logic")
        print("=" * 60)
        
        print("📊 Enhanced Score Calculation Formula:")
        print("Score = AdjustedSeverity + AdjustedPotentialImpact + AdjustedEaseOfExploitation")
        print("• Each component is adjusted based on security controls and environment context")
        print("• Maximum possible score: 15 points")
        
        print("\n📈 Base Severity Mapping:")
        print("• BLOCKER/CRITICAL: 5 points")
        print("• HIGH: 4 points") 
        print("• MEDIUM: 3 points")
        print("• LOW: 2 points")
        print("• INFO: 1 point")
        
        print("\n🔧 Context Adjustments:")
        print("• Security controls can reduce scores by -1 to -2 points per component")
        print("• Risk factors can increase scores by +1 to +2 points per component")
        print("• Adjustments are applied based on appsecai/risk_profiles/context_modifiers/vulnerability_framework.json")
        
        print(f"\n🎯 Current Threshold: {threshold}")
        print(f"• Vulnerabilities with score ≥ {threshold} are included in results")
        print(f"• Vulnerabilities with score < {threshold} are filtered out")
        
        # Check for enhanced framework files
        framework_file = "appsecai/risk_profiles/context_modifiers/vulnerability_framework.json"
        compliance_file = "appsecai/risk_profiles/context_modifiers/risk_context_template.json"
        
        print(f"\n📝 Enhanced Scoring Framework:")
        if os.path.exists(framework_file):
            try:
                import json
                with open(framework_file, 'r') as f:
                    config = json.load(f)
                    
                framework = config.get('vulnerability_scoring_framework', {})
                vul_categories = framework.get('vulnerability_categories', {})
                categories = len(vul_categories)
                print(f"• Framework file: {framework_file} ✅")
                print(f"• {categories} vulnerability categories configured")
                print(f"• Context-aware scoring with security controls integration")
                
            except Exception as e:
                print(f"• Framework file: {framework_file}  (Error: {e})")
        else:
            print(f"• Framework file: {framework_file}  (Not found)")
            
        if os.path.exists(compliance_file):
            print(f"• Compliance file: {compliance_file} ✅")
        else:
            print(f"• Compliance file: {compliance_file}  (Not found)")
            

    
    def _show_vulnerability_categories(self):
        """Show vulnerability categories from enhanced framework."""
        print("\n📋 Vulnerability Categories in Enhanced Framework")
        print("=" * 60)
        
        framework_file = "appsecai/risk_profiles/context_modifiers/vulnerability_framework.json"
        if not os.path.exists(framework_file):
            print(f" Framework file not found: {framework_file}")
            return
            
        try:
            import json
            with open(framework_file, 'r') as f:
                config = json.load(f)
                
            framework = config.get('vulnerability_scoring_framework', {})
            categories = framework.get('vulnerability_categories', {})
            
            print(f"📁 File: {framework_file}")
            print(f"📊 Total categories: {len(categories)}")
            print()
            
            for i, (category_name, category_config) in enumerate(categories.items(), 1):
                base_scores = category_config.get('base_scores', {})
                impact = base_scores.get('PotentialImpact', 0)
                exploitation = base_scores.get('EaseOfExploitation', 0)
                
                print(f"{i:2d}. {category_name}")
                print(f"    Impact: {impact}, Exploitation: {exploitation}")
                
                # Show some mapped vulnerabilities if available
                mapped_vulns = category_config.get('mapped_vulnerabilities', [])
                if mapped_vulns:
                    print(f"    Examples: {', '.join(mapped_vulns[:3])}{'...' if len(mapped_vulns) > 3 else ''}")
                print()
                
        except Exception as e:
            print(f" Error reading framework: {e}")
    
    def _test_enhanced_scoring_system(self, threshold):
        """Test the enhanced vulnerability scoring system with sample data."""
        print("\n🧪 Testing Enhanced Vulnerability Scoring System")
        print("=" * 60)
        
        framework_file = "appsecai/risk_profiles/context_modifiers/vulnerability_framework.json"
        if not os.path.exists(framework_file):
            print(f" Framework file not found: {framework_file}")
            return
            
        try:
            # Import the enhanced vulnerability scorer
            from appsecai.core.scorer import EnhancedVulnerabilityScorer
            
            # Initialize scorer
            scorer = EnhancedVulnerabilityScorer()
            
            # Create test vulnerabilities
            test_vulnerabilities = [
                {
                    'ruleKey': 'typescript:S5852',
                    'message': 'Make sure the regex used here is not vulnerable to ReDoS attacks',
                    'vulnerabilityProbability': 'MEDIUM',
                    'securityCategory': 'dos'
                },
                {
                    'ruleKey': 'docker:S6471',
                    'message': 'The "node" image runs with "root" as the default user',
                    'vulnerabilityProbability': 'MEDIUM',
                    'securityCategory': 'infrastructure'
                },
                {
                    'ruleKey': 'javascript:S1313',
                    'message': 'Make sure using a hardcoded IP address is safe',
                    'vulnerabilityProbability': 'LOW',
                    'securityCategory': 'infrastructure'
                }
            ]
            
            print("🔍 Testing with sample SonarQube vulnerabilities:")
            print()
            
            for i, vuln in enumerate(test_vulnerabilities, 1):
                # Score the vulnerability using enhanced scorer
                result = scorer.score_sonarqube_vulnerability(vuln)
                
                # Determine if it passes threshold
                passes_threshold = result.final_score >= int(threshold)
                status = "✅ INCLUDED" if passes_threshold else " FILTERED OUT"
                
                print(f"Test {i}: {vuln['message'][:50]}...")
                print(f"  Rule: {vuln['ruleKey']}")
                print(f"  Original Risk: {vuln['vulnerabilityProbability']}")
                print(f"  Category: {result.category}")
                print(f"  Enhanced Score: {result.final_score}")
                print(f"  Risk Level: {result.risk_level.value}")
                print(f"  Threshold: {threshold}")
                print(f"  Result: {status}")
                if result.justifications:
                    print(f"  Justification: {result.justifications[0][:60]}...")
                print()
                
        except Exception as e:
            print(f" Error testing enhanced scoring system: {e}")
            print("💡 Make sure enhanced_vulnerability_scorer.py is available")
    
    def _test_sast_connections(self):
        """Test SAST-related service connections (SonarQube & GitHub)."""
        print("\n🔍 Testing SAST Connections...")
        print("=" * 40)
        
        # Test SonarQube
        print("\n🏢 Testing SonarQube Connection...")
        try:
            import requests
            sonar_url = self.current_settings.get('sonar_url', 'http://localhost:9000')
            response = requests.get(f"{sonar_url}/api/system/status", timeout=5)
            if response.status_code == 200:
                print("   ✅ SonarQube: Connected")
            else:
                print(f"   ❌ SonarQube: HTTP {response.status_code}")
        except Exception as e:
            print(f"   ❌ SonarQube: Connection failed - {e}")
        
        # Test GitHub
        print("\n🔗 Testing GitHub Connection...")
        try:
            token = os.environ.get('GITHUB_TOKEN')
            if token:
                try:
                    from github import Github
                    g = Github(token)
                    user = g.get_user()
                    print(f"   ✅ GitHub: Connected as {user.login}")
                    
                    # Also test repo availability if one is set
                    repo_name = self.current_settings.get('github_repo')
                    if repo_name:
                        try:
                            repo = g.get_repo(repo_name)
                            print(f"   ✅ Repository '{repo_name}': Accessible")
                        except Exception as repo_err:
                            print(f"   ⚠️  Repository '{repo_name}': Not found or inaccessible")
                except ImportError:
                    print("   ❌ GitHub: PyGithub module not installed")
                except Exception as github_error:
                    print(f"   ❌ GitHub: Authentication failed - {github_error}")
            else:
                print("   ⚠️  GitHub: Token not configured")
        except Exception as e:
            print(f"   ❌ GitHub: Connection failed - {e}")
            
        input("\nPress Enter to continue...")

    def _test_dast_connections(self):
        """Test DAST-related connections (Target URLs)."""
        print("\n🔍 Testing DAST Connections...")
        print("=" * 40)
        
        targets = self._get_dast_urls()
        if not targets:
            print("⚠️  No DAST target URLs configured.")
        else:
            import requests
            for url in targets:
                print(f"\n🌐 Testing Target: {url}")
                try:
                    response = requests.get(url, timeout=5, verify=False)
                    if response.status_code < 400:
                        print(f"   ✅ Status: Reachable (HTTP {response.status_code})")
                    else:
                        print(f"   ⚠️  Status: HTTP {response.status_code}")
                except Exception as e:
                    print(f"   ❌ Connection failed: {e}")
                    
        print("\n🛡️  ZAP Status Check:")
        zap_path = os.environ.get('ZAP_REPORT_PATH')
        if zap_path and os.path.exists(zap_path):
            print(f"   ✅ ZAP Scan Profile: Exists at {zap_path}")
        else:
            print("   ℹ️  ZAP Status: Ready for new scan")
            
        input("\nPress Enter to continue...")
    
    def _save_configuration(self):
        """Save current configuration to .env file."""
        print("\n💾 Saving Configuration...")
        
        env_content = f"""# Caze AppSecAI CLI Configuration
# Generated by Interactive CLI

# GitHub Configuration
GITHUB_TOKEN={os.environ.get('GITHUB_TOKEN', '')}
GITHUB_REPO={os.environ.get('GITHUB_REPO', '')}
GITHUB_BASE_BRANCH={os.environ.get('GITHUB_BASE_BRANCH', 'main')}

# SonarQube Configuration
SONAR_URL={os.environ.get('SONAR_URL', 'http://localhost:9000')}
SONAR_USERNAME={os.environ.get('SONAR_USERNAME', 'admin')}
SONAR_PASSWORD={os.environ.get('SONAR_PASSWORD', '')}
SONAR_PROJECT_KEY={os.environ.get('SONAR_PROJECT_KEY', '')}

# LLM Configuration
LLM_MODEL={os.environ.get('LLM_MODEL', 'WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest')}
LLM_URL={os.environ.get('LLM_URL', 'http://4.247.140.236:11434')}
LLM_TIMEOUT={os.environ.get('LLM_TIMEOUT', '300')}
LLM_MAX_RETRIES={os.environ.get('LLM_MAX_RETRIES', '3')}

# AI Remediation Configuration
AI_BATCH_SIZE={os.environ.get('AI_BATCH_SIZE', '5')}
PR_BATCH_SIZE={os.environ.get('PR_BATCH_SIZE', '5')}
COMMIT_BATCH_SIZE={os.environ.get('COMMIT_BATCH_SIZE', '5')}

# DAST Configuration
DAST_URL={os.environ.get('DAST_URL', 'http://localhost:8080')}
ZAP_REPORT_PATH={os.environ.get('ZAP_REPORT_PATH', '')}

# SCA / Trivy Configuration
TRIVY_REPORT_PATH={os.environ.get('TRIVY_REPORT_PATH', '')}

# Enhanced Vulnerability Scoring Configuration
VULNERABILITY_THRESHOLD={os.environ.get('VULNERABILITY_THRESHOLD', '')}

# Output Configuration
OUTPUT_DIR={os.environ.get('OUTPUT_DIR', 'AppSecAI_output')}
"""
        
        try:
            with open('.env', 'w') as f:
                f.write(env_content)
            print("✅ Configuration saved to .env file")
        except Exception as e:
            print(f" Failed to save configuration: {e}")
        
        input("Press Enter to continue...")
    
    def _confirm_scan_context(self, scan_type: str) -> bool:
        """
        Display a summary of the scan context and ask for confirmation.
        Returns True to proceed, False to cancel.
        """
        # Ensure we are using the absolute latest configuration before scanning
        self._refresh_settings()
        
        print("\n" + "═"*60)
        print(f"🔍 {scan_type.replace('Security Scan', 'Configuration Review')}")
        print("═"*60)
        
        # Gather context data
        github_repo = os.environ.get('GITHUB_REPO', 'Not Set')
        sonar_url = os.environ.get('SONAR_URL', 'Not Set')
        dast_url = os.environ.get('DAST_URL', 'Not Set')
        trivy_target = os.environ.get('TRIVY_TARGET', 'Not Set')
        
        if 'DAST' in scan_type:
            print(f"  • DAST Target URL: {dast_url}")
            print(f"  • Scanner: OWASP ZAP")
        else:
            print(f"  • Repository:  {github_repo}")
            
            if 'SAST' in scan_type or 'Combined' in scan_type:
                print(f"  • SAST Target: {sonar_url} (SonarQube)")
            
            if 'SCA' in scan_type or 'Combined' in scan_type:
                triv_type = os.environ.get('TRIVY_TARGET_TYPE', 'fs').upper()
                type_map = {'FS': 'Filesystem', 'REPO': 'Repository', 'IMAGE': 'Container Image', 'K8S': 'Kubernetes'}
                display_type = type_map.get(triv_type, triv_type)
                print(f"  • SCA Target:  {trivy_target} ({display_type})")

        print("─"*60)
        
        # Mandatory Authorization Warning
        print("\n⚠️  WARNING:")
        print("   Ensure you have authorization to scan this target.")
        
        while True:
            choice = input("\nProceed? [Y/N]: ").strip().lower()
            
            if choice in ['', 'y', 'yes']:
                return True
            elif choice in ['q', 'quit', 'exit', 'n', 'no']:
                print("\n❌ Scan cancelled.")
                return False
            else:
                print("❌ Invalid input.")

    def _run_sast_scan(self):
        """Run SAST security scan — supports batch multi-repository scanning."""
        if not self._confirm_scan_context("SAST Security Scan"):
            return

        import sys
        import subprocess

        # ── Build repository list ──────────────────────────────────────────────
        repos_str = self.current_settings.get('github_repositories', '')
        repos = []
        if repos_str:
            for item in repos_str.split(';'):
                if not item.strip():
                    continue
                parts = [p.strip() for p in item.split('|')]
                repo_info = {"repo": parts[0], "branch": "main", "project_key": ""}
                if len(parts) > 1:
                    repo_info["branch"] = parts[1]
                if len(parts) > 2:
                    repo_info["project_key"] = parts[2]
                repos.append(repo_info)

        # Fallback: single github_repo setting (backward-compatible)
        if not repos and self.current_settings.get('github_repo'):
            repos.append({
                "repo": self.current_settings.get('github_repo'),
                "branch": self.current_settings.get('github_branch', 'main'),
                "project_key": os.environ.get('SONAR_PROJECT_KEY', '')
            })

        if not repos:
            print("\n GitHub repository not configured. Please configure it in Settings first.")
            input("Press Enter to continue...")
            return

        print(f"\n\U0001f512 Running SAST Scan")

        # ── Scan target selection ──────────────────────────────────────────────
        print("\nScan Target Options:")
        options = []
        if len(repos) > 1:
            options.append(f"Scan ALL configured repositories ({len(repos)} repos)")
            options.append("Select a specific repository from the list")
        else:
            options.append(f"Current configured repository: {repos[0]['repo']}")
        
        options.append("Custom repository URL")
        options.append("Current directory (local files)")
        options.append("Back to Main Menu")

        for idx, opt in enumerate(options, 1):
            print(f"{idx}. {opt}")

        choice = self._parse_input("Select target (or press Enter for option 1): ")
        if choice is None:   # cd command was handled
            return
        choice = choice.strip()

        if choice == '0' or choice == str(len(options)):
            print("\n🔙 Returning to Main Menu...")
            return

        targets = []   # list of dicts: {url, project_key, branch}

        # Resolve the selected choice index relative to the options list
        # We need to map the selected number back to the original logical choices
        if choice == '' or choice == '1':
            # Default: scan ALL repos (or the only one)
            for r in repos:
                targets.append({
                    "url": f"https://github.com/{r['repo']}.git",
                    "project_key": r.get('project_key', ''),
                    "branch": r.get('branch', 'main')
                })
        else:
            # Match the text of the selected option
            try:
                selected_idx = int(choice) - 1
                if 0 <= selected_idx < len(options):
                    selected_text = options[selected_idx]
                else:
                    print("❌ Invalid selection.")
                    input("Press Enter to continue...")
                    return
            except ValueError:
                print("❌ Invalid input.")
                input("Press Enter to continue...")
                return

            if selected_text == "Custom repository URL":
                url_input = self._parse_input("Enter repository URL: ")
                if url_input is None:
                    return
                targets.append({"url": url_input.strip(), "project_key": "", "branch": ""})
            elif selected_text == "Current directory (local files)":
                targets.append({"url": ".", "project_key": "", "branch": ""})
                print("⚠️  Note: Scanning current directory — not the configured GitHub repo.")
            elif selected_text == "Select a specific repository from the list":
                print("\nSelect Repository:")
                for i, r in enumerate(repos, 1):
                    print(f"  {i}. {r['repo']} (branch: {r['branch']})")
                try:
                    idx = int(input(f"Enter number (1-{len(repos)}): ")) - 1
                    if 0 <= idx < len(repos):
                        r = repos[idx]
                        targets.append({
                            "url": f"https://github.com/{r['repo']}.git",
                            "project_key": r.get('project_key', ''),
                            "branch": r.get('branch', 'main')
                        })
                    else:
                        print("❌ Invalid selection.")
                        input("Press Enter to continue...")
                        return
                except ValueError:
                    print("❌ Invalid input.")
                    input("Press Enter to continue...")
                    return

        print(f"✅ Will scan {len(targets)} repository(ies)")

        if not targets:
            print("No targets selected.")
            input("Press Enter to continue...")
            return

        print("\n🚀 Starting scan...")

        # ── AI remediation prompt ──────────────────────────────────────────────
        auto_fix_input = self._parse_input("Run AI remediation after scan? (y/N): ")
        if auto_fix_input is None:
            return
        auto_fix = auto_fix_input.strip().lower() == 'y'

        # ── Determine exe/python mode and base dirs ────────────────────────────
        frozen = getattr(sys, 'frozen', False)
        if frozen:
            base_dir = get_base_directory()
            output_dir = str(base_dir / "AppSecAI_output")
            clone_dir = str(base_dir / "cloned_repos")
        else:
            output_dir = None
            clone_dir = "cloned_repos"

        # ── Batch scan loop ────────────────────────────────────────────────────
        successful = 0
        total = len(targets)

        for i, t in enumerate(targets, 1):
            url = t["url"]
            project_key = t.get("project_key", "")
            branch = t.get("branch", "")

            if total > 1:
                print(f"\n\U0001f680 [{i}/{total}] Scanning: {url}")
            else:
                print(f"\n\U0001f680 Executing scan for: {url}")

            # Build command
            config_file_path = get_resource_path("appsecai/risk_profiles/app_config.yaml")
            if frozen:
                cmd_parts = [get_executable_path(), '--config', config_file_path, 'scan', '--type', 'sast', '--target', url, '--clone-dir', clone_dir]
            else:
               cmd_parts = [sys.executable, '-m', 'appsecai.cli.main', '--config', config_file_path, 'scan', '--type', 'sast', '--target', url, '--output-dir', output_dir, '--clone-dir', clone_dir]

            if project_key:
                cmd_parts.extend(['--project-key', project_key])
            if branch:
                cmd_parts.extend(['--branch', branch])
            
            # Pass user-configured threshold explicitly
            threshold_val = os.environ.get('VULNERABILITY_THRESHOLD', '2.5')
            threshold = threshold_val.strip() if threshold_val else '2.5'
            cmd_parts.extend(['--threshold', threshold])
            
            if auto_fix:
                cmd_parts.extend(['--auto-fix', '--interactive-pr'])
            
            # ── Pass SonarQube credentials explicitly ──────────────────────────
            sonar_url = os.environ.get('SONAR_URL', 'http://localhost:9000')
            sonar_user = os.environ.get('SONAR_USERNAME', 'admin')
            sonar_pass = os.environ.get('SONAR_PASSWORD', '')
            
            cmd_parts.extend(['--sonar-url', sonar_url])
            cmd_parts.extend(['--sonar-username', sonar_user])
            if sonar_pass:
                cmd_parts.extend(['--sonar-password', sonar_pass])
            
            # ── Pass GitHub Token explicitly ───────────────────────────────────
            github_token = os.environ.get('GITHUB_TOKEN', '')
            if github_token:
                cmd_parts.extend(['--github-token', github_token])

            print(f"   Command: {' '.join(cmd_parts)}")

            try:
                env_vars = os.environ.copy()
                result = subprocess.run(cmd_parts, env=env_vars, capture_output=False, text=True)

                if result.returncode == 0:
                    successful += 1
                    print(f"\n\u2705 Scan [{i}/{total}] completed successfully: {url}")
                    self.scan_results.append({
                        'type': 'SAST',
                        'target': url,
                        'timestamp': str(Path().cwd() / 'AppSecAI_output'),
                        'status': 'completed'
                    })
                else:
                    print(f"\n\u274c Scan [{i}/{total}] failed (exit code {result.returncode}): {url}")

            except Exception as e:
                print(f"\n\u274c Error running scan [{i}/{total}] for {url}: {e}")

        # ── Post-batch summary ─────────────────────────────────────────────────
        print(f"\n\u2728 Batch scan finished: {successful}/{total} repositories completed successfully.")

        if successful > 0:
            self._offer_scan_report_generation("SAST")

        input("\nPress Enter to continue...")
    
    def _run_sca_scan(self):
        """Run SCA analysis natively using Trivy — restores original intuitive flow with batch support."""
        if not self._confirm_scan_context("SCA Security Scan"):
            return

        import os
        from pathlib import Path
        import sys as _sys
        import subprocess as _subprocess

        print("\n📦 Native SCA (Trivy) Analysis")
        print("This flow executes standard native scanning to produce context-aware scoring")

        # ── Build repository list ──────────────────────────────────────────────
        repos_str = self.current_settings.get('github_repositories', '')
        repos = []
        if repos_str:
            for item in repos_str.split(';'):
                if not item.strip():
                    continue
                parts = [p.strip() for p in item.split('|')]
                repo_info = {"repo": parts[0], "branch": "main"}
                if len(parts) > 1:
                    repo_info["branch"] = parts[1]
                repos.append(repo_info)

        # Fallback: single github_repo setting
        sast_repo = self.current_settings.get('github_repo', '')
        if not repos and sast_repo:
            repos.append({
                "repo": sast_repo,
                "branch": self.current_settings.get('github_branch', 'main')
            })

        targets = []  # list of dicts: {target, target_type, label}

        self._refresh_settings()
        
        # ── Target selection Logic ────────────────────────────────────────
        if len(repos) > 1:
            # Scenario A: Multi-repo batch scan - Show the selection menu
            print("\nScan Target Options:")
            print(f"   1. Scan ALL configured repositories ({len(repos)} repos)")
            print("   2. Select a specific repository from the list")
            print("   3. Custom target (Container Image, Local Path, K8s, etc.)")
            print("   4. Current directory (local files)")

            choice = self._parse_input("\nSelect target (or press Enter for option 1): ")
            if choice is None:
                return
            choice = choice.strip()

            if choice == '3':
                # Custom target configuration
                self._configure_trivy_scan_settings()
                target_type = os.environ.get('TRIVY_TARGET_TYPE', 'fs')
                target = os.environ.get('TRIVY_TARGET', './')
                targets.append({"target": target, "target_type": target_type, "label": target})
            elif choice == '4':
                targets.append({"target": "./", "target_type": "fs", "label": "Current Directory"})
            elif choice == '2':
                print("\nSelect Repository:")
                for i, r in enumerate(repos, 1):
                    print(f"  {i}. {r['repo']}")
                idx_input = self._parse_input(f"Enter number (1-{len(repos)}): ")
                if idx_input is None: return
                try:
                    idx = int(idx_input.strip()) - 1
                    if 0 <= idx < len(repos):
                        r = repos[idx]
                        url = r['repo'] if r['repo'].startswith('http') else f"https://github.com/{r['repo']}.git"
                        targets.append({"target": url, "target_type": "repo", "label": r['repo']})
                except: return
            else:
                # Default: Scan ALL
                for r in repos:
                    url = r['repo'] if r['repo'].startswith('http') else f"https://github.com/{r['repo']}.git"
                    targets.append({"target": url, "target_type": "repo", "label": r['repo']})

        else:
            # Scenario B: Single repo or no repos (Restore "Before" logic + Smart Selection)
            trivy_target = os.environ.get('TRIVY_TARGET', './')
            trivy_type = os.environ.get('TRIVY_TARGET_TYPE', 'fs')
            
            # Smart Selection: If SAST repo and SCA target are both set and different, ask which one to scan.
            # We only do this if trivy_target is not the default './'
            if sast_repo and trivy_target != './' and trivy_target != sast_repo and (sast_repo not in trivy_target):
                print(f"\n💡 Multiple targets detected:")
                print(f"   1. Configured SAST Repository: {sast_repo}")
                print(f"   2. Configured SCA Target: {trivy_target} ({trivy_type})")
                print(f"   3. Configure a different target now")
                
                choice = (self._parse_input("\nWhich one would you like to scan? (1-3): ") or "1").strip()
                if choice == '2':
                    targets.append({"target": trivy_target, "target_type": trivy_type, "label": trivy_target})
                elif choice == '3':
                    self._configure_trivy_scan_settings()
                    targets.append({
                        "target": os.environ.get('TRIVY_TARGET', './'),
                        "target_type": os.environ.get('TRIVY_TARGET_TYPE', 'fs'),
                        "label": os.environ.get('TRIVY_TARGET', './')
                    })
                elif choice == '1':
                    url = sast_repo if sast_repo.startswith('http') else f"https://github.com/{sast_repo}.git"
                    targets.append({"target": url, "target_type": "repo", "label": sast_repo})
                else: 
                    print("ℹ️ SCA analysis cancelled.")
                    return
            
            elif sast_repo:
                print(f"\n💡 Detected configured github repository: {sast_repo}")
                
                while True:
                    reuse_choice = self._parse_input(f"Do you want to run the Trivy SCA scan against this repository? (Y/n): ")
                    if reuse_choice is None: return
                    reuse_val = (reuse_choice or "y").strip().lower()
                    if reuse_val in ['y', 'yes', 'n', 'no']: break
                    print("❌ Invalid input. Please enter 'y' or 'n'.")
                
                if reuse_val in ['y', 'yes']:
                    url = sast_repo if sast_repo.startswith('http') else f"https://github.com/{sast_repo}.git"
                    targets.append({"target": url, "target_type": "repo", "label": sast_repo})
                else:
                    while True:
                        config_choice = self._parse_input("Would you like to configure a different repository or target (image, k8s, etc.) now? (Y/n): ")
                        if config_choice is None: return
                        config_val = (config_choice or "y").strip().lower()
                        if config_val in ['y', 'yes', 'n', 'no']: break
                        print("❌ Invalid input. Please enter 'y' or 'n'.")
                        
                    if config_val in ['y', 'yes']:
                        self._configure_trivy_scan_settings()

                    targets.append({
                        "target": os.environ.get('TRIVY_TARGET', './'),
                        "target_type": os.environ.get('TRIVY_TARGET_TYPE', 'fs'),
                        "label": os.environ.get('TRIVY_TARGET', './')
                    })
            else:
                # Standard flow if no SAST repo is configured
                targets.append({
                    "target": os.environ.get('TRIVY_TARGET', './'),
                    "target_type": os.environ.get('TRIVY_TARGET_TYPE', 'fs'),
                    "label": os.environ.get('TRIVY_TARGET', './')
                })

            # Confirmation prompt (except for automatic reuse)
            if targets and targets[0]['label'] != sast_repo:
                target = targets[0]['target']
                target_type = targets[0]['target_type']
                
                # SMART TYPE DETECTION: If target is a URL but type is 'fs', it's almost certainly a mistake.
                if target_type == 'fs' and target.startswith('http'):
                    print(f"\n💡 Note: Your SCA target appears to be a repository URL ({target})")
                    print(f"   but the target type is set to 'fs' (Filesystem).")
                    fix_choice = (self._parse_input("   Would you like to switch to 'repo' type for this scan? (Y/n): ") or "y").strip().lower()
                    if fix_choice in ['y', 'yes']:
                        targets[0]['target_type'] = 'repo'
                        target_type = 'repo'
                        print("   ✅ Switched to 'repo' mode.")
                
                print(f"\n📄 Current Trivy Settings:")
                print(f"   Target Type: {targets[0]['target_type']}")
                print(f"   Target Path: {targets[0]['target']}")
                confirm = (self._parse_input("Is this configuration correct? (Y/n): ") or "y").strip().lower()
                if confirm not in ['y', 'yes']:
                    print("ℹ️ SCA analysis cancelled.")
                    return

        if not targets:
            print("❌ No targets selected for scanning.")
            return

        print(f"\n🚀 Starting SCA Scan ({len(targets)} targets)")
        
        base_dir = get_base_directory()
        output_dir = str(base_dir / "AppSecAI_output")

        # ── Batch Execution Loop ──────────────────────────────────────────
        for i, t in enumerate(targets, 1):
            if len(targets) > 1:
                print("\n" + "="*60)
                print(f"🔄 [{i}/{len(targets)}] SCANNING: {t['label']}")
                print("="*60)
            else:
                 print(f"\n🔄 SCANNING: {t['label']}")

            target = t['target']
            target_type = t['target_type']

            # Call the scan subcommand
            config_file_path = get_resource_path("appsecai/risk_profiles/app_config.yaml")
            if getattr(_sys, 'frozen', False):
                cmd_parts = [get_executable_path(), '--config', config_file_path, 'scan', '--type', 'sca', '--target-type', target_type, '--target', target]
            else:
                cmd_parts = [ sys.executable,'-m', 'appsecai.cli.main', '--config', config_file_path, 'scan', '--type', 'sca', '--target-type', target_type, '--target', target]

            # Pass user-configured threshold explicitly
            threshold_val = os.environ.get('VULNERABILITY_THRESHOLD', '2.5')
            threshold = threshold_val.strip() if threshold_val else '2.5'
            cmd_parts.extend(['--threshold', threshold])

            print(f"🚀 Executing: {' '.join(cmd_parts)}")

            try:
                env_vars = os.environ.copy()
                result = _subprocess.run(cmd_parts, env=env_vars, capture_output=False, text=True)
                
                status = 'completed' if result.returncode in (0, 1) else 'failed'
                if result.returncode == 0:
                    print(f"\n✅ SCA completed successfully for {t['label']} (Clean).")
                elif result.returncode == 1:
                    print(f"\n⚠️ SCA completed for {t['label']} (Findings found).")
                else:
                    print(f"\n❌ SCA failed for {t['label']} with exit code {result.returncode}.")

                self.scan_results.append({
                    'type': 'SCA',
                    'target': target,
                    'label': t['label'],
                    'timestamp': str(Path().cwd() / 'AppSecAI_output'),
                    'status': status,
                })

            except Exception as e:
                print(f"\n❌ Error running SCA analysis for {t['label']}: {e}")

        # ── Post-Batch PDF Generation ──────────────────────────────────────
        if any(r['status'] == 'completed' for r in self.scan_results if r['type'] == 'SCA'):
            print("\n" + "="*60)
            pdf_input = self._parse_input("Generate SCA Security Posture PDF report for these results? (Y/n): ")
            if pdf_input is not None and (pdf_input or "").strip().lower() not in ['n', 'no']:
                try:
                    from appsecai.reporting.posture_report import SecurityPostureReportGenerator
                    reports_output_dir = base_dir / "generated_reports"
                    reports_output_dir.mkdir(parents=True, exist_ok=True)

                    generator = SecurityPostureReportGenerator(
                        input_dir=output_dir,
                        output_dir=str(reports_output_dir),
                        force_report_type="sca_only",
                    )
                    generator.discover_and_load_data()
                    generator.analyze_security_posture()
                    pdf_path = generator.generate_pdf_report()
                    if pdf_path:
                        print(f"📄 SCA PDF report generated: {pdf_path}")
                        
                        if self._parse_input("\n🔍 Open reports directory? (y/N): ").strip().lower().startswith('y'):
                            import platform
                            if platform.system() == "Windows": os.startfile(reports_path := str(reports_output_dir))
                            elif platform.system() == "Darwin": _subprocess.run(["open", str(reports_output_dir)])
                            else: _subprocess.run(["xdg-open", str(reports_output_dir)])
                except Exception as pdf_err:
                    print(f"⚠️ Failed to generate SCA PDF report: {pdf_err}")


        input("\nPress Enter to continue...")


    def _auto_download_after_sast_scan(self, has_ai_remediation=False):
        """Auto-download reports after SAST scan completion."""
        try:
            import os
            import glob
            
            output_dir = self.current_settings.get('output_dir', 'AppSecAI_output')
            
            # Find the latest scan directory
            pattern = os.path.join(output_dir, "*_output_*")
            scan_dirs = sorted(glob.glob(pattern), reverse=True)
            
            if not scan_dirs:
                return
            
            latest_scan = scan_dirs[0]
            scan_name = os.path.basename(latest_scan)
            
            # Create downloads directory in user's Downloads folder
            import os
            user_downloads = os.path.join(os.path.expanduser("~"), "Downloads")
            downloads_dir = os.path.join(user_downloads, "Caze AppSecAI_Reports")
            os.makedirs(downloads_dir, exist_ok=True)
            
            print(f"\n📥 Auto-downloading scan reports...")
            
            # Download reports based on scan type
            downloaded_reports = self._auto_download_sast_reports(
                latest_scan, downloads_dir, scan_name, has_ai_remediation
            )
            
            if downloaded_reports:
                print(f"✅ Reports saved to '{downloads_dir}'")
            
        except Exception as e:
            print(f"⚠️  Could not auto-download reports: {e}")
    
    def _run_quick_comprehensive_scan(self):
        """Run all security scans (SAST, SCA, DAST) in a streamlined sequence."""
        print("\n" + "🚀" * 30)
        print("🚀 QUICK COMPREHENSIVE SCAN - INITIALIZING FULL SUITE")
        print("🚀" * 30)
        
        if not self._confirm_scan_context("Full Comprehensive Security Suite"):
            return

        print("\n[1/3] Starting SAST Scan...")
        self._run_sast_scan()
        
        print("\n[2/3] Starting SCA Scan...")
        self._run_sca_scan()
        
        print("\n[3/3] Starting DAST Scan...")
        self._run_dast_scan()
        
        print("\n" + "✅" * 30)
        print("✅ COMPREHENSIVE SCAN SUITE COMPLETED!")
        print("✅" * 30)
        input("\nPress Enter to return to Main Menu...")

    def _run_dast_scan(self):
        """Run DAST security scan for single or multiple URLs."""
        if not self._confirm_scan_context("DAST Security Scan"):
            return

        # Clear stale multi-URL session manifest if it exists
        try:
            manifest_path = get_base_directory() / "AppSecAI_output" / "dast_scan_session.json"
            if manifest_path.exists():
                manifest_path.unlink()
                print("🗑️ Cleaned up old DAST session manifest")
        except Exception:
            pass

        # Check for uploaded report FIRST
        uploaded_report = self._check_uploaded_zap_report()
        if uploaded_report and not uploaded_report.get('processed', False):
            print("\n" + "=" * 50)
            print("📤 UNPROCESSED UPLOADED ZAP REPORT DETECTED")
            print("=" * 50)
            print(f"File: {uploaded_report['metadata'].get('original_file', 'Unknown')}")
            print(f"Target URL: {uploaded_report['target_url']}")
            print(f"Uploaded: {uploaded_report['upload_time']}")
            print("\nOptions:")
            print("   1. Analyze this uploaded report now")
            print("   2. Run a fresh LIVE DAST scan instead")
            print("   0. Cancel and go back")
            
            choice = self._parse_input("\nSelect option (0-2): ")
            if choice is None:
                return
            
            choice = choice.strip()
            if choice == '0':
                return
            elif choice == '1':
                print("\n🏃 Starting analysis of uploaded report...")
                # Process the report
                report_path = uploaded_report['metadata'].get('original_file')
                target_url = uploaded_report['target_url']
                
                # Ask for environment settings
                env_settings = self._get_environment_settings_for_upload()
                if env_settings is None:
                    return
                
                results = self._process_uploaded_zap_report(report_path, target_url, env_settings)
                
                if results:
                    # Save metadata as processed
                    self._save_upload_metadata(results, report_path, target_url, env_settings)
                    
                    # Generate reports
                    print("\n📊 Generating comprehensive reports...")
                    report_paths = self._generate_reports_from_upload_v2(results, report_path, env_settings)
                    
                    # Also generate the legacy PDF report for compatibility
                    self._generate_pdf_report_for_upload(results, target_url)
                    
                    # Display summary
                    self._display_upload_summary_v2(results, report_paths)
                
                return
            # If choice is '2', continue with live scan configuration below
        
        # Get configured URLs
        configured_urls = self._get_dast_urls()
        current_url = self.current_settings.get('dast_url', 'http://localhost:8080')
        
        print(f"\n📍 Select Target URL:")
        if len(configured_urls) > 1:
            print(f"   1. Scan all configured URLs ({len(configured_urls)} URLs)")
            for i, url in enumerate(configured_urls, 1):
                print(f"      {i}. {url}")
            print(f"   2. Select single URL from list")
            print(f"   3. Enter new target URL")
        else:
            print(f"   1. Use existing target ({current_url})")
            print(f"   2. Enter new target URL")
        
        choice = self._parse_input(f"\nSelect option (1-{3 if len(configured_urls) > 1 else 2}) or press Enter to use option 1: ")
        if choice is None:  # cd command was handled
            return
        choice = choice.strip()
        
        target_urls = []
        
        if len(configured_urls) > 1:
            if choice == '2':
                # Select single URL from list
                print("\nSelect URL to scan:")
                for i, url in enumerate(configured_urls, 1):
                    print(f"   {i}. {url}")
                url_choice = self._parse_input(f"Select URL (1-{len(configured_urls)}): ")
                if url_choice is None:  # cd command was handled
                    return
                url_choice = url_choice.strip()
                try:
                    url_index = int(url_choice) - 1
                    if 0 <= url_index < len(configured_urls):
                        target_urls = [configured_urls[url_index]]
                    else:
                        print(" Invalid selection")
                        input("Press Enter to continue...")
                        return
                except ValueError:
                    print(" Invalid input")
                    input("Press Enter to continue...")
                    return
            elif choice == '3':
                # Enter new URL
                new_url = self._parse_input("Enter new target URL: ")
                if new_url is None:  # cd command was handled
                    return
                new_url = new_url.strip()
                if new_url:
                    target_urls = [new_url]
                else:
                    print(" No URL provided")
                    input("Press Enter to continue...")
                    return
            else:
                # Scan all configured URLs
                target_urls = configured_urls
        else:
            if choice == '2':
                # Enter new URL
                new_url = self._parse_input("Enter new target URL: ")
                if new_url is None:  # cd command was handled
                    return
                new_url = new_url.strip()
                if new_url:
                    target_urls = [new_url]
                else:
                    print(" No URL provided")
                    input("Press Enter to continue...")
                    return
            else:
                # Use current URL
                target_urls = [current_url]
        
        if not target_urls:
            print(" No target URLs selected")
            input("Press Enter to continue...")
            return
        
        # Show scan summary
        print(f"\n📊 Scan Summary:")
        print(f"   Total URLs to scan: {len(target_urls)}")
        for i, url in enumerate(target_urls, 1):
            print(f"   {i}. {url}")
        
        # Validate URL accessibility for all URLs
        print(f"\n🔍 Validating target connectivity...")
        import requests
        import socket
        from urllib.parse import urlparse
        
        accessible_urls = []
        for i, target_url in enumerate(target_urls, 1):
            print(f"\n[{i}/{len(target_urls)}] Testing {target_url}...")
            try:
                # First test DNS resolution
                parsed_url = urlparse(target_url)
                hostname = parsed_url.hostname
                
                try:
                    socket.gethostbyname(hostname)
                    print(f"   ✅ DNS resolution successful for {hostname}")
                except socket.gaierror:
                    print(f"    DNS resolution failed for {hostname}")
                    print("   💡 This indicates a network connectivity issue")
                    proceed = self._parse_input(f"   Continue with this URL anyway? (y/N): ")
                    if proceed is None:  # cd command was handled
                        return
                    proceed = proceed.strip().lower()
                    if proceed == 'y':
                        accessible_urls.append(target_url)
                    continue
                
                # Then test HTTP connectivity
                response = requests.head(target_url, timeout=10, allow_redirects=True)
                if response.status_code < 400:
                    print(f"   ✅ Target URL is accessible (HTTP {response.status_code})")
                    accessible_urls.append(target_url)
                else:
                    print(f"   ⚠️  Target URL returned HTTP {response.status_code}")
                    proceed = self._parse_input(f"   Continue with this URL anyway? (y/N): ")
                    if proceed is None:  # cd command was handled
                        return
                    proceed = proceed.strip().lower()
                    if proceed == 'y':
                        accessible_urls.append(target_url)
                        
            except requests.exceptions.RequestException as e:
                print(f"    Cannot connect to target URL: {str(e)}")
                print("   💡 Common issues:")
                print("      - URL is not accessible from your network")
                print("      - Target application is not running")
                print("      - Firewall blocking the connection")
                print("      - DNS resolution issues")
                
                proceed = self._parse_input(f"   Continue with this URL anyway? (y/N): ")
                if proceed is None:  # cd command was handled
                    return
                proceed = proceed.strip().lower()
                if proceed == 'y':
                    accessible_urls.append(target_url)
        
        if not accessible_urls:
            print("\n No accessible URLs to scan")
            input("Press Enter to continue...")
            return
        
        target_urls = accessible_urls
        print(f"\n✅ Total targets to scan: {len(target_urls)}")
        
        # Check ZAP availability first
        print("\n🔍 Checking OWASP ZAP availability...")
        
        try:
            # The actual ZAP availability and auto-installation is handled by zap_driver.py
            print("✅ OWASP ZAP availability will be verified during execution")
        except Exception as e:
            print(f" Error checking ZAP: {e}")
            input("Press Enter to continue...")
            return
        
        # Execute DAST scans for all URLs
        print(f"\n🚀 Starting DAST scan using OWASP ZAP...")
        print("⚠️  Note: DAST scans can take several minutes per URL")
        
        import sys
        import subprocess
        
        # Get current ZAP timeout setting
        zap_timeout = os.environ.get('ZAP_MAX_SCAN_TIME', '7200')
        print(f"🔧 Scan timeout per target: {int(zap_timeout)//60} minutes (ZAP configuration)")
        
        successful_scans = 0
        failed_scans = 0
        scan_results = []
        
        for i, target_url in enumerate(target_urls, 1):
            print(f"\n{'='*80}")
            print(f"🌐 Scanning URL {i} of {len(target_urls)}: {target_url}")
            print(f"{'='*80}")
            
            try:
                # Get base directory and output directory
                base_dir = get_base_directory()
                output_dir = str(base_dir / "AppSecAI_output")
                
                config_file_path = get_resource_path("appsecai/risk_profiles/app_config.yaml")
                if getattr(sys, 'frozen', False):
                    # Running as EXE - use executable directly
                    cmd_parts = [get_executable_path(), '--config', config_file_path, 'scan', '--type', 'dast', '--target', target_url, '--timeout', zap_timeout]
                    # CRITICAL: Pass explicit output directory to avoid temp folder
                    cmd_parts.extend(['--output-dir', output_dir])
                else:
                    # Running as Python - use module syntax
                    cmd_parts = [sys.executable, "-m", "appsecai.cli.main", '--config', config_file_path, 'scan', '--type', 'dast', '--target', target_url, '--timeout', zap_timeout]
                    # Also pass output directory for Python mode
                    cmd_parts.extend(['--output-dir', output_dir])
                
                # Pass user-configured threshold explicitly
                threshold = os.environ.get('VULNERABILITY_THRESHOLD', '2.5').strip() or '2.5'
                cmd_parts.extend(['--threshold', threshold])
                
                print(f"🔧 CLI command: {' '.join(cmd_parts)}")
                print("🔄 Starting ZAP and running scan...")
                
                # Use a very long timeout to avoid CLI timeout issues
                cli_timeout = 10800  # 3 hours - longer than ZAP timeout
                env_vars = os.environ.copy()
                result = subprocess.run(cmd_parts, env=env_vars, capture_output=False, text=True, timeout=cli_timeout)
                
                if result.returncode == 0:
                    print(f"\n✅ Scan {i}/{len(target_urls)} completed successfully!")
                    successful_scans += 1
                    scan_results.append({'url': target_url, 'status': 'success', 'returncode': 0})
                elif result.returncode == 1:
                    print(f"\n⚠️  Scan {i}/{len(target_urls)} completed with vulnerabilities found")
                    print("💡 This is expected when security issues are detected")
                    successful_scans += 1
                    scan_results.append({'url': target_url, 'status': 'success_with_vulns', 'returncode': 1})
                elif result.returncode == 3:
                    print(f"\n Scan {i}/{len(target_urls)} execution failed")
                    print("💡 This usually indicates:")
                    print("   - Target URL is not accessible")
                    print("   - Network connectivity issues")
                    failed_scans += 1
                    scan_results.append({'url': target_url, 'status': 'failed', 'returncode': 3})
                else:
                    print(f"\n Scan {i}/{len(target_urls)} failed with exit code {result.returncode}")
                    failed_scans += 1
                    scan_results.append({'url': target_url, 'status': 'failed', 'returncode': result.returncode})
                    
            except subprocess.TimeoutExpired:
                zap_timeout_val = int(os.environ.get('ZAP_MAX_SCAN_TIME', '7200'))
                timeout_minutes = zap_timeout_val // 60
                print(f"\n⏰ Scan {i}/{len(target_urls)} timed out ({timeout_minutes} minutes)")
                print("💡 Try scanning a smaller application or increase ZAP_MAX_SCAN_TIME in .env file")
                failed_scans += 1
                scan_results.append({'url': target_url, 'status': 'timeout', 'returncode': -1})
            except Exception as e:
                print(f"\n Error running scan {i}/{len(target_urls)}: {e}")
                failed_scans += 1
                scan_results.append({'url': target_url, 'status': 'error', 'returncode': -1})
        
        # Print summary
        print(f"\n{'='*80}")
        print(f"📊 DAST SCAN SUMMARY")
        print(f"{'='*80}")
        print(f"   Total URLs scanned: {len(target_urls)}")
        print(f"   ✅ Successful: {successful_scans}")
        print(f"    Failed: {failed_scans}")
        print(f"\n📋 Detailed Results:")
        for i, result in enumerate(scan_results, 1):
            status_icon = '✅' if result['status'] in ['success', 'success_with_vulns'] else ''
            print(f"   {status_icon} {i}. {result['url']} - {result['status']}")
        
        if successful_scans > 0:
            print(f"\n✅ {successful_scans} scan(s) completed successfully!")
            
            # Create a session manifest for multi-URL scans
            if len(target_urls) > 1:
                print("\n📊 Multiple URLs scanned - generating unified DAST report...")
                self._create_dast_session_manifest(target_urls, scan_results)
            
            self._offer_scan_report_generation("DAST")
            print("📋 Check the scan results for detailed vulnerability information and AI recommendations")
        else:
            print("\n All DAST scans failed")
            print("💡 Common DAST issues:")
            print("   - Target URLs are not accessible")
            print("   - Network connectivity issues")
            print("   - ZAP installation issues")
            print("   - Configuration problems")
        
        input("\nPress Enter to continue...")
    
    def _create_dast_session_manifest(self, target_urls, scan_results):
        """Create a manifest file for multi-URL DAST scan session."""
        try:
            import json
            from datetime import datetime
            
            base_dir = get_base_directory()
            output_dir = base_dir / "AppSecAI_output"
            manifest_path = output_dir / "dast_scan_session.json"
            
            # Get only successful URLs
            successful_urls = [
                result['url'] for result in scan_results 
                if result['status'] in ['success', 'success_with_vulns']
            ]
            
            manifest = {
                "session_timestamp": datetime.now().isoformat(),
                "total_urls": len(target_urls),
                "successful_urls": successful_urls,
                "scan_results": scan_results
            }
            
            with open(manifest_path, 'w', encoding='utf-8') as f:
                json.dump(manifest, f, indent=2)
            
            print(f"📝 Created scan session manifest: {manifest_path.name}")
            
        except Exception as e:
            print(f"⚠️  Warning: Could not create session manifest: {e}")
    
    def _run_combined_scan(self):
        """Run combined SAST + DAST scan with automatic report generation."""
        print("\n🔄 Combined SAST + DAST Security Scan")
        print("=" * 50)
        
        print("📋 This will perform a comprehensive security assessment:")
        print("   • SAST: Static code analysis via SonarQube")
        print("   • DAST: Dynamic application testing via ZAP")
        print("   • Automatic combined security posture report")
        print()
        
        # Get scan targets
        print("🎯 Scan Configuration:")
        
        # SAST target (repository)
        current_repo = self.current_settings.get('github_repo', '')
        if current_repo:
            sast_target = self._parse_input(f"SAST Repository (current: {current_repo}) or press Enter: ")
            if sast_target is None:  # cd command was handled
                return
            sast_target = sast_target.strip()
            if not sast_target:
                sast_target = f"https://github.com/{current_repo}.git"
        else:
            sast_target = self._parse_input("SAST Repository URL: ")
            if sast_target is None:  # cd command was handled
                return
            sast_target = sast_target.strip()
            if not sast_target:
                print(" SAST repository URL is required")
                input("Press Enter to continue...")
                return
        
        # DAST target (application URL)
        current_dast = os.environ.get('DAST_URL', 'https://www.saucedemo.com')
        dast_target = self._parse_input(f"DAST Application URL (current: {current_dast}) or press Enter: ")
        if dast_target is None:  # cd command was handled
            return
        dast_target = dast_target.strip()
        if not dast_target:
            dast_target = current_dast
        
        print(f"\n📊 Scan Summary:")
        print(f"   SAST Target: {sast_target}")
        print(f"   DAST Target: {dast_target}")
        
        confirm = self._parse_input("\n🚀 Start combined scan? (y/N): ")
        if confirm is None:  # cd command was handled
            return
        if not confirm.lower().startswith('y'):
            print(" Scan cancelled")
            input("Press Enter to continue...")
            return
        
        print(f"\n🔄 Starting combined security scan...")
        
        try:
            import subprocess
            import sys
            from datetime import datetime
            
            scan_start_time = datetime.now()
            
            # Run SAST scan
            print(f"\n📊 Phase 1: SAST Scan (Static Analysis)")
            print("=" * 40)
            
            base_dir = get_base_directory()
            clone_dir = str(base_dir / "cloned_repos")
            
            if getattr(sys, 'frozen', False):
                # Running as EXE - use executable directly
                sast_cmd = [get_executable_path(), "scan", "--type", "sast", "--target", sast_target, "--clone-dir", clone_dir]
            else:
                # Running as Python - use module syntax
                sast_cmd = [get_executable_path(), "scan", "--type", "sast", "--target", sast_target, "--clone-dir", "cloned_repos"]
            
            # ── Pass credentials explicitly ──────────────────────────────────
            sonar_url = os.environ.get('SONAR_URL', 'http://localhost:9000')
            sonar_user = os.environ.get('SONAR_USERNAME', 'admin')
            sonar_pass = os.environ.get('SONAR_PASSWORD', '')
            github_token = os.environ.get('GITHUB_TOKEN', '')
            threshold = os.environ.get('VULNERABILITY_THRESHOLD', '2.5').strip() or '2.5'
            
            for cmd in [sast_cmd]:
                cmd.extend(['--sonar-url', sonar_url])
                cmd.extend(['--sonar-username', sonar_user])
                if sonar_pass:
                    cmd.extend(['--sonar-password', sonar_pass])
                if github_token:
                    cmd.extend(['--github-token', github_token])
                cmd.extend(['--threshold', threshold])
                
            sast_result = subprocess.run(sast_cmd, capture_output=True, text=True)
            
            if sast_result.returncode == 0:
                print("✅ SAST scan completed successfully")
            else:
                print("⚠️  SAST scan completed with issues")
                print("📋 Check the output for details")
            
            # Run DAST scan
            print(f"\n🌐 Phase 2: DAST Scan (Dynamic Analysis)")
            print("=" * 40)
            
            if getattr(sys, 'frozen', False):
                # Running as EXE - use executable directly
                dast_cmd = [get_executable_path(), "scan", "--type", "dast", "--target", dast_target, "--timeout", "180"]
            else:
                # Running as Python - use module syntax
                dast_cmd = [get_executable_path(), "scan", "--type", "dast", "--target", dast_target, "--timeout", "180"]
            
            # ── Pass credentials explicitly for DAST ──────────────────────────
            if github_token:
                dast_cmd.extend(['--github-token', github_token])
            dast_cmd.extend(['--threshold', threshold])
            
            dast_result = subprocess.run(dast_cmd, capture_output=True, text=True)
            
            if dast_result.returncode == 0:
                print("✅ DAST scan completed successfully")
            else:
                print("⚠️  DAST scan completed with issues")
                print("📋 Check the output for details")
            
            # Generate combined report
            print(f"\n🛡️  Phase 3: Security Posture Report Generation")
            print("=" * 50)
            
            # Import and use the report generator directly (works in both Python and EXE)
            from appsecai.reporting.posture_report import SecurityPostureReportGenerator
            
            print(f"🔧 Generating combined report...")
            base_dir = get_base_directory()
            generator = SecurityPostureReportGenerator(
                input_dir=str(base_dir / "AppSecAI_output"),
                output_dir=str(base_dir / "generated_reports")
            )
            
            generator.discover_and_load_data()
            generator.analyze_security_posture()
            generator.generate_pdf_report()
            generator.generate_json_report()
            
            # Check if successful
            report_success = True
            
            if report_success:
                print("✅ Combined security posture report generated successfully!")
                
                # Show scan summary
                scan_duration = datetime.now() - scan_start_time
                print(f"\n📊 Combined Scan Summary:")
                print(f"   Duration: {scan_duration.total_seconds():.1f} seconds")
                print(f"   SAST Status: {'✅ Success' if sast_result.returncode == 0 else '⚠️ Issues'}")
                print(f"   DAST Status: {'✅ Success' if dast_result.returncode == 0 else '⚠️ Issues'}")
                print(f"   Report Status: ✅ Generated")
                
                # List generated files
                from pathlib import Path
                reports_dir = Path("generated_reports")
                if reports_dir.exists():
                    latest_reports = sorted(reports_dir.glob("security_posture_report_*"))[-2:]  # Get latest PDF and JSON
                    if latest_reports:
                        print(f"\n📁 Generated Reports:")
                        for report in latest_reports:
                            print(f"   • {report}")
                
                # Ask if user wants to open reports directory
                if input("\n🔍 Open reports directory? (y/N): ").lower().startswith('y'):
                    import platform
                    
                    base_dir = get_base_directory()
                    reports_path = str(base_dir / "generated_reports")
                    if platform.system() == "Windows":
                        os.startfile(reports_path)
                    elif platform.system() == "Darwin":  # macOS
                        subprocess.run(["open", reports_path])
                    else:  # Linux
                        subprocess.run(["xdg-open", reports_path])
            else:
                print(" Report generation failed")
                print("\n💡 You can manually generate reports later from the Reports menu")
            
            print(f"\n🎉 Combined security scan completed!")
            
        except Exception as e:
            print(f" Combined scan failed: {e}")
        
        input("\nPress Enter to continue...")
    
    def _run_quick_scan(self):
        """Run quick repository scan."""
        repo = self.current_settings.get('github_repo', '')
        if not repo:
            print("\n GitHub repository not configured. Please configure it in Settings first.")
            input("Press Enter to continue...")
            return
        
        print(f"\n📊 Running Quick Scan on {repo}...")
        self._run_sast_scan()
    
    def _run_custom_scan(self):
        """Run custom target scan."""
        print("\n🎯 Custom Target Scan")
        
        scan_type = input("Scan type (sast/dast): ").strip().lower()
        if scan_type not in ['sast', 'dast']:
            print(" Invalid scan type")
            input("Press Enter to continue...")
            return
        
        target = input("Enter target (URL for DAST, repo URL for SAST): ").strip()
        if not target:
            print(" Target is required")
            input("Press Enter to continue...")
            return
        
        if getattr(sys, 'frozen', False):
            cmd_parts = [get_executable_path(), 'scan', '--type', scan_type, '--target', target]
        else:
            cmd_parts = [get_executable_path(), 'scan', '--type', scan_type, '--target', target]
        
        # ── Pass credentials explicitly ──────────────────────────────────
        sonar_url = os.environ.get('SONAR_URL', 'http://localhost:9000')
        sonar_user = os.environ.get('SONAR_USERNAME', 'admin')
        sonar_pass = os.environ.get('SONAR_PASSWORD', '')
        github_token = os.environ.get('GITHUB_TOKEN', '')
        threshold = os.environ.get('VULNERABILITY_THRESHOLD', '2.5').strip() or '2.5'
        
        if scan_type == 'sast':
            cmd_parts.extend(['--sonar-url', sonar_url])
            cmd_parts.extend(['--sonar-username', sonar_user])
            if sonar_pass:
                cmd_parts.extend(['--sonar-password', sonar_pass])
        
        if github_token:
            cmd_parts.extend(['--github-token', github_token])
        cmd_parts.extend(['--threshold', threshold])
        
        try:
            import subprocess
            result = subprocess.run(cmd_parts, capture_output=False, text=True)
            
            if result.returncode == 0:
                print(f"\n✅ {scan_type.upper()} scan completed successfully!")
            else:
                print(f"\n {scan_type.upper()} scan failed")
                
        except Exception as e:
            print(f"\n Error running scan: {e}")
        
        input("\nPress Enter to continue...")
    
    def _dast_troubleshooting(self):
        """DAST troubleshooting and diagnostics."""
        print("\n🔧 DAST Troubleshooting")
        
        # Check ZAP installation
        print("🔍 Checking OWASP ZAP installation...")
        zap_path = os.path.join(os.getcwd(), 'external', 'ZAP_2.16.1')
        
        if os.path.exists(zap_path):
            print(f"✅ ZAP found at: {zap_path}")
            
            # Check ZAP executable
            zap_jar = os.path.join(zap_path, 'zap-2.16.1.jar')
            if os.path.exists(zap_jar):
                print(f"✅ ZAP JAR found: {zap_jar}")
            else:
                print(f" ZAP JAR not found: {zap_jar}")
        else:
            print(f" ZAP not found at: {zap_path}")
            print("\n💡 To install OWASP ZAP:")
            print("1. Download ZAP from: https://www.zaproxy.org/download/")
            print("2. Extract to: external/ZAP_2.16.1/")
            print("3. Ensure zap-2.16.1.jar exists in the directory")
        
        # Check Java
        print("\n🔍 Checking Java installation...")
        try:
            import subprocess
            result = subprocess.run(['java', '-version'], capture_output=True, text=True)
            if result.returncode == 0:
                print("✅ Java is installed")
                print(f"   Version info: {result.stderr.split()[2] if result.stderr else 'Unknown'}")
            else:
                print(" Java not found or not working")
        except Exception as e:
            print(f" Java check failed: {e}")
            print("💡 DAST scanning requires Java to run OWASP ZAP")
        
        # Check network connectivity
        print("\n🔍 Testing network connectivity...")
        test_url = input("Enter URL to test (or press Enter for saucedemo.com): ").strip()
        if not test_url:
            test_url = "https://www.saucedemo.com"
        
        try:
            import requests
            response = requests.get(test_url, timeout=10)
            print(f"✅ {test_url} is accessible (HTTP {response.status_code})")
        except Exception as e:
            print(f" Cannot access {test_url}: {e}")
            print("💡 Check your internet connection and firewall settings")
        
        print("\n📋 DAST Scan Tips:")
        print("• Use simple, publicly accessible websites for testing")
        print("• Avoid sites with aggressive bot protection")
        print("• DAST scans can take 5-15 minutes for small sites")
        print("• Try SAST scanning if DAST continues to fail")
        
        input("\nPress Enter to continue...")
    
    def _run_ai_fixes_dry_run(self):
        """Run AI fixes in dry-run mode."""
        print("\n🔧 AI Fixes (Dry Run)")
        print("🚧 AI remediation feature integration coming soon...")
        input("Press Enter to continue...")
    
    def _run_ai_fixes_with_prs(self):
        """Run AI fixes with PR creation."""
        print("\n🔀 AI Fixes + Create PRs")
        print("🚧 AI remediation feature integration coming soon...")
        input("Press Enter to continue...")
    
    def _configure_remediation(self):
        """Configure remediation settings."""
        while True:
            current_batch = os.environ.get('AI_BATCH_SIZE', '5')
            current_pr_batch = os.environ.get('PR_BATCH_SIZE', '5')
            current_commit_batch = os.environ.get('COMMIT_BATCH_SIZE', '5')
            
            print(f"""
┌─────────────────────────────────────────────────────────────┐
│                 REMEDIATION SETTINGS                        │
├─────────────────────────────────────────────────────────────┤
│  1. Set AI Processing Batch Size                            │
│  2. Set PR Creation Batch Size                              │
│  3. Set Commit Batch Size                                   │
│  4. Set LLM Timeout                                         │
│  5. Set Max Retries                                         │
│  0. Back to Remediation Menu                                │
└─────────────────────────────────────────────────────────────┘

Current Settings:
  AI Batch Size: {current_batch} vulnerabilities per batch
  PR Batch Size: {current_pr_batch} vulnerabilities per PR
  Commit Batch Size: {current_commit_batch} vulnerabilities per commit
            """)
            
            choice = input(" Select an option (0-5): ").strip()
            
            if choice == '1':
                new_batch = input(f"Enter AI batch size (current: {current_batch}): ").strip()
                if new_batch.isdigit():
                    os.environ['AI_BATCH_SIZE'] = new_batch
                    print(f"✅ AI batch size set to: {new_batch}")
                    
            elif choice == '2':
                new_pr_batch = input(f"Enter PR batch size (current: {current_pr_batch}): ").strip()
                if new_pr_batch.isdigit():
                    os.environ['PR_BATCH_SIZE'] = new_pr_batch
                    print(f"✅ PR batch size set to: {new_pr_batch}")
                    
            elif choice == '3':
                new_commit_batch = input(f"Enter commit batch size (current: {current_commit_batch}): ").strip()
                if new_commit_batch.isdigit():
                    os.environ['COMMIT_BATCH_SIZE'] = new_commit_batch
                    print(f"✅ Commit batch size set to: {new_commit_batch}")
                    
            elif choice == '4':
                current_timeout = os.environ.get('LLM_TIMEOUT', '300')
                new_timeout = input(f"Enter LLM timeout in seconds (current: {current_timeout}): ").strip()
                if new_timeout.isdigit():
                    os.environ['LLM_TIMEOUT'] = new_timeout
                    print(f"✅ LLM timeout set to: {new_timeout} seconds")
                    
            elif choice == '5':
                current_retries = os.environ.get('LLM_MAX_RETRIES', '3')
                new_retries = input(f"Enter max retries (current: {current_retries}): ").strip()
                if new_retries.isdigit():
                    os.environ['LLM_MAX_RETRIES'] = new_retries
                    print(f"✅ Max retries set to: {new_retries}")
                    
            elif choice == '0':
                break
            else:
                print(" Invalid choice. Please try again.")
            
            if choice != '0':
                input("Press Enter to continue...")
    
    def _select_scan_results(self):
        """Select scan results to fix."""
        print("\n📋 Select Scan Results")
        print("🚧 Scan result selection coming soon...")
        input("Press Enter to continue...")
    
    def _sast_reports_menu(self):
        """Handle SAST reports menu."""
        self.navigation_stack.append("SAST Reports")
        
        while True:
            # Check if we should exit this menu
            if self.exit_levels > 0:
                self.exit_levels -= 1
                break
            
            self._display_breadcrumb()
            
            print("""
┌─────────────────────────────────────────────────────────────┐
│                    SAST SCAN REPORTS                        │
├─────────────────────────────────────────────────────────────┤
│  1. List Available SAST Scans                               │
│  2. Download Reports by Scan ID                             │
│  3. Download Latest SAST Reports                            │
│  4. Clean Old SAST Reports                                  │
│  0. Back to Reports Menu                                    │
└─────────────────────────────────────────────────────────────┘
            """)
            
            choice = self._parse_input("👉 Select option (0-4) or command (cd <menu>, cd/, cd ..): ")
            if choice is None:
                continue
            
            if choice == '1':
                self._list_sast_scans()
            elif choice == '2':
                self._download_sast_by_id()
            elif choice == '3':
                self._download_latest_sast()
            elif choice == '4':
                self._clean_old_sast_reports()
            elif choice == '0':
                self.navigation_stack.pop()
                break
            else:
                print(" Invalid choice. Please try again.")
    
    def _dast_reports_menu(self):
        """Handle DAST reports menu."""
        self.navigation_stack.append("DAST Reports")
        
        while True:
            # Check if we should exit this menu
            if self.exit_levels > 0:
                self.exit_levels -= 1
                break
            
            self._display_breadcrumb()
            
            print("""
┌─────────────────────────────────────────────────────────────┐
│                    DAST SCAN REPORTS                        │
├─────────────────────────────────────────────────────────────┤
│  1. List Available DAST Scans                               │
│  2. Download Reports by Scan ID                             │
│  3. Download Latest DAST Reports                            │
│  4. View AI Recommendations                                 │
│  5. Clean Old DAST Reports                                  │
│  0. Back to Reports Menu                                    │
└─────────────────────────────────────────────────────────────┘
            """)
            
            choice = self._parse_input("👉 Select option (0-6) or command (cd <menu>, cd/, cd ..): ")
            if choice is None:
                continue
            
            if choice == '1':
                self._list_dast_scans()
            elif choice == '2':
                self._download_dast_by_id()
            elif choice == '3':
                self._download_latest_dast()
            elif choice == '4':
                self._view_ai_recommendations()
            elif choice == '5':
                self._clean_old_dast_reports()
            elif choice == '0':
                self.navigation_stack.pop()
                break
            else:
                print(" Invalid choice. Please try again.")
    
    def _list_sast_scans(self):
        """List available SAST scans."""
        print("\n📋 Available SAST Scans")
        print("=" * 60)
        
        output_dir = self.current_settings.get('output_dir', 'AppSecAI_output')
        
        try:
            import os
            import glob
            from datetime import datetime
            
            # Find all SAST output directories
            pattern = os.path.join(output_dir, "*_output_*")
            scan_dirs = glob.glob(pattern)
            
            if not scan_dirs:
                print(" No SAST scans found")
                input("Press Enter to continue...")
                return
            
            # Sort by timestamp (newest first)
            scan_dirs.sort(reverse=True)
            
            print(f"{'ID':<3} {'Repository':<25} {'Date':<12} {'Time':<8} {'Files':<6}")
            print("-" * 60)
            
            for i, scan_dir in enumerate(scan_dirs[:10], 1):  # Show last 10 scans
                dir_name = os.path.basename(scan_dir)
                parts = dir_name.split('_')
                
                if len(parts) >= 3:
                    repo_name = parts[0]
                    timestamp = parts[-1]
                    
                    # Parse timestamp
                    try:
                        dt = datetime.strptime(timestamp, '%Y%m%d_%H%M%S')
                        date_str = dt.strftime('%Y-%m-%d')
                        time_str = dt.strftime('%H:%M:%S')
                    except:
                        date_str = timestamp[:8]
                        time_str = timestamp[9:] if len(timestamp) > 8 else ""
                    
                    # Count files in directory
                    file_count = len([f for f in os.listdir(scan_dir) if os.path.isfile(os.path.join(scan_dir, f))])
                    
                    print(f"{i:<3} {repo_name:<25} {date_str:<12} {time_str:<8} {file_count:<6}")
            
            print(f"\nShowing {min(len(scan_dirs), 10)} of {len(scan_dirs)} total scans")
            
        except Exception as e:
            print(f" Error listing scans: {e}")
        
        input("\nPress Enter to continue...")
    
    def _download_sast_by_id(self):
        """Download SAST reports by scan ID."""
        print("\n📥 Download SAST Reports by ID")
        print("=" * 40)
        
        # First show available scans
        self._list_sast_scans()
        
        scan_id = input("\nEnter scan ID (1-10): ").strip()
        
        if not scan_id.isdigit():
            print(" Invalid scan ID")
            input("Press Enter to continue...")
            return
        
        try:
            output_dir = self.current_settings.get('output_dir', 'AppSecAI_output')
            import os
            import glob
            import shutil
            
            # Find scan directories
            pattern = os.path.join(output_dir, "*_output_*")
            scan_dirs = sorted(glob.glob(pattern), reverse=True)
            
            scan_index = int(scan_id) - 1
            if scan_index < 0 or scan_index >= len(scan_dirs):
                print(" Invalid scan ID")
                input("Press Enter to continue...")
                return
            
            selected_scan = scan_dirs[scan_index]
            scan_name = os.path.basename(selected_scan)
            
            # Create downloads directory in user's Downloads folder
            import os
            user_downloads = os.path.join(os.path.expanduser("~"), "Downloads")
            downloads_dir = os.path.join(user_downloads, "CazeAppSecAI_Reports")
            os.makedirs(downloads_dir, exist_ok=True)
            
            # Copy available reports
            reports_copied = []
            
            # Look for specific report files
            report_files = [
                ('filtered_vulnerabilities_*.csv', 'High-Priority Issues'),
                ('hotspots_with_code_*.csv', 'Vulnerability Summary'),
                ('hotspots_with_code_*.json', 'Complete Vulnerability Data')
            ]
            
            # Also check for AI fix files in vulnerability-fixes directory
            ai_fix_dir = "vulnerability-fixes"
            if os.path.exists(ai_fix_dir):
                ai_report_files = [
                    ('fixes_*.csv', 'AI Fixes Results'),
                    ('fix_report_*.md', 'AI Fix Report')
                ]
                
                for pattern, description in ai_report_files:
                    files = glob.glob(os.path.join(ai_fix_dir, pattern))
                    for file_path in files:
                        filename = os.path.basename(file_path)
                        dest_path = os.path.join(downloads_dir, f"{scan_name}_{filename}")
                        shutil.copy2(file_path, dest_path)
                        reports_copied.append((dest_path, description))
            
            for pattern, description in report_files:
                files = glob.glob(os.path.join(selected_scan, pattern))
                for file_path in files:
                    filename = os.path.basename(file_path)
                    dest_path = os.path.join(downloads_dir, f"{scan_name}_{filename}")
                    shutil.copy2(file_path, dest_path)
                    reports_copied.append((dest_path, description))
            
            if reports_copied:
                print(f"\n✅ Downloaded {len(reports_copied)} reports to '{downloads_dir}':")
                for file_path, description in reports_copied:
                    print(f"   📄 {os.path.basename(file_path)} - {description}")
            else:
                print(" No reports found for this scan")
            
        except Exception as e:
            print(f" Error downloading reports: {e}")
        
        input("\nPress Enter to continue...")
    
    def _download_latest_sast(self):
        """Download latest SAST reports."""
        print("\n📊 Download Latest SAST Reports")
        print("=" * 35)
        
        try:
            output_dir = self.current_settings.get('output_dir', 'AppSecAI_output')
            import os
            import glob
            import shutil
            
            # Find latest scan directory
            pattern = os.path.join(output_dir, "*_output_*")
            scan_dirs = sorted(glob.glob(pattern), reverse=True)
            
            if not scan_dirs:
                print(" No SAST scans found")
                input("Press Enter to continue...")
                return
            
            latest_scan = scan_dirs[0]
            scan_name = os.path.basename(latest_scan)
            
            print(f"Latest scan: {scan_name}")
            
            # Create downloads directory in user's Downloads folder
            import os
            user_downloads = os.path.join(os.path.expanduser("~"), "Downloads")
            downloads_dir = os.path.join(user_downloads, "CazeAppSecAI_Reports")
            os.makedirs(downloads_dir, exist_ok=True)
            
            # Auto-download standard reports
            self._auto_download_sast_reports(latest_scan, downloads_dir, scan_name)
            
        except Exception as e:
            print(f" Error downloading latest reports: {e}")
        
        input("\nPress Enter to continue...")
    
    def _auto_download_sast_reports(self, scan_dir, downloads_dir, scan_name, has_ai_fixes=False):
        """Auto-download SAST reports after scan completion."""
        import os
        import glob
        import shutil
        
        reports_downloaded = []
        
        try:
            # Always download these for SAST scans
            standard_reports = [
                ('hotspots_with_code_*.csv', 'Vulnerability_Summary.csv'),
                ('filtered_vulnerabilities_*.csv', 'High_Priority_Issues.csv')
            ]
            
            for pattern, output_name in standard_reports:
                files = glob.glob(os.path.join(scan_dir, pattern))
                if files:
                    source_file = files[0]  # Take the first match
                    dest_file = os.path.join(downloads_dir, f"{scan_name}_{output_name}")
                    shutil.copy2(source_file, dest_file)
                    reports_downloaded.append(dest_file)
            
            # If AI fixes were generated, also download AI recommendations
            if has_ai_fixes:
                # Look for AI fix files in the vulnerability-fixes directory
                ai_fix_dir = "vulnerability-fixes"
                if os.path.exists(ai_fix_dir):
                    ai_patterns = [
                        ('fixes_*.csv', 'AI_Fixes_Results.csv'),
                        ('fix_report_*.md', 'AI_Fix_Report.md')
                    ]
                    
                    for pattern, output_name in ai_patterns:
                        files = glob.glob(os.path.join(ai_fix_dir, pattern))
                        if files:
                            # Get the most recent file
                            source_file = max(files, key=os.path.getmtime)
                            dest_file = os.path.join(downloads_dir, f"{scan_name}_{output_name}")
                            shutil.copy2(source_file, dest_file)
                            reports_downloaded.append(dest_file)
            
            if reports_downloaded:
                print(f"\n📥 Auto-downloaded {len(reports_downloaded)} reports to '{downloads_dir}':")
                for report in reports_downloaded:
                    print(f"   📄 {os.path.basename(report)}")
            
        except Exception as e:
            print(f"⚠️  Error auto-downloading reports: {e}")
        
        return reports_downloaded
    
    def _list_dast_scans(self):
        """List available DAST scans."""
        print("\n📋 Available DAST Scans")
        print("=" * 60)
        
        try:
            import os
            import glob
            from datetime import datetime
            
            # Find ZAP reports
            zap_reports_dir = "zap_reports"
            if not os.path.exists(zap_reports_dir):
                print(" No DAST scans found")
                input("Press Enter to continue...")
                return
            
            # Find HTML and JSON reports
            html_reports = glob.glob(os.path.join(zap_reports_dir, "*.html"))
            json_reports = glob.glob(os.path.join(zap_reports_dir, "*.json"))
            
            all_reports = html_reports + json_reports
            
            if not all_reports:
                print(" No DAST reports found")
                input("Press Enter to continue...")
                return
            
            # Sort by modification time (newest first)
            all_reports.sort(key=lambda x: os.path.getmtime(x), reverse=True)
            
            print(f"{'ID':<3} {'Report Name':<40} {'Type':<6} {'Size':<8}")
            print("-" * 60)
            
            for i, report_path in enumerate(all_reports[:10], 1):
                filename = os.path.basename(report_path)
                file_type = filename.split('.')[-1].upper()
                file_size = os.path.getsize(report_path)
                size_str = f"{file_size // 1024}KB" if file_size > 1024 else f"{file_size}B"
                
                print(f"{i:<3} {filename:<40} {file_type:<6} {size_str:<8}")
            
            print(f"\nShowing {min(len(all_reports), 10)} of {len(all_reports)} total reports")
            
        except Exception as e:
            print(f" Error listing DAST scans: {e}")
        
        input("\nPress Enter to continue...")
    
    def _download_dast_by_id(self):
        """Download DAST reports by scan ID."""
        print("\n📥 Download DAST Reports by ID")
        print("=" * 40)
        
        # First show available scans
        self._list_dast_scans()
        
        scan_id = input("\nEnter report ID (1-10): ").strip()
        
        if not scan_id.isdigit():
            print(" Invalid report ID")
            input("Press Enter to continue...")
            return
        
        try:
            import os
            import glob
            import shutil
            
            # Find ZAP reports
            zap_reports_dir = "zap_reports"
            html_reports = glob.glob(os.path.join(zap_reports_dir, "*.html"))
            json_reports = glob.glob(os.path.join(zap_reports_dir, "*.json"))
            all_reports = sorted(html_reports + json_reports, key=lambda x: os.path.getmtime(x), reverse=True)
            
            report_index = int(scan_id) - 1
            if report_index < 0 or report_index >= len(all_reports):
                print(" Invalid report ID")
                input("Press Enter to continue...")
                return
            
            selected_report = all_reports[report_index]
            
            # Create downloads directory in user's Downloads folder
            import os
            user_downloads = os.path.join(os.path.expanduser("~"), "Downloads")
            downloads_dir = os.path.join(user_downloads, "Caze AppSecAI_Reports")
            os.makedirs(downloads_dir, exist_ok=True)
            
            # Copy report
            filename = os.path.basename(selected_report)
            dest_path = os.path.join(downloads_dir, filename)
            shutil.copy2(selected_report, dest_path)
            
            print(f"\n✅ Downloaded DAST report:")
            print(f"   📄 {filename}")
            print(f"   📁 Location: {dest_path}")
            
        except Exception as e:
            print(f" Error downloading report: {e}")
        
        input("\nPress Enter to continue...")
    
    def _download_latest_dast(self):
        """Download latest DAST reports."""
        print("\n📊 Download Latest DAST Reports")
        print("=" * 35)
        
        try:
            import os
            import glob
            import shutil
            
            # Find latest DAST reports
            zap_reports_dir = "zap_reports"
            if not os.path.exists(zap_reports_dir):
                print(" No DAST reports found")
                input("Press Enter to continue...")
                return
            
            html_reports = glob.glob(os.path.join(zap_reports_dir, "*.html"))
            json_reports = glob.glob(os.path.join(zap_reports_dir, "*.json"))
            
            if not html_reports and not json_reports:
                print(" No DAST reports found")
                input("Press Enter to continue...")
                return
            
            # Create downloads directory in user's Downloads folder
            import os
            user_downloads = os.path.join(os.path.expanduser("~"), "Downloads")
            downloads_dir = os.path.join(user_downloads, "CazeAppSecAI_Reports")
            os.makedirs(downloads_dir, exist_ok=True)
            
            reports_downloaded = []
            
            # Download latest HTML report
            if html_reports:
                latest_html = max(html_reports, key=os.path.getmtime)
                filename = os.path.basename(latest_html)
                dest_path = os.path.join(downloads_dir, filename)
                shutil.copy2(latest_html, dest_path)
                reports_downloaded.append(filename)
            
            # Download latest JSON report
            if json_reports:
                latest_json = max(json_reports, key=os.path.getmtime)
                filename = os.path.basename(latest_json)
                dest_path = os.path.join(downloads_dir, filename)
                shutil.copy2(latest_json, dest_path)
                reports_downloaded.append(filename)
            
            if reports_downloaded:
                print(f"\n✅ Downloaded {len(reports_downloaded)} latest DAST reports:")
                for report in reports_downloaded:
                    print(f"   📄 {report}")
            
        except Exception as e:
            print(f" Error downloading latest DAST reports: {e}")
        
        input("\nPress Enter to continue...")
    
    def _clean_old_sast_reports(self):
        """Clean old SAST reports."""
        print("\n🗑️  Clean Old SAST Reports")
        print("=" * 30)
        
        days = input("Delete reports older than how many days? (default: 30): ").strip()
        if not days:
            days = "30"
        
        if not days.isdigit():
            print(" Invalid number of days")
            input("Press Enter to continue...")
            return
        
        try:
            import os
            import glob
            import time
            
            days_int = int(days)
            cutoff_time = time.time() - (days_int * 24 * 60 * 60)
            
            output_dir = self.current_settings.get('output_dir', 'AppSecAI_output')
            pattern = os.path.join(output_dir, "*_output_*")
            scan_dirs = glob.glob(pattern)
            
            deleted_count = 0
            for scan_dir in scan_dirs:
                if os.path.getmtime(scan_dir) < cutoff_time:
                    import shutil
                    shutil.rmtree(scan_dir)
                    deleted_count += 1
                    print(f"🗑️  Deleted: {os.path.basename(scan_dir)}")
            
            if deleted_count == 0:
                print(f"✅ No reports older than {days} days found")
            else:
                print(f"\n✅ Deleted {deleted_count} old SAST reports")
            
        except Exception as e:
            print(f" Error cleaning reports: {e}")
        
        input("\nPress Enter to continue...")
    
    def _view_ai_recommendations(self):
        """View AI recommendations from latest DAST scan."""
        print("\n🤖 AI Vulnerability Recommendations")
        print("=" * 40)
        
        try:
            # Find latest ZAP report with AI recommendations
            zap_reports_dir = "zap_reports"
            if not os.path.exists(zap_reports_dir):
                print(" No DAST reports found")
                input("Press Enter to continue...")
                return
            
            # Look for the most recent scan directory
            scan_dirs = [d for d in os.listdir(zap_reports_dir) if os.path.isdir(os.path.join(zap_reports_dir, d))]
            if not scan_dirs:
                print(" No DAST scan directories found")
                input("Press Enter to continue...")
                return
            
            # Sort by modification time to get the latest
            scan_dirs.sort(key=lambda x: os.path.getmtime(os.path.join(zap_reports_dir, x)), reverse=True)
            latest_scan_dir = os.path.join(zap_reports_dir, scan_dirs[0])
            
            # Look for AI recommendations file (JSON format)
            recommendations_file = None
            for file in os.listdir(latest_scan_dir):
                if 'recommendations' in file.lower() and file.endswith('.json'):
                    recommendations_file = os.path.join(latest_scan_dir, file)
                    break
            
            if not recommendations_file:
                print(" No AI recommendations found in latest scan")
                print("💡 AI recommendations are generated during DAST scans")
                print("💡 Run a new DAST scan to generate recommendations")
                input("Press Enter to continue...")
                return
            
            # Load and display recommendations
            import json
            with open(recommendations_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            recommendations = data.get('recommendations', [])
            if not recommendations:
                print(" No recommendations found in file")
                input("Press Enter to continue...")
                return
            
            print(f"📊 Found {len(recommendations)} AI-generated recommendations")
            print(f"📁 From scan: {scan_dirs[0]}")
            print()
            
            # Display top 5 recommendations
            for i, rec in enumerate(recommendations[:5], 1):
                vuln = rec.get('vulnerability', {})
                recommendation = rec.get('recommendation', 'No recommendation available')
                
                print(f"🔍 Recommendation {i}:")
                print(f"   Title: {vuln.get('name', 'Unknown')}")
                print(f"   Risk: {vuln.get('risk', 'Unknown')}")
                print(f"   Score: {vuln.get('score', 'N/A')}")
                print(f"   🤖 AI Recommendation:")
                print(f"      {recommendation[:200]}{'...' if len(recommendation) > 200 else ''}")
                print()
            
            if len(recommendations) > 5:
                print(f"... and {len(recommendations) - 5} more recommendations")
                print("💡 Download the full report for complete details")
            
        except Exception as e:
            print(f" Error viewing AI recommendations: {e}")
        
        input("\nPress Enter to continue...")
    
    def _clean_old_dast_reports(self):
        """Clean old DAST reports."""
        print("\n🗑️  Clean Old DAST Reports")
        print("=" * 30)
        
        days = input("Delete reports older than how many days? (default: 30): ").strip()
        if not days:
            days = "30"
        
        if not days.isdigit():
            print(" Invalid number of days")
            input("Press Enter to continue...")
            return
        
        try:
            import os
            import glob
            import time
            
            days_int = int(days)
            cutoff_time = time.time() - (days_int * 24 * 60 * 60)
            
            zap_reports_dir = "zap_reports"
            if not os.path.exists(zap_reports_dir):
                print("✅ No DAST reports directory found")
                input("Press Enter to continue...")
                return
            
            all_files = glob.glob(os.path.join(zap_reports_dir, "*"))
            
            deleted_count = 0
            for file_path in all_files:
                if os.path.getmtime(file_path) < cutoff_time:
                    os.remove(file_path)
                    deleted_count += 1
                    print(f"🗑️  Deleted: {os.path.basename(file_path)}")
            
            if deleted_count == 0:
                print(f"✅ No reports older than {days} days found")
            else:
                print(f"\n✅ Deleted {deleted_count} old DAST reports")
            
        except Exception as e:
            print(f" Error cleaning reports: {e}")
        
        input("\nPress Enter to continue...")
    
    def _generate_security_posture_report(self):
        """Generate security posture report based on available data."""
        print("\n🛡️  Security Posture Report Generator")
        print("=" * 50)
        
        print("📋 This will generate a security assessment report including:")
        print("   • Executive summary with risk assessment")
        print("   • Vulnerability analysis and trends")
        print("   • Security controls evaluation")
        print("   • Prioritized remediation recommendations")
        print("   • Professional PDF and JSON formats")
        print("   • Report type will be determined by available scan data")
        print()
        
        # Check for available data
        import os
        from pathlib import Path
        # Use get_base_directory() to work correctly in both CLI and EXE versions
        base_dir = get_base_directory()
        cazelabs_dir = base_dir / "AppSecAI_output"
        if not cazelabs_dir.exists():
            print(f" No scan data found in {cazelabs_dir}")
            print("💡 Please run SAST or DAST scans first to generate data")
            input("Press Enter to continue...")
            return
        
        # Check for scan results - search recursively in subdirectories
        zap_files = list(Path(cazelabs_dir).glob("**/security_recommendations*.json"))
        sonar_files = list(Path(cazelabs_dir).glob("**/sonarqube_*.csv")) + \
                     list(Path(cazelabs_dir).glob("**/sonarqube_*.json")) + \
                     list(Path(cazelabs_dir).glob("**/filtered_vulnerabilities_*.csv")) + \
                     list(Path(cazelabs_dir).glob("**/filtered_vulnerabilities_*.json"))
        
        if not zap_files and not sonar_files:
            print(" No scan results found")
            print("💡 Please run security scans first:")
            print("   • DAST scan for web application vulnerabilities")
            print("   • SAST scan for source code vulnerabilities")
            input("Press Enter to continue...")
            return
        
        print(f"📊 Found scan data:")
        if zap_files:
            print(f"   • {len(zap_files)} ZAP/DAST scan results")
        if sonar_files:
            print(f"   • {len(sonar_files)} SonarQube/SAST scan results")
        print()
        
        # Format selection
        print("📄 Select report format:")
        print("   1. PDF only (recommended)")
        print("   2. JSON only")
        print("   3. Both PDF and JSON")
        
        format_choice = input("👉 Select format (1-3): ").strip()
        
        format_map = {'1': 'pdf', '2': 'json', '3': 'both'}
        report_format = format_map.get(format_choice, 'pdf')
        
        # Report type selection
        print("\n📊 Select report focus:")
        print("   1. Auto-detect (recommended)")
        print("   2. SAST-focused (Static Analysis only)")
        print("   3. DAST-focused (Dynamic Analysis only)")
        # print("   4. Unified (SAST + DAST combined)")
        
        type_choice = input("👉 Select report focus (1-3, Default: 1): ").strip()
        
        type_map = {
            '1': 'auto',
            '2': 'sast_only',
            '3': 'dast_only',
            '4': 'unified'
        }
        force_report_type = type_map.get(type_choice, 'auto')
        
        print(f"\n🔄 Generating {report_format.upper()} security posture report ({force_report_type})...")
        
        try:
            # Import and use the report generator directly (works in both Python and EXE)
            from appsecai.reporting.posture_report import SecurityPostureReportGenerator
            
            base_dir = get_base_directory()
            generator = SecurityPostureReportGenerator(
                input_dir=str(base_dir / "AppSecAI_output"),
                output_dir=str(base_dir / "generated_reports"),
                force_report_type=force_report_type
            )
            
            generator.discover_and_load_data()
            generator.analyze_security_posture()
            
            # Generate reports based on format selection
            if report_format == "pdf":
                generator.generate_pdf_report()
            elif report_format == "json":
                generator.generate_json_report()
            else:  # both
                generator.generate_pdf_report()
                generator.generate_json_report()
            
            # Check if successful
            success = True
            
            if success:
                print("✅ Security posture report generated successfully!")
                print("\n📁 Generated files:")
                
                # List generated files
                reports_dir = Path("generated_reports")
                if reports_dir.exists():
                    for file in sorted(reports_dir.glob("security_posture_report_*")):
                        print(f"   • {file}")
                
                print(f"\n💡 Reports saved in: generated_reports/")
                
                # Ask if user wants to open the directory
                if input("\n🔍 Open reports directory? (y/N): ").lower().startswith('y'):
                    import platform
                    
                    base_dir = get_base_directory()
                    reports_path = str(base_dir / "generated_reports")
                    if platform.system() == "Windows":
                        os.startfile(reports_path)
                    elif platform.system() == "Darwin":  # macOS
                        subprocess.run(["open", reports_path])
                    else:  # Linux
                        subprocess.run(["xdg-open", reports_path])
                        
            else:
                print(" Report generation failed.")
                
        except Exception as e:
            print(f" Error generating report: {e}")
        
        input("\nPress Enter to continue...")

    def _offer_scan_report_generation(self, scan_type: str):
        """Offer to generate security report after scan completion."""
        print(f"\n📊 {scan_type} Scan Report Generation")
        print("=" * 40)
        
        # Check what data is available for the specific scan type
        from pathlib import Path
        # Use get_base_directory() to work correctly in both CLI and EXE versions
        base_dir = get_base_directory()
        cazelabs_dir = base_dir / "AppSecAI_output"
        
        if scan_type == "SAST":
            # Search recursively for SAST data files (they may be in subdirectories)
            has_data = False
            if cazelabs_dir.exists():
                # Check for both sonarqube and filtered_vulnerabilities files
                sast_files = list(cazelabs_dir.glob("**/sonarqube_*.csv")) + \
                            list(cazelabs_dir.glob("**/sonarqube_*.json")) + \
                            list(cazelabs_dir.glob("**/filtered_vulnerabilities_*.csv")) + \
                            list(cazelabs_dir.glob("**/filtered_vulnerabilities_*.json"))
                has_data = bool(sast_files)
                if has_data:
                    print(f"✅ Found SAST data: {len(sast_files)} files")
            report_type = "SAST-focused"
        elif scan_type == "DAST":
            # Search recursively for DAST data files (they may be in subdirectories)
            has_data = False
            if cazelabs_dir.exists():
                # Check for JSON files (primary format)
                json_files = list(cazelabs_dir.glob("**/security_recommendations*.json"))
                # Check for CSV files (fallback format)
                csv_files = list(cazelabs_dir.glob("**/security_recommendations*.csv"))
                has_data = bool(json_files or csv_files)
                if has_data:
                    print(f"✅ Found DAST data: {len(json_files)} JSON files, {len(csv_files)} CSV files")
            report_type = "DAST-focused"
        else:
            print("⚠️  Unknown scan type")
            return
        
        if has_data:
            print(f"📋 {scan_type} scan data detected.")
            if input(f"Generate {report_type} security report? (y/N): ").lower().startswith('y'):
                self._generate_individual_report(scan_type)
            else:
                print("ℹ️  Report generation skipped")
            
            # Check if both SAST and DAST data are available for unified report
            self._check_and_offer_unified_report(scan_type, cazelabs_dir)
        else:
            print(f"⚠️  No {scan_type} scan data found for report generation")
    
    def _check_and_offer_unified_report(self, current_scan_type: str, cazelabs_dir):
        """Check if both SAST and DAST data exist and offer unified report generation."""
        try:
            # Check for SAST data
            sast_files = list(cazelabs_dir.glob("**/sonarqube_*.csv")) + \
                        list(cazelabs_dir.glob("**/sonarqube_*.json")) + \
                        list(cazelabs_dir.glob("**/filtered_vulnerabilities_*.csv")) + \
                        list(cazelabs_dir.glob("**/filtered_vulnerabilities_*.json"))
            has_sast = bool(sast_files)
            
            # Check for DAST data
            dast_files = list(cazelabs_dir.glob("**/security_recommendations*.json")) + \
                        list(cazelabs_dir.glob("**/security_recommendations*.csv"))
            has_dast = bool(dast_files)
            
            # Only offer unified report if both types exist
            if False and has_sast and has_dast:  # Unified report hidden as per user request
                print(f"\n🔄 Unified Report Available")
                print("=" * 40)
                print("✅ Both SAST and DAST scan data detected!")
                print("📊 You can generate a unified report combining both scan types.")
                
                if input("Generate unified SAST + DAST report? (y/N): ").lower().startswith('y'):
                    self._generate_unified_report()
        except Exception as e:
            # Silently fail - this is just an offer, not critical
            pass
    
    def _generate_unified_report(self):
        """Generate unified SAST + DAST security report."""
        print(f"\n🔄 Generating Unified SAST + DAST Security Report...")
        print(f"📋 This report will combine findings from both scan types")
        
        try:
            from pathlib import Path
            
            # Get the correct base directory
            base_dir = get_base_directory()
            cazelabs_path = base_dir / "AppSecAI_output"
            
            # Verify both data types exist
            sast_files = list(cazelabs_path.glob("**/sonarqube_*.csv")) + \
                         list(cazelabs_path.glob("**/sonarqube_*.json")) + \
                         list(cazelabs_path.glob("**/filtered_vulnerabilities_*.csv")) + \
                         list(cazelabs_path.glob("**/filtered_vulnerabilities_*.json"))
            
            dast_files = list(cazelabs_path.glob("**/security_recommendations*.json")) + \
                         list(cazelabs_path.glob("**/security_recommendations*.csv"))
            
            if not sast_files:
                print(f" No SAST scan data found")
                input("Press Enter to continue...")
                return
            
            if not dast_files:
                print(f" No DAST scan data found")
                input("Press Enter to continue...")
                return
            
            print(f"✅ Found {len(sast_files)} SAST data files")
            print(f"✅ Found {len(dast_files)} DAST data files")
            
            # Import and use the report generator directly
            from appsecai.reporting.posture_report import SecurityPostureReportGenerator
            
            print("🎯 Generating unified report (SAST + DAST)")
            
            # Generate unified report - use "unified" as force_report_type
            base_dir = get_base_directory()
            generator = SecurityPostureReportGenerator(
                input_dir=str(base_dir / "AppSecAI_output"),
                output_dir=str(base_dir / "generated_reports"),
                force_report_type="unified"  # New unified report type
            )
            
            generator.discover_and_load_data()
            generator.analyze_security_posture()
            generator.generate_pdf_report()
            
            print(f"✅ Unified security report generated successfully!")
            
            # Show generated files
            reports_dir = base_dir / "generated_reports"
            if reports_dir.exists():
                latest_reports = sorted(reports_dir.glob("security_posture_report_*"))[-1:]
                if latest_reports:
                    print(f"📁 Generated Report: {latest_reports[0]}")
            
            # Ask to open
            if input("🔍 Open report? (y/N): ").lower().startswith('y'):
                self._open_reports_directory()
                
        except Exception as e:
            print(f" Unified report generation error: {e}")
            import traceback
            traceback.print_exc()
        
        input("\nPress Enter to continue...")
    
    def _generate_individual_report(self, scan_type: str):
        """Generate individual SAST or DAST focused report."""
        print(f"\n🔄 Generating {scan_type}-Only Security Report...")
        print(f"📋 This report will contain only {scan_type} findings and analysis")
        
        try:
            import subprocess
            import sys
            from pathlib import Path
            
            # Check if data exists before generating report
            # Get the correct base directory
            base_dir = get_base_directory()
            cazelabs_path = base_dir / "AppSecAI_output"
            
            if scan_type == "SAST":
                # Search recursively for SAST data files (they may be in subdirectories)
                sast_files = list(cazelabs_path.glob("**/sonarqube_*.csv")) + \
                             list(cazelabs_path.glob("**/sonarqube_*.json")) + \
                             list(cazelabs_path.glob("**/filtered_vulnerabilities_*.csv")) + \
                             list(cazelabs_path.glob("**/filtered_vulnerabilities_*.json"))
                if not sast_files:
                    print(f" No SAST scan data found in {cazelabs_path}/")
                    print("💡 Run a SAST scan first before generating reports")
                    input("Press Enter to continue...")
                    return
                else:
                    print(f"✅ Found {len(sast_files)} SAST data files")
                    for f in sast_files[:3]:  # Show first 3 files
                        print(f"   📄 {f.name}")
            elif scan_type == "DAST":
                # Search recursively for DAST data files (they may be in subdirectories)
                dast_files = list(cazelabs_path.glob("**/security_recommendations*.json")) + \
                             list(cazelabs_path.glob("**/security_recommendations*.csv"))
                if not dast_files:
                    print(f" No DAST scan data found in {cazelabs_path}/")
                    print(f"🔍 Searched in: {cazelabs_path}")
                    print("💡 Run a DAST scan first before generating reports")
                    input("Press Enter to continue...")
                    return
                else:
                    print(f"✅ Found {len(dast_files)} DAST data files")
                    for f in dast_files[:3]:  # Show first 3 files
                        print(f"   📄 {f.name}")
            
            # Import and use the report generator directly (works in both Python and EXE)
            from appsecai.reporting.posture_report import SecurityPostureReportGenerator
            
            # Determine report type
            if scan_type == "DAST":
                force_report_type = "dast_only"
                print("🎯 Generating DAST-focused report (Dynamic Application Security Testing)")
            elif scan_type == "SAST":
                force_report_type = "sast_only"
                print("🎯 Generating SAST-focused report (Static Application Security Testing)")
            else:
                force_report_type = None
                print("🎯 Generating auto-detected report type")
            
            # Generate report with absolute paths
            base_dir = get_base_directory()
            generator = SecurityPostureReportGenerator(
                input_dir=str(base_dir / "AppSecAI_output"),
                output_dir=str(base_dir / "generated_reports"),
                force_report_type=force_report_type
            )
            
            generator.discover_and_load_data()
            generator.analyze_security_posture()
            generator.generate_pdf_report()
            
            # Check if successful
            success = True
            
            if success:
                print(f"✅ {scan_type} security report generated successfully!")
                
                # Show generated files - use get_base_directory() for both CLI and EXE
                base_dir = get_base_directory()
                reports_dir = base_dir / "generated_reports"
                if reports_dir.exists():
                    latest_reports = sorted(reports_dir.glob("security_posture_report_*"))[-1:]
                    if latest_reports:
                        print(f"📁 Generated Report: {latest_reports[0]}")
                
                # Ask to open
                if input("🔍 Open report? (y/N): ").lower().startswith('y'):
                    self._open_reports_directory()
            else:
                print(f" {scan_type} report generation failed")
                print("\n💡 You can generate reports manually from the Reports menu")
                print("💡 Try running: python generate_security_posture_report.py --report-type sast_only")
                
        except Exception as e:
            print(f" Report generation error: {e}")
            import traceback
            traceback.print_exc()
        
        input("\nPress Enter to continue...")
    

    
    def _open_reports_directory(self):
        """Open the reports directory in file explorer."""
        try:
            import subprocess
            import platform
            
            # Get the correct reports path using get_base_directory
            # This handles both CLI (current dir) and EXE (CazeAppSecReport folder) correctly
            base_dir = get_base_directory()
            reports_path = str(base_dir / "generated_reports")
            
            # Create directory if it doesn't exist
            Path(reports_path).mkdir(parents=True, exist_ok=True)
            
            if platform.system() == "Windows":
                os.startfile(reports_path)
            elif platform.system() == "Darwin":  # macOS
                subprocess.run(["open", reports_path])
            else:  # Linux
                subprocess.run(["xdg-open", reports_path])
        except Exception as e:
            print(f"⚠️  Could not open directory: {e}")

    def _vulnerability_trends(self):
        """Show vulnerability trends."""
        print("\n📈 Vulnerability Trends")
        print("🚧 Trends analysis coming soon...")
        input("Press Enter to continue...")
    
    def _scan_history_overview(self):
        """Show scan history overview."""
        print("\n🔍 Scan History Overview")
        print("🚧 History overview coming soon...")
        input("Press Enter to continue...")
    
    def _view_scan_history(self):
        """View scan history."""
        print("\n📋 Scan History")
        
        if not self.scan_results:
            print("No scan results available.")
        else:
            for i, result in enumerate(self.scan_results, 1):
                print(f"{i}. {result['type']} - {result['target']} - {result['status']}")
        
        input("\nPress Enter to continue...")

    def _configure_deployment_settings(self):
        """Configure deployment settings in appsecai/risk_profiles/context_modifiers/risk_context_template.json."""
        self.navigation_stack.append("Deployment Settings")
        
        while True:
            # Check if we should exit this menu
            if self.exit_levels > 0:
                self.exit_levels -= 1
                break
            
            self._display_breadcrumb()
            
            print("""
┌──────────────────────────────────────────────────────────────────────┐
│                  CONFIGURE DEPLOYMENT SETTINGS                       │
├──────────────────────────────────────────────────────────────────────┤
│  Options (type command or use cd):                                   │
│                                                                      │
│  1. product and version  - App name & version                        │
│     (cd product)                                                     │
│                                                                      │
│  2. environment          - Deployment type, General compliance       │
│     (cd env)                                                         │
│                                                                      │
│  3. runtime              - Container, monitoring & resource limits   │
│     (cd runtime)                                                     │
│                                                                      │
│  4. service              - Service auth & rate limiting              │
│     (cd service)                                                     │
│                                                                      │
│  5. security controls    - Security features (RBAC, WAF, MFA, etc.)  │
│     (cd security,cd controls)                                        │
│                                                                      │
│  0. back or cd/..        - Return to Settings Menu                   │ 
└──────────────────────────────────────────────────────────────────────┘
            """)
            
            choice = self._parse_input("👉 Select option (0-6), command, or cd navigation: ")
            if choice is None:
                continue
            
            # Handle numeric options
            if choice == '1' or choice == 'product and version' or choice == 'product':
                self._configure_product_version()
            elif choice == '2' or choice == 'environment' or choice == 'env':
                self._configure_environment()
            elif choice == '3' or choice == 'runtime' or choice == 'container':
                self._configure_runtime()
            elif choice == '4' or choice == 'service':
                self._configure_service()
            elif choice == '5' or choice == 'security controls' or choice == 'security' or choice == 'controls':
                self._configure_security_controls_new()
            elif choice == '0' or choice == 'back':
                self.navigation_stack.pop()
                break
            else:
                print("❌ Invalid choice. Please try again.")
                print("💡 Available: 1-5, product, environment, runtime, service, security controls, back")
    
    def _configure_product_version(self):
        """Configure product name and version."""
        self.navigation_stack.append("Product and Version")
        
        while True:
            # Check if we should exit this menu
            if self.exit_levels > 0:
                self.exit_levels -= 1
                break
            
            self._display_breadcrumb()
            
            print("\n" + "="*60)
            print("PRODUCT AND VERSION CONFIGURATION")
            print("="*60)
            
            # Load current settings
            config = self._load_compliance_config()
            current_product = config.get('AppSecAI', {}).get('product', 'Not Set')
            current_version = config.get('AppSecAI', {}).get('version', 'Not Set')
            
            print(f"\nCurrent Product: {current_product}")
            print(f"Current Version: {current_version}")
            
            # Get new values
            print("\nEnter new values (or press Enter to keep current, or '0' to go back):")
            product = input("Product name: ").strip()
            
            # Check for back command
            if product == '0':
                self.navigation_stack.pop()
                break
            
            if product:
                config['AppSecAI']['product'] = product
                print(f"✅ Product updated to: {product}")
            
            version = input("Version: ").strip()
            
            # Check for back command
            if version == '0':
                self.navigation_stack.pop()
                break
            
            if version:
                config['AppSecAI']['version'] = version
                print(f"✅ Version updated to: {version}")
            
            if product or version:
                self._save_compliance_config(config)
                print("\n✅ Changes saved to appsecai/risk_profiles/context_modifiers/risk_context_template.json")
            
            choice = input("\nPress Enter to go back or any key to reconfigure: ").strip()
            # Always go back after configuration
            self.navigation_stack.pop()
            break
    
    def _configure_environment(self):
        """Configure environment deployment settings."""
        self.navigation_stack.append("Environment")
        
        while True:
            # Check if we should exit this menu
            if self.exit_levels > 0:
                self.exit_levels -= 1
                break
            
            self._display_breadcrumb()
            
            print("\n" + "="*60)
            print("ENVIRONMENT CONFIGURATION")
            print("="*60)
            
            config = self._load_compliance_config()
            env = config.get('AppSecAI', {}).get('environment', {})
            
            # Display current settings
            print("\nCurrent Environment Settings:")
            print(f"  deployment_type:                    {env.get('deployment_type', 'Not Set')}")
            print(f"  internet_exposure:                  {str(env.get('internet_exposure', False)).lower()}")
            print(f"  api_type:                           {env.get('api_type', 'Not Set')}")
            print(f"  https_enabled:                      {str(env.get('https_enabled', False)).lower()}")
            print(f"  data_classification:                {env.get('data_classification', 'Not Set')}")
            print(f"  pii_present:                        {str(env.get('pii_present', False)).lower()}")
            print(f"  logging_audit_required:             {str(env.get('logging_audit_required', False)).lower()}")
            print(f"  encryption_in_transit_required:     {str(env.get('encryption_in_transit_required', False)).lower()}")
            print(f"  encryption_at_rest_required:        {str(env.get('encryption_at_rest_required', False)).lower()}")
            print(f"  system_criticality:                 {env.get('system_criticality', 'Not Set')}")
            
            # Configure each setting
            print("\nConfigure Settings:")
            print("For boolean values, type 'true' or 'false'")
            print("For text values, type the value directly")
            print("Press Enter to skip and keep current value")
            print()
            
            # Deployment Type
            while True:
                value = input("  deployment_type (public/Internal_only): ").strip().lower()
                if not value:
                    break  # Skip if empty
                if value in ['public', 'internal_only']:
                    env['deployment_type'] = value
                    break
                else:
                    print("  ❌ Invalid value! Please enter 'public' or 'Internal_only'")
                    continue
            
            # Internet Exposure
            while True:
                value = input("  internet_exposure (true/false): ").strip().lower()
                if not value:
                    break
                if value in ['true', 'false']:
                    env['internet_exposure'] = (value == 'true')
                    break
                else:
                    print("  ❌ Invalid value! Please enter 'true' or 'false'")
            
            # API Type
            while True:
                value = input("  api_type (rest/graphql/soap/none): ").strip().lower()
                if not value:
                    break  # Skip if empty
                if value in ['rest', 'graphql', 'soap', 'none']:
                    env['api_type'] = value
                    break
                else:
                    print("  ❌ Invalid value! Please enter 'rest', 'graphql', 'soap', or 'none'")
                    continue
            
            # HTTPS Enabled
            while True:
                value = input("  https_enabled (true/false): ").strip().lower()
                if not value:
                    break
                if value in ['true', 'false']:
                    env['https_enabled'] = (value == 'true')
                    break
                else:
                    print("  ❌ Invalid value! Please enter 'true' or 'false'")
            
            # Data Classification
            while True:
                value = input("  data_classification (public/internal/confidential/restricted): ").strip().lower()
                if not value:
                    break  # Skip if empty
                if value in ['public', 'internal', 'confidential', 'restricted']:
                    env['data_classification'] = value
                    break
                else:
                    print("  ❌ Invalid value! Please enter 'public', 'internal', 'confidential', or 'restricted'")
                    continue
            
            # PII Present
            while True:
                value = input("  pii_present (true/false): ").strip().lower()
                if not value:
                    break
                if value in ['true', 'false']:
                    env['pii_present'] = (value == 'true')
                    break
                else:
                    print("  ❌ Invalid value! Please enter 'true' or 'false'")
            
            # Logging Audit Required
            while True:
                value = input("  logging_audit_required (true/false): ").strip().lower()
                if not value:
                    break
                if value in ['true', 'false']:
                    env['logging_audit_required'] = (value == 'true')
                    break
                else:
                    print("  ❌ Invalid value! Please enter 'true' or 'false'")
            
            # Encryption in Transit
            while True:
                value = input("  encryption_in_transit_required (true/false): ").strip().lower()
                if not value:
                    break
                if value in ['true', 'false']:
                    env['encryption_in_transit_required'] = (value == 'true')
                    break
                else:
                    print("  ❌ Invalid value! Please enter 'true' or 'false'")
            
            # Encryption at Rest
            while True:
                value = input("  encryption_at_rest_required (true/false): ").strip().lower()
                if not value:
                    break
                if value in ['true', 'false']:
                    env['encryption_at_rest_required'] = (value == 'true')
                    break
                else:
                    print("  ❌ Invalid value! Please enter 'true' or 'false'")
            
            # System Criticality
            while True:
                value = input("  system_criticality (low/medium/high/business_critical): ").strip().lower()
                if not value:
                    break  # Skip if empty
                if value in ['low', 'medium', 'high', 'business_critical']:
                    env['system_criticality'] = value
                    break
                else:
                    print("  ❌ Invalid value! Please enter 'low', 'medium', 'high', or 'business_critical'")
                    continue
            
            # Save back to config
            config['AppSecAI']['environment'] = env
            self._save_compliance_config(config)
            print("\n✅ Environment settings saved to appsecai/risk_profiles/context_modifiers/risk_context_template.json")
            
            choice = input("\nPress Enter to go back or any key to reconfigure: ").strip()
            # Always go back after configuration
            self.navigation_stack.pop()
            break
    
    def _configure_runtime(self):
        """Configure runtime settings."""
        self.navigation_stack.append("Runtime")
        
        while True:
            # Check if we should exit this menu
            if self.exit_levels > 0:
                self.exit_levels -= 1
                break
            
            self._display_breadcrumb()
            
            print("\n" + "="*60)
            print("RUNTIME CONFIGURATION")
            print("="*60)
            
            config = self._load_compliance_config()
            runtime = config.get('AppSecAI', {}).get('runtime', {})
            
            # Display current settings
            print("\nCurrent Runtime Settings:")
            print(f"  containerized:                  {str(runtime.get('containerized', False)).lower()}")
            print(f"  root_container:                 {str(runtime.get('root_container', False)).lower()}")
            print(f"  container_sig_enforced:         {str(runtime.get('container_sig_enforced', False)).lower()}")
            print(f"  runtime_monitoring_enabled:     {str(runtime.get('runtime_monitoring_enabled', False)).lower()}")
            print(f"  service_authn:                  {str(runtime.get('service_authn', False)).lower()}")
            print(f"  rate_limiting_enabled:          {str(runtime.get('rate_limiting_enabled', False)).lower()}")
            print(f"  memory_limits_enforced:         {str(runtime.get('memory_limits_enforced', False)).lower()}")
            print(f"  cpu_limits_enforced:            {str(runtime.get('cpu_limits_enforced', False)).lower()}")
            
            # Language runtime versions
            lang_runtime = runtime.get('language_runtime', {})
            print("\n  Language Runtime Versions:")
            print(f"    python_version: {lang_runtime.get('python_version', 'Not Set')}")
            print(f"    node_version: {lang_runtime.get('node_version', 'Not Set')}")
            print(f"    go: {lang_runtime.get('go', 'Not Set')}")
            print(f"    java: {lang_runtime.get('java', 'Not Set')}")
            
            # Configure each setting
            print("\nConfigure Settings (type 'true' or 'false', or press Enter to skip):")
            print()
            
            while True:
                value = input("  containerized (true/false): ").strip().lower()
                if not value: break
                if value in ['true', 'false']:
                    runtime['containerized'] = (value == 'true')
                    break
                print("  ❌ Invalid value! Please enter 'true' or 'false'")
            
            while True:
                value = input("  root_container (true/false): ").strip().lower()
                if not value: break
                if value in ['true', 'false']:
                    runtime['root_container'] = (value == 'true')
                    break
                print("  ❌ Invalid value! Please enter 'true' or 'false'")
            
            while True:
                value = input("  container_sig_enforced (true/false): ").strip().lower()
                if not value: break
                if value in ['true', 'false']:
                    runtime['container_sig_enforced'] = (value == 'true')
                    break
                print("  ❌ Invalid value! Please enter 'true' or 'false'")
            
            while True:
                value = input("  runtime_monitoring_enabled (true/false): ").strip().lower()
                if not value: break
                if value in ['true', 'false']:
                    runtime['runtime_monitoring_enabled'] = (value == 'true')
                    break
                print("  ❌ Invalid value! Please enter 'true' or 'false'")
            
            while True:
                value = input("  service_authn (true/false): ").strip().lower()
                if not value: break
                if value in ['true', 'false']:
                    runtime['service_authn'] = (value == 'true')
                    break
                print("  ❌ Invalid value! Please enter 'true' or 'false'")
            
            while True:
                value = input("  rate_limiting_enabled (true/false): ").strip().lower()
                if not value: break
                if value in ['true', 'false']:
                    runtime['rate_limiting_enabled'] = (value == 'true')
                    break
                print("  ❌ Invalid value! Please enter 'true' or 'false'")
            
            while True:
                value = input("  memory_limits_enforced (true/false): ").strip().lower()
                if not value: break
                if value in ['true', 'false']:
                    runtime['memory_limits_enforced'] = (value == 'true')
                    break
                print("  ❌ Invalid value! Please enter 'true' or 'false'")
            
            while True:
                value = input("  cpu_limits_enforced (true/false): ").strip().lower()
                if not value: break
                if value in ['true', 'false']:
                    runtime['cpu_limits_enforced'] = (value == 'true')
                    break
                print("  ❌ Invalid value! Please enter 'true' or 'false'")
            
            # Configure language runtime versions
            print("\nConfigure Language Runtime Versions:")
            print("Enter language name and version, or press Enter to finish")
            print("Examples: python_version, node_version, go, java, ruby, php, dotnet, etc.")
            
            if 'language_runtime' not in runtime:
                runtime['language_runtime'] = {}
            
            # Show existing languages
            if runtime['language_runtime']:
                print("\nExisting Language Runtimes:")
                for lang, ver in runtime['language_runtime'].items():
                    print(f"  {lang}: {ver}")
            
            print("\nAdd/Update Language Runtimes:")
            while True:
                lang_name = input("Language name (or press Enter to finish): ").strip()
                if not lang_name:
                    break
                
                # Validate version format
                while True:
                    lang_version = input(f"Version for {lang_name} : ").strip()
                    if not lang_version:
                        print("⚠️  Version cannot be empty. Skipping this language...")
                        break
                    
                    # Check if version looks like a valid version number
                    # Allow formats like: 3.11, 18, 1.20.5, 21.0.1, etc.
                    import re
                    if re.match(r'^\d+(\.\d+)*$', lang_version):
                        runtime['language_runtime'][lang_name] = lang_version
                        print(f"✅ Added/Updated: {lang_name} = {lang_version}")
                        break
                    else:
                        print(f"❌ Invalid version format! Please enter a valid version number (e.g., 3.11, 18.0, 1.20.5)")
                        print(f"   Version should contain only numbers and dots (e.g., 3.11 or 18.0.1)")
                        continue
            
            # Save back to config
            config['AppSecAI']['runtime'] = runtime
            self._save_compliance_config(config)
            print("\n✅ Runtime settings saved to appsecai/risk_profiles/context_modifiers/risk_context_template.json")
            
            choice = input("\nPress Enter to go back or any key to reconfigure: ").strip()
            # Always go back after configuration
            self.navigation_stack.pop()
            break
    
    def _configure_service(self):
        """Configure service-level settings."""
        self.navigation_stack.append("Service")
        
        while True:
            # Check if we should exit this menu
            if self.exit_levels > 0:
                self.exit_levels -= 1
                break
            
            self._display_breadcrumb()
            
            print("\n" + "="*60)
            print("SERVICE CONFIGURATION")
            print("="*60)
            
            config = self._load_compliance_config()
            
            # Service settings can be in runtime or a separate service section
            # Check both locations for backward compatibility
            if 'service' not in config.get('AppSecAI', {}):
                config['AppSecAI']['service'] = {}
            
            service = config['AppSecAI']['service']
            runtime = config.get('AppSecAI', {}).get('runtime', {})
            
            # Initialize default service fields if not present (only 4 fields)
            service_defaults = {
                'service_authn': False,
                'rate_limiting_enabled': False,
                'memory_limits_enforced': False,
                'cpu_limits_enforced': False
            }
            
            # Merge defaults with existing values
            for key, default_value in service_defaults.items():
                if key not in service:
                    service[key] = runtime.get(key, default_value)
            
            # Display current settings
            print("\nCurrent Service Settings:")
            print(f"  service_authn:                    {str(service.get('service_authn', False)).lower()}")
            print(f"  rate_limiting_enabled:            {str(service.get('rate_limiting_enabled', False)).lower()}")
            print(f"  memory_limits_enforced:           {str(service.get('memory_limits_enforced', False)).lower()}")
            print(f"  cpu_limits_enforced:              {str(service.get('cpu_limits_enforced', False)).lower()}")
            
            # Configure each setting
            print("\nConfigure Settings (type 'true' or 'false', or press Enter to skip):")
            print()
            
            while True:
                value = input("  service_authn (true/false): ").strip().lower()
                if not value: break
                if value in ['true', 'false']:
                    service['service_authn'] = (value == 'true')
                    runtime['service_authn'] = (value == 'true')  # Keep in sync
                    break
                print("  ❌ Invalid value! Please enter 'true' or 'false'")
            
            while True:
                value = input("  rate_limiting_enabled (true/false): ").strip().lower()
                if not value: break
                if value in ['true', 'false']:
                    service['rate_limiting_enabled'] = (value == 'true')
                    runtime['rate_limiting_enabled'] = (value == 'true')  # Keep in sync
                    break
                print("  ❌ Invalid value! Please enter 'true' or 'false'")
            
            while True:
                value = input("  memory_limits_enforced (true/false): ").strip().lower()
                if not value: break
                if value in ['true', 'false']:
                    service['memory_limits_enforced'] = (value == 'true')
                    runtime['memory_limits_enforced'] = (value == 'true')  # Keep in sync
                    break
                print("  ❌ Invalid value! Please enter 'true' or 'false'")
            
            while True:
                value = input("  cpu_limits_enforced (true/false): ").strip().lower()
                if not value: break
                if value in ['true', 'false']:
                    service['cpu_limits_enforced'] = (value == 'true')
                    runtime['cpu_limits_enforced'] = (value == 'true')  # Keep in sync
                    break
                print("  ❌ Invalid value! Please enter 'true' or 'false'")
            
            # Save back to config
            config['AppSecAI']['service'] = service
            config['AppSecAI']['runtime'] = runtime
            self._save_compliance_config(config)
            print("\n✅ Service settings saved to appsecai/risk_profiles/context_modifiers/risk_context_template.json")
            
            choice = input("\nPress Enter to go back or any key to reconfigure: ").strip()
            # Always go back after configuration
            self.navigation_stack.pop()
            break
    
    def _configure_security_controls_new(self):
        """Configure security controls."""
        self.navigation_stack.append("Security Controls")
        
        while True:
            # Check if we should exit this menu
            if self.exit_levels > 0:
                self.exit_levels -= 1
                break
            
            self._display_breadcrumb()
            
            print("\n" + "="*60)
            print("SECURITY CONTROLS CONFIGURATION")
            print("="*60)
            
            config = self._load_compliance_config()
            controls = config.get('AppSecAI', {}).get('security_controls', {})
            
            # Display all current settings
            print("\nCurrent Security Controls (All):")
            control_keys = list(controls.keys())
            for key in control_keys:
                # Align the true/false text
                padding = 50 - len(key)
                print(f"  {key}:{' ' * padding}{str(controls.get(key, False)).lower()}")
            
            # Configure each setting
            print(f"\nConfigure Settings (type 'true' or 'false', or press Enter to skip):")
            print(f"Total controls: {len(control_keys)}")
            print("=" * 60)
            print()
            
            for key in control_keys:
                while True:
                    value = input(f"  {key} (true/false): ").strip().lower()
                    if not value: break
                    if value in ['true', 'false']:
                        controls[key] = (value == 'true')
                        break
                    print("  ❌ Invalid value! Please enter 'true' or 'false'")
            
            # Save back to config
            config['AppSecAI']['security_controls'] = controls
            self._save_compliance_config(config)
            print("\n✅ Security controls saved to appsecai/risk_profiles/context_modifiers/risk_context_template.json")
            
            choice = input("\nPress Enter to go back or any key to reconfigure: ").strip()
            # Always go back after configuration
            self.navigation_stack.pop()
            break
    
    def _load_compliance_config(self):
        """Load appsecai/risk_profiles/context_modifiers/risk_context_template.json configuration."""
        try:
            with open(get_resource_path('appsecai/risk_profiles/context_modifiers/risk_context_template.json'), 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            # Return default structure if file doesn't exist
            return {
                "AppSecAI": {
                    "product": "",
                    "version": "",
                    "environment": {},
                    "runtime": {},
                    "security_controls": {}
                }
            }
        except Exception as e:
            print(f"Error loading compliance config: {e}")
            return {}
    
    def _save_compliance_config(self, config):
        """Save configuration to appsecai/risk_profiles/context_modifiers/risk_context_template.json."""
        try:
            with open(get_resource_path('appsecai/risk_profiles/context_modifiers/risk_context_template.json'), 'w') as f:
                json.dump(config, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving compliance config: {e}")
            return False

    def _validate_deployment_input(self, field_name, value, field_type):
        """
        Validate deployment configuration input against framework requirements.
        
        Args:
            field_name: Name of the field being validated
            value: User input value
            field_type: Type of field (text, boolean, etc.)
        
        Returns:
            Tuple of (is_valid, validated_value, error_message)
        """
        # Define valid values for each field based on vulnerability_framework.json
        # RESTRICTED to only allowed values
        valid_values = {
            'deployment_type': ['public', 'internal_only'],  # Only 2 options
            'api_type': ['none'],  # Only 'none' allowed
            'data_classification': ['public', 'internal_only'],  # Only 2 options
            'system_criticality': ['business_critical']  # Only 1 option
        }
        
        # Validate based on field type
        if field_type == 'choice' and field_name in valid_values:
            if value.lower() in valid_values[field_name]:
                return True, value.lower(), None
            else:
                return False, None, f"Invalid value. Must be one of: {', '.join(valid_values[field_name])}"
        
        elif field_type == 'boolean':
            # Boolean validation with clear y=yes, n=no explanation
            value_lower = value.lower().strip()
            if value_lower in ['y', 'yes']:
                return True, True, None  # Return boolean True
            elif value_lower in ['n', 'no']:
                return True, False, None  # Return boolean False
            elif value_lower == '':
                return True, None, None  # Keep current value
            else:
                return False, None, " Invalid input. Enter 'y' (yes) or 'n' (no)"
        
        elif field_type == 'text':
            # Text validation (non-empty)
            if value.strip():
                return True, value.strip(), None
            else:
                return False, None, "Value cannot be empty"
        
        elif field_type == 'version':
            # Version validation (any format)
            if value.strip():
                return True, value.strip(), None
            else:
                return False, None, "Version cannot be empty"
        
        # Default: accept any value
        return True, value, None

    def _configure_product_info(self, app_config):
        """Configure product name and version."""
        print("\n📦 Product & Version Information")
        print("=" * 40)
        
        current_product = app_config.get('product', 'Caze_HireSense')
        current_version = app_config.get('version', '1.0.0 RC2')
        
        print(f"Current Product: {current_product}")
        new_product = input("Enter product name (or press Enter to keep current): ").strip()
        if new_product:
            app_config['product'] = new_product
            print(f"✅ Product updated to: {new_product}")
        
        print(f"\nCurrent Version: {current_version}")
        new_version = input("Enter version (or press Enter to keep current): ").strip()
        if new_version:
            app_config['version'] = new_version
            print(f"✅ Version updated to: {new_version}")
        
        input("\nPress Enter to continue...")

    def _configure_environment_settings(self, env_config):
        """Configure environment deployment settings."""
        print("\n🌍 Environment Settings")
        print("=" * 40)
        
        # Deployment Type - RESTRICTED TO 2 OPTIONS
        print("\n1. Deployment Type:")
        print("   ⚠️  Only 2 options allowed:")
        print("   • public - Application is publicly accessible")
        print("   • internal_only - Application is internal only")
        print(f"   Current: {env_config.get('deployment_type', 'public')}")
        while True:
            deployment_type = input("   Enter deployment type (public/internal_only): ").strip()
            if not deployment_type:
                break  # Keep current value
            
            is_valid, validated_value, error_msg = self._validate_deployment_input(
                'deployment_type', deployment_type, 'choice'
            )
            if is_valid:
                env_config['deployment_type'] = validated_value
                print(f"   ✅ Set to: {validated_value}")
                break
            else:
                print(f"    {error_msg}")
                print("   💡 Please enter either 'public' or 'internal_only'")
        
        # Internet Exposure - WITH CLEAR Y/N EXPLANATION
        print("\n2. Internet Exposure:")
        print("   💡 Enter 'y' (yes) or 'n' (no)")
        print("   • y = yes (application is exposed to internet)")
        print("   • n = no (application is not exposed to internet)")
        print(f"   Current: {'yes' if env_config.get('internet_exposure', True) else 'no'}")
        while True:
            internet_input = input("   Internet exposure (y/n): ").strip().lower()
            if not internet_input:
                break  # Keep current value
            
            is_valid, validated_value, error_msg = self._validate_deployment_input(
                'internet_exposure', internet_input, 'boolean'
            )
            if is_valid:
                if validated_value is not None:  # User provided input
                    env_config['internet_exposure'] = validated_value
                    print(f"   ✅ Set to: {'yes' if validated_value else 'no'}")
                break
            else:
                print(f"   {error_msg}")
                print("   💡 Please enter 'y' for yes or 'n' for no")
        
        # API Type - RESTRICTED TO 'none' ONLY
        print("\n3. API Type:")
        print("   ⚠️  Only 'none' is allowed")
        print(f"   Current: {env_config.get('api_type', 'none')}")
        api_confirm = input("   Keep as 'none'? (Y/n): ").strip().lower()
        if api_confirm not in ['n', 'no']:
            env_config['api_type'] = 'none'
            print("   ✅ Set to: none")
        else:
            print("   ⚠️  API type must be 'none'. Keeping current value.")
        
        # HTTPS Enabled - WITH CLEAR Y/N EXPLANATION
        print("\n4. HTTPS Enabled:")
        print("   💡 Enter 'y' (yes) or 'n' (no)")
        print("   • y = yes (HTTPS is enabled)")
        print("   • n = no (HTTPS is not enabled)")
        print(f"   Current: {'yes' if env_config.get('https_enabled', True) else 'no'}")
        while True:
            https_input = input("   Is HTTPS enabled? (y/n): ").strip().lower()
            if not https_input:
                break  # Keep current value
            
            is_valid, validated_value, error_msg = self._validate_deployment_input(
                'https_enabled', https_input, 'boolean'
            )
            if is_valid:
                if validated_value is not None:
                    env_config['https_enabled'] = validated_value
                    print(f"   ✅ Set to: {'yes' if validated_value else 'no'}")
                break
            else:
                print(f"   {error_msg}")
                print("   💡 Please enter 'y' for yes or 'n' for no")
        
        # Data Classification - RESTRICTED TO 2 OPTIONS
        print("\n5. Data Classification:")
        print("   ⚠️  Only 2 options allowed:")
        print("   • public - Data is public")
        print("   • internal_only - Data is internal only")
        print(f"   Current: {env_config.get('data_classification', 'public')}")
        while True:
            data_classification = input("   Enter data classification (public/internal_only): ").strip()
            if not data_classification:
                break  # Keep current value
            
            is_valid, validated_value, error_msg = self._validate_deployment_input(
                'data_classification', data_classification, 'choice'
            )
            if is_valid:
                env_config['data_classification'] = validated_value
                print(f"   ✅ Set to: {validated_value}")
                break
            else:
                print(f"    {error_msg}")
                print("   💡 Please enter either 'public' or 'internal_only'")
        
        # PII Present - WITH CLEAR Y/N EXPLANATION
        print("\n6. PII (Personally Identifiable Information) Present:")
        print("   💡 Enter 'y' (yes) or 'n' (no)")
        print("   • y = yes (application handles PII)")
        print("   • n = no (application does not handle PII)")
        print(f"   Current: {'yes' if env_config.get('pii_present', True) else 'no'}")
        while True:
            pii_input = input("   Does application handle PII? (y/n): ").strip().lower()
            if not pii_input:
                break  # Keep current value
            
            is_valid, validated_value, error_msg = self._validate_deployment_input(
                'pii_present', pii_input, 'boolean'
            )
            if is_valid:
                if validated_value is not None:
                    env_config['pii_present'] = validated_value
                    print(f"   ✅ Set to: {'yes' if validated_value else 'no'}")
                break
            else:
                print(f"   {error_msg}")
                print("   💡 Please enter 'y' for yes or 'n' for no")
        
        # Logging/Audit Required - WITH CLEAR Y/N EXPLANATION
        print("\n7. Logging & Audit Required:")
        print("   💡 Enter 'y' (yes) or 'n' (no)")
        print("   • y = yes (logging/audit is required)")
        print("   • n = no (logging/audit is not required)")
        print(f"   Current: {'yes' if env_config.get('logging_audit_required', True) else 'no'}")
        while True:
            logging_input = input("   Is logging/audit required? (y/n): ").strip().lower()
            if not logging_input:
                break  # Keep current value
            
            is_valid, validated_value, error_msg = self._validate_deployment_input(
                'logging_audit_required', logging_input, 'boolean'
            )
            if is_valid:
                if validated_value is not None:
                    env_config['logging_audit_required'] = validated_value
                    print(f"   ✅ Set to: {'yes' if validated_value else 'no'}")
                break
            else:
                print(f"   {error_msg}")
                print("   💡 Please enter 'y' for yes or 'n' for no")
        
        # Encryption in Transit - WITH CLEAR Y/N EXPLANATION
        print("\n8. Encryption in Transit Required:")
        print("   💡 Enter 'y' (yes) or 'n' (no)")
        print("   • y = yes (encryption in transit is required)")
        print("   • n = no (encryption in transit is not required)")
        print(f"   Current: {'yes' if env_config.get('encryption_in_transit_required', True) else 'no'}")
        while True:
            encryption_transit_input = input("   Is encryption in transit required? (y/n): ").strip().lower()
            if not encryption_transit_input:
                break  # Keep current value
            
            is_valid, validated_value, error_msg = self._validate_deployment_input(
                'encryption_in_transit_required', encryption_transit_input, 'boolean'
            )
            if is_valid:
                if validated_value is not None:
                    env_config['encryption_in_transit_required'] = validated_value
                    print(f"   ✅ Set to: {'yes' if validated_value else 'no'}")
                break
            else:
                print(f"   {error_msg}")
                print("   💡 Please enter 'y' for yes or 'n' for no")
        
        # Encryption at Rest - WITH CLEAR Y/N EXPLANATION
        print("\n9. Encryption at Rest Required:")
        print("   💡 Enter 'y' (yes) or 'n' (no)")
        print("   • y = yes (encryption at rest is required)")
        print("   • n = no (encryption at rest is not required)")
        print(f"   Current: {'yes' if env_config.get('encryption_at_rest_required', True) else 'no'}")
        while True:
            encryption_rest_input = input("   Is encryption at rest required? (y/n): ").strip().lower()
            if not encryption_rest_input:
                break  # Keep current value
            
            is_valid, validated_value, error_msg = self._validate_deployment_input(
                'encryption_at_rest_required', encryption_rest_input, 'boolean'
            )
            if is_valid:
                if validated_value is not None:
                    env_config['encryption_at_rest_required'] = validated_value
                    print(f"   ✅ Set to: {'yes' if validated_value else 'no'}")
                break
            else:
                print(f"   {error_msg}")
                print("   💡 Please enter 'y' for yes or 'n' for no")
        
        # System Criticality - RESTRICTED TO 'business_critical' ONLY
        print("\n10. System Criticality:")
        print("   ⚠️  Only 'business_critical' is allowed")
        print(f"   Current: {env_config.get('system_criticality', 'business_critical')}")
        criticality_confirm = input("   Keep as 'business_critical'? (Y/n): ").strip().lower()
        if criticality_confirm not in ['n', 'no']:
            env_config['system_criticality'] = 'business_critical'
            print("   ✅ Set to: business_critical")
        else:
            print("   ⚠️  System criticality must be 'business_critical'. Keeping current value.")
        
        print("\n✅ Environment settings updated")
        input("Press Enter to continue...")

    def _configure_runtime_settings(self, runtime_config):
        """Configure runtime deployment settings."""
        print("\n⚙️  Runtime Configuration")
        print("=" * 40)
        
        # Containerized - WITH CLEAR Y/N EXPLANATION
        print("\n1. Containerized:")
        print("   💡 Enter 'y' (yes) or 'n' (no)")
        print("   • y = yes (application is containerized)")
        print("   • n = no (application is not containerized)")
        print(f"   Current: {'yes' if runtime_config.get('containerized', True) else 'no'}")
        while True:
            containerized_input = input("   Is application containerized? (y/n): ").strip().lower()
            if not containerized_input:
                break  # Keep current value
            
            is_valid, validated_value, error_msg = self._validate_deployment_input(
                'containerized', containerized_input, 'boolean'
            )
            if is_valid:
                if validated_value is not None:
                    runtime_config['containerized'] = validated_value
                    print(f"   ✅ Set to: {'yes' if validated_value else 'no'}")
                break
            else:
                print(f"   {error_msg}")
                print("   💡 Please enter 'y' for yes or 'n' for no")
        
        # Root Container - WITH CLEAR Y/N EXPLANATION
        print("\n2. Root Container:")
        print("   💡 Enter 'y' (yes) or 'n' (no)")
        print("   • y = yes (container runs as root)")
        print("   • n = no (container does not run as root)")
        print(f"   Current: {'yes' if runtime_config.get('root_container', True) else 'no'}")
        while True:
            root_input = input("   Does container run as root? (y/n): ").strip().lower()
            if not root_input:
                break
            is_valid, validated_value, error_msg = self._validate_deployment_input('root_container', root_input, 'boolean')
            if is_valid:
                if validated_value is not None:
                    runtime_config['root_container'] = validated_value
                    print(f"   ✅ Set to: {'yes' if validated_value else 'no'}")
                break
            else:
                print(f"   {error_msg}")
        
        # Container Signature Enforced - WITH CLEAR Y/N EXPLANATION
        print("\n3. Container Signature Enforced:")
        print("   💡 Enter 'y' (yes) or 'n' (no)")
        print(f"   Current: {'yes' if runtime_config.get('container_sig_enforced', False) else 'no'}")
        while True:
            container_sig_input = input("   Is container signature enforced? (y/n): ").strip().lower()
            if not container_sig_input:
                break
            is_valid, validated_value, error_msg = self._validate_deployment_input('container_sig_enforced', container_sig_input, 'boolean')
            if is_valid:
                if validated_value is not None:
                    runtime_config['container_sig_enforced'] = validated_value
                    print(f"   ✅ Set to: {'yes' if validated_value else 'no'}")
                break
            else:
                print(f"   {error_msg}")
        
        # Runtime Monitoring - WITH CLEAR Y/N EXPLANATION
        print("\n4. Runtime Monitoring Enabled:")
        print("   💡 Enter 'y' (yes) or 'n' (no)")
        print(f"   Current: {'yes' if runtime_config.get('runtime_monitoring_enabled', False) else 'no'}")
        while True:
            runtime_monitoring_input = input("   Is runtime monitoring enabled? (y/n): ").strip().lower()
            if not runtime_monitoring_input:
                break
            is_valid, validated_value, error_msg = self._validate_deployment_input('runtime_monitoring_enabled', runtime_monitoring_input, 'boolean')
            if is_valid:
                if validated_value is not None:
                    runtime_config['runtime_monitoring_enabled'] = validated_value
                    print(f"   ✅ Set to: {'yes' if validated_value else 'no'}")
                break
            else:
                print(f"   {error_msg}")
        
        # Language Runtime - DYNAMIC CONFIGURATION
        print("\n5. Language Runtime Versions:")
        print("   Configure programming languages and their versions used in your application")
        
        # Get existing language runtime or create new
        lang_runtime = runtime_config.get('language_runtime', {})
        
        # Show current languages
        if lang_runtime:
            print("\n   Current Languages:")
            for lang, version in lang_runtime.items():
                print(f"     • {lang}: {version}")
        else:
            print("\n   No languages configured yet")
        
        print("\n   Options:")
        print("     1. Add/Update languages (keeps existing)")
        print("     2. Remove a language")
        print("     3. Replace all languages (overwrites)")
        print("     4. Keep current configuration")
        
        lang_choice = input("\n   Select option (1-4): ").strip()
        
        if lang_choice == '1':
            # Add/Update languages - KEEPS EXISTING
            print("\n   📝 Add/Update Language Versions")
            print("   " + "=" * 40)
            print("   ℹ️  This will ADD to or UPDATE existing languages")
            print("   Common languages: python, node, java, go, ruby, php, dotnet, rust, etc.")
            print("   Enter language name and version, or press Enter when done")
            print()
            
            while True:
                lang_name = input("   Language name (or press Enter to finish): ").strip().lower()
                if not lang_name:
                    break
                
                # Show current version if exists
                current_version = lang_runtime.get(lang_name, 'Not set')
                print(f"   Current version for {lang_name}: {current_version}")
                
                lang_version = input(f"   Version for {lang_name}: ").strip()
                if lang_version:
                    lang_runtime[lang_name] = lang_version
                    print(f"   ✅ {lang_name} set to version {lang_version}")
                else:
                    print(f"   ⚠️  Skipped {lang_name} (no version provided)")
                print()
        
        elif lang_choice == '2':
            # Remove a language
            if lang_runtime:
                print("\n   🗑️  Remove Language")
                print("   Current languages:")
                lang_list = list(lang_runtime.keys())
                for i, lang in enumerate(lang_list, 1):
                    print(f"     {i}. {lang}: {lang_runtime[lang]}")
                
                remove_choice = input("\n   Enter number to remove (or press Enter to cancel): ").strip()
                if remove_choice.isdigit():
                    idx = int(remove_choice) - 1
                    if 0 <= idx < len(lang_list):
                        removed_lang = lang_list[idx]
                        del lang_runtime[removed_lang]
                        print(f"   ✅ Removed {removed_lang}")
                    else:
                        print("    Invalid selection")
                else:
                    print("   ℹ️  Cancelled")
            else:
                print("   ⚠️  No languages to remove")
        
        elif lang_choice == '3':
            # Replace all languages - OVERWRITES EVERYTHING
            print("\n   🔄 Replace All Languages")
            print("   " + "=" * 40)
            print("   ⚠️  This will REMOVE all existing languages and start fresh")
            
            if lang_runtime:
                print("\n   Current languages will be removed:")
                for lang, version in lang_runtime.items():
                    print(f"     • {lang}: {version}")
                
                confirm = input("\n   Are you sure you want to replace all? (y/N): ").strip().lower()
                if not confirm.startswith('y'):
                    print("   ℹ️  Cancelled - keeping existing languages")
                else:
                    # Clear all existing languages
                    lang_runtime = {}
                    print("   ✅ All existing languages cleared")
                    
                    # Now add new languages
                    print("\n   📝 Add New Language Versions")
                    print("   Common languages: python, node, java, go, ruby, php, dotnet, rust, etc.")
                    print("   Enter language name and version, or press Enter when done")
                    print()
                    
                    while True:
                        lang_name = input("   Language name (or press Enter to finish): ").strip().lower()
                        if not lang_name:
                            break
                        
                        lang_version = input(f"   Version for {lang_name}: ").strip()
                        if lang_version:
                            lang_runtime[lang_name] = lang_version
                            print(f"   ✅ {lang_name} set to version {lang_version}")
                        else:
                            print(f"   ⚠️  Skipped {lang_name} (no version provided)")
                        print()
                    
                    if not lang_runtime:
                        print("   ⚠️  No languages added - language_runtime will be empty")
            else:
                print("\n   No existing languages to replace")
                print("   Use option 1 to add languages")
        
        # Save the updated language runtime
        runtime_config['language_runtime'] = lang_runtime
        
        # Service Authentication - WITH CLEAR Y/N EXPLANATION
        print("\n6. Service Authentication:")
        print("   💡 Enter 'y' (yes) or 'n' (no)")
        print(f"   Current: {'yes' if runtime_config.get('service_authn', True) else 'no'}")
        while True:
            service_authn_input = input("   Is service authentication enabled? (y/n): ").strip().lower()
            if not service_authn_input:
                break
            is_valid, validated_value, error_msg = self._validate_deployment_input('service_authn', service_authn_input, 'boolean')
            if is_valid:
                if validated_value is not None:
                    runtime_config['service_authn'] = validated_value
                    print(f"   ✅ Set to: {'yes' if validated_value else 'no'}")
                break
            else:
                print(f"   {error_msg}")
        
        # Rate Limiting - WITH CLEAR Y/N EXPLANATION
        print("\n7. Rate Limiting Enabled:")
        print("   💡 Enter 'y' (yes) or 'n' (no)")
        print(f"   Current: {'yes' if runtime_config.get('rate_limiting_enabled', False) else 'no'}")
        while True:
            rate_limiting_input = input("   Is rate limiting enabled? (y/n): ").strip().lower()
            if not rate_limiting_input:
                break
            is_valid, validated_value, error_msg = self._validate_deployment_input('rate_limiting_enabled', rate_limiting_input, 'boolean')
            if is_valid:
                if validated_value is not None:
                    runtime_config['rate_limiting_enabled'] = validated_value
                    print(f"   ✅ Set to: {'yes' if validated_value else 'no'}")
                break
            else:
                print(f"   {error_msg}")
        
        # Memory Limits - WITH CLEAR Y/N EXPLANATION
        print("\n8. Memory Limits Enforced:")
        print("   💡 Enter 'y' (yes) or 'n' (no)")
        print(f"   Current: {'yes' if runtime_config.get('memory_limits_enforced', False) else 'no'}")
        while True:
            memory_limits_input = input("   Are memory limits enforced? (y/n): ").strip().lower()
            if not memory_limits_input:
                break
            is_valid, validated_value, error_msg = self._validate_deployment_input('memory_limits_enforced', memory_limits_input, 'boolean')
            if is_valid:
                if validated_value is not None:
                    runtime_config['memory_limits_enforced'] = validated_value
                    print(f"   ✅ Set to: {'yes' if validated_value else 'no'}")
                break
            else:
                print(f"   {error_msg}")
        
        # CPU Limits - WITH CLEAR Y/N EXPLANATION
        print("\n9. CPU Limits Enforced:")
        print("    Enter 'y' (yes) or 'n' (no)")
        print(f"   Current: {'yes' if runtime_config.get('cpu_limits_enforced', True) else 'no'}")
        while True:
            cpu_limits_input = input("   Are CPU limits enforced? (y/n): ").strip().lower()
            if not cpu_limits_input:
                break
            is_valid, validated_value, error_msg = self._validate_deployment_input('cpu_limits_enforced', cpu_limits_input, 'boolean')
            if is_valid:
                if validated_value is not None:
                    runtime_config['cpu_limits_enforced'] = validated_value
                    print(f"   ✅ Set to: {'yes' if validated_value else 'no'}")
                break
            else:
                print(f"   {error_msg}")
        
        print("\n✅ Runtime settings updated")
        input("Press Enter to continue...")

    def _configure_security_controls(self, security_config):
        """Configure security controls settings."""
        print("\n Security Controls Configuration")
        print("=" * 40)
        print("Configure which security controls are enabled in your deployment")
        print()
        
        # Define all security controls with descriptions
        controls = [
            ('rbac_enabled', 'RBAC (Role-Based Access Control)'),
            ('waf_enabled', 'WAF (Web Application Firewall)'),
            ('ids_enabled', 'IDS (Intrusion Detection System)'),
            ('nfw_enabled', 'NFW (Network Firewall)'),
            ('sso_enabled', 'SSO (Single Sign-On)'),
            ('mfa_required_for_admin', 'MFA Required for Admin'),
            ('infrastructure_as_code_scan_enabled', 'Infrastructure as Code Scanning'),
            ('dependency_vulnerability_scan_enabled', 'Dependency Vulnerability Scanning'),
            ('container_image_scan_enabled', 'Container Image Scanning'),
            ('api_input_validation', 'API Input Validation'),
            ('api_authentication_required', 'API Authentication Required'),
            ('secrets_vault_enabled', 'Secrets Vault'),
            ('rate_limiting_enabled', 'Rate Limiting'),
            ('cloud_security_posture_management', 'Cloud Security Posture Management'),
            ('business_logic_testing', 'Business Logic Testing'),
            ('data_loss_prevention', 'Data Loss Prevention'),
            ('network_segmentation', 'Network Segmentation'),
            ('privileged_access_management', 'Privileged Access Management'),
            ('api_security_gateway', 'API Security Gateway'),
            ('third_party_risk_assessment', 'Third Party Risk Assessment'),
            ('input_validation', 'Input Validation'),
            ('key_management_system', 'Key Management System')
        ]
        
        print("💡 For each control:")
        print("   • Enter 'y' (yes) to enable")
        print("   • Enter 'n' (no) to disable")
        print("   • Press Enter to keep current value")
        print()
        
        for key, description in controls:
            current_value = security_config.get(key, False)
            while True:
                response = input(f"{description} (current: {'enabled' if current_value else 'disabled'}) [y/n]: ").strip().lower()
                if not response:
                    break  # Keep current value
                
                is_valid, validated_value, error_msg = self._validate_deployment_input(key, response, 'boolean')
                if is_valid:
                    if validated_value is not None:
                        security_config[key] = validated_value
                    break
                else:
                    print(f"   {error_msg}")
        
        print("\n✅ Security controls updated")
        input("Press Enter to continue...")

    def _save_deployment_config(self, compliance_data, compliance_file):
        """Save deployment configuration to appsecai/risk_profiles/context_modifiers/risk_context_template.json."""
        try:
            import json
            with open(compliance_file, 'w') as f:
                json.dump(compliance_data, f, indent=2)
            print(f"✅ Configuration saved to {compliance_file}")
            return True
        except Exception as e:
            print(f" Error saving configuration: {e}")
            return False

    def _view_deployment_config(self, app_config):
        """View current deployment configuration."""
        print("\n📄 Current Deployment Configuration")
        print("=" * 60)
        
        import json
        print(json.dumps(app_config, indent=2))
        
        input("\nPress Enter to continue...")
    
    def _show_how_to(self):
        """Display How To guide with main features."""
        print("""
╔══════════════════════════════════════════════════════════════╗
║                          HOW TO                              ║
╚══════════════════════════════════════════════════════════════╝

📋 MAIN FEATURES:

   🔍 SAST Scan (Code Analysis):
      • Scans source code for vulnerabilities
      • Requires: GitHub repository URL
      • Time: 5-15 minutes
      • Example: Scan your GitHub repo

   🌐 DAST Scan (Web App Testing):
      • Tests running web applications
      • Requires: Web application URL
      • Time: 10-30 minutes
      • Example: Scan https://yourapp.com

   🤖 AI Remediation:
      • Automatically fixes vulnerabilities
      • Creates GitHub pull requests
      • Review before merging

   📊 Reports:
      • PDF and JSON formats
      • Saved in generated_reports/ folder
      • Includes all findings and recommendations

Press Enter to return to main menu...
        """)
        input()
    
    def _show_help(self):
        """Display help information."""
        print("""
╔══════════════════════════════════════════════════════════════╗
║                    APPSECAI HELP / USAGE GUID                  ║
╚══════════════════════════════════════════════════════════════╝

📖 NAVIGATION COMMANDS:

   • Use numbers (1, 2, 3, 4) to select menu options
   • Type 'cd <menu>' to navigate directly (e.g., 'cd scan')
   • Type 'cd ..' to go back one level
   • Type 'cd /' to return to the main menu

⚡ BINARY / COMMAND LINE USAGE:

   If using the portable EXE/Binary:
   AppSecAI-windows.exe scan --type sast --target <github-url>

   If using Python:
   python -m cli scan --type sast --target <github-url>

🔍 SCANNING EXAMPLES:

   Run SAST (Static Risk Analysis):
   ... scan --type sast --target <github-url>

   Run DAST (Dynamic Risk Analysis):
   ... scan --type dast --target <web-url>

   Run SCA (Dependency Risk Analysis):
   ... scan --type sca --target <github-url>

  

📊 REPORTING & FIXES:

   Generate PDF/HTML Reports:
   ... report --input AppSecAI_output/scan_results.json --format pdf,html

   Run AI Remediation:
   ... fix --input scan_results.json --create-prs --interactive

💡 PRO TIPS:

   • Standard Output: All scan data is saved in 'AppSecAI_output/'
   • Thresholds: Set score to 7-12 in Settings to filter noise
   • ZAP Upload: You can analyze existing ZAP HTML reports via the 
     DAST Settings menu without running a new live scan.
   • macOS: If blocked, go to Privacy & Security to 'Allow Anyway'

📁 OUTPUT LOCATIONS:

   • Primary Results: AppSecAI_output/
   • PDF/HTML Reports: generated_reports/
   • AI Fixes: vulnerability-fixes/
   • DAST RAW: zap_reports/

Press Enter to return to main menu...
        """)
        input()
    
    def _show_about_appsecai(self):
        """Display About AppSecAI information."""
        print("""
╔══════════════════════════════════════════════════════════════╗
║                      ABOUT APPSECAI                          ║
╚══════════════════════════════════════════════════════════════╝


APPSECAI:


AppSecAI is an AI-native application security tool that helps

security and development teams analyze, prioritize, and remediate

application security vulnerabilities.


It supports security analysis across:


• SAST - Static Application Security Testing

• DAST - Dynamic Application Security Testing

• SCA - Software Composition Analysis


AppSecAI uses application context, runtime exposure, business

risk, and security controls to prioritize findings and focus on

high-impact vulnerabilities.


KEY CAPABILITIES:


• Context-aware vulnerability prioritization

• AI-generated secure code fixes

• AI-driven security recommendations

• SAST, DAST, and SCA result analysis

• CLI-based execution and reporting

• Configurable application security context


IMPORTANT NOTE:


AppSecAI results should be reviewed and validated by security

and development teams before applying fixes or making production

changes.


WEBSITE: https://www.cazelabs.com

Press Enter to return to main menu...
        """)
        input()



    def _get_environment_settings_for_upload(self):
        """Prompt user for environment settings to enhance vulnerability scoring."""
        print("\n⚙️  Environment Context Configuration")
        print("=" * 50)
        print("\n💡 Providing environment context helps prioritize vulnerabilities")
        print("   based on your actual deployment configuration.")
        
        use_current = self._parse_input("\nUse current environment settings from config? (Y/n): ")
        if use_current is None:  # cd command was handled
            return None
        
        if use_current.strip().lower() != 'n':
            # Use existing environment settings
            print("✅ Using current environment settings")
            return {
                'use_existing': True
            }
        
        # Prompt for custom environment settings
        print("\n📋 Custom Environment Settings")
        env_settings = self._prompt_environment_settings()
        
        return env_settings

    def _prompt_environment_settings(self):
        """Prompt user for detailed environment settings."""
        settings = {}
        
        # System Criticality
        print("\n1️⃣  System Criticality")
        print("   • critical - Mission-critical systems (payment, auth)")
        print("   • high - Important business systems")
        print("   • medium - Standard applications")
        print("   • low - Development/testing systems")
        
        criticality = self._parse_input("Enter system criticality (critical/high/medium/low): ")
        if criticality is None:
            return None
        settings['system_criticality'] = criticality.strip().lower() or 'medium'
        
        # Internet Exposure
        print("\n2️⃣  Internet Exposure")
        print("   • public - Publicly accessible from internet")
        print("   • internal - Internal network only")
        print("   • private - Private/VPN access only")
        
        exposure = self._parse_input("Enter internet exposure (public/internal/private): ")
        if exposure is None:
            return None
        settings['internet_exposure'] = exposure.strip().lower() or 'public'
        
        # Data Sensitivity
        print("\n3️⃣  Data Sensitivity")
        print("   • pii - Personally Identifiable Information")
        print("   • financial - Financial/payment data")
        print("   • confidential - Business confidential data")
        print("   • public - Public data only")
        
        data_sensitivity = self._parse_input("Enter data sensitivity (pii/financial/confidential/public): ")
        if data_sensitivity is None:
            return None
        settings['data_sensitivity'] = data_sensitivity.strip().lower() or 'public'
        
        # Compliance Requirements
        print("\n4️⃣  Compliance Requirements (comma-separated)")
        print("   Examples: PCI-DSS, HIPAA, GDPR, SOC2, ISO27001")
        
        compliance = self._parse_input("Enter compliance requirements (or press Enter to skip): ")
        if compliance is None:
            return None
        if compliance.strip():
            settings['compliance_requirements'] = [c.strip() for c in compliance.split(',')]
        else:
            settings['compliance_requirements'] = []
        
        print("\n✅ Environment settings configured")
        return settings

    def _get_target_url_for_upload(self, report_path):
        """Get target URL for the uploaded report."""
        # Try to extract URL from report first (silently)
        extracted_url = self._extract_target_url_from_report(report_path)
        
        if extracted_url and extracted_url != "Not specified":
            # URL found - use it automatically without asking
            print(f"\n✅ Detected target URL: {extracted_url}")
            return extracted_url
        
        # Could not extract URL - ask user
        print("\n🎯 Target URL Configuration")
        print("=" * 40)
        print("\n💡 Could not automatically detect target URL from report")
        print("   Please enter the URL that was scanned by ZAP")
        
        # Prompt for URL
        while True:
            target_url = self._parse_input("\nEnter target URL (e.g., example.com): ")
            if target_url is None:  # cd command
                return None
            
            target_url = target_url.strip()
            
            if not target_url:
                print("❌ Please enter a valid URL")
                continue
            
            if not target_url.startswith('http://') and not target_url.startswith('https://'):
                print("💡 Auto-appending http:// to target URL")
                target_url = f"http://{target_url}"
            
            print(f"✅ Using target URL: {target_url}")
            return target_url

    def _extract_target_url_from_report(self, report_path):
        """Extract target URL from ZAP report with multiple strategies."""
        try:
            from bs4 import BeautifulSoup
            from urllib.parse import urlparse
            from collections import Counter
            import re
            
            with open(report_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            soup = BeautifulSoup(content, 'html.parser')
            
            # Strategy 1: Look for "Site:" in h2 tags
            h2_tags = soup.find_all('h2')
            for h2 in h2_tags:
                text = h2.get_text(strip=True)
                if text.startswith('Site:'):
                    target_url = text.replace('Site:', '').strip()
                    if target_url.startswith('http'):
                        return target_url
            
            # Strategy 2: Look in alerts table for URLs
            alerts_table = soup.find("table", class_="alerts")
            if alerts_table:
                rows = alerts_table.find_all("tr")
                for row in rows[1:]:  # Skip header
                    cells = row.find_all("td")
                    if len(cells) >= 2:
                        url_cell = cells[1]
                        url_text = url_cell.get_text(strip=True)
                        if url_text.startswith('http'):
                            parsed = urlparse(url_text)
                            return f"{parsed.scheme}://{parsed.netloc}/"
            
            # Strategy 3: Look in results tables for URL instances
            results_tables = soup.find_all("table", class_="results")
            url_candidates = []
            
            for table in results_tables:
                rows = table.find_all("tr")
                for row in rows:
                    cells = row.find_all("td")
                    if len(cells) >= 2:
                        label = cells[0].get_text(strip=True)
                        if label == "URL":
                            url_text = cells[1].get_text(strip=True)
                            if url_text.startswith('http'):
                                url_candidates.append(url_text)
            
            # If we found URLs in results tables, get the most common base URL
            if url_candidates:
                base_urls = []
                excluded_domains = ['checkmarx.com', 'owasp.org', 'cwe.mitre.org', 
                                  'github.com', 'mozilla.org', 'mozilla.com', 'mozilla.net',
                                  'w3.org', 'zaproxy.org', 'portswigger.net',
                                  'firefox.settings.services.mozilla.com', 
                                  'firefox-settings-attachments.cdn.mozilla.net']
                
                for url in url_candidates:
                    parsed = urlparse(url)
                    domain = parsed.netloc.lower()
                    
                    # Skip excluded domains
                    if not any(excluded in domain for excluded in excluded_domains):
                        base_url = f"{parsed.scheme}://{parsed.netloc}/"
                        base_urls.append(base_url)
                
                if base_urls:
                    # Return the most common base URL
                    most_common = Counter(base_urls).most_common(1)[0][0]
                    return most_common
            
            # Strategy 4: Regex search for URLs in entire document
            url_pattern = r'https?://[^\s<>"]+\.[^\s<>"]+'
            all_urls = re.findall(url_pattern, content)
            
            if all_urls:
                excluded_domains = ['checkmarx.com', 'owasp.org', 'cwe.mitre.org', 
                                  'github.com', 'mozilla.org', 'mozilla.com', 'mozilla.net',
                                  'w3.org', 'zaproxy.org', 'portswigger.net']
                
                base_urls = []
                for url in all_urls:
                    parsed = urlparse(url)
                    domain = parsed.netloc.lower()
                    
                    if not any(excluded in domain for excluded in excluded_domains):
                        base_url = f"{parsed.scheme}://{parsed.netloc}/"
                        base_urls.append(base_url)
                
                if base_urls:
                    # Return the most common base URL
                    most_common = Counter(base_urls).most_common(1)[0][0]
                    return most_common
            
            return None
            
        except Exception as e:
            # Silent failure - will prompt user
            return None

    def _process_uploaded_zap_report(self, report_path, target_url, env_settings):
        """Process uploaded ZAP report using same logic as DAST scan."""
        try:
            # Import the ZAP processor (same as DAST scan uses)
            from appsecai.drivers.dast.dast_processor import ZAPReportAnalyzer
            
            # Update environment settings if custom settings provided
            if not env_settings.get('use_existing', False):
                self._apply_custom_environment_settings(env_settings)
            
            # Get threshold from settings
            threshold = self.current_settings.get('vulnerability_threshold', 10)
            
            # Get config path
            config_path = "appsecai/risk_profiles/context_modifiers/vulnerability_framework.json"
            
            print(f"🎯 Processing with threshold: {threshold}")
            
            # Test LLM connection before processing
            print("🔍 Testing LLM connection...")
            try:
                import requests
                llm_url = os.environ.get('LLM_URL', 'http://4.247.140.236:11434')
                test_response = requests.get(f"{llm_url}/api/tags", timeout=10)
                if test_response.status_code == 200:
                    print(f"✅ LLM connection successful to {llm_url}")
                else:
                    print(f"⚠️  LLM connection issue: HTTP {test_response.status_code}")
            except Exception as e:
                print(f"⚠️  LLM connection failed: {e}")
                print("💡 AI recommendations may not be available")
            
            # Get LLM configuration from environment (same as DAST scanner)
            llm_url = os.environ.get('LLM_URL', 'http://4.247.140.236:11434')
            llm_model = os.environ.get('LLM_MODEL', 'WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B')
            
            print(f"🔧 Using LLM: {llm_url} with model: {llm_model}")
            
            # Initialize analyzer with same parameters as DAST scan
            analyzer = ZAPReportAnalyzer(
                html_file_path=report_path,
                ollama_url=llm_url,  # Pass LLM URL like DAST scanner does
                model=llm_model,     # Pass LLM model like DAST scanner does
                threshold_score=threshold,
                config_path=config_path,
                target_url=target_url,
                output_dir="AppSecAI_output"  # ✅ FIX: Explicit output directory for CSV generation
            )
            
            # Process using same logic as DAST scan
            # Enable AI recommendations for consistent experience with live DAST scans
            results = analyzer.analyze_and_recommend(
                output_file=None,
                generate_llm=True  # Enable AI recommendations for full analysis
            )
            
            return results
            
        except Exception as e:
            print(f"❌ Error processing ZAP report: {e}")
            import traceback
            traceback.print_exc()
            return None

    def _generate_reports_from_upload_v2(self, results, original_report_path, env_settings):
        """Generate comprehensive reports from uploaded ZAP scan results."""
        try:
            from datetime import datetime
            from pathlib import Path
            import os
            
            # Create output directory
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_dir = self.get_base_directory() if hasattr(self, 'get_base_directory') else Path(os.getcwd())
            output_dir = base_dir / f"AppSecAI_output/uploaded_zap_{timestamp}"
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Convert results to report format
            vulnerabilities = results.get('vulnerabilities', [])
            
            # Prepare scan results in expected format
            scan_results = [{
                'scan_type': 'DAST',
                'source': 'Uploaded ZAP Report',
                'original_report': str(original_report_path),
                'target_url': results.get('target_url', 'Unknown'),
                'timestamp': timestamp,
                'vulnerabilities': self._convert_zap_vulnerabilities_to_report_format(vulnerabilities)
            }]
            
            # Generate reports using existing report generator
            from appsecai.reporting.engine import ReportGenerator, ReportData
            
            # Prepare report data
            report_data = ReportData(
                scan_results=scan_results,
                metadata={
                    'source': 'Uploaded ZAP Report',
                    'original_file': os.path.basename(original_report_path),
                    'upload_timestamp': timestamp,
                    'target_url': results.get('target_url', 'Unknown'),
                    'environment_settings': env_settings,
                    'total_vulnerabilities': results.get('total_vulnerabilities', 0),
                    'original_summary': results.get('original_summary', {}),
                    'prioritized_summary': results.get('prioritized_summary', {})
                }
            )
            
            # Initialize report generator
            report_config = {
                'template_dir': './templates',
                'include_executive_summary': True
            }
            generator = ReportGenerator(report_config)
            
            # Generate reports in multiple formats including PDF
            formats = ['html', 'pdf', 'csv', 'json']
            generated_files = generator.generate_report(report_data, formats, str(output_dir))
            
            return generated_files
            
        except Exception as e:
            print(f"❌ Error generating reports: {e}")
            import traceback
            traceback.print_exc()
            return []

    def _convert_zap_vulnerabilities_to_report_format(self, vulnerabilities):
        """Convert ZAP processor vulnerabilities to report generator format."""
        converted = []
        
        for vuln in vulnerabilities:
            # Map fields to report generator expected format
            converted_vuln = {
                'severity': vuln.get('risk', vuln.get('enhanced_risk_level', 'Low')),
                'title': vuln.get('name', 'Unknown'),
                'description': vuln.get('description', ''),
                'url': vuln.get('instances', [{}])[0].get('URL', '') if vuln.get('instances') else '',
                'risk_score': vuln.get('score', 0),
                'enhanced_score': vuln.get('enhanced_score', vuln.get('score', 0)),
                'enhanced_risk_level': vuln.get('enhanced_risk_level', vuln.get('risk', 'Low')),
                'enhanced_category': vuln.get('enhanced_category', vuln.get('mapped_type', 'Unknown')),
                'is_priority': vuln.get('is_priority', False),
                'priority_reason': vuln.get('priority_reason', ''),
                'original_risk': vuln.get('original_risk', vuln.get('risk', 'Unknown')),
                'solution': vuln.get('solution', ''),
                'instances_count': vuln.get('instances_count', '0'),
                'file_path': '',  # DAST doesn't have file paths
                'line_number': '',  # DAST doesn't have line numbers
            }
            
            converted.append(converted_vuln)
        
        return converted

    def _display_upload_summary_v2(self, results, report_paths):
        """Display summary of uploaded ZAP report analysis."""
        print("\n" + "=" * 60)
        print("📊 ANALYSIS SUMMARY")
        print("=" * 60)
        
        vulnerabilities = results.get('vulnerabilities', [])
        prioritized_summary = results.get('prioritized_summary', {})
        
        # Count unique vulnerability types
        unique_types = len(set(v.get('name', '') for v in vulnerabilities))
        
        print(f"\n🔍 Total Vulnerability Instances: {len(vulnerabilities)}")
        print(f"🔍 Unique Vulnerability Types: {unique_types}")
        print(f"🎯 Target URL: {results.get('target_url', 'Unknown')}")
        
        print("\n📈 Risk Distribution:")
        for risk in ['High', 'Medium', 'Low', 'Informational']:
            count = prioritized_summary.get(risk, 0)
            if count > 0:
                print(f"   • {risk}: {count}")
        
        # Show priority vulnerabilities
        priority_vulns = [v for v in vulnerabilities if v.get('is_priority', False)]
        
        if priority_vulns:
            print(f"\n🔝 Top {min(5, len(priority_vulns))} Priority Vulnerabilities:")
            for i, vuln in enumerate(priority_vulns[:5], 1):
                print(f"\n   {i}. [{vuln.get('risk', 'Unknown')}] {vuln.get('name', 'Unknown')}")
                print(f"      Score: {vuln.get('score', 0):.2f}/10.0")
                print(f"      Original Risk: {vuln.get('original_risk', 'Unknown')}")
                if vuln.get('instances'):
                    url = vuln['instances'][0].get('URL', 'N/A')
                    print(f"      URL: {url[:60]}...")
        else:
            print("\n💡 No vulnerabilities exceeded the priority threshold")
        
        # Show generated reports
        if report_paths:
            print("\n📝 Generated Reports:")
            for report_path in report_paths:
                print(f"   • {report_path}")
        
        print("\n" + "=" * 60)

    def _save_upload_metadata_simple(self, report_path, target_url):
        """Save simple metadata about uploaded ZAP report (no processing yet)."""
        try:
            import json
            from datetime import datetime
            from pathlib import Path
            import os
            
            base_dir = self.get_base_directory() if hasattr(self, 'get_base_directory') else Path(os.getcwd())
            metadata_path = base_dir / "AppSecAI_output" / "uploaded_zap_latest.json"
            
            # Create directory if needed
            metadata_path.parent.mkdir(parents=True, exist_ok=True)
            
            metadata = {
                "upload_timestamp": datetime.now().isoformat(),
                "original_file": str(report_path),
                "target_url": target_url,
                "processed": False  # Not processed yet
            }
            
            with open(metadata_path, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2)
            
        except Exception as e:
            print(f"⚠️  Could not save metadata: {e}")

    def _save_upload_metadata(self, results, report_path, target_url, env_settings):
        """Save metadata about uploaded ZAP report for reuse in DAST scan."""
        try:
            import json
            from datetime import datetime
            from pathlib import Path
            import os
            
            base_dir = self.get_base_directory() if hasattr(self, 'get_base_directory') else Path(os.getcwd())
            metadata_path = base_dir / "AppSecAI_output" / "uploaded_zap_latest.json"
            
            metadata = {
                "upload_timestamp": datetime.now().isoformat(),
                "original_file": str(report_path),
                "target_url": target_url,
                "total_vulnerabilities": results.get('total_vulnerabilities', 0),
                "prioritized_summary": results.get('prioritized_summary', {}),
                "processed": True,
                "environment_settings": env_settings
            }
            
            with open(metadata_path, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2)
            
            print(f"✅ Upload metadata saved for reuse in DAST scan")
            
        except Exception as e:
            # Don't fail if metadata save fails
            pass

    def _check_uploaded_zap_report(self):
        """Check if there's an uploaded ZAP report available."""
        try:
            import json
            from pathlib import Path
            from datetime import datetime
            
            base_dir = self.get_base_directory() if hasattr(self, 'get_base_directory') else Path(os.getcwd())
            metadata_path = base_dir / "AppSecAI_output" / "uploaded_zap_latest.json"
            manual_path = os.environ.get('ZAP_REPORT_PATH', '').strip().strip('"').strip("'").strip()
            
            metadata = None
            
            # 1. Check if we have a manual path that changed and exists
            # Prioritize manual path if it exists and differs from metadata
            if manual_path and os.path.exists(manual_path):
                # If metadata exists, check if it matches the manual path
                if metadata_path.exists():
                    with open(metadata_path, 'r', encoding='utf-8') as f:
                        existing_meta = json.load(f)
                    
                    # If paths are the same, just use existing metadata
                    if existing_meta.get('original_file') == manual_path:
                        metadata = existing_meta
                
                # If no metadata or paths differ, create/use synthetic metadata for the manual path
                if not metadata:
                    metadata = {
                        "upload_timestamp": datetime.fromtimestamp(os.path.getmtime(manual_path)).isoformat(),
                        "original_file": manual_path,
                        "target_url": "Manually configured URL",
                        "total_vulnerabilities": 0,
                        "processed": False
                    }
            
            # 2. Fallback: Check for metadata file alone (for previous uploads)
            elif not metadata and metadata_path.exists():
                with open(metadata_path, 'r', encoding='utf-8') as f:
                    metadata = json.load(f)
                    
            if not metadata:
                return None
            
            # Format timestamp for display
            upload_time = metadata.get('upload_timestamp', '')
            if upload_time:
                try:
                    dt = datetime.fromisoformat(upload_time)
                    upload_time = dt.strftime('%Y-%m-%d %H:%M')
                except:
                    pass
            
            return {
                'upload_time': upload_time,
                'target_url': metadata.get('target_url', 'Unknown'),
                'total_vulnerabilities': metadata.get('total_vulnerabilities', 0),
                'processed': metadata.get('processed', False),
                'metadata': metadata
            }
            
        except Exception as e:
            return None

    def _generate_pdf_report_for_upload(self, results, target_url):
        """Generate PDF security posture report for uploaded ZAP scan (same as DAST)."""
        try:
            from appsecai.reporting.posture_report import SecurityPostureReportGenerator
            from pathlib import Path
            import os
            
            # Get base directory
            base_dir = self.get_base_directory() if hasattr(self, 'get_base_directory') else Path(os.getcwd())
            
            print("🎯 Generating PDF security posture report...")
            
            generator = SecurityPostureReportGenerator(
                input_dir=str(base_dir / "AppSecAI_output"),
                output_dir=str(base_dir / "generated_reports"),
                force_report_type="dast_only"  # DAST-focused report
            )
            
            generator.discover_and_load_data()
            generator.analyze_security_posture()
            pdf_path = generator.generate_pdf_report()
            
            if pdf_path:
                print(f"✅ PDF security posture report generated!")
                print(f"📁 Report location: {pdf_path}")
                
                # Ask to open report like live DAST scans do
                if input("🔍 Open report? (y/N): ").lower().startswith('y'):
                    self._open_reports_directory()
            else:
                print("⚠️  PDF report generation completed (check generated_reports folder)")
                
                # Still offer to open reports directory even if PDF generation had issues
                if input("🔍 Open reports directory? (y/N): ").lower().startswith('y'):
                    self._open_reports_directory()
                
        except Exception as e:
            print(f"⚠️  Could not generate PDF report: {e}")
            # Don't fail the whole process if PDF generation fails

    def _apply_custom_environment_settings(self, env_settings):
        """Apply custom environment settings to the compliance config."""
        try:
            import json
            import os
            
            # Load current compliance config
            compliance_path = "appsecai/risk_profiles/context_modifiers/risk_context_template.json"
            if os.path.exists(compliance_path):
                with open(compliance_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            else:
                config = {"AppSecAI": {}}
            
            # Update environment settings
            if 'AppSecAI' not in config:
                config['AppSecAI'] = {}
            if 'environment' not in config['AppSecAI']:
                config['AppSecAI']['environment'] = {}
            
            env = config['AppSecAI']['environment']
            
            if 'system_criticality' in env_settings:
                env['system_criticality'] = env_settings['system_criticality']
            if 'internet_exposure' in env_settings:
                env['internet_exposure'] = env_settings['internet_exposure']
            if 'data_sensitivity' in env_settings:
                env['data_sensitivity'] = env_settings['data_sensitivity']
            if 'compliance_requirements' in env_settings:
                env['compliance_requirements'] = env_settings['compliance_requirements']
            
            # Save updated config (temporary for this session)
            with open(compliance_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
            
            print("✅ Applied custom environment settings")
            
        except Exception as e:
            print(f"⚠️  Warning: Could not apply custom settings: {e}")

def main():
    """Main entry point for interactive CLI."""
    try:
        app = InteractiveCLI()
        app.start()
    except KeyboardInterrupt:
        print("\n\n👋 Session cancelled by user. Goodbye!")
        import sys
        sys.exit(0)

if __name__ == "__main__":
    main()