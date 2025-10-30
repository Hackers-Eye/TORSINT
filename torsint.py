#!/usr/bin/env python3
"""
████████╗ ██████╗ ██████╗ ███████╗██╗███╗   ██╗████████╗
╚══██╔══╝██╔═══██╗██╔══██╗██╔════╝██║████╗  ██║╚══██╔══╝
   ██║   ██║   ██║██████╔╝███████╗██║██╔██╗ ██║   ██║   
   ██║   ██║   ██║██╔══██╗╚════██║██║██║╚██╗██║   ██║   
   ██║   ╚██████╔╝██║  ██║███████║██║██║ ╚████║   ██║   
   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   

TORSINT - Dark Web Intelligence & Credential Monitoring Platform
Version 2.0 |

PLATFORM:    Kali Linux ARM64 
DEVELOPER:   Krish Ghosh
LICENSE:     Authorized Security Research Only

SECURITY NOTICE:
This tool is designed for legitimate security research and authorized
defensive operations only. Users must comply with all applicable laws
and obtain proper authorization before deployment.

FEATURES:
• Advanced Pattern Recognition
• Tor Network Anonymity
• Real-time Threat Intelligence
• Automated Credential Monitoring
• Enterprise Reporting System
"""

import re
import requests
import time
import json
import os
import sys
import argparse
from datetime import datetime
from stem import Signal
from stem.control import Controller
import threading
from concurrent.futures import ThreadPoolExecutor
import dns.resolver
import hashlib
import base64
import signal

# =============================================================================
# CONFIGURATION SECTION
# =============================================================================
CONFIG = {
    "target_domains": ["yourcompany.com"],
    "scan_interval": 3600,
    "tor_proxy": "socks5h://127.0.0.1:9050",
    "tor_control_port": 9051,
    "max_threads": 3,
    "output_file": "/opt/torsint/reports/findings.json",
    "log_file": "/opt/torsint/logs/operations.log"
}

# =============================================================================
# ERROR HANDLER CLASS
# =============================================================================
class ErrorHandler:
    @staticmethod
    def handle_network_error(error, url, context=""):
        error_msg = f"Network error for {url}: {error}"
        if context:
            error_msg += f" | Context: {context}"
        print(f"[-] {error_msg}")
        ErrorHandler.log_error(error, f"network_{context}")
        return None

    @staticmethod
    def handle_tor_error(error, context=""):
        error_msg = f"Tor error: {error}"
        if context:
            error_msg += f" | Context: {context}"
        print(f"[-] {error_msg}")
        ErrorHandler.log_error(error, f"tor_{context}")
        return False

    @staticmethod
    def handle_file_error(error, filename, context=""):
        error_msg = f"File error for {filename}: {error}"
        if context:
            error_msg += f" | Context: {context}"
        print(f"[-] {error_msg}")
        ErrorHandler.log_error(error, f"file_{context}")
        return False

    @staticmethod
    def handle_parsing_error(error, data_type, context=""):
        error_msg = f"Parsing error for {data_type}: {error}"
        if context:
            error_msg += f" | Context: {context}"
        print(f"[-] {error_msg}")
        ErrorHandler.log_error(error, f"parse_{context}")
        return None

    @staticmethod
    def log_error(error, error_type="unknown"):
        try:
            error_entry = {
                'timestamp': datetime.now().isoformat(),
                'error_type': error_type,
                'error_message': str(error),
                'error_class': type(error).__name__
            }
            # Ensure log directory exists
            os.makedirs(os.path.dirname(CONFIG['log_file']), exist_ok=True)
            with open(CONFIG['log_file'], 'a', encoding='utf-8') as f:
                f.write(f"ERROR: {json.dumps(error_entry)}\n")
        except Exception as log_error:
            print(f"[CRITICAL] Failed to log error: {log_error}")

    @staticmethod
    def safe_execute(func, *args, **kwargs):
        """Safely execute a function with comprehensive error handling"""
        try:
            return func(*args, **kwargs)
        except Exception as e:
            ErrorHandler.log_error(e, f"safe_execute_{func.__name__}")
            return None

# =============================================================================
# ADVANCED MODULE 1: INTELLIGENT PATTERN MATCHING
# =============================================================================
class PatternMatcher:
    def __init__(self):
        self.patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b',
            'credential_pair': r'(?i)(username|email|user|login|account)[\s:=]+([^\s]+)[\s\S]{1,50}?(password|pass|pwd|key)[\s:=]+([^\s]+)',
            'api_key': r'(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)[\s:=]+["\']?([a-zA-Z0-9_\-]{20,50})["\']?',
            'credit_card': r'\b(?:\d[ -]*?){13,16}\b',
            'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'md5_hash': r'\b[a-fA-F0-9]{32}\b',
            'sha1_hash': r'\b[a-fA-F0-9]{40}\b'
        }
    
    def extract_patterns(self, text):
        """Extract multiple pattern types from text with error handling"""
        if not text or not isinstance(text, str):
            return {}
        
        findings = {}
        try:
            for pattern_name, pattern in self.patterns.items():
                try:
                    matches = re.findall(pattern, text)
                    if matches:
                        findings[pattern_name] = matches
                except re.error as e:
                    ErrorHandler.handle_parsing_error(e, f"regex_{pattern_name}")
                    continue
                except Exception as e:
                    ErrorHandler.log_error(e, f"pattern_extraction_{pattern_name}")
                    continue
        except Exception as e:
            ErrorHandler.log_error(e, "extract_patterns_main")
        
        return findings
    
    def validate_email_domain(self, email, target_domains):
        """Validate if email belongs to target domains with error handling"""
        try:
            if not email or not isinstance(email, str):
                return False
            
            if not validate_email(email):
                return False
            
            domain = email.split('@')[-1].lower()
            return any(target_domain.lower() in domain for target_domain in target_domains)
        except Exception as e:
            ErrorHandler.log_error(e, "validate_email_domain")
            return False

# =============================================================================
# ADVANCED MODULE 2: TOR NETWORK MANAGER
# =============================================================================
class TorManager:
    def __init__(self, control_port=9051):
        self.control_port = control_port
        self.session = None
        self.setup_tor_session()
    
    def setup_tor_session(self):
        """Configure requests session for Tor with error handling"""
        try:
            self.session = requests.Session()
            self.session.proxies = {
                'http': CONFIG['tor_proxy'],
                'https': CONFIG['tor_proxy']
            }
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0'
            })
            # Set reasonable timeouts and retry strategy
            self.session.request = lambda method, url, **kwargs: self._safe_request(method, url, **kwargs)
        except Exception as e:
            ErrorHandler.handle_tor_error(e, "session_setup")
    
    def _safe_request(self, method, url, **kwargs):
        """Safe wrapper around requests with timeout and error handling"""
        if 'timeout' not in kwargs:
            kwargs['timeout'] = 30
        try:
            return requests.Session.request(self.session, method, url, **kwargs)
        except Exception as e:
            raise e
    
    def renew_identity(self):
        """Renew Tor circuit with comprehensive error handling and retries"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                with Controller.from_port(port=self.control_port) as controller:
                    controller.authenticate()
                    controller.signal(Signal.NEWNYM)
                    print("[+] Tor circuit renewed - New identity acquired")
                    return True
            except Exception as e:
                error_msg = f"Tor identity renewal failed (attempt {attempt + 1}/{max_retries}): {e}"
                print(f"[-] {error_msg}")
                
                if attempt < max_retries - 1:
                    time.sleep(2)
                else:
                    ErrorHandler.handle_tor_error(e, "identity_renewal")
                    return False
        return False
    
    def make_request(self, url, timeout=30, max_retries=2):
        """Make anonymous request through Tor with comprehensive error handling"""
        if not self.session:
            print("[-] Tor session not initialized")
            return None
        
        for attempt in range(max_retries):
            try:
                response = self.session.get(url, timeout=timeout)
                response.raise_for_status()
                return response.text
                
            except requests.exceptions.Timeout:
                print(f"[-] Request timeout for {url} (attempt {attempt + 1}/{max_retries})")
            except requests.exceptions.ConnectionError as e:
                print(f"[-] Connection error for {url}: {e}")
            except requests.exceptions.HTTPError as e:
                status_code = e.response.status_code if e.response else "Unknown"
                print(f"[-] HTTP error {status_code} for {url}")
                break  # Don't retry on HTTP errors
            except requests.exceptions.RequestException as e:
                print(f"[-] Request exception for {url}: {e}")
            except Exception as e:
                print(f"[-] Unexpected error for {url}: {e}")
            
            if attempt < max_retries - 1:
                time.sleep(3)
        
        return None
    
    def verify_tor_connection(self):
        """Verify Tor connection with fallback and error handling"""
        try:
            test_url = "http://check.torproject.org"
            response = self.session.get(test_url, timeout=30)
            if "Congratulations" in response.text:
                print("[+] Tor connection verified successfully")
                return True
            else:
                print("[-] Tor connection failed - not using Tor network")
                return False
        except requests.exceptions.RequestException as e:
            print(f"[-] Tor verification failed: {e}")
            return False
        except Exception as e:
            ErrorHandler.handle_tor_error(e, "connection_verification")
            return False

# =============================================================================
# ADVANCED MODULE 3: INTELLIGENCE SOURCES
# =============================================================================
class IntelligenceSources:
    def __init__(self, tor_manager):
        self.tor_manager = tor_manager
        self.sources = {
            "paste_sites": [
                "http://pastebin.com/archive",
            ]
        }
    
    def scan_paste_sites(self):
        """Scan paste sites for leaked credentials with comprehensive error handling"""
        findings = []
        print("[*] Scanning paste sites for leaked data...")
        
        for site in self.sources["paste_sites"]:
            print(f"    -> Checking {site}")
            try:
                content = self.tor_manager.make_request(site)
                if content:
                    site_findings = self.analyze_content(content, site)
                    if site_findings:
                        findings.extend(site_findings)
                time.sleep(5)  # Rate limiting
            except Exception as e:
                ErrorHandler.handle_network_error(e, site, "paste_site_scan")
                continue  # Continue with next site even if one fails
        
        return findings
    
    def analyze_content(self, content, source):
        """Analyze content for sensitive information with error handling"""
        if not content or not isinstance(content, str):
            return []
        
        findings = []
        try:
            matcher = PatternMatcher()
            patterns = matcher.extract_patterns(content)
            
            for pattern_type, matches in patterns.items():
                for match in matches:
                    try:
                        if pattern_type == 'email':
                            email = match if isinstance(match, str) else match[0]
                            if matcher.validate_email_domain(email, CONFIG['target_domains']):
                                finding = {
                                    'type': 'EMAIL_LEAK',
                                    'value': email,
                                    'source': source,
                                    'timestamp': datetime.now().isoformat(),
                                    'severity': 'HIGH'
                                }
                                findings.append(finding)
                        elif pattern_type == 'credential_pair':
                            finding = {
                                'type': 'CREDENTIAL_PAIR',
                                'value': str(match),
                                'source': source,
                                'timestamp': datetime.now().isoformat(),
                                'severity': 'CRITICAL'
                            }
                            findings.append(finding)
                    except Exception as e:
                        ErrorHandler.log_error(e, f"process_match_{pattern_type}")
                        continue
        except Exception as e:
            ErrorHandler.handle_parsing_error(e, "content_analysis", source)
        
        return findings

# =============================================================================
# CORE TORSINT ENGINE
# =============================================================================
class TorsintEngine:
    def __init__(self):
        self.banner()
        if not self.validate_environment():
            sys.exit(1)
        
        self.tor_manager = TorManager()
        self.pattern_matcher = PatternMatcher()
        self.intel_sources = IntelligenceSources(self.tor_manager)
        self.running = False
        
        # Setup signal handlers for graceful shutdown
        self.setup_signal_handlers()
    
    def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            print(f"\n[*] Received signal {signum}. Shutting down gracefully...")
            self.shutdown()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def banner(self):
        """Display Torsint banner"""
        print(__doc__)
    
    def validate_environment(self):
        """Validate the execution environment with comprehensive checks"""
        print("[*] Validating environment...")
        
        # Check configuration first
        if CONFIG['target_domains'] == ["yourcompany.com"]:
            print("[-] ERROR: Please configure target domains in CONFIG section!")
            print("[-] Edit the CONFIG dictionary at the top of torsint.py")
            return False
        
        # Check if required directories exist or create them
        required_dirs = [
            os.path.dirname(CONFIG['output_file']),
            os.path.dirname(CONFIG['log_file'])
        ]
        
        for dir_path in required_dirs:
            try:
                os.makedirs(dir_path, exist_ok=True)
                print(f"[+] Ensured directory exists: {dir_path}")
            except Exception as e:
                print(f"[-] Failed to create directory {dir_path}: {e}")
                return False
        
        # Check Tor connection
        if not self.check_tor_connection():
            print("[-] Tor connection failed! Please ensure Tor is running.")
            print("    Run: sudo systemctl start tor")
            return False
        
        print("[+] Environment validation passed")
        return True
    
    def check_tor_connection(self):
        """Check if Tor connection is working with error handling"""
        try:
            if hasattr(self, 'tor_manager') and self.tor_manager:
                return self.tor_manager.verify_tor_connection()
            else:
                temp_tor = TorManager()
                return temp_tor.verify_tor_connection()
        except Exception as e:
            ErrorHandler.handle_tor_error(e, "connection_check")
            return False
    
    def scan_cycle(self):
        """Execute one complete scan cycle with comprehensive error handling"""
        print("\n[*] Starting Torsint intelligence cycle...")
        all_findings = []
        
        try:
            # Scan paste sites
            paste_findings = self.intel_sources.scan_paste_sites()
            if paste_findings:
                all_findings.extend(paste_findings)
            
            # Process and save findings
            for finding in all_findings:
                try:
                    self.save_finding(finding)
                    self.alert_finding(finding)
                except Exception as e:
                    ErrorHandler.log_error(e, "process_finding")
                    continue  # Continue with next finding even if one fails
        
        except Exception as e:
            ErrorHandler.log_error(e, "scan_cycle_main")
            print(f"[-] Error in scan cycle: {e}")
        
        return all_findings
    
    def save_finding(self, finding):
        """Save finding with comprehensive file operation error handling"""
        try:
            output_file = CONFIG['output_file']
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            # Initialize file if it doesn't exist or is corrupted
            if not os.path.exists(output_file):
                initial_data = {"findings": [], "metadata": {}}
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(initial_data, f, indent=2)
            
            # Read existing data
            try:
                with open(output_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                # If file is corrupted or doesn't exist, reinitialize
                data = {"findings": [], "metadata": {}}
            
            # Update data
            if 'findings' not in data:
                data['findings'] = []
            if 'metadata' not in data:
                data['metadata'] = {}
            
            data['findings'].append(finding)
            data['metadata']['last_updated'] = datetime.now().isoformat()
            data['metadata']['total_findings'] = len(data['findings'])
            
            # Write back to file
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            ErrorHandler.handle_file_error(e, CONFIG['output_file'], "save_finding")
    
    def alert_finding(self, finding):
        """Alert about important findings with error handling"""
        try:
            if finding.get('severity') in ['CRITICAL', 'HIGH']:
                print(f"\n[!] ALERT: {finding['severity']} severity finding!")
                print(f"    Type: {finding.get('type', 'Unknown')}")
                print(f"    Value: {finding.get('value', 'Unknown')[:100]}...")
                print(f"    Source: {finding.get('source', 'Unknown')}")
                print(f"    Time: {finding.get('timestamp', 'Unknown')}")
                print("    " + "="*50)
        except Exception as e:
            ErrorHandler.log_error(e, "alert_finding")
    
    def continuous_monitoring(self):
        """Start continuous monitoring with comprehensive error handling"""
        self.running = True
        cycle_count = 0
        consecutive_errors = 0
        max_consecutive_errors = 5
        
        print("[*] Starting Torsint continuous monitoring...")
        print(f"[*] Scan interval: {CONFIG['scan_interval']} seconds")
        print(f"[*] Target domains: {', '.join(CONFIG['target_domains'])}")
        print("[*] Press Ctrl+C to stop monitoring\n")
        
        try:
            while self.running and consecutive_errors < max_consecutive_errors:
                cycle_count += 1
                print(f"\n[+] Monitoring Cycle #{cycle_count}")
                print(f"    Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                
                try:
                    findings = self.scan_cycle()
                    
                    if findings:
                        print(f"[+] Cycle completed: Found {len(findings)} new items")
                        consecutive_errors = 0  # Reset error counter on success
                    else:
                        print("[+] Cycle completed: No new findings")
                        consecutive_errors = 0  # Reset error counter on successful scan
                
                except Exception as e:
                    consecutive_errors += 1
                    print(f"[-] Error in cycle {cycle_count} (consecutive errors: {consecutive_errors}): {e}")
                    ErrorHandler.log_error(e, f"monitoring_cycle_{cycle_count}")
                
                # Display summary report every 5 cycles
                if cycle_count % 5 == 0:
                    try:
                        print("\n" + "="*60)
                        report = self.generate_report()
                        print(report)
                        print("="*60)
                    except Exception as e:
                        ErrorHandler.log_error(e, "report_generation")
                
                # Renew Tor identity every 2 cycles
                if cycle_count % 2 == 0:
                    try:
                        self.tor_manager.renew_identity()
                    except Exception as e:
                        ErrorHandler.log_error(e, "tor_renewal")
                
                # Safe sleep with interrupt checking
                if consecutive_errors < max_consecutive_errors:
                    try:
                        for _ in range(CONFIG['scan_interval']):
                            if not self.running:
                                break
                            time.sleep(1)
                    except KeyboardInterrupt:
                        print("\n[*] Monitoring interrupted by user")
                        break
                
        except Exception as e:
            ErrorHandler.log_error(e, "continuous_monitoring_main")
            print(f"[-] Critical error in monitoring loop: {e}")
        finally:
            self.shutdown()
    
    def shutdown(self):
        """Clean shutdown of Torsint with error handling"""
        self.running = False
        print("\n[*] Torsint is shutting down...")
        try:
            report = self.generate_report()
            print("[+] Final report:")
            print(report)
        except Exception as e:
            ErrorHandler.log_error(e, "shutdown_report")
            print("[-] Could not generate final report")
        
        print("[+] Thank you for using Torsint!")
    
    def generate_report(self):
        """Generate summary report with error handling"""
        try:
            if not os.path.exists(CONFIG['output_file']):
                return "No findings report available yet."
            
            with open(CONFIG['output_file'], 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            findings = data.get('findings', [])
            critical_count = len([f for f in findings if f.get('severity') == 'CRITICAL'])
            high_count = len([f for f in findings if f.get('severity') == 'HIGH'])
            
            report = f"""
▓▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀ TORSINT REPORT ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▓

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total Findings: {len(findings)}
Critical Findings: {critical_count}
High Severity Findings: {high_count}
Target Domains: {', '.join(CONFIG['target_domains'])}

Recent Findings:
"""
            for finding in findings[-10:]:
                value_preview = str(finding.get('value', ''))[:50]
                report += f"  • [{finding.get('severity', 'UNKNOWN')}] {finding.get('type', 'UNKNOWN')}: {value_preview}...\n"
            
            report += "▓▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▓"
            
            return report
        except Exception as e:
            ErrorHandler.log_error(e, "generate_report")
            return f"Error generating report: {e}"

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================
def validate_email(email):
    """Validate email format with error handling"""
    try:
        if not email or not isinstance(email, str):
            return False
        regex_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
        return re.fullmatch(regex_pattern, email) is not None
    except Exception as e:
        ErrorHandler.log_error(e, "validate_email")
        return False

def print_usage_guide():
    """Print usage guide"""
    guide = """
▓▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀ TORSINT USAGE GUIDE ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▓

Basic Usage:
  torsint                         # Continuous monitoring
  torsint -s                      # Single scan
  torsint -d company.com          # Target specific domain
  torsint -i 1800 -s              # 30min interval, single scan

Features:
  • Multi-pattern credential detection
  • Tor anonymity with circuit renewal
  • JSON logging and reporting
  • Real-time alerts for critical findings
  • Domain validation and data enrichment

Legal Requirements:
  ✓ Only scan authorized domains
  ✓ Obtain proper permissions
  ✓ Follow ethical guidelines
  ✓ Respect privacy laws

▓▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▓
"""
    print(guide)

# =============================================================================
# MAIN EXECUTION
# =============================================================================
def main():
    """Main function with top-level error handling"""
    try:
        parser = argparse.ArgumentParser(description='Torsint - Dark Web Intelligence Tool')
        parser.add_argument('-d', '--domains', help='Target domains (comma-separated)')
        parser.add_argument('-i', '--interval', type=int, help='Scan interval in seconds')
        parser.add_argument('-s', '--single', action='store_true', help='Single scan mode')
        
        args = parser.parse_args()
        
        # Update configuration from command line with validation
        if args.domains:
            try:
                domains = [domain.strip() for domain in args.domains.split(',')]
                if domains and all(domains):
                    CONFIG['target_domains'] = domains
                else:
                    print("[-] Invalid domains provided")
                    return 1
            except Exception as e:
                print(f"[-] Error parsing domains: {e}")
                return 1
        
        if args.interval:
            if args.interval > 0:
                CONFIG['scan_interval'] = args.interval
            else:
                print("[-] Interval must be positive")
                return 1
        
        # Initialize and run Torsint engine
        torsint = TorsintEngine()
        
        if args.single:
            findings = torsint.scan_cycle()
            print("\n" + torsint.generate_report())
        else:
            torsint.continuous_monitoring()
        
        return 0
        
    except KeyboardInterrupt:
        print("\n[*] Torsint terminated by user")
        return 0
    except Exception as e:
        ErrorHandler.log_error(e, "main_function")
        print(f"[-] Critical error in Torsint: {e}")
        return 1

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help']:
        print_usage_guide()
    else:
        exit_code = main()
        sys.exit(exit_code)