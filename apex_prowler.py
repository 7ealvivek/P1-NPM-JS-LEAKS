#!/usr/bin/env python3

import os
import sys
import subprocess
import argparse
import json
import datetime
import shutil
import concurrent.futures
import time
import requests
from threading import Lock

# --- Configuration ---
# EDIT THESE VALUES
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/T03JPK11LNM/B0908RQP1GB/hrmkhkKGbO72J0OMa9g4kb0"

# Paths to tools if they are not in your system's PATH
# Example: GITLEAKS_PATH = "/home/user/tools/gitleaks"
# Leave as is if they are in your PATH.
TOOL_PATHS = {
    "katana": "katana", "httpx": "httpx", "gau": "gau", "subjs": "subjs",
    "nuclei": "nuclei", "gitleaks": "gitleaks", "secretfinder": "secretfinder",
    "js-beautify": "js-beautify", "keyscope": "keyscope"
}

# Heuristics for Dependency Confusion
PUBLIC_PACKAGE_BLOCKLIST = [
    'react', 'react-dom', 'vue', 'angular', 'jquery', 'lodash', 'moment', 'express',
    'axios', 'webpack', 'next', 'nuxt', 'svelte', 'redux', 'jest', 'eslint', 'babel',
    'typescript', 'core-js', 'bootstrap', 'd3', 'three', 'material-ui'
]
PRIVATE_PACKAGE_KEYWORDS = ['internal', '-api', 'private', '-sdk', 'corp', 'confidential']

# --- Color & Logging Setup ---
class C:
    RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE, END = '\033[91m', '\033[92m', '\033[93m', '\033[94m', '\033[95m', '\033[96m', '\033[97m', '\033[0m'

log_lock = Lock()
def log(level, message):
    with log_lock:
        color_map = {"INFO": C.BLUE, "SUCCESS": C.GREEN, "WARN": C.YELLOW, "ERROR": C.RED, "TASK": C.CYAN, "FINDING": C.MAGENTA}
        print(f"{color_map.get(level, C.WHITE)}[{level.ljust(7)}] {C.END}{message}")

# --- Banner ---
def display_banner():
    banner = f"""
{C.BLUE}
        ____  _   _
       / ___|| | | |  ___  _ __
       \\___ \\| |_| | / _ \\| '_ \\
        ___) |  _  ||  __/| | | |
       |____/|_| |_| \\___||_| |_|

{C.WHITE}   A  P  E  X     P  R  O  W  L  E  R{C.END}
{C.MAGENTA}   -------------------------------------
      {C.GREEN}Bugcrowd:  bugcrowd.com/realvivek
      {C.CYAN}X/Twitter: x.com/starkcharry
      {C.WHITE}GitHub:    github.com/7ealvivek
{C.MAGENTA}   -------------------------------------
{C.END}"""
    print(banner)
    time.sleep(0.5)

# --- Tool Runner & Dependency Check ---
def check_tools():
    log("INFO", "Checking for required tools...")
    for tool, path in TOOL_PATHS.items():
        if not shutil.which(path):
            log("ERROR", f"Tool '{tool}' not found at path '{path}'. Please install it or correct the path in TOOL_PATHS.")
            sys.exit(1)
    log("SUCCESS", "All required tools are installed.")

def run_command(command, log_file=None):
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if log_file:
        with open(log_file, 'w') as f:
            f.write(process.stdout)
    if process.returncode != 0:
        log("WARN", f"Command failed with exit code {process.returncode}: {command}")
        log("WARN", f"Stderr: {process.stderr.strip()}")
    return process.stdout

# --- Slack Notifier ---
def send_slack_alert(data):
    try:
        requests.post(SLACK_WEBHOOK_URL, json=data, timeout=10)
    except requests.RequestException as e:
        log("ERROR", f"Failed to send Slack alert: {e}")

def format_slack_message(status, tool, sev, type, details, url):
    color_map = {"VERIFIED": "#FF0000", "DEP_CONFUSION": "#D2691E", "UNVERIFIED": "#FFA500"}
    emoji_map = {"VERIFIED": "🔥", "DEP_CONFUSION": "⛓️", "UNVERIFIED": "⚠️"}

    return {
        "attachments": [{
            "color": color_map.get(status, "#FFA500"),
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": f"{emoji_map.get(status, ' ')} {sev.upper()} Finding", "emoji": True}},
                {"type": "section", "fields": [
                    {"type": "mrkdwn", "text": f"*Scanner:*\n{tool}"},
                    {"type": "mrkdwn", "text": f"*Source:*\n<{url}>"}
                ]},
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*Vulnerability/Package:*\n`{type}`"}},
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*Details:*\n```{details}```"}}
            ]
        }]
    }

# --- Scanner Modules ---
def run_discovery(hosts_file, ips_file, use_gau, output_dir):
    log("TASK", "Starting asset discovery...")
    raw_js_file = os.path.join(output_dir, "js_urls.raw")

    commands = []
    if os.path.exists(hosts_file) and os.path.getsize(hosts_file) > 0:
        if use_gau:
            log("INFO", "GAU is enabled for deep discovery.")
            commands.append(f"{TOOL_PATHS['gau']} --threads 10 --providers wayback,otx,commoncrawl < {hosts_file} >> {raw_js_file}")
        commands.append(f"{TOOL_PATHS['subjs']} -i {hosts_file} -c 25 >> {raw_js_file}")
        commands.append(f"{TOOL_PATHS['katana']} -silent -list {hosts_file} -jc -d 5 -c 25 >> {raw_js_file}")

    if os.path.exists(ips_file) and os.path.getsize(ips_file) > 0:
        commands.append(f"{TOOL_PATHS['katana']} -silent -list {ips_file} -jc -d 3 >> {raw_js_file}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(commands)) as executor:
        executor.map(run_command, commands)

    log("INFO", "De-duplicating and verifying live JS URLs...")
    js_urls_file = os.path.join(output_dir, "js_urls.txt")
    run_command(f"sort -u {raw_js_file} | {TOOL_PATHS['httpx']} -silent -mc 200 > {js_urls_file}")
    
    with open(js_urls_file) as f:
        count = sum(1 for _ in f)
    log("SUCCESS", f"Discovery complete. Found {count} live JavaScript files.")
    return js_urls_file

def run_dependency_confusion(hosts_file, output_dir):
    log("TASK", "Scanning for Dependency Confusion...")
    package_json_urls_file = os.path.join(output_dir, "exposed_package_jsons.txt")
    run_command(f"{TOOL_PATHS['httpx']} -l {hosts_file} -path /package.json -mc 200 -silent > {package_json_urls_file}")
    
    if not os.path.exists(package_json_urls_file) or os.path.getsize(package_json_urls_file) == 0:
        log("INFO", "No exposed package.json files found.")
        return

    log("SUCCESS", f"Found exposed package.json files! Analyzing dependencies...")
    with open(package_json_urls_file) as f:
        for url in f:
            url = url.strip()
            try:
                r = requests.get(url, timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
                    for pkg in deps:
                        if pkg in PUBLIC_PACKAGE_BLOCKLIST: continue

                        # Check if package exists on public NPM registry
                        npm_url = f"https://registry.npmjs.org/{pkg}"
                        npm_check = requests.head(npm_url, timeout=5)
                        if npm_check.status_code == 404:
                            # It doesn't exist. Now check for private name heuristics.
                            is_private_name = any(kw in pkg for kw in PRIVATE_PACKAGE_KEYWORDS)
                            
                            if is_private_name:
                                log("FINDING", f"HIGH-CONFIDENCE Dependency Confusion: {pkg} from {url}")
                                details = f"High-confidence private package '{pkg}' is NOT registered on public NPM. It was found in an exposed package.json and matches private naming heuristics."
                                alert = format_slack_message("DEP_CONFUSION", "Package Prowler", "Critical", pkg, details, url)
                                send_slack_alert(alert)

            except Exception as e:
                log("WARN", f"Could not analyze package.json from {url}: {e}")

def run_secrets_scan(js_urls_file, output_dir):
    log("TASK", "Scanning for Hardcoded Secrets...")
    secrets_output = os.path.join(output_dir, "secrets_findings")
    os.makedirs(secrets_output, exist_ok=True)
    
    commands = [
        f"{TOOL_PATHS['nuclei']} -l {js_urls_file} -t exposures/tokens/ -s critical,high -json -o {os.path.join(secrets_output, 'nuclei.json')}",
        f"{TOOL_PATHS['secretfinder']} -i {js_urls_file} --json -o {os.path.join(secrets_output, 'secretfinder.json')}"
    ]
    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.map(run_command, commands)
        
    log("INFO", "Downloading JS files for Gitleaks deep scan...")
    js_content_dir = os.path.join(output_dir, "js_content")
    os.makedirs(js_content_dir, exist_ok=True)
    run_command(f"xargs -a {js_urls_file} -n 1 -P 10 wget -q -P {js_content_dir} --no-check-certificate")
    
    # Beautify JS for better scanning
    for filename in os.listdir(js_content_dir):
        run_command(f"{TOOL_PATHS['js-beautify']} -f {os.path.join(js_content_dir, filename)} -o {os.path.join(js_content_dir, filename)}")
        
    run_command(f"{TOOL_PATHS['gitleaks']} detect -s {js_content_dir} --no-git -r {os.path.join(secrets_output, 'gitleaks.json')}")

    log("SUCCESS", "Initial secret scan complete. Consolidating findings...")
    return consolidate_and_verify_secrets(secrets_output, js_urls_file)

def consolidate_and_verify_secrets(scan_dir, js_urls_file):
    log("TASK", "Consolidating and Verifying Secrets...")
    all_secrets = set()
    raw_findings = []

    # Parse Nuclei
    try:
        with open(os.path.join(scan_dir, "nuclei.json")) as f:
            for line in f:
                d = json.loads(line)
                secret = d.get('extracted-results', [d.get('matcher-name', 'N/A')])[0]
                all_secrets.add(secret)
                raw_findings.append({'tool': 'Nuclei', 'secret': secret, 'type': d['template-id'], 'url': d['host']})
    except FileNotFoundError: pass

    # Parse Gitleaks
    try:
        with open(os.path.join(scan_dir, 'gitleaks.json')) as f:
            data = json.load(f)
            for d in data:
                all_secrets.add(d['Secret'])
                filename = os.path.basename(d['File'])
                url = next((line.strip() for line in open(js_urls_file) if filename in line), d['File'])
                raw_findings.append({'tool': 'Gitleaks', 'secret': d['Secret'], 'type': d['Description'], 'url': url})
    except (FileNotFoundError, json.JSONDecodeError): pass

    # Parse SecretFinder
    try:
        with open(os.path.join(scan_dir, 'secretfinder.json')) as f:
            data = json.load(f)
            for d in data.get('results', []):
                 all_secrets.add(d['secret'])
                 raw_findings.append({'tool': 'SecretFinder', 'secret': d['secret'], 'type': d['type_of_secret'], 'url': d['url']})
    except (FileNotFoundError, json.JSONDecodeError): pass
    
    if not all_secrets:
        log("INFO", "No potential secrets found to verify.")
        return
        
    secrets_to_verify_file = os.path.join(scan_dir, "secrets_to_verify.txt")
    with open(secrets_to_verify_file, 'w') as f:
        f.write('\n'.join(all_secrets))

    log("INFO", f"Verifying {len(all_secrets)} unique potential secrets with Keyscope...")
    verified_file = os.path.join(scan_dir, "verified.json")
    run_command(f"{TOOL_PATHS['keyscope']} -f {secrets_to_verify_file} --json -o {verified_file}")
    
    verified_secrets = set()
    try:
        with open(verified_file) as f:
            data = json.load(f)
            for finding in data.get('findings', []):
                if finding.get('verified') is True:
                    verified_secrets.add(finding['secret_value'])
    except (FileNotFoundError, json.JSONDecodeError): pass
        
    log("SUCCESS", f"Verification complete. Found {len(verified_secrets)} confirmed, active secrets.")
    
    # Final Reporting Loop
    for finding in raw_findings:
        if finding['secret'] in verified_secrets:
            log("FINDING", f"VERIFIED CRITICAL secret found by {finding['tool']} in {finding['url']}")
            alert = format_slack_message("VERIFIED", finding['tool'], "Verified Critical", finding['type'], finding['secret'], finding['url'])
        else:
            log("FINDING", f"UNVERIFIED secret found by {finding['tool']} in {finding['url']}")
            alert = format_slack_message("UNVERIFIED", finding['tool'], "High", finding['type'], finding['secret'], finding['url'])
        send_slack_alert(alert)


# --- Main Orchestrator ---
def main():
    parser = argparse.ArgumentParser(description="Apex Prowler - Automated Secret & Dependency Confusion Hunter")
    parser.add_argument('-t', '--targets', required=True, help="Path to a file containing target hosts, one per line.")
    parser.add_argument('-g', '--use-gau', action='store_true', help="Enable GAU for deep discovery from web archives (slower).")
    parser.add_argument('-p', '--dep-confusion', action='store_true', help="Enable the Dependency Confusion scanning module.")
    parser.add_argument('--no-secrets', action='store_true', help="Disable the hardcoded secrets scanning module.")

    args = parser.parse_args()
    
    display_banner()
    check_tools()

    output_dir = os.path.join("results", f"apex_prowler_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}")
    os.makedirs(output_dir, exist_ok=True)
    log("INFO", f"Results will be saved in: {output_dir}")

    # Normalize targets
    hosts_file = os.path.join(output_dir, "targets.hosts")
    ips_file = os.path.join(output_dir, "targets.ips")
    with open(args.targets) as f_in, open(hosts_file, 'w') as f_hosts, open(ips_file, 'w') as f_ips:
        for line in f_in:
            line = line.strip().replace("https://", "").replace("http://", "").split('/')[0]
            if line:
                # Basic IP regex
                if all(c.isdigit() or c == '.' for c in line) and line.count('.') == 3:
                     f_ips.write(line + '\n')
                else:
                     f_hosts.write(line + '\n')

    # Main workflow
    js_urls_file = run_discovery(hosts_file, ips_file, args.use_gau, output_dir)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = []
        if args.dep_confusion:
            futures.append(executor.submit(run_dependency_confusion, hosts_file, output_dir))
        if not args.no_secrets and os.path.exists(js_urls_file) and os.path.getsize(js_urls_file) > 0:
            futures.append(executor.submit(run_secrets_scan, js_urls_file, output_dir))
        
        # Wait for all tasks to complete
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as e:
                log("ERROR", f"A scanning module failed: {e}")

    log("SUCCESS", "Apex Prowler scan complete.")

if __name__ == "__main__":
    main()
