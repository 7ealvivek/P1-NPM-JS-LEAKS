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
import re
from threading import Lock

# Suppress only the InsecureRequestWarning from urllib3
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# --- Configuration ---
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/T03JPK11LNM/B0908RQP1GB/hrmkhkKGbO72J0OMa9g4kb0"
CUSTOM_GITLEAKS_CONFIG_PATH = "./custom-gitleaks.toml"
TOOL_PATHS = {
    "katana": "katana", "httpx": "httpx", "gau": "gau", "subjs": "subjs",
    "nuclei": "nuclei", "gitleaks": "gitleaks", "secretfinder": "secretfinder",
    "mantra": "mantra", "js-beautify": "js-beautify", "keyscope": "keyscope"
}
PUBLIC_PACKAGE_BLOCKLIST = ['react','react-dom','vue','angular','jquery','lodash','moment','express','axios','webpack']

# --- UI & Helper Functions ---
class C: RED,GREEN,YELLOW,BLUE,MAGENTA,CYAN,WHITE,END='\033[91m','\033[92m','\033[93m','\033[94m','\033[95m','\033[96m','\033[97m','\033[0m'
log_lock=Lock()
def log(level, message, overwrite=False):
    end_char = '\r' if overwrite else '\n'
    with log_lock:
        sys.stdout.write(f"{' ' * 120}\r");sys.stdout.flush()
        color_map={"INFO":C.BLUE,"SUCCESS":C.GREEN,"WARN":C.YELLOW,"ERROR":C.RED,"TASK":C.CYAN,"FINDING":C.MAGENTA}
        sys.stdout.write(f"{color_map.get(level,C.WHITE)}[{level.ljust(7)}] {C.END}{message}{end_char}");sys.stdout.flush()
def display_banner():
    print(f"""{C.BLUE}
        ____  _   _             ____  _
       / ___|| | | |  ___  _ __ / ___|| |__   __ _ _ __   __ _  ___
       \\___ \\| |_| | / _ \\| '_ \\\\___ \\| '_ \\ / _` | '_ \\ / _` |/ _ \\
        ___) |  _  ||  __/| | | |___) | | | | (_| | | | | (_| |  __/
       |____/|_| |_| \\___||_| |_|____/|_| |_|\\__,_|_| |_|\\__, |\\___|
{C.WHITE}   A  P  E  X     P  R  O  W  L  E  R          |___/  {C.MAGENTA}v3.1{C.END}
{C.MAGENTA}   ------------------------------------------------------------
      {C.GREEN}Bugcrowd:  bugcrowd.com/realvivek
      {C.CYAN}X/Twitter: x.com/starkcharry
      {C.WHITE}GitHub:    github.com/7ealvivek
{C.MAGENTA}   ------------------------------------------------------------
{C.END}""");time.sleep(0.5)
def check_tools():
    log("TASK","Checking for required tools...")
    if not os.path.exists(CUSTOM_GITLEAKS_CONFIG_PATH):log("ERROR",f"Gitleaks config not found at: {CUSTOM_GITLEAKS_CONFIG_PATH}. Please create it.");sys.exit(1)
    for tool in TOOL_PATHS:
        if not shutil.which(TOOL_PATHS[tool]): log("ERROR",f"Tool '{tool}' not found.");sys.exit(1)
    log("SUCCESS","All required tools are installed.")
def run_command(command):
    try:
        p=subprocess.run(command,shell=True,capture_output=True,text=True,check=False)
        if p.returncode not in [0,1,2]: log("WARN", f"Command exited non-zero (code {p.returncode}): {command.split()[0]}...")
        return p
    except FileNotFoundError:log("ERROR", f"Command not found: {command.split()[0]}.");sys.exit(1)
def send_slack_alert(data):
    if not SLACK_WEBHOOK_URL or "XXX" in SLACK_WEBHOOK_URL:return
    try:requests.post(SLACK_WEBHOOK_URL,json=data,timeout=10)
    except requests.RequestException:pass
def format_slack_message(status,tool,sev,finding_type,details,url):
    colors={"VERIFIED":"#FF0000","HIGH_CONFIDENCE":"#D2691E"};emojis={"VERIFIED":"🔥","HIGH_CONFIDENCE":"🌟"}
    return{"attachments":[{"color":colors.get(status,"#FFA500"),"blocks":[
        {"type":"header","text":{"type":"plain_text","text":f"{emojis.get(status,' ')} {sev.upper()} Finding","emoji":True}},
        {"type":"section","fields":[{"type":"mrkdwn","text":f"*Scanner:*\n{tool}"},{"type":"mrkdwn","text":f"*Source:*\n<{url}>"}]},
        {"type":"section","text":{"type":"mrkdwn","text":f"*Finding/Package:*\n`{finding_type}`"}},
        {"type":"section","text":{"type":"mrkdwn","text":f"*Details:*\n```{details}```"}}]}]}

# --- Core Modules ---
def run_discovery(hosts_file,direct_js_file,output_dir,use_gau):
    log("TASK","Phase 1: Asset Discovery",overwrite=True);raw_js_file=os.path.join(output_dir,"js.raw");open(raw_js_file,'a').close();cmds=[]
    if os.path.exists(hosts_file)and os.path.getsize(hosts_file)>0:
        if use_gau:log("INFO", "GAU is enabled for deep discovery.")
        cmds.extend([f"{TOOL_PATHS['subjs']} -i {hosts_file} -c 25 >> {raw_js_file}",f"{TOOL_PATHS['katana']} -silent -list {hosts_file} -jc -d 5 >> {raw_js_file}"])
        if use_gau:cmds.append(f"{TOOL_PATHS['gau']} -t 10 < {hosts_file} >> {raw_js_file}")
    if cmds:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(cmds))as e:e.map(run_command,cmds)
    final_urls_file=os.path.join(output_dir,"js.txt");run_command(f"cat {raw_js_file} {direct_js_file} 2>/dev/null|sort -u|{TOOL_PATHS['httpx']} -silent -mc 200 > {final_urls_file}");count=0
    if os.path.exists(final_urls_file):
        with open(final_urls_file)as f:count=sum(1 for _ in f)
    log("SUCCESS",f"Phase 1 Complete. Found {C.YELLOW}{count}{C.END} live JS files for analysis.");return final_urls_file

def run_secrets_scan(js_urls_file,output_dir):
    log("TASK","Phase 2: Initial Parallel Scan",overwrite=True);so=os.path.join(output_dir,"findings");os.makedirs(so,exist_ok=True)
    sc=[f"{TOOL_PATHS['nuclei']} -l {js_urls_file} -t exposures/tokens/ -s critical,high -j -o {os.path.join(so,'nuclei.json')} -silent",f"cat {js_urls_file}|{TOOL_PATHS['mantra']} -s > {os.path.join(so,'mantra.txt')}",f"secretfinder -i {js_urls_file} -o {os.path.join(so,'sf_report.html')}"]
    with concurrent.futures.ThreadPoolExecutor(max_workers=3)as e:list(e.map(run_command,sc))
    log("SUCCESS","Phase 2 Complete. Initial scanners finished.")
    log("TASK","Phase 3: Deep Scan with Gitleaks",overwrite=True);jcd=os.path.join(output_dir,"js_content");os.makedirs(jcd,exist_ok=True)
    run_command(f"cat {js_urls_file}|xargs -n 1 -P 10 wget -q -P {jcd} --no-check-certificate")
    for fn in os.listdir(jcd):
        if os.path.isfile(os.path.join(jcd,fn)):run_command(f"{TOOL_PATHS['js-beautify']} -r {os.path.join(jcd,fn)}")
    run_command(f"{TOOL_PATHS['gitleaks']} detect -s {jcd} --no-git -r {os.path.join(so,'gitleaks.json')} -c {CUSTOM_GITLEAKS_CONFIG_PATH}")
    log("SUCCESS","Phase 3 Complete. Deep scan finished.");consolidate_and_verify(so,js_urls_file)

def consolidate_and_verify(scan_dir,js_urls_file):
    log("TASK","Phase 4: Consolidating Findings...",overwrite=True)
    raw_findings, all_secrets = [], set()
    total_findings = 0
    
    # --- Parser Definitions ---
    parsers = {
        "Nuclei": ("nuclei.json", "jsonl"),
        "Gitleaks": ("gitleaks.json", "json"),
        "Mantra": ("mantra.txt", "text"),
        "SecretFinder": ("sf_report.html", "html")
    }

    # --- Master Parsing Loop with Transparent Logging ---
    for tool, (filename, file_type) in parsers.items():
        count = 0
        file_path = os.path.join(scan_dir, filename)
        if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
            log("INFO", f"  -> No output from {tool} to process.")
            continue
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                if file_type == "html":
                    content = f.read()
                    blocks = re.findall(r'<h6>(.*?)</h6>.*?<ul>(.*?)</ul>', content, re.DOTALL)
                    for url, findings_html in blocks:
                        for item in re.findall(r'<li>(.*?)</li>', findings_html):
                            if ':' in item:
                                parts = item.split(':', 1); f_type, secret = parts[0].strip(), parts[1].strip()
                                all_secrets.add(secret); raw_findings.append({'tool':tool,'secret':secret,'type':f_type,'url':url.strip()}); count+=1
                else:
                    lines = f.readlines() if file_type in ["jsonl", "text"] else [f.read()]
                    for line in lines:
                        if not line.strip(): continue
                        if file_type == "jsonl": item = json.loads(line)
                        elif file_type == "json": item = json.loads(line) # Handles single JSON object file
                        else: item = line

                        if tool == "Nuclei": s, m = item.get('extracted-results',[item.get('matcher-name','N/A')])[0], {'type': item['template-id'],'url':item['host']}
                        elif tool == "Gitleaks": s, m = item['Secret'], {'type':item['Description'],'url':next((l.strip() for l in open(js_urls_file)if os.path.basename(item['File'])in l),item['File'])}
                        elif tool == "Mantra":
                            if "found in"in item and "secret"in item: p=item.split();s=p[p.index("secret:")+1].strip("'");m={'type':item.split('[')[1].split(']')[0],'url':p[p.index("in")+1]}
                            else: continue
                        
                        all_secrets.add(s); raw_findings.append({'tool':tool,'secret':s,**m}); count+=1
                        if file_type == "json" and isinstance(json.loads(line), list): break # Gitleaks is a list in a single json file
            log("INFO", f"  -> Consolidated {count} findings from {tool}.")
            total_findings += count
        except Exception as e:
            log("WARN", f"  -> Failed to parse output from {tool}. Error: {e}")

    # --- Verification and Alerting ---
    if not all_secrets:log("SUCCESS","Phase 4 Complete. No potential secrets found.");return
    log("INFO",f"Phase 4 Complete. Total raw findings: {total_findings}. Verifying {len(all_secrets)} unique secrets...",overwrite=True)
    sf=os.path.join(scan_dir,"secrets.txt");vf=os.path.join(scan_dir,"verified.json")
    with open(sf,'w')as f:f.write('\n'.join(s for s in all_secrets if s))
    run_command(f"{TOOL_PATHS['keyscope']} -f {sf} --json -o {vf}")
    verified_secrets=set()
    try:
        with open(vf) as f:
            for find in json.load(f).get('findings',[]):
                if find.get('verified')is True:verified_secrets.add(find['secret_value'])
    except Exception:pass
    log("SUCCESS",f"Phase 5 Complete. Verification found {C.YELLOW}{len(verified_secrets)}{C.END} active secrets.")
    log("TASK","Phase 6: Reporting High-Priority Findings...",overwrite=True)
    sent_secrets=set()
    for finding in raw_findings:
        secret=finding.get('secret')
        if not secret or secret in sent_secrets:continue
        
        is_verified=secret in verified_secrets
        is_high_confidence=finding['tool']=='Gitleaks'
        
        if is_verified: status,sev,color="VERIFIED","Verified Critical",C.RED
        elif is_high_confidence: status,sev,color="HIGH_CONFIDENCE","High-Confidence",C.YELLOW
        else: continue
            
        log("FINDING",f"{'🔥'if is_verified else'🌟'} {color}[{sev.upper()}]{C.END} [{finding['tool']}] {finding['type']}")
        log("FINDING",f"{C.WHITE}   ├─ URL:    {finding['url']}{C.END}")
        log("FINDING",f"{C.WHITE}   └─ Secret: {secret}{C.END}")
        alert=format_slack_message(status,finding['tool'],sev,finding['type'],secret,finding['url'])
        send_slack_alert(alert)
        sent_secrets.add(secret)
    if not sent_secrets: log("SUCCESS","All findings were low-confidence and logged locally.")
    else: log("SUCCESS","All high-priority alerts sent to Terminal and Slack.")

# --- Main Orchestrator ---
def main():
    parser=argparse.ArgumentParser(description="Apex Prowler v3.1 - The Inspector")
    parser.add_argument('-t','--targets',required=True,help="File containing target assets.")
    parser.add_argument('-g','--use-gau',action='store_true',help="Enable GAU for deep discovery.")
    args=parser.parse_args()
    display_banner();check_tools()
    od=os.path.join("results",f"apex_prowler_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}");os.makedirs(od,exist_ok=True)
    log("INFO",f"Results will be saved in: {C.WHITE}{od}{C.END}")
    hf=os.path.join(od,"d_hosts.txt");djf=os.path.join(od,"d_js.txt")
    with open(args.targets)as fi,open(hf,'w')as fh,open(djf,'w')as fj:
        for l in fi:
            l=l.strip();
            if not l:continue
            if ".js"in l:fj.write(l+'\n')
            else:h=l.replace("https://","").replace("http://","").split('/')[0];h and fh.write(h+'\n')
    juf=run_discovery(hf,djf,od,args.use_gau)
    # The dependency confusion module was removed for simplicity but can be re-added to the executor below if desired.
    if os.path.exists(juf)and os.path.getsize(juf)>0:run_secrets_scan(juf,od)
    log("SUCCESS",f"Apex Prowler scan finished. Logs are in {od}")

if __name__=="__main__":
    try:main()
    except KeyboardInterrupt:log("WARN","\nScan interrupted.");sys.exit(0)
