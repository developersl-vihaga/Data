import socket
import nmap
from datetime import datetime
from prettytable import PrettyTable

def get_os_info(ip):
    """Perform OS detection using nmap"""
    try:
        nm = nmap.PortScanner()
        print(f"\n🔍 Performing OS detection on {ip}...")
        nm.scan(hosts=ip, arguments='-O')
        
        for host in nm.all_hosts():
            if 'osmatch' in nm[host]:
                return nm[host]
        return None
    except Exception as e:
        print(f"❌ OS detection error: {e}")
        return None

def categorize_vulnerability(vuln_name):
    """Categorize vulnerabilities into common types"""
    vuln_lower = vuln_name.lower()
    
    categories = {
        'dos': 'Denial-of-Service',
        'denial': 'Denial-of-Service',
        'rce': 'Remote Code Execution',
        'remote code': 'Remote Code Execution',
        'sqli': 'SQL Injection',
        'sql injection': 'SQL Injection',
        'xss': 'Cross-Site Scripting',
        'csrf': 'Cross-Site Request Forgery',
        'auth': 'Authentication Bypass',
        'authentication': 'Authentication Bypass',
        'buffer': 'Buffer Overflow',
        'overflow': 'Buffer Overflow',
        'info': 'Information Disclosure',
        'disclosure': 'Information Disclosure',
        'ssl': 'Cryptographic Issues',
        'tls': 'Cryptographic Issues',
        'weak': 'Weak Configuration'
    }
    
    for key, category in categories.items():
        if key in vuln_lower:
            return category
    return 'General Vulnerability'

def determine_severity(vuln_name, output):
    """Determine vulnerability severity"""
    output_lower = str(output).lower()
    vuln_lower = vuln_name.lower()
    
    if 'critical' in output_lower or 'exploit' in output_lower:
        return 'High'
    elif 'heartbleed' in vuln_lower or 'shellshock' in vuln_lower:
        return 'High'
    elif 'warning' in output_lower or 'medium' in output_lower:
        return 'Medium'
    elif 'info' in output_lower or 'low' in output_lower:
        return 'Low'
    else:
        return 'Medium'

def scan_vulnerabilities(ip):
    """Perform vulnerability scanning"""
    try:
        nm = nmap.PortScanner()
        print(f"\n🔍 Scanning {ip} for vulnerabilities...")
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
        print(f"❌ Vulnerability scan error: {e}")
        return []

def print_fancy_report(ip, os_info, vulnerabilities):
    """Display beautiful report in console"""
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Header
    print("\n" + "="*45)
    print("|    NETWORK VULNERABILITY ASSESSMENT     |")
    print("="*45)
    
    # Target Info
    print(f"\n🔍 Target IP: {ip}")
    print(f"🕒 Scan Time: {current_time}")
    try:
        print(f"🌐 Hostname: {socket.getfqdn(ip)}")
    except:
        print("🌐 Hostname: Unknown")
    
    # OS Detection
    print("\n" + "-"*30)
    print("💻 OPERATING SYSTEM DETECTION")
    print("-"*30)
    if os_info and 'osmatch' in os_info:
        best_os = max(os_info['osmatch'], key=lambda x: int(x['accuracy']))
        print(f"✅ Detected OS: {best_os['name']} ({best_os['accuracy']}% confidence)")
        print("Possible matches:")
        for osmatch in os_info['osmatch'][:3]:  # Top 3 matches
            print(f"- {osmatch['name']} ({osmatch['accuracy']}%)")
    else:
        print("❌ OS detection failed")
    
    # Vulnerabilities
    if vulnerabilities:
        print("\n" + "-"*30)
        print("🚨 VULNERABILITY FINDINGS")
        print("-"*30)
        
        table = PrettyTable()
        table.field_names = ["Port", "Service", "Vulnerability", "Category", "Severity"]
        table.align = "l"
        
        for vuln in vulnerabilities:
            # Add emoji based on severity
            severity = ""
            if vuln['severity'] == "High":
                severity = "🔴 High"
            elif vuln['severity'] == "Medium":
                severity = "🟠 Medium"
            else:
                severity = "🟢 Low"
            
            table.add_row([
                vuln['port'],
                vuln['service'],
                vuln['name'],
                vuln['type'],
                severity
            ])
        
        print(table)
        
        # Summary
        print("\n" + "-"*25)
        print("📊 SUMMARY")
        print("-"*25)
        high = sum(1 for v in vulnerabilities if v['severity'] == "High")
        med = sum(1 for v in vulnerabilities if v['severity'] == "Medium")
        low = sum(1 for v in vulnerabilities if v['severity'] == "Low")
        print(f"🔴 Critical Vulnerabilities: {high}")
        print(f"🟠 Medium Vulnerabilities: {med}")
        print(f"🟢 Low Vulnerabilities: {low}")
        
        # Recommendations
        print("\n" + "-"*30)
        print("🔧 RECOMMENDED ACTIONS")
        print("-"*30)
        
        if high > 0:
            print("1. Immediately patch critical vulnerabilities")
        if any(v['type'] == 'Authentication Bypass' for v in vulnerabilities):
            print("2. Strengthen authentication mechanisms")
        if any(v['type'] == 'Denial-of-Service' for v in vulnerabilities):
            print("3. Implement DoS protection measures")
        if any(v['type'] == 'SQL Injection' for v in vulnerabilities):
            print("4. Sanitize database inputs and use prepared statements")
        print("5. Update all systems to latest versions")
        
    else:
        print("\n🎉 No vulnerabilities found!")
    
    # Footer
    print("\n" + "="*45)
    if vulnerabilities:
        print(f"|  SCAN COMPLETED - {len(vulnerabilities)} VULNERABILITIES FOUND |")
    else:
        print("|       SCAN COMPLETED - CLEAN SYSTEM       |")
    print("="*45)

def main():
    """Main function"""
    print("=== Professional Vulnerability Scanner ===")
    target_ip = input("Enter target IP address: ")
    
    # Perform scans
    os_info = get_os_info(target_ip)
    vulnerabilities = scan_vulnerabilities(target_ip)
    
    # Display report
    print_fancy_report(target_ip, os_info, vulnerabilities)

if __name__ == "__main__":
    main()
