#!/usr/bin/env python3
# scanner.py - Complete Linux Security Scanner (All Phases)

import os
import json
import csv
from datetime import datetime
from utils import *
from config import *

# ============================================
# PHASE 1: BASIC SYSTEM INFORMATION
# ============================================

def get_hostname():
    return run_command("hostname")

def get_logged_in_user():
    return run_command("whoami")

def get_kernel_version():
    return run_command("uname -r")

def get_uptime():
    return run_command("uptime -p")

def get_disk_usage():
    percent = run_command("df -h / | awk 'NR==2 {print $5}' | sed 's/%//'")
    full_output = run_command("df -h /")
    try:
        percent_int = int(percent) if percent else 0
    except:
        percent_int = 0
    
    status = "✅ OK"
    if percent_int >= DISK_CRITICAL_THRESHOLD:
        status = "🚨 CRITICAL"
    elif percent_int >= DISK_WARNING_THRESHOLD:
        status = "⚠️ WARNING"
    
    return percent_int, full_output, status

def get_memory_usage():
    total = run_command("free -m | awk 'NR==2 {print $2}'")
    available = run_command("free -m | awk 'NR==2 {print $7}'")
    full_output = run_command("free -h")
    
    try:
        total_int = int(total) if total else 1
        available_int = int(available) if available else 0
        used = total_int - available_int
        percent = round((used / total_int) * 100) if total_int > 0 else 0
    except:
        percent = 0
    
    status = "✅ OK"
    if percent >= DISK_CRITICAL_THRESHOLD:
        status = "🚨 CRITICAL"
    elif percent >= DISK_WARNING_THRESHOLD:
        status = "⚠️ WARNING"
    
    return percent, full_output, status

def get_cpu_usage():
    idle = run_command("top -bn1 | grep 'Cpu(s)' | awk '{print $8}' | cut -d'%' -f1")
    full_output = run_command("top -bn1 | head -5")
    
    try:
        idle_float = float(idle) if idle else 0
        used = round(100 - idle_float)
    except:
        used = 0
    
    status = "✅ OK"
    if used >= DISK_CRITICAL_THRESHOLD:
        status = "🚨 CRITICAL"
    elif used >= DISK_WARNING_THRESHOLD:
        status = "⚠️ WARNING"
    
    return used, full_output, status

def get_loaded_modules():
    return run_command("lsmod | wc -l")

def get_running_processes():
    return run_command("ps aux | wc -l")

# ============================================
# PHASE 2: SECURITY CHECKS
# ============================================

def check_firewall():
    """Check if firewall is enabled (UFW or iptables)"""
    # Check UFW first
    ufw_status = run_command("ufw status 2>/dev/null | grep -q 'Status: active' && echo 'active' || echo 'inactive'")
    if "active" in ufw_status.lower():
        return {"status": "Enabled", "risk": "pass", "details": "UFW is active"}
    
    # Check iptables
    iptables = run_command("sudo iptables -L 2>/dev/null | grep -v 'Chain' | grep -v 'target' | head -5")
    if iptables and len(iptables) > 10:
        return {"status": "Enabled", "risk": "pass", "details": "iptables rules detected"}
    
    return {"status": "Disabled", "risk": "high", "details": "No firewall detected"}

def check_ssh():
    """Check SSH configuration"""
    results = {}
    
    # Check if SSH is running
    ssh_running = is_service_running("ssh")
    results["running"] = ssh_running
    
    if not ssh_running:
        return {"status": "Not Running", "risk": "high", "details": "SSH service is not running"}
    
    # Check root login
    root_login = run_command("grep '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}'")
    if not root_login:
        root_login = "yes"  # Default is yes if not specified
    
    # Check password authentication
    password_auth = run_command("grep '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}'")
    if not password_auth:
        password_auth = "yes"  # Default is yes
    
    results["root_login"] = root_login
    results["password_auth"] = password_auth
    
    # Determine risk
    risk = "pass"
    details = []
    if root_login.lower() == "yes":
        risk = "high"
        details.append("Root login is enabled")
    if password_auth.lower() == "yes":
        if risk != "high":
            risk = "medium"
        details.append("Password authentication is enabled")
    
    if not details:
        details = ["SSH is securely configured"]
    
    return {
        "status": "Running",
        "risk": risk,
        "details": ", ".join(details),
        "root_login": root_login,
        "password_auth": password_auth
    }

def check_open_ports():
    """Check for open ports and identify dangerous ones"""
    # Get listening ports
    ports_output = run_command("ss -tuln | grep LISTEN | awk '{print $5}' | cut -d':' -f2 | sort -n")
    open_ports = [p for p in ports_output.split('\n') if p]
    
    # Dangerous ports
    dangerous_ports = {
        "21": "FTP (insecure, use SFTP)",
        "23": "Telnet (insecure, use SSH)",
        "25": "SMTP (potential for spam)",
        "110": "POP3 (insecure, use IMAP)",
        "143": "IMAP (insecure, use IMAPS)",
        "445": "SMB (Windows file sharing)",
        "3306": "MySQL (ensure secure configuration)",
        "5900": "VNC (ensure secure configuration)"
    }
    
    findings = []
    for port in open_ports:
        if port in dangerous_ports:
            findings.append(f"Port {port}: {dangerous_ports[port]}")
    
    risk = "pass"
    if findings:
        risk = "medium" if len(findings) <= 2 else "high"
    
    return {
        "open_ports": open_ports,
        "count": len(open_ports),
        "risk": risk,
        "findings": findings if findings else ["No dangerous ports detected"]
    }

def check_running_services():
    """Check running services and identify risky ones"""
    services = run_command("systemctl list-units --type=service --state=running | grep '.service' | awk '{print $1}'")
    service_list = [s for s in services.split('\n') if s]
    
    # Risky services to check
    risky_services = {
        "telnet": "Insecure remote access",
        "ftp": "Insecure file transfer",
        "rlogin": "Insecure remote login",
        "rexec": "Insecure remote execution",
        "rsh": "Insecure remote shell",
        "samba": "SMB file sharing (if not needed)",
        "httpd": "Web server (ensure secure)",
        "nginx": "Web server (ensure secure)",
        "mysql": "Database (ensure secure)",
        "postgresql": "Database (ensure secure)"
    }
    
    findings = []
    for service in service_list:
        service_lower = service.lower()
        for risky, reason in risky_services.items():
            if risky in service_lower:
                findings.append(f"{service}: {reason}")
    
    risk = "pass"
    if findings:
        risk = "medium" if len(findings) <= 2 else "high"
    
    return {
        "services": service_list,
        "count": len(service_list),
        "risk": risk,
        "findings": findings if findings else ["No risky services detected"]
    }

def check_installed_updates():
    """Check for pending system updates"""
    # Check apt updates (Debian/Ubuntu)
    run_command("sudo apt update 2>/dev/null")
    updates = run_command("apt list --upgradable 2>/dev/null | grep -c upgradable")
    
    try:
        update_count = int(updates) if updates else 0
    except:
        update_count = 0
    
    risk = "pass"
    if update_count > 10:
        risk = "high"
    elif update_count > 0:
        risk = "medium"
    
    return {
        "count": update_count,
        "risk": risk,
        "details": f"{update_count} updates available" if update_count > 0 else "System is up to date"
    }

def check_password_policy():
    """Check password policy settings"""
    # Check minimum password length
    min_len = run_command("grep '^PASS_MIN_LEN' /etc/login.defs 2>/dev/null | awk '{print $2}'")
    try:
        min_len_int = int(min_len) if min_len else 0
    except:
        min_len_int = 0
    
    # Check password expiration
    max_days = run_command("grep '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}'")
    try:
        max_days_int = int(max_days) if max_days else 0
    except:
        max_days_int = 0
    
    findings = []
    risk = "pass"
    
    if min_len_int < PASSWORD_MIN_LENGTH:
        risk = "medium"
        findings.append(f"Minimum password length is {min_len_int} (recommend {PASSWORD_MIN_LENGTH})")
    
    if max_days_int > PASSWORD_MAX_DAYS or max_days_int == 0:
        if risk != "medium":
            risk = "medium"
        findings.append(f"Password expiration is {max_days_int if max_days_int > 0 else 'disabled'} (recommend {PASSWORD_MAX_DAYS})")
    
    if not findings:
        findings = ["Password policy meets recommendations"]
    
    return {
        "min_length": min_len_int,
        "max_days": max_days_int,
        "risk": risk,
        "findings": findings
    }

# ============================================
# PHASE 3: ADVANCED SECURITY CHECKS
# ============================================

def check_world_writable_files():
    """Check for world-writable files in critical directories"""
    # Check specific critical directories only (for performance)
    critical_dirs = ["/etc", "/var", "/home", "/tmp"]
    findings = []
    
    for directory in critical_dirs:
        if os.path.exists(directory):
            cmd = f"find {directory} -type f -perm -0002 -ls 2>/dev/null | head -5"
            output = run_command(cmd)
            if output:
                # Count lines, limit to first 3
                lines = output.split('\n')[:3]
                for line in lines:
                    if line.strip():
                        findings.append(line)
    
    risk = "pass"
    if len(findings) > 0:
        risk = "medium" if len(findings) <= 5 else "high"
    
    return {
        "count": len(findings),
        "risk": risk,
        "findings": findings if findings else ["No world-writable files found in critical directories"],
        "warning": "Full system scan not performed for performance reasons"
    }

def check_suid_files():
    """Check for SUID files"""
    # Check common SUID file locations
    cmd = "find /bin /usr/bin /sbin /usr/sbin -perm -4000 -type f 2>/dev/null | head -10"
    output = run_command(cmd)
    
    findings = [f for f in output.split('\n') if f.strip()]
    
    risk = "pass"
    if len(findings) > 5:
        risk = "medium"
    elif len(findings) > 10:
        risk = "high"
    
    return {
        "count": len(findings),
        "risk": risk,
        "findings": findings if findings else ["No SUID files detected in standard locations"],
        "warning": "Limited to standard directories for performance"
    }

def check_cron_jobs():
    """Check scheduled cron jobs"""
    # Check system cron jobs
    system_cron = run_command("ls -la /etc/cron* 2>/dev/null")
    user_cron = run_command("crontab -l 2>/dev/null")
    
    findings = []
    if user_cron:
        findings.append("User cron jobs configured")
    if system_cron:
        findings.append("System cron jobs configured")
    
    risk = "pass"  # Cron jobs themselves aren't risky
    
    return {
        "has_system_cron": bool(system_cron),
        "has_user_cron": bool(user_cron),
        "risk": "pass",
        "findings": findings if findings else ["No cron jobs detected"]
    }

def check_failed_logins():
    """Check failed login attempts"""
    # Check lastlog for failed attempts
    cmd = "sudo lastb 2>/dev/null | head -20"
    output = run_command(cmd)
    failed_lines = [l for l in output.split('\n') if l.strip()]
    
    cmd2 = "sudo lastlog 2>/dev/null | grep -v 'Never' | wc -l"
    login_count = run_command(cmd2)
    
    risk = "pass"
    findings = []
    
    if len(failed_lines) > 10:
        risk = "medium"
        findings.append(f"{len(failed_lines)} failed login attempts detected")
    elif len(failed_lines) > 0:
        risk = "low"
        findings.append(f"{len(failed_lines)} failed login attempts detected")
    else:
        findings = ["No failed login attempts detected"]
    
    return {
        "failed_count": len(failed_lines),
        "risk": risk,
        "findings": findings
    }

def check_usb_devices():
    """Check for USB devices"""
    cmd = "lsusb 2>/dev/null"
    output = run_command(cmd)
    usb_lines = [l for l in output.split('\n') if l.strip()]
    
    return {
        "count": len(usb_lines),
        "devices": usb_lines if usb_lines else ["No USB devices detected"],
        "risk": "pass"  # USB devices aren't inherently risky
    }

def check_mounted_drives():
    """Check mounted drives"""
    cmd = "mount | grep -v 'tmpfs' | grep -v 'devtmpfs'"
    output = run_command(cmd)
    mounts = [m for m in output.split('\n') if m.strip()]
    
    # Check for network shares
    network_shares = [m for m in mounts if 'nfs' in m.lower() or 'cifs' in m.lower() or 'smb' in m.lower()]
    
    risk = "pass"
    if network_shares:
        risk = "low"
        findings = [f"Network shares mounted: {len(network_shares)}"]
    else:
        findings = ["No network shares detected"]
    
    return {
        "count": len(mounts),
        "network_shares": len(network_shares),
        "risk": risk,
        "findings": findings
    }

# ============================================
# MAIN SCANNER FUNCTION - RUNS ALL CHECKS
# ============================================

def run_full_scan():
    """Run all security checks and return comprehensive results"""
    print("\n" + "🚀" * 35)
    print("     COMPLETE LINUX SECURITY SCANNER - ALL PHASES")
    print("🚀" * 35)
    print(f"Scan Date: {get_timestamp()}")
    
    results = {
        "scan_timestamp": get_timestamp(),
        "phase1": {},
        "phase2": {},
        "phase3": {},
        "summary": {}
    }
    
    # ============================================
    # PHASE 1: Basic System Information
    # ============================================
    print_section_header("PHASE 1: BASIC SYSTEM INFORMATION")
    
    results["phase1"]["os_info"] = get_os_info()
    print(f"  Operating System: {results['phase1']['os_info']}")
    
    results["phase1"]["hostname"] = get_hostname()
    print(f"  Hostname: {results['phase1']['hostname']}")
    
    results["phase1"]["user"] = get_logged_in_user()
    print(f"  Logged-in User: {results['phase1']['user']}")
    
    results["phase1"]["kernel"] = get_kernel_version()
    print(f"  Kernel Version: {results['phase1']['kernel']}")
    
    results["phase1"]["uptime"] = get_uptime()
    print(f"  System Uptime: {results['phase1']['uptime']}")
    
    disk_percent, disk_output, disk_status = get_disk_usage()
    results["phase1"]["disk"] = {"percent": disk_percent, "status": disk_status}
    print(f"  Disk Usage: {disk_percent}% {disk_status}")
    
    mem_percent, mem_output, mem_status = get_memory_usage()
    results["phase1"]["memory"] = {"percent": mem_percent, "status": mem_status}
    print(f"  Memory Usage: {mem_percent}% {mem_status}")
    
    cpu_percent, cpu_output, cpu_status = get_cpu_usage()
    results["phase1"]["cpu"] = {"percent": cpu_percent, "status": cpu_status}
    print(f"  CPU Usage: {cpu_percent}% {cpu_status}")
    
    results["phase1"]["modules"] = get_loaded_modules()
    results["phase1"]["processes"] = get_running_processes()
    print(f"  Loaded Modules: {results['phase1']['modules']}")
    print(f"  Running Processes: {results['phase1']['processes']}")
    
    # ============================================
    # PHASE 2: Security Checks
    # ============================================
    print_section_header("PHASE 2: SECURITY CHECKS")
    
    # Firewall
    results["phase2"]["firewall"] = check_firewall()
    print(f"  Firewall: {results['phase2']['firewall']['status']} [{results['phase2']['firewall']['risk'].upper()}]")
    
    # SSH
    results["phase2"]["ssh"] = check_ssh()
    print(f"  SSH: {results['phase2']['ssh']['status']} [{results['phase2']['ssh']['risk'].upper()}]")
    if "details" in results["phase2"]["ssh"]:
        print(f"    → {results['phase2']['ssh']['details']}")
    
    # Open Ports
    results["phase2"]["ports"] = check_open_ports()
    print(f"  Open Ports: {results['phase2']['ports']['count']} found [{results['phase2']['ports']['risk'].upper()}]")
    for finding in results["phase2"]["ports"]["findings"][:3]:
        print(f"    → {finding}")
    
    # Running Services
    results["phase2"]["services"] = check_running_services()
    print(f"  Running Services: {results['phase2']['services']['count']} found [{results['phase2']['services']['risk'].upper()}]")
    for finding in results["phase2"]["services"]["findings"][:3]:
        print(f"    → {finding}")
    
    # Updates
    results["phase2"]["updates"] = check_installed_updates()
    print(f"  Updates: {results['phase2']['updates']['details']} [{results['phase2']['updates']['risk'].upper()}]")
    
    # Password Policy
    results["phase2"]["password"] = check_password_policy()
    print(f"  Password Policy: [{results['phase2']['password']['risk'].upper()}]")
    for finding in results["phase2"]["password"]["findings"]:
        print(f"    → {finding}")
    
    # ============================================
    # PHASE 3: Advanced Security Checks
    # ============================================
    print_section_header("PHASE 3: ADVANCED SECURITY CHECKS")
    
    # World Writable Files
    results["phase3"]["world_writable"] = check_world_writable_files()
    print(f"  World Writable Files: {results['phase3']['world_writable']['count']} found [{results['phase3']['world_writable']['risk'].upper()}]")
    for finding in results["phase3"]["world_writable"]["findings"][:3]:
        print(f"    → {finding}")
    
    # SUID Files
    results["phase3"]["suid"] = check_suid_files()
    print(f"  SUID Files: {results['phase3']['suid']['count']} found [{results['phase3']['suid']['risk'].upper()}]")
    
    # Cron Jobs
    results["phase3"]["cron"] = check_cron_jobs()
    print(f"  Cron Jobs: {results['phase3']['cron']['risk'].upper()}")
    for finding in results["phase3"]["cron"]["findings"]:
        print(f"    → {finding}")
    
    # Failed Logins
    results["phase3"]["failed_logins"] = check_failed_logins()
    print(f"  Failed Logins: {results['phase3']['failed_logins']['failed_count']} attempts [{results['phase3']['failed_logins']['risk'].upper()}]")
    for finding in results["phase3"]["failed_logins"]["findings"]:
        print(f"    → {finding}")
    
    # USB Devices
    results["phase3"]["usb"] = check_usb_devices()
    print(f"  USB Devices: {results['phase3']['usb']['count']} found")
    
    # Mounted Drives
    results["phase3"]["mounted"] = check_mounted_drives()
    print(f"  Mounted Drives: {results['phase3']['mounted']['count']} total, {results['phase3']['mounted']['network_shares']} network shares [{results['phase3']['mounted']['risk'].upper()}]")
    
    # ============================================
    # SUMMARY & SCORING
    # ============================================
    results["summary"] = calculate_summary(results)
    
    print_section_header("SECURITY SUMMARY")
    print(f"  ✅ PASS: {results['summary']['pass']}")
    print(f"  🟢 LOW: {results['summary']['low']}")
    print(f"  🟡 MEDIUM: {results['summary']['medium']}")
    print(f"  🔴 HIGH: {results['summary']['high']}")
    print(f"  🚨 CRITICAL: {results['summary']['critical']}")
    print(f"\n  📊 OVERALL SECURITY SCORE: {results['summary']['score']}/100")
    
    security_level = "EXCELLENT" if results['summary']['score'] >= 90 else \
                     "GOOD" if results['summary']['score'] >= 70 else \
                     "FAIR" if results['summary']['score'] >= 50 else "POOR"
    print(f"  📈 SECURITY LEVEL: {security_level}")
    
    return results

def calculate_summary(results):
    """Calculate security summary and score"""
    # Count risks by level
    risk_counts = {"pass": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    total_checks = 0
    
    # Phase 2 checks
    for key, value in results["phase2"].items():
        if isinstance(value, dict) and "risk" in value:
            risk = value["risk"]
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
            total_checks += 1
    
    # Phase 3 checks
    for key, value in results["phase3"].items():
        if isinstance(value, dict) and "risk" in value:
            risk = value["risk"]
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
            total_checks += 1
    
    # Calculate score (100 - sum of risk weights)
    risk_weights = {"pass": 0, "low": 5, "medium": 15, "high": 30, "critical": 50}
    total_penalty = sum(risk_counts[risk] * risk_weights.get(risk, 0) for risk in risk_counts)
    max_penalty = total_checks * 50
    score = max(0, 100 - (total_penalty / max_penalty * 100)) if total_checks > 0 else 100
    
    return {
        "pass": risk_counts["pass"],
        "low": risk_counts["low"],
        "medium": risk_counts["medium"],
        "high": risk_counts["high"],
        "critical": risk_counts["critical"],
        "score": round(score, 1),
        "total_checks": total_checks
    }

# ============================================
# REPORT GENERATION
# ============================================

def save_report_txt(results, filename=None):
    """Save results as text file"""
    if not filename:
        filename = f"reports/security_report_{get_date_for_filename()}.txt"
    
    os.makedirs("reports", exist_ok=True)
    
    with open(filename, 'w') as f:
        f.write("="*70 + "\n")
        f.write("  LINUX SECURITY SCANNER REPORT\n")
        f.write("="*70 + "\n")
        f.write(f"Scan Date: {results['scan_timestamp']}\n\n")
        
        # Phase 1
        f.write("PHASE 1: BASIC SYSTEM INFORMATION\n")
        f.write("-"*70 + "\n")
        for key, value in results["phase1"].items():
            if isinstance(value, dict):
                f.write(f"  {key}: {value}\n")
            else:
                f.write(f"  {key}: {value}\n")
        
        # Phase 2
        f.write("\nPHASE 2: SECURITY CHECKS\n")
        f.write("-"*70 + "\n")
        for key, value in results["phase2"].items():
            if isinstance(value, dict):
                f.write(f"  {key.upper()}:\n")
                for k, v in value.items():
                    f.write(f"    {k}: {v}\n")
            else:
                f.write(f"  {key}: {value}\n")
        
        # Phase 3
        f.write("\nPHASE 3: ADVANCED SECURITY CHECKS\n")
        f.write("-"*70 + "\n")
        for key, value in results["phase3"].items():
            if isinstance(value, dict):
                f.write(f"  {key.upper()}:\n")
                for k, v in value.items():
                    f.write(f"    {k}: {v}\n")
            else:
                f.write(f"  {key}: {value}\n")
        
        # Summary
        f.write("\n" + "="*70 + "\n")
        f.write("  SECURITY SUMMARY\n")
        f.write("="*70 + "\n")
        for key, value in results["summary"].items():
            f.write(f"  {key}: {value}\n")
    
    return filename

def save_report_csv(results, filename=None):
    """Save results as CSV file"""
    if not filename:
        filename = f"reports/security_report_{get_date_for_filename()}.csv"
    
    os.makedirs("reports", exist_ok=True)
    
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Category", "Check", "Status", "Risk", "Details"])
        
        # Phase 2 checks
        for key, value in results["phase2"].items():
            if isinstance(value, dict):
                status = value.get("status", "N/A")
                risk = value.get("risk", "N/A")
                details = value.get("details", value.get("findings", ["N/A"])[0])
                writer.writerow(["Phase 2", key, status, risk, details])
        
        # Phase 3 checks
        for key, value in results["phase3"].items():
            if isinstance(value, dict):
                status = "OK" if value.get("risk") == "pass" else "Warning"
                risk = value.get("risk", "N/A")
                details = value.get("findings", ["N/A"])[0] if "findings" in value else str(value)
                writer.writerow(["Phase 3", key, status, risk, details])
    
    return filename

def save_report_json(results, filename=None):
    """Save results as JSON file"""
    if not filename:
        filename = f"reports/security_report_{get_date_for_filename()}.json"
    
    os.makedirs("reports", exist_ok=True)
    
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    return filename

# ============================================
# COMMAND-LINE INTERFACE
# ============================================

if __name__ == "__main__":
    import sys
    
    print("\n🔐 LINUX SECURITY SCANNER")
    print("-"*70)
    
    # Run the scan
    results = run_full_scan()
    
    # Save reports
    txt_file = save_report_txt(results)
    csv_file = save_report_csv(results)
    json_file = save_report_json(results)
    
    print_section_header("REPORTS SAVED")
    print(f"  📄 TXT: {txt_file}")
    print(f"  📊 CSV: {csv_file}")
    print(f"  📋 JSON: {json_file}")
    print("\n" + "="*70)
    print("  ✅ SCAN COMPLETE! Thank you for using Linux Security Scanner.")
    print("="*70)