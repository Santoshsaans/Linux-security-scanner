# config.py
# Complete configuration with risk levels and thresholds

# ============================================
# THRESHOLDS
# ============================================

# Disk Usage
DISK_WARNING_THRESHOLD = 80
DISK_CRITICAL_THRESHOLD = 90

# Memory Usage
MEMORY_WARNING_THRESHOLD = 80
MEMORY_CRITICAL_THRESHOLD = 90

# CPU Usage
CPU_WARNING_THRESHOLD = 70
CPU_CRITICAL_THRESHOLD = 85

# Password Policy
PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_DAYS = 90

# ============================================
# RISK LEVELS & SCORING
# ============================================

RISK_LEVELS = {
    "pass": {"emoji": "✅", "label": "PASS", "score": 0},
    "low": {"emoji": "🟢", "label": "LOW", "score": 10},
    "medium": {"emoji": "🟡", "label": "MEDIUM", "score": 25},
    "high": {"emoji": "🔴", "label": "HIGH", "score": 50},
    "critical": {"emoji": "🚨", "label": "CRITICAL", "score": 75}
}

# ============================================
# CHECK DEFINITIONS WITH FIX RECOMMENDATIONS
# ============================================

SECURITY_CHECKS = {
    "firewall": {
        "check": "Firewall Status",
        "risk_if_fail": "high",
        "recommendation": "Enable UFW firewall",
        "fix_command": "sudo ufw enable && sudo ufw default deny incoming"
    },
    "ssh_root": {
        "check": "SSH Root Login",
        "risk_if_fail": "high",
        "recommendation": "Disable root login over SSH",
        "fix_command": "sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl restart sshd"
    },
    "ssh_password": {
        "check": "SSH Password Authentication",
        "risk_if_fail": "medium",
        "recommendation": "Use SSH keys instead of passwords",
        "fix_command": "sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl restart sshd"
    },
    "telnet": {
        "check": "Telnet Service",
        "risk_if_fail": "critical",
        "recommendation": "Telnet is insecure. Disable it and use SSH",
        "fix_command": "sudo systemctl stop telnet && sudo systemctl disable telnet"
    },
    "password_policy": {
        "check": "Password Policy",
        "risk_if_fail": "medium",
        "recommendation": f"Set minimum password length to {PASSWORD_MIN_LENGTH} days",
        "fix_command": f"sudo sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN {PASSWORD_MIN_LENGTH}/' /etc/login.defs"
    },
    "password_expiry": {
        "check": "Password Expiry",
        "risk_if_fail": "medium",
        "recommendation": f"Set password max age to {PASSWORD_MAX_DAYS} days",
        "fix_command": f"sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS {PASSWORD_MAX_DAYS}/' /etc/login.defs"
    },
    "updates": {
        "check": "System Updates",
        "risk_if_fail": "medium",
        "recommendation": "Install pending security updates",
        "fix_command": "sudo apt update && sudo apt upgrade -y"
    },
    "world_writable": {
        "check": "World Writable Files",
        "risk_if_fail": "high",
        "recommendation": "Remove world-writable permissions from critical files",
        "fix_command": "sudo chmod o-w /etc/passwd /etc/shadow /etc/sudoers"
    },
    "suid_files": {
        "check": "SUID Files",
        "risk_if_fail": "medium",
        "recommendation": "Review and remove unnecessary SUID permissions",
        "fix_command": "sudo find / -perm -4000 -type f -exec ls -l {} \\;"
    },
    "failed_logins": {
        "check": "Failed Login Attempts",
        "risk_if_fail": "low",
        "recommendation": "Monitor and investigate failed login attempts",
        "fix_command": "sudo fail2ban-client status"
    }
}