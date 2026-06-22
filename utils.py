# utils.py
# Complete utility functions for all phases

import subprocess
import platform
import re
from datetime import datetime

def run_command(command):
    """
    Run a Linux command and return its output as a string.
    """
    try:
        result = subprocess.run(
            command, 
            shell=True, 
            capture_output=True, 
            text=True,
            timeout=10
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return "Command timed out"
    except Exception as e:
        return f"Error: {e}"

def run_command_with_status(command):
    """
    Run a command and return (output, exit_code)
    """
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.stdout.strip(), result.returncode
    except Exception as e:
        return f"Error: {e}", 1

def get_os_info():
    """Get OS distribution name and version"""
    if subprocess.run("which lsb_release", shell=True, capture_output=True).returncode == 0:
        return run_command("lsb_release -ds")
    elif subprocess.run("test -f /etc/os-release", shell=True).returncode == 0:
        return run_command("grep '^PRETTY_NAME' /etc/os-release | cut -d'=' -f2 | tr -d '\"'")
    else:
        return run_command("uname -s -r")

def print_section_header(title):
    """Print a formatted section header"""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70)

def get_timestamp():
    """Get current timestamp for reports"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def get_date_for_filename():
    """Get date string for filenames"""
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def parse_percentage(output):
    """Extract percentage from command output"""
    try:
        numbers = re.findall(r'\d+', output)
        return int(numbers[0]) if numbers else 0
    except:
        return 0

def is_service_running(service_name):
    """Check if a service is running"""
    cmd = f"systemctl is-active {service_name} 2>/dev/null || service {service_name} status 2>/dev/null | grep -q 'running'"
    result = run_command(cmd)
    return "active" in result.lower() or "running" in result.lower()

def is_package_installed(package):
    """Check if a package is installed"""
    cmd = f"dpkg -l {package} 2>/dev/null | grep -q '^ii'"
    return subprocess.run(cmd, shell=True).returncode == 0